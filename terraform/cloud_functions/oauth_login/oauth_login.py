import os
import json
from typing import Any, Dict, Optional

import jwt
from flask import make_response
from google.cloud import bigquery
from google.oauth2 import id_token
from google.auth.transport import requests

client = bigquery.Client()

ALLOWED_ORIGINS = {"https://innerbeer.com", "https://www.innerbeer.com", "http://localhost:3000", "http://127.0.0.1:3000"}
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
PROJECT_ID = os.environ.get("PROJECT_ID")
DATASET_ID = os.environ.get("DATASET_ID")
USERS_TABLE = f"{PROJECT_ID}.{DATASET_ID}.users" if PROJECT_ID and DATASET_ID else None


def set_cors_headers(response, request=None):
    origin = None
    if request is not None:
        origin = request.headers.get("Origin")
    allow_origin = origin if origin in ALLOWED_ORIGINS else "https://innerbeer.com"
    response.headers.set("Access-Control-Allow-Origin", allow_origin)
    response.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS")
    response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.set("Vary", "Origin")
    response.headers.set("Access-Control-Max-Age", "3600")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


def error_response(message: str, status: int = 400, request=None):
    resp = make_response(json.dumps({"error": message}), status)
    resp.headers.set("Content-Type", "application/json")
    return set_cors_headers(resp, request)


from typing import Tuple

def split_name(full_name: Optional[str]) -> Tuple[str, Optional[str]]:
    if not full_name:
        return "", None
    parts = full_name.strip().split()
    if len(parts) == 0:
        return "", None
    if len(parts) == 1:
        return parts[0], None
    return parts[0], " ".join(parts[1:])


def upsert_user(cuid: str, email: str, first_name: str, last_name: Optional[str], profile_pic_url: Optional[str]) -> Dict[str, Any]:
    if not USERS_TABLE:
        raise ValueError("Server misconfigured: PROJECT_ID/DATASET_ID not set")

    query = f"""
    MERGE `{USERS_TABLE}` AS t
    USING (
      SELECT
        @cuid AS cuid,
        @first_name AS first_name,
        @last_name AS last_name,
        @email AS email,
        @profile_pic_url AS profile_pic_url
    ) AS s
    ON t.email = s.email
    WHEN MATCHED THEN UPDATE SET
      t.cuid = s.cuid,
      t.first_name = s.first_name,
      t.last_name = s.last_name,
      t.profile_pic_url = s.profile_pic_url
    WHEN NOT MATCHED THEN INSERT (cuid, first_name, last_name, email, profile_pic_url)
    VALUES (s.cuid, s.first_name, s.last_name, s.email, s.profile_pic_url)
    """

    params = [
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
        bigquery.ScalarQueryParameter("first_name", "STRING", first_name),
        bigquery.ScalarQueryParameter("last_name", "STRING", last_name),
        bigquery.ScalarQueryParameter("email", "STRING", email),
        bigquery.ScalarQueryParameter("profile_pic_url", "STRING", profile_pic_url),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    client.query(query, job_config=job_config).result()
    return {
        "cuid": cuid,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "profile_pic_url": profile_pic_url,
    }


def verify_google_id_token(token: str) -> Dict[str, Any]:
    if not OAUTH_CLIENT_ID:
        raise ValueError("Server misconfigured: missing OAUTH_CLIENT_ID")
    req = requests.Request()
    return id_token.verify_oauth2_token(token, req, OAUTH_CLIENT_ID)


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        body = request.get_json(silent=True) or {}
        token = body.get("id_token")
        if not token:
            return error_response("id_token is required", 400, request)

        claims = verify_google_id_token(token)
        cuid = claims.get("sub")
        email = claims.get("email")

        # Prefer explicit body overrides, else map Google fields
        name = body.get("name") or claims.get("name")
        first_name_override = body.get("first_name")
        last_name_override = body.get("last_name")
        if first_name_override is not None or last_name_override is not None:
            first_name = first_name_override or ""
            last_name = last_name_override
        else:
            first_name, last_name = split_name(name)

        profile_pic_url = body.get("profile_pic_url") or claims.get("picture")

        if not cuid or not email or not first_name:
            return error_response("missing required fields (cuid/email/first_name)", 400, request)

        user = upsert_user(cuid, email, first_name, last_name, profile_pic_url)

        resp = make_response(json.dumps({"user": user}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 400, request)
    except Exception as e:
        return error_response(str(e), 500, request)
