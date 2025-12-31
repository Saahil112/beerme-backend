import os
import json
from typing import Any, Dict, List, Optional

import jwt
from flask import make_response
from google.cloud import bigquery

client = bigquery.Client()

ALLOWED_ORIGINS = {
    "https://innerbeer.com",
    "https://www.innerbeer.com",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}

JWT_SECRET = os.environ.get("JWT_SECRET")
PROJECT_ID = os.environ.get("PROJECT_ID")
DATASET_ID = os.environ.get("DATASET_ID")
USERS_TABLE = f"{PROJECT_ID}.{DATASET_ID}.users" if PROJECT_ID and DATASET_ID else None
BUDDIES_TABLE = f"{PROJECT_ID}.{DATASET_ID}.buddies" if PROJECT_ID and DATASET_ID else None
REQUIRED_SCOPE = "recommendations:read"


def set_cors_headers(response, request=None):
    origin = request.headers.get("Origin") if request else None
    allow_origin = origin if origin in ALLOWED_ORIGINS else "https://innerbeer.com"
    response.headers.set("Access-Control-Allow-Origin", allow_origin)
    response.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS")
    response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.set("Access-Control-Max-Age", "3600")
    response.headers.set("Vary", "Origin")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


def error_response(message: str, status: int = 400, request=None):
    resp = make_response(json.dumps({"error": message}), status)
    resp.headers.set("Content-Type", "application/json")
    return set_cors_headers(resp, request)


def verify_token(request) -> Optional[Dict[str, Any]]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        scopes = decoded.get("scopes", [])
        if REQUIRED_SCOPE not in scopes:
            return None
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def list_pending_requests(cuid: str, limit: int = 50) -> List[Dict[str, Any]]:
    if not USERS_TABLE or not BUDDIES_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    query = f"""
    SELECT
      u.cuid,
      u.username,
      u.first_name,
      u.last_name,
      u.profile_pic_url,
      b.requested_at
    FROM `{BUDDIES_TABLE}` AS b
    LEFT JOIN `{USERS_TABLE}` AS u
      ON b.cuid = u.cuid
    WHERE b.friend_cuid = @cuid
      AND b.status = 'pending'
    ORDER BY b.requested_at DESC
    LIMIT @limit
    """
    params = [
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
        bigquery.ScalarQueryParameter("limit", "INT64", limit),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = client.query(query, job_config=job_config).result()
    result = []
    for r in rows:
        row_dict = dict(r)
        if row_dict.get("requested_at"):
            row_dict["requested_at"] = row_dict["requested_at"].isoformat()
        result.append(row_dict)
    return result


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    if not JWT_SECRET:
        return error_response("Server misconfigured: missing JWT_SECRET", 500, request)

    claims = verify_token(request)
    if claims is None:
        return error_response("Unauthorized", 401, request)

    if request.method.upper() != "POST":
        return error_response("Method not allowed", 405, request)

    try:
        body = request.get_json(silent=True) or {}
        limit_raw = body.get("limit")
        try:
            limit = int(limit_raw) if limit_raw is not None else 50
        except (TypeError, ValueError):
            limit = 50

        # Prefer explicit cuid from body; fallback to JWT `sub`
        cuid = (body.get("cuid") or claims.get("sub") or "").strip()
        if not cuid:
            return error_response("Missing required field: cuid", 400, request)

        results = list_pending_requests(cuid, limit)
        resp = make_response(json.dumps({"requests": results}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except Exception as e:
        return error_response(str(e), 500, request)
