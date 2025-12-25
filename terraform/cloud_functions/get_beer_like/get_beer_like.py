import os
import json
from typing import Any, Dict, Optional

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
BEER_LIKES_TABLE = f"{PROJECT_ID}.{DATASET_ID}.beer_likes" if PROJECT_ID and DATASET_ID else None
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


def normalize_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        trimmed = value.strip()
        return trimmed if trimmed else None
    return str(value)


def fetch_beer_like(table: str, cuid: str, beer_name: str) -> Optional[Dict[str, Any]]:
    query = f"""
    SELECT cuid, beer_name, beer_id, ind_like_status, ind_starred, user_rating, user_comments
    FROM `{table}`
    WHERE cuid = @cuid AND beer_name = @beer_name
    LIMIT 1
    """
    params = [
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
        bigquery.ScalarQueryParameter("beer_name", "STRING", beer_name),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    return dict(rows[0]) if rows else None


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    if not JWT_SECRET:
        return error_response("Server misconfigured: missing JWT_SECRET", 500, request)
    if not BEER_LIKES_TABLE:
        return error_response("Server misconfigured: missing PROJECT_ID or DATASET_ID", 500, request)

    claims = verify_token(request)
    if claims is None:
        return error_response("Unauthorized", 401, request)

    if request.method.upper() != "POST":
        return error_response("Method not allowed", 405, request)

    try:
        body = request.get_json(silent=True) or {}
        cuid = normalize_string(body.get("cuid")) or ""
        beer_name = normalize_string(body.get("beer_name")) or ""

        if not cuid:
            return error_response("Missing required field: cuid", 400, request)
        if not beer_name:
            return error_response("Missing required field: beer_name", 400, request)

        record = fetch_beer_like(BEER_LIKES_TABLE, cuid, beer_name)
        resp = make_response(json.dumps({"like": record}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except Exception as e:
        return error_response(str(e), 500, request)
