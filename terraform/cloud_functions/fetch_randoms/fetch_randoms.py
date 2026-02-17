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
COMPILED_DATA_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.compiled_data" if PROJECT_ID and DATASET_ID else None
)
REQUIRED_SCOPE = "recommendations:read"
DEFAULT_LIMIT = 10
MAX_LIMIT = 100


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


def parse_limit(value: Any) -> int:
    if value is None:
        return DEFAULT_LIMIT
    try:
        limit = int(value)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer")
    if limit <= 0:
        raise ValueError("limit must be greater than 0")
    return min(limit, MAX_LIMIT)


def fetch_randoms(table: str, limit: int) -> List[Dict[str, Any]]:
    query = f"""
    SELECT *
    FROM `{table}`
    ORDER BY RAND()
    LIMIT @limit
    """
    params = [
        bigquery.ScalarQueryParameter("limit", "INT64", limit),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = client.query(query, job_config=job_config).result()
    return [dict(r) for r in rows]


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    if not COMPILED_DATA_TABLE:
        return error_response(
            "Server misconfigured: missing PROJECT_ID or DATASET_ID", 500, request
        )

    if request.method.upper() != "POST":
        return error_response("Method not allowed", 405, request)

    try:
        body = request.get_json(silent=True) or {}
        limit = parse_limit(body.get("limit"))

        results = fetch_randoms(COMPILED_DATA_TABLE, limit)
        resp = make_response(json.dumps({"data": results}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 400, request)
    except Exception as e:
        return error_response(str(e), 500, request)
