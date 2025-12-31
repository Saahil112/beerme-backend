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


def search_users_by_username(prefix: str, exclude_cuid: str = None, limit: int = 5) -> List[Dict[str, Any]]:
    if not USERS_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")
    
    query = f"""
    SELECT 
    distinct users.cuid
    , users.username
    , users.first_name
    , users.last_name
    , users.profile_pic_url
    , buddies.status AS buddy_status
    FROM `{USERS_TABLE}` users
    LEFT JOIN `{BUDDIES_TABLE}` AS buddies ON users.cuid = buddies.friend_cuid
    WHERE users.username IS NOT NULL
        AND LOWER(users.username) LIKE CONCAT(LOWER(@prefix), '%')
        AND users.cuid != @exclude_cuid
    ORDER BY users.username ASC
    LIMIT @limit
    """
    params = [
        bigquery.ScalarQueryParameter("prefix", "STRING", prefix),
        bigquery.ScalarQueryParameter("exclude_cuid", "STRING", exclude_cuid or ""),
        bigquery.ScalarQueryParameter("limit", "INT64", limit),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = client.query(query, job_config=job_config).result()
    return [dict(r) for r in rows]


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
        q = (body.get("q") or "").strip()
        limit_raw = body.get("limit")
        try:
            limit = int(limit_raw) if limit_raw is not None else 5
        except (TypeError, ValueError):
            limit = 5

        if not q:
            resp = make_response(json.dumps({"results": []}), 200)
            resp.headers.set("Content-Type", "application/json")
            return set_cors_headers(resp, request)

        # Extract current user's cuid from JWT claims to exclude from results
        current_user_cuid = claims.get("sub")
        
        results = search_users_by_username(q, exclude_cuid=current_user_cuid, limit=limit)
        resp = make_response(json.dumps({"results": results}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except Exception as e:
        return error_response(str(e), 500, request)
