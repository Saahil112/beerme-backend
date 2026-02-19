import os
import json
from typing import Any, Dict, Optional

from flask import make_response
import jwt
from google.cloud import bigquery

client = bigquery.Client()

ALLOWED_ORIGINS = {
    "https://innerbeer.com",
    "https://www.innerbeer.com",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}

PROJECT_ID = os.environ.get("PROJECT_ID")
DATASET_ID = os.environ.get("DATASET_ID")
USERS_TABLE = f"{PROJECT_ID}.{DATASET_ID}.users" if PROJECT_ID and DATASET_ID else None
BALANCES_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.balances" if PROJECT_ID and DATASET_ID else None
)
REQUIRED_SCOPE = "recommendations:read"
JWT_SECRET = os.environ.get("JWT_SECRET")


def verify_token(request) -> Optional[Dict[str, Any]]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        if not JWT_SECRET:
            # Missing server config for JWT secret
            return None
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        scopes = decoded.get("scopes", [])
        if REQUIRED_SCOPE not in scopes:
            return None
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


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


def fetch_user_by_cuid(cuid: str) -> Optional[Dict[str, Any]]:
    if not USERS_TABLE:
        raise ValueError("Server misconfigured: PROJECT_ID/DATASET_ID not set")

    query = f"""
    SELECT
        u.first_name
        , u.last_name
        , u.email
        , u.profile_pic_url
        , u.username
        , u.created_at
        , u.updated_at
        , u.ind_first_time_user
        , u.user_level
        , u.count_brews_chugged
        , u.count_brews_commented
        , u.count_brews_liked
        , u.count_brews_disliked
        , u.count_brews_rated
        , u.count_brews_starred
        , u.count_brews_wishlisted
        , COALESCE(b.balance, 0) AS balance
    FROM `{USERS_TABLE}` u
    LEFT JOIN `{BALANCES_TABLE}` b
        ON u.cuid = b.cuid AND b.wallet_type = 'BOTTLE_CAPS'
    WHERE u.cuid = @cuid
    LIMIT 1
    """
    params = [bigquery.ScalarQueryParameter("cuid", "STRING", cuid)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    if not rows:
        return None
    row = rows[0]
    return {
        "first_name": row.first_name,
        "last_name": row.last_name,
        "email": row.email,
        "profile_pic_url": row.profile_pic_url,
        "username": row.username,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "ind_first_time_user": bool(row.ind_first_time_user)
        if row.ind_first_time_user is not None
        else False,
        "user_level": int(row.user_level)
        if getattr(row, "user_level", None) is not None
        else None,
        "count_brews_chugged": int(row.count_brews_chugged)
        if getattr(row, "count_brews_chugged", None) is not None
        else 0,
        "count_brews_commented": int(row.count_brews_commented)
        if getattr(row, "count_brews_commented", None) is not None
        else 0,
        "count_brews_liked": int(row.count_brews_liked)
        if getattr(row, "count_brews_liked", None) is not None
        else 0,
        "count_brews_disliked": int(row.count_brews_disliked)
        if getattr(row, "count_brews_disliked", None) is not None
        else 0,
        "count_brews_rated": int(row.count_brews_rated)
        if getattr(row, "count_brews_rated", None) is not None
        else 0,
        "count_brews_starred": int(row.count_brews_starred)
        if getattr(row, "count_brews_starred", None) is not None
        else 0,
        "count_brews_wishlisted": int(row.count_brews_wishlisted)
        if getattr(row, "count_brews_wishlisted", None) is not None
        else 0,
        "balance": int(row.balance) if getattr(row, "balance", None) is not None else 0,
    }


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        # Require Authorization token and derive cuid from it
        claims = verify_token(request)
        if claims is None:
            return error_response("Unauthorized", 401, request)

        cuid = claims.get("cuid") or claims.get("sub") or claims.get("email")
        if not cuid:
            return error_response(
                "Missing required field: cuid (derive from Authorization token)",
                400,
                request,
            )

        user = fetch_user_by_cuid(cuid)
        resp = make_response(json.dumps({"user": user}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 500, request)
    except Exception as e:
        return error_response(str(e), 500, request)
