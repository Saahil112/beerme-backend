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
LEVELS_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.levels" if PROJECT_ID and DATASET_ID else None
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


def fetch_user_counts_and_level(cuid: str) -> Optional[Dict[str, Any]]:
    if not USERS_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    query = f"""
    SELECT count_brews_chugged, user_level
    FROM `{USERS_TABLE}`
    WHERE cuid = @cuid
    LIMIT 1
    """
    params = [bigquery.ScalarQueryParameter("cuid", "STRING", cuid)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    if not rows:
        return None
    row = dict(rows[0])
    return row


def find_level_for_count(count: int) -> Optional[int]:
    if not LEVELS_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    query = f"""
    SELECT level_rank
    FROM `{LEVELS_TABLE}`
    WHERE @count >= lower_threshold
    AND @count <= upper_threshold
    ORDER BY level_rank DESC
    LIMIT 1
    """
    params = [bigquery.ScalarQueryParameter("count", "INT64", count)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    if not rows:
        return None
    return int(rows[0]["level_rank"])


def update_user_level_in_table(cuid: str, new_level: int) -> None:
    if not USERS_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    query = f"""
    UPDATE `{USERS_TABLE}`
    SET user_level = @new_level, updated_at = CURRENT_TIMESTAMP()
    WHERE cuid = @cuid
    """
    params = [
        bigquery.ScalarQueryParameter("new_level", "INT64", new_level),
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    client.query(query, job_config=job_config).result()


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

        user_row = fetch_user_counts_and_level(cuid)
        if user_row is None:
            return error_response("User not found", 404, request)

        count = user_row.get("count_brews_chugged") or 0
        existing_user_level = user_row.get("user_level")
        try:
            existing_user_level_int = (
                int(existing_user_level) if existing_user_level is not None else -1
            )
        except Exception:
            existing_user_level_int = -1

        level_rank = find_level_for_count(int(count))
        if level_rank is None:
            resp = make_response(
                json.dumps(
                    {
                        "updated": False,
                        "reason": "no_matching_level",
                        "previous_user_level": existing_user_level,
                        "computed_level_rank": None,
                    }
                ),
                200,
            )
            resp.headers.set("Content-Type", "application/json")
            return set_cors_headers(resp, request)

        updated = False
        if level_rank >= existing_user_level_int:
            update_user_level_in_table(cuid, level_rank)
            updated = True

        resp = make_response(
            json.dumps(
                {
                    "updated": updated,
                    "previous_user_level": existing_user_level,
                    "computed_level_rank": level_rank,
                }
            ),
            200,
        )
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 500, request)
    except Exception as e:
        return error_response(str(e), 500, request)
