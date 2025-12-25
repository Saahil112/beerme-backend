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


def to_bool_or_none(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ValueError("Boolean fields must be true, false, or null")


def parse_rating(value: Any) -> Optional[str]:
    """Validate rating in [0, 5] and return a normalized string."""
    if value is None:
        return None
    try:
        rating = float(value)
    except (TypeError, ValueError):
        raise ValueError("user_rating must be numeric")
    if rating < 0 or rating > 5:
        raise ValueError("user_rating must be between 0 and 5")
    # store as string to match table schema
    return str(rating)


def upsert_beer_like(
    table: str,
    cuid: str,
    beer_name: str,
    beer_id: Optional[str],
    ind_like_status: Optional[bool],
    user_rating: Optional[str],
    user_comments: Optional[str],
    ind_starred: Optional[bool],
) -> Dict[str, Any]:
    merge_sql = f"""
    MERGE `{table}` AS t
    USING (
      SELECT
        @cuid AS cuid,
        @beer_name AS beer_name,
        @beer_id AS beer_id,
        @ind_like_status AS ind_like_status,
        @user_rating AS user_rating,
        @user_comments AS user_comments,
        @ind_starred AS ind_starred
    ) AS s
    ON t.cuid = s.cuid AND t.beer_name = s.beer_name
    WHEN MATCHED THEN UPDATE SET
      beer_id = COALESCE(s.beer_id, t.beer_id),
      ind_like_status = COALESCE(s.ind_like_status, t.ind_like_status),
      user_rating = COALESCE(s.user_rating, t.user_rating),
      user_comments = COALESCE(s.user_comments, t.user_comments),
      ind_starred = COALESCE(s.ind_starred, t.ind_starred)
    WHEN NOT MATCHED THEN
      INSERT (cuid, beer_name, beer_id, ind_like_status, user_rating, user_comments, ind_starred)
      VALUES (s.cuid, s.beer_name, s.beer_id, s.ind_like_status, s.user_rating, s.user_comments, s.ind_starred)
    """

    params = [
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
        bigquery.ScalarQueryParameter("beer_name", "STRING", beer_name),
        bigquery.ScalarQueryParameter("beer_id", "STRING", beer_id),
        bigquery.ScalarQueryParameter("ind_like_status", "BOOL", ind_like_status),
        bigquery.ScalarQueryParameter("user_rating", "STRING", user_rating),
        bigquery.ScalarQueryParameter("user_comments", "STRING", user_comments),
        bigquery.ScalarQueryParameter("ind_starred", "BOOL", ind_starred),
    ]
    merge_config = bigquery.QueryJobConfig(query_parameters=params)
    client.query(merge_sql, job_config=merge_config).result()

    select_sql = f"""
    SELECT cuid, beer_name, beer_id, ind_like_status, user_rating, user_comments, ind_starred
    FROM `{table}`
    WHERE cuid = @cuid AND beer_name = @beer_name
    LIMIT 1
    """
    select_config = bigquery.QueryJobConfig(query_parameters=params[:2])
    rows = list(client.query(select_sql, job_config=select_config).result())
    return dict(rows[0]) if rows else {}


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
        beer_id = normalize_string(body.get("beer_id"))
        ind_like_status = to_bool_or_none(body.get("ind_like_status"))
        ind_starred = to_bool_or_none(body.get("ind_starred"))
        user_rating = parse_rating(body.get("user_rating"))
        user_comments = normalize_string(body.get("user_comments"))

        if not cuid:
            return error_response("Missing required field: cuid", 400, request)
        if not beer_name:
            return error_response("Missing required field: beer_name", 400, request)

        has_mutations = any(
            value is not None
            for value in [beer_id, ind_like_status, ind_starred, user_rating, user_comments]
        )
        if not has_mutations:
            return error_response("At least one of ind_like_status, ind_starred, user_rating, user_comments, or beer_id must be provided", 400, request)

        record = upsert_beer_like(
            BEER_LIKES_TABLE,
            cuid,
            beer_name,
            beer_id,
            ind_like_status,
            user_rating,
            user_comments,
            ind_starred,
        )

        resp = make_response(json.dumps({"like": record}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 400, request)
    except Exception as e:
        return error_response(str(e), 500, request)
