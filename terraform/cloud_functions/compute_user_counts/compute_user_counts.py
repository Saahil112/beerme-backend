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
BEER_LIKES_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.beer_likes" if PROJECT_ID and DATASET_ID else None
)
USERS_TABLE = f"{PROJECT_ID}.{DATASET_ID}.users" if PROJECT_ID and DATASET_ID else None
REQUIRED_SCOPE = "recommendations:read"


def verify_token(request) -> Optional[Dict[str, Any]]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        decoded = jwt.decode(token, os.environ.get("JWT_SECRET"), algorithms=["HS256"])
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


def recompute_counts_for_user(cuid: str) -> Dict[str, int]:
    """Aggregate counts from beer_likes for the given `cuid` and return the computed counts.

    This function does not perform any HTTP handling; it can be imported and called from other code.
    """
    if not BEER_LIKES_TABLE or not USERS_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    agg_query = f"""
    SELECT
      COALESCE(SUM(CASE WHEN ind_tried = TRUE THEN 1 ELSE 0 END), 0) AS count_brews_chugged,
      COALESCE(SUM(CASE WHEN (ind_like_status = TRUE OR LOWER(CAST(ind_like_status AS STRING)) IN ('liked','like','1','true')) THEN 1 ELSE 0 END), 0) AS count_brews_liked,
      COALESCE(SUM(CASE WHEN (ind_like_status = FALSE OR LOWER(CAST(ind_like_status AS STRING)) IN ('disliked','dislike','-1','false')) THEN 1 ELSE 0 END), 0) AS count_brews_disliked,
      COALESCE(SUM(CASE WHEN user_rating IS NOT NULL THEN 1 ELSE 0 END), 0) AS count_brews_rated,
            COALESCE(SUM(CASE WHEN user_comments IS NOT NULL THEN 1 ELSE 0 END), 0) AS count_brews_commented,
            COALESCE(SUM(CASE WHEN ind_starred = TRUE THEN 1 ELSE 0 END), 0) AS count_brews_starred,
            COALESCE(SUM(CASE WHEN ind_wishlist = TRUE THEN 1 ELSE 0 END), 0) AS count_brews_wishlisted
    FROM `{BEER_LIKES_TABLE}`
    WHERE cuid = @cuid
    """

    params = [bigquery.ScalarQueryParameter("cuid", "STRING", cuid)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(agg_query, job_config=job_config).result())
    if not rows:
        counts = {
            "count_brews_chugged": 0,
            "count_brews_liked": 0,
            "count_brews_disliked": 0,
            "count_brews_rated": 0,
            "count_brews_commented": 0,
            "count_brews_starred": 0,
            "count_brews_wishlisted": 0,
        }
    else:
        row = rows[0]
        counts = {
            "count_brews_chugged": int(row.count_brews_chugged or 0),
            "count_brews_liked": int(row.count_brews_liked or 0),
            "count_brews_disliked": int(row.count_brews_disliked or 0),
            "count_brews_rated": int(row.count_brews_rated or 0),
            "count_brews_commented": int(getattr(row, "count_brews_commented", 0) or 0),
            "count_brews_starred": int(row.count_brews_starred or 0),
            "count_brews_wishlisted": int(row.count_brews_wishlisted or 0),
        }

    # Persist counts into users table (no-op if user doesn't exist)
    update_query = f"""
    UPDATE `{USERS_TABLE}`
    SET
      count_brews_chugged = @count_brews_chugged,
      count_brews_liked = @count_brews_liked,
      count_brews_disliked = @count_brews_disliked,
      count_brews_rated = @count_brews_rated,
            count_brews_commented = @count_brews_commented,
      count_brews_starred = @count_brews_starred,
      count_brews_wishlisted = @count_brews_wishlisted,
      updated_at = CURRENT_TIMESTAMP()
    WHERE cuid = @cuid
    """

    update_params = [
        bigquery.ScalarQueryParameter(
            "count_brews_chugged", "INT64", counts["count_brews_chugged"]
        ),
        bigquery.ScalarQueryParameter(
            "count_brews_liked", "INT64", counts["count_brews_liked"]
        ),
        bigquery.ScalarQueryParameter(
            "count_brews_disliked", "INT64", counts["count_brews_disliked"]
        ),
        bigquery.ScalarQueryParameter(
            "count_brews_rated", "INT64", counts["count_brews_rated"]
        ),
        bigquery.ScalarQueryParameter(
            "count_brews_commented", "INT64", counts["count_brews_commented"]
        ),
        bigquery.ScalarQueryParameter(
            "count_brews_starred", "INT64", counts["count_brews_starred"]
        ),
        bigquery.ScalarQueryParameter(
            "count_brews_wishlisted", "INT64", counts["count_brews_wishlisted"]
        ),
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
    ]
    update_job_config = bigquery.QueryJobConfig(query_parameters=update_params)
    client.query(update_query, job_config=update_job_config).result()

    return counts


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

        counts = recompute_counts_for_user(cuid)
        resp = make_response(json.dumps({"counts": counts}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 500, request)
    except Exception as e:
        return error_response(str(e), 500, request)
