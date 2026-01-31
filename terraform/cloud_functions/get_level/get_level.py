import os
import json
from typing import Any, Dict, Optional

from flask import make_response
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
LEVELS_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.levels" if PROJECT_ID and DATASET_ID else None
)


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


def fetch_level_by_rank(level_rank: int) -> Optional[Dict[str, Any]]:
    if not LEVELS_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    query = f"""
    SELECT *
    FROM `{LEVELS_TABLE}`
    WHERE level_rank = @level_rank
    LIMIT 1
    """

    params = [bigquery.ScalarQueryParameter("level_rank", "INT64", level_rank)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    if not rows:
        return None
    row = rows[0]
    # Convert Row to plain dict, normalizing datetimes if present
    row_dict = {}
    for k, v in dict(row).items():
        try:
            if hasattr(v, "isoformat"):
                row_dict[k] = v.isoformat()
            else:
                row_dict[k] = v
        except Exception:
            row_dict[k] = v
    return row_dict


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        body = request.get_json(silent=True) or {}
        user_level = body.get("user_level")
        if user_level is None:
            return error_response("Missing required field: user_level", 400, request)

        try:
            level_rank = int(user_level)
        except (ValueError, TypeError):
            return error_response("Invalid user_level: must be integer", 400, request)

        level = fetch_level_by_rank(level_rank)
        resp = make_response(json.dumps({"level": level}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 500, request)
    except Exception as e:
        return error_response(str(e), 500, request)
