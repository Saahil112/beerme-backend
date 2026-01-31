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
USERS_TABLE = f"{PROJECT_ID}.{DATASET_ID}.users" if PROJECT_ID and DATASET_ID else None


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
    SELECT cuid, first_name, last_name, email, profile_pic_url, username, created_at, updated_at, ind_first_time_user, user_level, count_brews_chugged
    FROM `{USERS_TABLE}`
    WHERE cuid = @cuid
    LIMIT 1
    """
    params = [bigquery.ScalarQueryParameter("cuid", "STRING", cuid)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    if not rows:
        return None
    row = rows[0]
    return {
        "cuid": row.cuid,
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
    }


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        body = request.get_json(silent=True) or {}
        cuid = body.get("cuid")
        if not cuid:
            return error_response("Missing required field: cuid", 400, request)

        user = fetch_user_by_cuid(cuid)
        resp = make_response(json.dumps({"user": user}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 500, request)
    except Exception as e:
        return error_response(str(e), 500, request)
