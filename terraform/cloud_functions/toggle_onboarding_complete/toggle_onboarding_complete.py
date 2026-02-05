import os
import json
from typing import Any, Dict

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


def set_onboarding_complete(cuid: str) -> int:
    if not USERS_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    query = f"""
    UPDATE `{USERS_TABLE}`
    SET ind_first_time_user = FALSE
    WHERE cuid = @cuid
    """

    params = [bigquery.ScalarQueryParameter("cuid", "STRING", cuid)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    job = client.query(query, job_config=job_config)
    job.result()  # wait
    affected = int(getattr(job, "num_dml_affected_rows", 0) or 0)
    return affected


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        body = request.get_json(silent=True) or {}
        cuid = body.get("cuid")
        if not cuid:
            return error_response("Missing required field: cuid", 400, request)

        affected = set_onboarding_complete(str(cuid))
        resp = make_response(json.dumps({"updated": affected}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 500, request)
    except Exception as e:
        return error_response(str(e), 500, request)
