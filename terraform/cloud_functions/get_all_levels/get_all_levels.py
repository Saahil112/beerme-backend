import os
import json
from typing import Any, Dict, Optional, List

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
    response.headers.set("Access-Control-Allow-Methods", "GET, OPTIONS")
    response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.set("Access-Control-Max-Age", "3600")
    response.headers.set("Vary", "Origin")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


def error_response(message: str, status: int = 400, request=None):
    resp = make_response(json.dumps({"error": message}), status)
    resp.headers.set("Content-Type", "application/json")
    return set_cors_headers(resp, request)


def fetch_all_levels() -> List[Dict[str, Any]]:
    if not LEVELS_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    query = f"""
    SELECT *
    FROM `{LEVELS_TABLE}`
    ORDER BY level_rank ASC
    """

    rows = list(client.query(query).result())
    result = []
    for row in rows:
        row_dict = {}
        for k, v in dict(row).items():
            try:
                if hasattr(v, "isoformat"):
                    row_dict[k] = v.isoformat()
                else:
                    row_dict[k] = v
            except Exception:
                row_dict[k] = v
        result.append(row_dict)
    return result


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        levels = fetch_all_levels()
        resp = make_response(json.dumps({"levels": levels}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except ValueError as ve:
        return error_response(str(ve), 500, request)
    except Exception as e:
        return error_response(str(e), 500, request)
