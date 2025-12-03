import os
import json
import jwt
from typing import Any, Dict
from flask import make_response
from google.cloud import bigquery

client = bigquery.Client()

JWT_SECRET = os.environ.get("JWT_SECRET")
REQUIRED_SCOPE = "recommendations:read"
ALLOWED_ORIGIN = "https://innerbeer.com"


def set_cors_headers(response):
    response.headers.set("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
    response.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS")
    response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.set("Access-Control-Max-Age", "3600")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


def verify_token(request) -> Dict[str, Any] | None:
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


def search_beer_names(project: str, dataset: str, prefix: str, limit: int = 3) -> list[Dict[str, Any]]:
    table = f"{project}.{dataset}.compiled_data"
    query = f"""
    SELECT beer_id, beer_name, beer_image, beer_brewery, beer_abv, beer_primary_style
    FROM `{table}`
    WHERE LOWER(beer_name) LIKE CONCAT(LOWER(@prefix), '%')
    ORDER BY beer_name ASC
    LIMIT @limit
    """
    params = [
        bigquery.ScalarQueryParameter("prefix", "STRING", prefix),
        bigquery.ScalarQueryParameter("limit", "INT64", limit),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = client.query(query, job_config=job_config).result()
    return [dict(r) for r in rows]


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204))

    if not JWT_SECRET:
        resp = make_response(json.dumps({"error": "Server misconfigured: missing JWT_SECRET"}), 500)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp)

    claims = verify_token(request)
    if claims is None:
        resp = make_response(json.dumps({"error": "Unauthorized"}), 401)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp)

    try:
        data = request.get_json(silent=True) or {}
        q = (data.get("q") or "").strip()
        limit = int(data.get("limit", 3))
        if not q:
            resp = make_response(json.dumps({"suggestions": []}), 200)
            resp.headers.set("Content-Type", "application/json")
            return set_cors_headers(resp)

        project = os.environ.get("PROJECT_ID")
        dataset = os.environ.get("DATASET_ID")
        suggestions = search_beer_names(project, dataset, q, limit)
        resp = make_response(json.dumps({"suggestions": suggestions}), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp)
    except Exception as e:
        resp = make_response(json.dumps({"error": str(e)}), 500)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp)
