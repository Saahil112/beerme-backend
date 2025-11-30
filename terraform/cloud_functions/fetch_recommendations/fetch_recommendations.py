import os
import json
import jwt
from google.cloud import bigquery
from typing import Any, Dict
from flask import make_response

client = bigquery.Client()

JWT_SECRET = os.environ.get("JWT_SECRET")
REQUIRED_SCOPE = "recommendations:read"

ALLOWED_ORIGIN = "https://innerbeer.com"

def set_cors_headers(response):
    """Set CORS headers on response"""
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


def fetch_recommendations(project: str, dataset: str, beer_name: str | None, beer_id: str | None, limit: int = 5):
    recs_table = f"{project}.{dataset}.recs_catalog"

    params = []
    if beer_id:
        query = f"""
        SELECT *
        FROM `{recs_table}` r
        WHERE r.source_beer_id = @beer_id
        LIMIT @limit
        """
        params.append(bigquery.ScalarQueryParameter("beer_id", "STRING", beer_id))
    elif beer_name:
        query = f"""
        SELECT *
        FROM `{recs_table}` r
        WHERE r.source_beer_name = @beer_name
        LIMIT @limit
        """
        params.append(bigquery.ScalarQueryParameter("beer_name", "STRING", beer_name))
    else:
        # Fetch all recommendations
        query = f"""
        SELECT *
        FROM `{recs_table}` r
        LIMIT @limit
        """

    params.append(bigquery.ScalarQueryParameter("limit", "INT64", limit))
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = client.query(query, job_config=job_config).result()
    return [dict(r) for r in rows]


def main(request):
    # Handle CORS preflight
    if request.method == "OPTIONS" or request.method.upper() == "OPTIONS":
        response = make_response("", 204)
        return set_cors_headers(response)

    if not JWT_SECRET:
        response = make_response(json.dumps({"error": "Server misconfigured: missing JWT_SECRET"}), 500)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)

    claims = verify_token(request)
    if claims is None:
        response = make_response(json.dumps({"error": "Unauthorized"}), 401)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)

    try:
        data = request.get_json(silent=True) or {}
        beer_name = data.get("beer_name")
        beer_id = data.get("beer_id")
        limit = int(data.get("limit", 5))
        project = os.environ.get("PROJECT_ID")
        dataset = os.environ.get("DATASET_ID")
        results = fetch_recommendations(project, dataset, beer_name, beer_id, limit)
        response = make_response(json.dumps({"recommendations": results}), 200)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)
    except Exception as e:
        response = make_response(json.dumps({"error": str(e)}), 500)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)
