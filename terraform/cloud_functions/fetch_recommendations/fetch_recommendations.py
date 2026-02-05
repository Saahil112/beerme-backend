import os
import json
import jwt
import logging
from google.cloud import bigquery
from typing import Any, Dict, Optional
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


def filter_exact_beer_type(
    recommendations: list[Dict[str, Any]],
) -> list[Dict[str, Any]]:
    """
    Filter recommendations where source_beer_primary_style exactly matches rec_beer_primary_style.

    Args:
        recommendations: List of recommendation dictionaries

    Returns:
        Filtered list of recommendations with matching beer types
    """
    return [
        rec
        for rec in recommendations
        if rec.get("source_beer_primary_style") == rec.get("rec_beer_primary_style")
    ]


def filter_abv_difference(
    recommendations: list[Dict[str, Any]], max_diff: float = 1.0
) -> list[Dict[str, Any]]:
    """
    Filter recommendations where the absolute ABV difference is within the specified threshold.

    Args:
        recommendations: List of recommendation dictionaries
        max_diff: Maximum allowed absolute difference in ABV (default: 1.0%)

    Returns:
        Filtered list of recommendations within ABV threshold
    """
    filtered = []
    for rec in recommendations:
        source_abv = rec.get("source_beer_abv")
        rec_abv = rec.get("rec_beer_abv")

        # Skip if either ABV is missing
        if source_abv is None or rec_abv is None:
            continue

        # Convert to float if needed and check difference
        try:
            source_abv = float(source_abv)
            rec_abv = float(rec_abv)
            if abs(source_abv - rec_abv) <= max_diff:
                filtered.append(rec)
        except (ValueError, TypeError):
            # Skip entries with invalid ABV values
            continue

    return filtered


def fetch_recommendations(
    project: str,
    dataset: str,
    beer_name: str | None,
    beer_id: str | None,
    limit: int = 5,
    filter_beer_type: bool = False,
    filter_abv: bool = False,
    max_abv_diff: float = 1.0,
    cuid: Optional[str] = None,
):
    recs_table = f"{project}.{dataset}.recs_catalog"
    likes_table = f"{project}.{dataset}.beer_likes"

    # We'll select recs plus any matching beer_likes fields for the given user
    select_fields = (
        "r.*, bl.ind_like_status AS ind_like_status, bl.ind_starred AS ind_starred, "
        "bl.ind_tried AS ind_tried, bl.ind_wishlist AS ind_wishlist, bl.user_rating AS user_rating, bl.user_comments AS user_comments"
    )

    # Left join on cuid and the recommended beer name
    join_clause = f"LEFT JOIN `{likes_table}` bl ON bl.cuid = @cuid AND bl.beer_name = r.rec_beer_name"

    params = []
    if beer_id:
        query = f"""
        SELECT {select_fields}
        FROM `{recs_table}` r
        {join_clause}
        WHERE r.source_beer_id = @beer_id
        {"AND r.rec_beer_primary_style = r.source_beer_primary_style" if filter_beer_type else ""}
        LIMIT @limit
        """
        params.append(bigquery.ScalarQueryParameter("beer_id", "STRING", beer_id))
    elif beer_name:
        query = f"""
        SELECT {select_fields}
        FROM `{recs_table}` r
        {join_clause}
        WHERE r.source_beer_name = @beer_name
        {"AND r.rec_beer_primary_style = r.source_beer_primary_style" if filter_beer_type else ""}
        LIMIT @limit
        """
        params.append(bigquery.ScalarQueryParameter("beer_name", "STRING", beer_name))
    else:
        # Fetch all recommendations
        query = f"""
        SELECT {select_fields}
        FROM `{recs_table}` r
        {join_clause}
        {"WHERE r.rec_beer_primary_style = r.source_beer_primary_style" if filter_beer_type else ""}
        LIMIT @limit
        """

    # Bind cuid (may be None) and limit
    params.append(bigquery.ScalarQueryParameter("cuid", "STRING", cuid))
    params.append(bigquery.ScalarQueryParameter("limit", "INT64", limit))

    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = client.query(query, job_config=job_config).result()
    results = [dict(r) for r in rows]

    if filter_abv:
        results = filter_abv_difference(results, max_abv_diff)

    return results


def main(request):
    # Handle CORS preflight
    if request.method == "OPTIONS" or request.method.upper() == "OPTIONS":
        response = make_response("", 204)
        return set_cors_headers(response)

    # Determine if an Authorization header was provided. If present, require a valid token.
    auth_header = request.headers.get("Authorization", "")
    claims = None
    if auth_header:
        # Token was provided; ensure server has secret configured
        if not JWT_SECRET:
            response = make_response(
                json.dumps({"error": "Server misconfigured: missing JWT_SECRET"}), 500
            )
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

        # Filter parameters
        filter_beer_type = data.get("filter_beer_type", False)
        filter_abv = data.get("filter_abv", False)
        max_abv_diff = float(data.get("max_abv_diff", 1.0))

        project = os.environ.get("PROJECT_ID")
        dataset = os.environ.get("DATASET_ID")
        # Derive user cuid from claims (support different token shapes). If no token
        # was provided, `claims` will be None and `cuid` will remain None (anonymous).
        original_cuid = None
        if isinstance(claims, dict):
            original_cuid = (
                claims.get("cuid") or claims.get("sub") or claims.get("email")
            )

        # Do not enforce token-only cuid presence. Support both authenticated calls
        # (where cuid may be present) and anonymous calls (no cuid).
        logging.info("JWT claims: %s", claims)
        logging.info("original_cuid(from token): %r", original_cuid)

        cuid = original_cuid

        results = fetch_recommendations(
            project,
            dataset,
            beer_name,
            beer_id,
            limit,
            filter_beer_type,
            filter_abv,
            max_abv_diff,
            cuid,
        )
        response = make_response(json.dumps({"recommendations": results}), 200)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)
    except Exception as e:
        response = make_response(json.dumps({"error": str(e)}), 500)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)
