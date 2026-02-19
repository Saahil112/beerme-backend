import os
import json
from typing import Any, Dict, List, Optional

import requests
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
SYSTEM_API_KEY = (os.environ.get("SYSTEM_API_KEY") or "").strip()
REWARD_USER_URL = os.environ.get("REWARD_USER_URL")
REQUIRED_SCOPE = "recommendations:read"

USERS_TABLE = f"{PROJECT_ID}.{DATASET_ID}.users" if PROJECT_ID and DATASET_ID else None
LEVELS_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.levels" if PROJECT_ID and DATASET_ID else None
)
MILESTONE_GRANTS_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.milestone_grants" if PROJECT_ID and DATASET_ID else None
)


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


def get_user_level(cuid: str) -> Optional[int]:
    """Fetch the user's current level from the users table."""
    query = f"""
    SELECT user_level
    FROM `{USERS_TABLE}`
    WHERE cuid = @cuid
    LIMIT 1
    """
    params = [bigquery.ScalarQueryParameter("cuid", "STRING", cuid)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    if not rows or rows[0].user_level is None:
        return None
    return int(rows[0].user_level)


def get_level_rewards(user_level: int) -> List[Dict[str, Any]]:
    """Fetch all levels up to and including the user's current level
    that have bottlecap_rewards > 0."""
    query = f"""
    SELECT level_rank, bottlecap_rewards
    FROM `{LEVELS_TABLE}`
    WHERE level_rank <= @user_level
      AND bottlecap_rewards IS NOT NULL
      AND bottlecap_rewards > 0
    ORDER BY level_rank ASC
    """
    params = [bigquery.ScalarQueryParameter("user_level", "INT64", user_level)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    return [
        {"level_rank": int(r.level_rank), "bottlecap_rewards": int(r.bottlecap_rewards)}
        for r in rows
    ]


def get_granted_milestones(cuid: str) -> set:
    """Return the set of milestone_values already granted for LEVEL_UP milestones."""
    query = f"""
    SELECT milestone_value
    FROM `{MILESTONE_GRANTS_TABLE}`
    WHERE cuid = @cuid
      AND milestone_type = 'LEVEL_UP'
    """
    params = [bigquery.ScalarQueryParameter("cuid", "STRING", cuid)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    return {r.milestone_value for r in rows}


def record_milestone_grant(
    grant_id: str,
    cuid: str,
    milestone_type: str,
    milestone_value: str,
    reward_amount: int,
    transaction_id: str,
):
    """Insert a record into milestone_grants to prevent duplicate rewards."""
    query = f"""
    INSERT INTO `{MILESTONE_GRANTS_TABLE}`
        (grant_id, cuid, milestone_type, milestone_value, reward_amount,
         transaction_id, granted_at)
    VALUES
        (@grant_id, @cuid, @milestone_type, @milestone_value, @reward_amount,
         @transaction_id, CURRENT_TIMESTAMP())
    """
    params = [
        bigquery.ScalarQueryParameter("grant_id", "STRING", grant_id),
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
        bigquery.ScalarQueryParameter("milestone_type", "STRING", milestone_type),
        bigquery.ScalarQueryParameter("milestone_value", "STRING", milestone_value),
        bigquery.ScalarQueryParameter("reward_amount", "INT64", reward_amount),
        bigquery.ScalarQueryParameter("transaction_id", "STRING", transaction_id),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    client.query(query, job_config=job_config).result()


def call_reward_user(cuid: str, amount: int) -> Dict[str, Any]:
    """Call the reward-user cloud function using the system API key."""
    resp = requests.post(
        REWARD_USER_URL,
        json={"cuid": cuid, "amount": amount, "reason": "REWARD"},
        headers={
            "Content-Type": "application/json",
            "X-System-API-Key": SYSTEM_API_KEY,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def main(request):
    """Check and grant unclaimed milestone rewards for the authenticated user.

    Called after level-up events. For each level the user has reached that has
    a bottlecap_rewards value and hasn't been granted yet, issues the reward
    via the reward-user function and records it in milestone_grants.

    Returns a summary of newly granted rewards.
    """
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        # Auth — user-initiated (JWT)
        claims = verify_token(request)
        if claims is None:
            return error_response("Unauthorized", 401, request)

        cuid = claims.get("cuid") or claims.get("sub") or claims.get("email")
        if not cuid:
            return error_response("Missing cuid in token", 400, request)

        if not USERS_TABLE or not LEVELS_TABLE or not MILESTONE_GRANTS_TABLE:
            return error_response(
                "Server misconfigured: missing PROJECT_ID or DATASET_ID", 500, request
            )
        if not SYSTEM_API_KEY or not REWARD_USER_URL:
            return error_response(
                "Server misconfigured: missing SYSTEM_API_KEY or REWARD_USER_URL",
                500,
                request,
            )

        # 1. Get user's current level
        user_level = get_user_level(cuid)
        if user_level is None:
            return error_response("User not found or has no level", 404, request)

        # 2. Get all levels with rewards up to current level
        level_rewards = get_level_rewards(user_level)
        if not level_rewards:
            resp = make_response(
                json.dumps(
                    {"message": "No milestone rewards configured", "grants": []}
                ),
                200,
            )
            resp.headers.set("Content-Type", "application/json")
            return set_cors_headers(resp, request)

        # 3. Get already-granted milestones
        granted = get_granted_milestones(cuid)

        # 4. Issue rewards for unclaimed milestones
        new_grants = []
        for lr in level_rewards:
            milestone_value = str(lr["level_rank"])
            if milestone_value in granted:
                continue

            # Call reward_user to issue the transaction
            reward_resp = call_reward_user(cuid, lr["bottlecap_rewards"])
            reward_txn_id = reward_resp.get("reward_transaction_id", "")

            # Record the grant
            import uuid

            grant_id = str(uuid.uuid4())
            record_milestone_grant(
                grant_id=grant_id,
                cuid=cuid,
                milestone_type="LEVEL_UP",
                milestone_value=milestone_value,
                reward_amount=lr["bottlecap_rewards"],
                transaction_id=reward_txn_id,
            )

            new_grants.append(
                {
                    "level_rank": lr["level_rank"],
                    "reward_amount": lr["bottlecap_rewards"],
                    "transaction_id": reward_txn_id,
                    "grant_id": grant_id,
                }
            )

        resp = make_response(
            json.dumps(
                {
                    "message": f"{len(new_grants)} milestone reward(s) granted",
                    "grants": new_grants,
                }
            ),
            200,
        )
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)

    except requests.exceptions.HTTPError as he:
        return error_response(
            f"Failed to issue reward: {he.response.text if he.response else str(he)}",
            502,
            request,
        )
    except Exception as e:
        return error_response(str(e), 500, request)
