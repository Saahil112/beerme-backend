import os
import json
import uuid
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
ADMIN_CUID = os.environ.get("ADMIN_CUID")
AUTHORIZED_CUIDS = set(
    c.strip() for c in os.environ.get("AUTHORIZED_CUIDS", "").split(",") if c.strip()
)
WALLET_TYPE = "BOTTLE_CAPS"
REQUIRED_SCOPE = "recommendations:read"

TRANSACTIONS_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.transactions" if PROJECT_ID and DATASET_ID else None
)
BALANCES_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.balances" if PROJECT_ID and DATASET_ID else None
)
TXN_REASON_CODES_TABLE = (
    f"{PROJECT_ID}.{DATASET_ID}.txn_reason_codes" if PROJECT_ID and DATASET_ID else None
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


def validate_reason_code(reason_code: str, expected_is_credit: bool) -> bool:
    """Check that the reason_code exists in txn_reason_codes, is active,
    and its is_credit flag matches the expected value."""
    query = f"""
    SELECT is_credit
    FROM `{TXN_REASON_CODES_TABLE}`
    WHERE reason_code = @reason_code
      AND is_active = TRUE
    """
    params = [bigquery.ScalarQueryParameter("reason_code", "STRING", reason_code)]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    rows = list(client.query(query, job_config=job_config).result())
    if not rows:
        return False
    return rows[0].is_credit == expected_is_credit


def insert_transaction(
    transaction_id: str,
    cuid: str,
    amount: int,
    transaction_type: str,
    reason_code: str,
    related_entity_type: str = None,
    related_entity_id: str = None,
):
    """Insert a single row into the transactions table."""
    query = f"""
    INSERT INTO `{TRANSACTIONS_TABLE}`
        (transaction_id, cuid, amount, transaction_type, reason_code,
         related_entity_type, related_entity_id, created_at, wallet_type)
    VALUES
        (@transaction_id, @cuid, @amount, @transaction_type, @reason_code,
         @related_entity_type, @related_entity_id, CURRENT_TIMESTAMP(), @wallet_type)
    """
    params = [
        bigquery.ScalarQueryParameter("transaction_id", "STRING", transaction_id),
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
        bigquery.ScalarQueryParameter("amount", "INT64", amount),
        bigquery.ScalarQueryParameter("transaction_type", "STRING", transaction_type),
        bigquery.ScalarQueryParameter("reason_code", "STRING", reason_code),
        bigquery.ScalarQueryParameter(
            "related_entity_type", "STRING", related_entity_type
        ),
        bigquery.ScalarQueryParameter("related_entity_id", "STRING", related_entity_id),
        bigquery.ScalarQueryParameter("wallet_type", "STRING", WALLET_TYPE),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    client.query(query, job_config=job_config).result()


def refresh_balance(cuid: str):
    """Recompute balance for a cuid by summing all transactions and upsert into balances."""
    query = f"""
    MERGE `{BALANCES_TABLE}` AS B
    USING (
        SELECT
            @cuid AS cuid,
            COALESCE(SUM(amount), 0) AS balance,
            @wallet_type AS wallet_type
        FROM `{TRANSACTIONS_TABLE}`
        WHERE cuid = @cuid AND wallet_type = @wallet_type
    ) AS T
    ON B.cuid = T.cuid AND B.wallet_type = T.wallet_type
    WHEN MATCHED THEN
        UPDATE SET balance = T.balance, updated_at = CURRENT_TIMESTAMP()
    WHEN NOT MATCHED THEN
        INSERT (cuid, balance, updated_at, wallet_type)
        VALUES (T.cuid, T.balance, CURRENT_TIMESTAMP(), T.wallet_type)
    """
    params = [
        bigquery.ScalarQueryParameter("cuid", "STRING", cuid),
        bigquery.ScalarQueryParameter("wallet_type", "STRING", WALLET_TYPE),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    client.query(query, job_config=job_config).result()


def main(request):
    """Deposit bottlecaps into the admin account.

    Creates a single ADMIN transaction (credit) to the admin wallet,
    then refreshes the admin balance.

    Request body (JSON):
      - amount (int, required): number of bottlecaps to deposit (must be > 0)
    """
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        # Auth
        claims = verify_token(request)
        if claims is None:
            return error_response("Unauthorized", 401, request)

        # Admin-role check: only authorized accounts can deposit
        caller_cuid = claims.get("cuid") or claims.get("sub") or claims.get("email")
        if not caller_cuid or caller_cuid not in AUTHORIZED_CUIDS:
            return error_response("Forbidden: admin access required", 403, request)

        if not TRANSACTIONS_TABLE or not BALANCES_TABLE or not TXN_REASON_CODES_TABLE:
            return error_response(
                "Server misconfigured: missing PROJECT_ID or DATASET_ID", 500, request
            )

        if not ADMIN_CUID:
            return error_response(
                "Server misconfigured: missing ADMIN_CUID", 500, request
            )

        # Parse body
        body = request.get_json(silent=True) or {}
        amount = body.get("amount")

        if amount is None:
            return error_response("Missing required field: amount", 400, request)
        try:
            amount = int(amount)
        except (ValueError, TypeError):
            return error_response("amount must be an integer", 400, request)
        if amount <= 0:
            return error_response("amount must be greater than 0", 400, request)

        # Validate reason code
        if not validate_reason_code("ADMIN", expected_is_credit=True):
            return error_response(
                "ADMIN reason_code is not active or misconfigured", 500, request
            )

        # Generate transaction ID
        txn_id = str(uuid.uuid4())

        # Credit the admin account
        insert_transaction(
            transaction_id=txn_id,
            cuid=ADMIN_CUID,
            amount=amount,
            transaction_type="CREDIT",
            reason_code="ADMIN",
        )

        # Refresh admin balance
        refresh_balance(ADMIN_CUID)

        resp_data = {
            "message": "Admin deposit successful",
            "transaction_id": txn_id,
            "amount": amount,
        }
        resp = make_response(json.dumps(resp_data), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)

    except Exception as e:
        return error_response(str(e), 500, request)
