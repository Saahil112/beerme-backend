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
SYSTEM_API_KEY = (os.environ.get("SYSTEM_API_KEY") or "").strip()
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


def lookup_reason_code(reason_code: str) -> Optional[bool]:
    """Look up a reason_code in txn_reason_codes.

    Returns the ``is_credit`` flag (True/False) when the code exists and is
    active, or ``None`` when it is missing / inactive.
    """
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
        return None
    return bool(rows[0].is_credit)


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
    """Admin transfer – issue or revoke bottlecaps for a user.

    Creates two linked transactions (double-entry bookkeeping):
      * When the reason code is a *credit* (is_credit=True):
          1. CREDIT +amount  → target user   (reason from request)
          2. DEBIT  −amount  → admin account  (same reason)
      * When the reason code is a *debit* (is_credit=False):
          1. DEBIT  −amount  → target user   (reason from request)
          2. CREDIT +amount  → admin account  (same reason)

    Request body (JSON):
      - cuid   (str, required): the target user
      - amount (int, required): number of bottlecaps (must be > 0)
      - reason (str, required): an active reason_code from txn_reason_codes

    Both balances are refreshed after the transactions.
    """
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    try:
        # Auth: support both JWT (admin users) and system API key (internal services)
        is_system_call = False
        api_key = request.headers.get("X-System-API-Key", "")
        if api_key and SYSTEM_API_KEY and api_key == SYSTEM_API_KEY:
            is_system_call = True
        else:
            claims = verify_token(request)
            if claims is None:
                return error_response("Unauthorized", 401, request)

            # Admin-role check: only authorized accounts can issue rewards
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
        target_cuid = body.get("cuid")
        amount = body.get("amount")
        reason = (body.get("reason") or "").strip().upper()

        if not target_cuid:
            return error_response("Missing required field: cuid", 400, request)
        if amount is None:
            return error_response("Missing required field: amount", 400, request)
        if not reason:
            return error_response("Missing required field: reason", 400, request)
        try:
            amount = int(amount)
        except (ValueError, TypeError):
            return error_response("amount must be an integer", 400, request)
        if amount <= 0:
            return error_response("amount must be greater than 0", 400, request)

        # Validate reason code and determine transaction direction
        is_credit = lookup_reason_code(reason)
        if is_credit is None:
            return error_response(
                f"reason_code '{reason}' is not active or does not exist", 400, request
            )

        # Generate linked transaction IDs
        user_txn_id = str(uuid.uuid4())
        admin_txn_id = str(uuid.uuid4())

        if is_credit:
            # Credit flow: +amount to user, -amount from admin
            user_txn_type = "CREDIT"
            user_amount = amount
            admin_txn_type = "DEBIT"
            admin_amount = -amount
        else:
            # Debit flow: -amount from user, +amount to admin
            user_txn_type = "DEBIT"
            user_amount = -amount
            admin_txn_type = "CREDIT"
            admin_amount = amount

        # 1. User-side transaction
        insert_transaction(
            transaction_id=user_txn_id,
            cuid=target_cuid,
            amount=user_amount,
            transaction_type=user_txn_type,
            reason_code=reason,
            related_entity_type="transaction",
            related_entity_id=admin_txn_id,
        )

        # 2. Admin-side counter-transaction
        insert_transaction(
            transaction_id=admin_txn_id,
            cuid=ADMIN_CUID,
            amount=admin_amount,
            transaction_type=admin_txn_type,
            reason_code=reason,
            related_entity_type="transaction",
            related_entity_id=user_txn_id,
        )

        # Refresh balances for both accounts
        refresh_balance(target_cuid)
        refresh_balance(ADMIN_CUID)

        resp_data = {
            "message": "Transfer completed successfully",
            "user_transaction_id": user_txn_id,
            "admin_transaction_id": admin_txn_id,
            "cuid": target_cuid,
            "amount": amount,
            "reason": reason,
            "direction": "credit" if is_credit else "debit",
        }
        resp = make_response(json.dumps(resp_data), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)

    except Exception as e:
        return error_response(str(e), 500, request)
