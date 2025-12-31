import os
import json
from typing import Any, Dict, Optional

import jwt
from flask import make_response
from google.cloud import bigquery

client = bigquery.Client()

ALLOWED_ORIGINS = {
    "https://innerbeer.com",
    "https://www.innerbeer.com",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}

JWT_SECRET = os.environ.get("JWT_SECRET")
PROJECT_ID = os.environ.get("PROJECT_ID")
DATASET_ID = os.environ.get("DATASET_ID")
BUDDIES_TABLE = f"{PROJECT_ID}.{DATASET_ID}.buddies" if PROJECT_ID and DATASET_ID else None
REQUIRED_SCOPE = "recommendations:read"


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


def verify_token(request) -> Optional[Dict[str, Any]]:
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


def normalize_string(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s if s else None
    return str(v)


def send_friend_request(sender_cuid: str, receiver_cuid: str) -> Dict[str, Any]:
    if not BUDDIES_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    query = f"""
    MERGE `{BUDDIES_TABLE}` AS t
    USING (
        SELECT @sender AS cuid,
                     @receiver AS friend_cuid,
                     'pending' AS status,
                     CURRENT_TIMESTAMP() AS requested_at
    ) AS s
    ON t.cuid = s.cuid AND t.friend_cuid = s.friend_cuid
    WHEN MATCHED THEN UPDATE SET
        t.status = 'pending',
        t.requested_at = COALESCE(t.requested_at, s.requested_at),
        t.accepted_at = NULL
    WHEN NOT MATCHED THEN INSERT (cuid, friend_cuid, status, requested_at, accepted_at)
    VALUES (s.cuid, s.friend_cuid, s.status, s.requested_at, NULL);
    """
    params = [
        bigquery.ScalarQueryParameter("sender", "STRING", sender_cuid),
        bigquery.ScalarQueryParameter("receiver", "STRING", receiver_cuid),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    client.query(query, job_config=job_config).result()

    # Return the current state of the request
    select_sql = f"""
    SELECT cuid, friend_cuid, status, requested_at, accepted_at
    FROM `{BUDDIES_TABLE}`
    WHERE cuid = @sender AND friend_cuid = @receiver
    LIMIT 1
    """
    rows = list(client.query(select_sql, job_config=job_config).result())
    if rows:
        r = rows[0]
        return {
            "cuid": r.cuid,
            "friend_cuid": r.friend_cuid,
            "status": r.status,
            "requested_at": r.requested_at.isoformat() if r.requested_at else None,
            "accepted_at": r.accepted_at.isoformat() if r.accepted_at else None,
        }
    return {"cuid": sender_cuid, "friend_cuid": receiver_cuid, "status": "pending"}


def accept_friend_request(sender_cuid: str, receiver_cuid: str) -> list[Dict[str, Any]]:
    if not BUDDIES_TABLE:
        raise ValueError("Server misconfigured: missing PROJECT_ID or DATASET_ID")

    # BigQuery script to insert reciprocal accepted row and update original pending -> accepted
    script = f"""
    DECLARE ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP();

    -- Insert or update reciprocal accepted row (receiver -> sender)
    MERGE `{BUDDIES_TABLE}` AS t
    USING (
      SELECT @receiver AS cuid,
             @sender AS friend_cuid,
             'accepted' AS status,
             ts AS accepted_at
    ) AS s
    ON t.cuid = s.cuid AND t.friend_cuid = s.friend_cuid
    WHEN MATCHED THEN UPDATE SET
      t.status = 'accepted',
      t.accepted_at = s.accepted_at
    WHEN NOT MATCHED THEN INSERT (cuid, friend_cuid, status, requested_at, accepted_at)
    VALUES (s.cuid, s.friend_cuid, s.status, NULL, s.accepted_at);

    -- Update original pending row (sender -> receiver)
    UPDATE `{BUDDIES_TABLE}`
    SET status = 'accepted', accepted_at = ts
    WHERE cuid = @sender AND friend_cuid = @receiver AND status = 'pending';
    """

    params = [
        bigquery.ScalarQueryParameter("sender", "STRING", sender_cuid),
        bigquery.ScalarQueryParameter("receiver", "STRING", receiver_cuid),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    client.query(script, job_config=job_config).result()

    # Return both rows
    select_sql = f"""
    SELECT cuid, friend_cuid, status, requested_at, accepted_at
    FROM `{BUDDIES_TABLE}`
    WHERE (cuid = @sender AND friend_cuid = @receiver)
       OR (cuid = @receiver AND friend_cuid = @sender)
    ORDER BY cuid ASC
     """
    rows = list(client.query(select_sql, job_config=job_config).result())
    return [
        {
            "cuid": r.cuid,
            "friend_cuid": r.friend_cuid,
            "status": r.status,
            "requested_at": r.requested_at.isoformat() if r.requested_at else None,
            "accepted_at": r.accepted_at.isoformat() if r.accepted_at else None,
        }
        for r in rows
    ]


def main(request):
    if request.method.upper() == "OPTIONS":
        return set_cors_headers(make_response("", 204), request)

    if not JWT_SECRET:
        return error_response("Server misconfigured: missing JWT_SECRET", 500, request)
    if not BUDDIES_TABLE:
        return error_response("Server misconfigured: missing PROJECT_ID or DATASET_ID", 500, request)

    claims = verify_token(request)
    if claims is None:
        return error_response("Unauthorized", 401, request)

    if request.method.upper() != "POST":
        return error_response("Method not allowed", 405, request)

    try:
        body = request.get_json(silent=True) or {}
        action = (body.get("action") or "").strip().lower()
        sender_cuid = normalize_string(body.get("sender_cuid")) or ""
        receiver_cuid = normalize_string(body.get("receiver_cuid")) or ""

        if action not in {"send", "accept"}:
            return error_response("action must be 'send' or 'accept'", 400, request)
        if not sender_cuid or not receiver_cuid:
            return error_response("sender_cuid and receiver_cuid are required", 400, request)
        if sender_cuid == receiver_cuid:
            return error_response("sender and receiver must be different", 400, request)

        if action == "send":
            record = send_friend_request(sender_cuid, receiver_cuid)
            resp_body = {"request": record}
        else:
            records = accept_friend_request(sender_cuid, receiver_cuid)
            resp_body = {"friendship": records}

        resp = make_response(json.dumps(resp_body), 200)
        resp.headers.set("Content-Type", "application/json")
        return set_cors_headers(resp, request)
    except Exception as e:
        return error_response(str(e), 500, request)
