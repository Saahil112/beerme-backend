import os
import json
import time
import jwt
import sys
from typing import Dict, Any
from flask import make_response

ALLOWED_ORIGIN = "https://innerbeer.com"

def set_cors_headers(response):
    """Set CORS headers on response"""
    response.headers.set("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
    response.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS")
    response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.set("Access-Control-Max-Age", "3600")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    return response

JWT_SECRET = os.environ.get("JWT_SECRET")
USER_CREDENTIALS_RAW = os.environ.get("USER_CREDENTIALS", "{}")
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "3600"))

try:
    USER_CREDENTIALS: Dict[str, str] = json.loads(USER_CREDENTIALS_RAW)
except Exception:
    USER_CREDENTIALS = {}


def issue_token(email: str) -> str:
    now = int(time.time())
    payload: Dict[str, Any] = {
        "sub": email,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "scopes": ["recommendations:read"],
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def main(request):
    # Debug: Force flush to stderr for immediate logging
    print(f"Request method: '{request.method}', type: {type(request.method)}", file=sys.stderr, flush=True)
    print(f"Request headers: {dict(request.headers)}", file=sys.stderr, flush=True)
    
    # Handle CORS preflight
    if request.method == "OPTIONS" or request.method.upper() == "OPTIONS":
        print("Handling OPTIONS request", file=sys.stderr, flush=True)
        response = make_response("", 204)
        return set_cors_headers(response)

    print("Not an OPTIONS request, processing normally", file=sys.stderr, flush=True)
    if not JWT_SECRET:
        response = make_response(json.dumps({"error": "Server misconfigured: missing JWT_SECRET"}), 500)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)

    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        response = make_response(json.dumps({
            "error": "email and password required",
            "debug_method": str(request.method),
            "debug_headers": str(dict(request.headers))
        }), 400)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)

    stored = USER_CREDENTIALS.get(email)
    if stored is None:
        response = make_response(json.dumps({"error": "invalid credentials"}), 401)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)

    # For MVP we compare plaintext; replace with hashed comparison (bcrypt) later.
    if stored != password:
        response = make_response(json.dumps({"error": "invalid credentials"}), 401)
        response.headers.set("Content-Type", "application/json")
        return set_cors_headers(response)

    token = issue_token(email)
    response = make_response(json.dumps({
        "token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
        "scope": "recommendations:read"
    }), 200)
    response.headers.set("Content-Type", "application/json")
    return set_cors_headers(response)
