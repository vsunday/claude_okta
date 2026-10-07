#!/usr/bin/env python3

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
import requests
from dotenv import load_dotenv

# Resolve relative to this file so the script works from any working directory.
ENV_FILE = Path(__file__).resolve().parent / ".env"


def env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value


def build_client_assertion(
    issuer: str,
    client_id: str,
    key_id: str,
    private_key_path: str,
) -> str:
    now = int(time.time())
    token_endpoint = f"{issuer}/v1/token"
    private_key = Path(private_key_path).read_text()

    return jwt.encode(
        {
            "iss": client_id,
            "sub": client_id,
            "aud": token_endpoint,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        },
        private_key,
        algorithm="RS256",
        headers={
            "kid": key_id,
            "typ": "JWT",
        },
    )


def get_okta_token(issuer: str, client_assertion: str) -> dict[str, Any]:
    response = requests.post(
        f"{issuer}/v1/token",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "client_credentials",
            "scope": "anthropic.access",
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "client_assertion": client_assertion,
        },
        timeout=30,
    )

    if not response.ok:
        raise RuntimeError(
            f"Okta token request failed: {response.status_code} {response.text}"
        )

    body = response.json()

    if not body.get("access_token"):
        raise RuntimeError(f"Okta access_token missing: {body}")

    return body


def exchange_anthropic_token(
    okta_token: str,
    federation_rule_id: str,
    organization_id: str,
    service_account_id: str,
    workspace_id: str | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": okta_token,
        "federation_rule_id": federation_rule_id,
        "organization_id": organization_id,
        "service_account_id": service_account_id,
    }

    if workspace_id:
        payload["workspace_id"] = workspace_id

    response = requests.post(
        "https://api.anthropic.com/v1/oauth/token",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )

    if not response.ok:
        raise RuntimeError(
            f"Anthropic token exchange failed: "
            f"{response.status_code} {response.text}"
        )

    body = response.json()

    if not body.get("access_token"):
        raise RuntimeError(f"Anthropic access_token missing: {body}")

    return body


def call_messages_api(
    access_token: str,
    model: str,
    prompt: str,
) -> dict[str, Any]:
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 256,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        },
        timeout=120,
    )

    if not response.ok:
        raise RuntimeError(
            f"Messages API request failed: {response.status_code} {response.text}"
        )

    return response.json()


def main() -> int:
    # Variables already set in the shell take precedence over .env.
    load_dotenv(ENV_FILE)

    issuer = env("OKTA_ISSUER").rstrip("/")
    client_id = env("OKTA_CLIENT_ID")
    key_id = env("OKTA_KEY_ID")
    private_key_path = env("OKTA_PRIVATE_KEY_PATH")

    federation_rule_id = env("ANTHROPIC_FEDERATION_RULE_ID")
    organization_id = env("ANTHROPIC_ORGANIZATION_ID")
    service_account_id = env("ANTHROPIC_SERVICE_ACCOUNT_ID")
    workspace_id = os.getenv("ANTHROPIC_WORKSPACE_ID")

    client_assertion = build_client_assertion(
        issuer=issuer,
        client_id=client_id,
        key_id=key_id,
        private_key_path=private_key_path,
    )

    okta_response = get_okta_token(
        issuer=issuer,
        client_assertion=client_assertion,
    )

    okta_token = okta_response["access_token"]
    # Signature is verified by Anthropic; decode only for local sanity checks.
    okta_header = jwt.get_unverified_header(okta_token)
    okta_claims = jwt.decode(okta_token, options={"verify_signature": False})

    if okta_claims.get("aud") != "https://api.anthropic.com":
        raise RuntimeError(
            f"Invalid Okta JWT audience: {okta_claims.get('aud')}"
        )

    if okta_claims.get("sub") != client_id:
        raise RuntimeError(
            f"Invalid Okta JWT subject: {okta_claims.get('sub')}"
        )

    print(
        json.dumps(
            {
                "okta_token": {
                    "kid": okta_header.get("kid"),
                    "iss": okta_claims.get("iss"),
                    "sub": okta_claims.get("sub"),
                    "aud": okta_claims.get("aud"),
                    "expires_in": okta_response.get("expires_in"),
                }
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    anthropic_response = exchange_anthropic_token(
        okta_token=okta_token,
        federation_rule_id=federation_rule_id,
        organization_id=organization_id,
        service_account_id=service_account_id,
        workspace_id=workspace_id,
    )

    anthropic_token = anthropic_response["access_token"]

    result: dict[str, Any] = {
        "anthropic_token_exchange": {
            "token_type": anthropic_response.get("token_type"),
            "expires_in": anthropic_response.get("expires_in"),
            "scope": anthropic_response.get("scope"),
            "access_token": "obtained",
        }
    }

    if "--messages" in sys.argv:
        model = env("ANTHROPIC_MODEL")
        prompt = (
            os.getenv("ANTHROPIC_PROMPT")
            or "WIFの接続テストです。短く応答してください。"
        )

        result["messages"] = call_messages_api(
            access_token=anthropic_token,
            model=model,
            prompt=prompt,
        )

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "error": str(error),
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)
