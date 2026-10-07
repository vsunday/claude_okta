# Okta → Anthropic Workload Identity Federation

A script that authenticates to the Anthropic API with an Okta-issued token
(workload identity federation) instead of a static API key.

How it works:

1. Signs a JWT client assertion with your RSA private key (`private_key_jwt`).
2. Gets an access token from Okta with the `client_credentials` grant (scope `anthropic.access`).
3. Checks the token's `aud` (`https://api.anthropic.com`) and `sub` (your client ID) locally.
4. Lets the Anthropic SDK (`WorkloadIdentityCredentials`) exchange the Okta token for an Anthropic access token and refresh it.

## Prerequisites

- Python 3.10+
- An Okta API service app that uses public key / private key client authentication, plus a custom authorization server with an `anthropic.access` scope and the audience `https://api.anthropic.com`
- An Anthropic federation rule and service account that trust that Okta issuer

## Setup

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in the values
```

Store the private key outside the repository, and point `OKTA_PRIVATE_KEY_PATH` at it.

## Usage

```sh
# Token exchange only (prints expiry, never the token)
python wif_okta_anthropic.py

# Token exchange + a test Messages API call (requires ANTHROPIC_MODEL)
python wif_okta_anthropic.py --messages
```

Environment variables you set in the shell take precedence over `.env`.
See `.env.example` for the full list.

## License

[MIT](LICENSE)
