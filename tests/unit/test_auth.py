import base64
import os

import pytest
import yaml
from fastapi.testclient import TestClient

from app import dependencies
from app.config import GLOBALCONFIG
from app.main import app

client = TestClient(app)

SALT = GLOBALCONFIG['salt'].encode()
PASSWORD = GLOBALCONFIG['encryption_key'].encode()
FIXTURE_FQDN = "cratosauthtestfixture.invalid"
FIXTURE_SITE_PATH = os.path.join('sites', f"{FIXTURE_FQDN}.yaml")
AUTHKEY = "B" * 40
ROUTE = "/v1/feedmapping"


@pytest.fixture(scope="module")
def validToken():
    siteConfig = {
        'enabled': True,
        'debug': False,
        'company': 'Auth Test Co',
        'tag': 'authtest',
        'mispVerifyCert': True,
        'mispTimeoutSeconds': 5,
        'mispDebug': False,
        'memcached_all_timeout': 60,
        'falsepositive_timeout': '1d',
        'list_stats': '1d',
        'allowed_ips': ["203.0.113.0/24"],
        'custom_feeds': {'cust1': ':incident-classification=cust1'},
        'ignore_to_ids': [],
        'blacklisted_api_tokens': [],
    }
    with open(FIXTURE_SITE_PATH, 'w') as f:
        yaml.dump(siteConfig, f)

    plainText = f"https;443;{FIXTURE_FQDN};{AUTHKEY};2099-01-01"
    result = dependencies.encryptString(plainText, SALT, PASSWORD)
    assert result['status']
    yield result['detail']

    os.remove(FIXTURE_SITE_PATH)


def test_no_credentials_rejected():
    response = client.get(ROUTE)
    assert response.status_code == 403


def test_query_token_valid(validToken):
    response = client.get(ROUTE, params={"token": validToken})
    assert response.status_code == 200


def test_header_token_valid(validToken):
    response = client.get(ROUTE, headers={"token": validToken})
    assert response.status_code == 200


def test_header_token_garbage_rejected():
    response = client.get(ROUTE, headers={"token": "garbage-not-a-token"})
    assert response.status_code == 403


def test_http_basic_cratos_username_valid_password(validToken):
    response = client.get(ROUTE, auth=("cratos", validToken))
    assert response.status_code == 200


def test_http_basic_cratos_username_invalid_password_rejected():
    """ "abc" is unambiguously invalid base64 (incorrect padding), so this must hit
    getApiToken's early rejection rather than falling through to checkApiToken. """
    response = client.get(ROUTE, auth=("cratos", "abc"))
    assert response.status_code == 403
    assert response.json()['detail'] == "Could not validate token, or token not set."


def test_http_basic_split_username_password_fallback(validToken):
    """ Some security products choke on long HTTP Basic passwords, so the token can be
    split across username and password and Cratos concatenates them back together. """
    splitPoint = len(validToken) // 2
    username = validToken[:splitPoint]
    password = validToken[splitPoint:]
    response = client.get(ROUTE, auth=(username, password))
    assert response.status_code == 200


def test_http_basic_garbage_credentials_rejected():
    response = client.get(ROUTE, auth=("not-base64!", "also-not-base64!"))
    assert response.status_code == 403
    assert response.json()['detail'] == "Could not validate token, or token not set."


# --- Reverse-proxy IP resolution: the allowlist check must honor the resolved
# X-Forwarded-For client IP, not the raw transport-layer peer address. This repo's
# config.yaml has reverse_proxy: True, so getApiToken must use request.state.client_ip
# (computed by the logRequest middleware from the configured header/regex) rather than
# request.client.host (always the proxy's own address in a real deployment, and the
# literal string "testclient" for TestClient requests with no X-Forwarded-For header).

def test_reverse_proxy_resolved_ip_outside_allowlist_rejected(validToken):
    """ Regression test: before the fix, getApiToken used request.client.host, which for
    TestClient is always the literal "testclient" string - unconditionally bypassed by
    ipOnAllowList regardless of the resolved X-Forwarded-For IP or the site's allowed_ips.
    This proves the resolved IP is now what's actually checked. """
    response = client.get(
        ROUTE, headers={"token": validToken, "X-Forwarded-For": "8.8.8.8"}
    )
    assert response.status_code == 403


def test_reverse_proxy_resolved_ip_inside_allowlist_accepted(validToken):
    # The fixture site's allowed_ips is ["203.0.113.0/24"].
    response = client.get(
        ROUTE, headers={"token": validToken, "X-Forwarded-For": "203.0.113.5"}
    )
    assert response.status_code == 200


def test_reverse_proxy_resolved_ip_uses_last_hop_in_chain(validToken):
    # nginx's $proxy_add_x_forwarded_for appends the real client IP after anything the
    # client itself sent, so a spoofed leading hop must not affect the outcome - only the
    # trailing (nginx-appended, trustworthy) IP should be evaluated against the allowlist.
    response = client.get(
        ROUTE, headers={"token": validToken, "X-Forwarded-For": "127.0.0.1, 203.0.113.5"}
    )
    assert response.status_code == 200

    response = client.get(
        ROUTE, headers={"token": validToken, "X-Forwarded-For": "203.0.113.5, 8.8.8.8"}
    )
    assert response.status_code == 403


# --- Token generation endpoint correctness ---

def validTokenPayload(**overrides):
    payload = {
        "proto": "https", "port": "443", "domain": "misp.example.net",
        "auth": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD", "expire": "2030-12-12",
    }
    payload.update(overrides)
    return payload


def test_generate_token_json_rejects_proto_with_trailing_garbage():
    """ Regression test: validateProtoFormat used to be r'^https|http$', which due to
    missing grouping parses as (^https)|(http$) - so "httpsXXXEVILXXX" incorrectly passed
    Pydantic validation (it starts with "https"). Must now be rejected with 422. """
    response = client.post(
        "/v1/generate_token_json", json=validTokenPayload(proto="httpsXXXEVILXXX")
    )
    assert response.status_code == 422


@pytest.mark.parametrize("port", ["8080", "8443", "1024", "65535"])
def test_generate_token_json_accepts_high_ports(port):
    """ Regression test: dependencies.validateStringBool's port regex used to only cover
    0-999 and 1020-1023, silently rejecting every other valid port (including common ones
    like 8080/8443) even though the Pydantic model already accepted them. """
    response = client.post("/v1/generate_token_json", json=validTokenPayload(port=port))
    assert response.status_code == 200
    assert "token" in response.json()


def test_generate_token_json_invalid_input_returns_error_not_fake_token():
    """ Regression test: formPostJson used to return result['detail'] as the "token" field
    unconditionally, even when encryptString failed validation - producing a 200 OK response
    with the literal string "Invalid config token format" standing in as if it were a real
    token. "9999-12-31" passes Pydantic's date type + regex (any 4-digit year), but fails
    dependencies.py's stricter 19xx/20xx-only check, so it's a real, naturally occurring
    case where Pydantic validation passes but encryptString legitimately rejects the input. """
    response = client.post(
        "/v1/generate_token_json", json=validTokenPayload(expire="9999-12-31")
    )
    assert response.status_code == 415
    assert response.json()['detail'] == "Invalid config token format"


def test_generate_token_form_invalid_input_shows_error_not_fake_token():
    response = client.post("/v1/generate_token_form", data=validTokenPayload(expire="9999-12-31"))
    assert response.status_code == 200
    assert "ERROR: Invalid config token format" in response.text
