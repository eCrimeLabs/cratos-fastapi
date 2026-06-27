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
