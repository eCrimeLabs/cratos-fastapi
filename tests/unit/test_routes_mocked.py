import os

import pytest
import yaml
from fastapi.testclient import TestClient

from app import dependencies
from app.config import GLOBALCONFIG
from app.core import feeds, misp
from app.main import app

client = TestClient(app)

SALT = GLOBALCONFIG['salt'].encode()
PASSWORD = GLOBALCONFIG['encryption_key'].encode()
FIXTURE_FQDN = "cratosroutestestfixture.invalid"
FIXTURE_SITE_PATH = os.path.join('sites', f"{FIXTURE_FQDN}.yaml")
AUTHKEY = "C" * 40


@pytest.fixture(scope="module")
def validToken():
    siteConfig = {
        'enabled': True,
        'debug': False,
        'company': 'Routes Test Co',
        'tag': 'routestest',
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


@pytest.fixture
def authHeaders(validToken):
    return {"token": validToken}


def fakeGETRequest(returnValue):
    def _fake(*args, **kwargs):
        return dict(returnValue)
    return _fake


# --- /robots.txt ---

def test_robots_txt():
    response = client.get("/robots.txt")
    assert response.status_code == 200
    assert "Disallow: /" in response.text


# --- /v1/check ---

def test_check_success(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': True, 'status_code': 200, 'encoding': 'utf-8', 'content': {'version': '2.4.180'}}
    ))
    response = client.get("/v1/check", headers=authHeaders)
    assert response.status_code == 200
    assert response.json()['content']['version'] == '2.4.180'


def test_check_connection_error_maps_to_503(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': False, 'error_num': 2, 'error': 'MISP - Connection error'}
    ))
    response = client.get("/v1/check", headers=authHeaders)
    assert response.status_code == 503


def test_check_timeout_maps_to_504(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': False, 'error_num': 3, 'error': 'MISP - Connection error, timeout'}
    ))
    response = client.get("/v1/check", headers=authHeaders)
    assert response.status_code == 504


def test_check_auth_failure_maps_to_403(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': False, 'error_num': 1, 'error': 'MISP - Authentication failed', 'status_code': 403, 'content': 'Authentication failed', 'encoding': 'utf-8'}
    ))
    response = client.get("/v1/check", headers=authHeaders)
    assert response.status_code == 403


def test_check_missing_version_key_maps_to_415(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': True, 'status_code': 200, 'encoding': 'utf-8', 'content': {'no_version_here': True}}
    ))
    response = client.get("/v1/check", headers=authHeaders)
    assert response.status_code == 415


# --- /v1/statistics ---
# These are the regression cases for the KeyError crash fixed in app/core/misp.py:
# mispGetStatistics/mispGetWarninglists used to assume a 'content' key always exists,
# but ConnectionError/Timeout responses from mispGETRequest never set one.

def test_statistics_success(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': True, 'status_code': 200, 'encoding': 'utf-8', 'content': {'ip-src': 42}}
    ))
    response = client.get("/v1/statistics", headers=authHeaders)
    assert response.status_code == 200
    assert response.json()['content']['ip-src'] == 42


def test_statistics_connection_error_does_not_crash(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': False, 'error_num': 2, 'error': 'MISP - Connection error'}
    ))
    response = client.get("/v1/statistics", headers=authHeaders)
    assert response.status_code == 503


def test_statistics_timeout_does_not_crash(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': False, 'error_num': 3, 'error': 'MISP - Connection error, timeout'}
    ))
    response = client.get("/v1/statistics", headers=authHeaders)
    assert response.status_code == 504


def test_statistics_non_dict_content_maps_to_415(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': True, 'status_code': 200, 'encoding': 'utf-8', 'content': 'not-json'}
    ))
    response = client.get("/v1/statistics", headers=authHeaders)
    assert response.status_code == 415


# --- /v1/warninglist ---

def test_warninglist_index_success(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest({
        'status': True, 'status_code': 200, 'encoding': 'utf-8',
        'content': {'Warninglists': [{'Warninglist': {'id': '1', 'name': 'test-list'}}]}
    }))
    response = client.get("/v1/warninglist/id/0/output/json", headers=authHeaders)
    assert response.status_code == 200


def test_warninglist_connection_error_does_not_crash(authHeaders, monkeypatch):
    monkeypatch.setattr(misp, 'mispGETRequest', fakeGETRequest(
        {'status': False, 'error_num': 2, 'error': 'MISP - Connection error'}
    ))
    response = client.get("/v1/warninglist/id/0/output/json", headers=authHeaders)
    assert response.status_code == 503


# --- /v1/clear_cache (no MISP call at all; just shouldn't crash without memcached) ---

def test_clear_cache_ok_without_memcached(authHeaders):
    response = client.delete(
        "/v1/clear_cache/feed/incident/type/ipv4/age/1h/output/txt",
        headers=authHeaders,
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}


# --- /v1/feed error paths ---

def test_feed_misp_search_failure_maps_to_503(authHeaders, monkeypatch):
    def fakeSearch(requestData):
        return {'status': False, 'error_num': 10, 'error': 'PyMISP to MISP - Connection error'}

    monkeypatch.setattr(misp, 'mispSearchAttributesSimpel', fakeSearch)
    response = client.get(
        "/v1/feed/incident/type/ipv4/age/1h/output/txt", headers=authHeaders
    )
    assert response.status_code == 503


def test_feed_unhandled_exception_maps_to_500(authHeaders, monkeypatch):
    def raisingGetFeedsData(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(feeds, 'get_feeds_data', raisingGetFeedsData)
    response = client.get(
        "/v1/feed/incident/type/ipv4/age/1h/output/txt", headers=authHeaders
    )
    assert response.status_code == 500
    assert response.json()['detail'] == "Thread error"
