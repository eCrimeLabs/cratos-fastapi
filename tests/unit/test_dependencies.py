import base64
import hashlib
import os

import pytest
import yaml

from app import dependencies
from app.config import GLOBALCONFIG

SALT = GLOBALCONFIG['salt'].encode()
PASSWORD = GLOBALCONFIG['encryption_key'].encode()
FIXTURE_FQDN = "cratospytestfixture.invalid"
FIXTURE_SITE_PATH = os.path.join('sites', f"{FIXTURE_FQDN}.yaml")
AUTHKEY = "A" * 40


def buildToken(domain=FIXTURE_FQDN, proto="https", port="443", auth=AUTHKEY, expire="2099-01-01"):
    plainText = f"{proto};{port};{domain};{auth};{expire}"
    result = dependencies.encryptString(plainText, SALT, PASSWORD)
    assert result['status'], f"Fixture token failed to encrypt: {result}"
    return result['detail']


def writeFixtureSite(allowed_ips=None, blacklisted_api_tokens=None):
    siteConfig = {
        'enabled': True,
        'debug': False,
        'company': 'Pytest Fixture Co',
        'tag': 'pytestfixture',
        'mispVerifyCert': True,
        'mispTimeoutSeconds': 5,
        'mispDebug': False,
        'memcached_all_timeout': 60,
        'falsepositive_timeout': '1d',
        'list_stats': '1d',
        'allowed_ips': allowed_ips if allowed_ips is not None else ["203.0.113.0/24"],
        'custom_feeds': {'cust1': ':incident-classification=cust1'},
        'ignore_to_ids': [],
        'blacklisted_api_tokens': blacklisted_api_tokens if blacklisted_api_tokens is not None else [],
    }
    with open(FIXTURE_SITE_PATH, 'w') as f:
        yaml.dump(siteConfig, f)


@pytest.fixture
def fixtureSite():
    writeFixtureSite()
    yield FIXTURE_FQDN
    if os.path.exists(FIXTURE_SITE_PATH):
        os.remove(FIXTURE_SITE_PATH)


# --- isUrlSafeBase64 ---

def test_is_url_safe_base64_valid():
    token = base64.urlsafe_b64encode(b"hello world").decode()
    assert dependencies.isUrlSafeBase64(token)['status'] is True


def test_is_url_safe_base64_invalid():
    result = dependencies.isUrlSafeBase64("abc")
    assert result['status'] is False


# --- cidrToIPs ---

def test_cidr_to_ips_slash_30():
    assert dependencies.cidrToIPs("192.0.2.0/30") == [
        "192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"
    ]


def test_cidr_to_ips_slash_32_single_host():
    assert dependencies.cidrToIPs("192.0.2.5/32") == ["192.0.2.5"]


def test_cidr_to_ips_slash_24():
    ips = dependencies.cidrToIPs("192.0.2.0/24")
    assert len(ips) == 256
    assert ips[0] == "192.0.2.0"
    assert ips[-1] == "192.0.2.255"


def test_cidr_to_ips_normalizes_host_bits_when_not_strict():
    # strict=False means a CIDR with host bits set (.5 in a /30) is normalized
    # to its containing network (192.0.2.4/30) rather than raising.
    assert dependencies.cidrToIPs("192.0.2.5/30") == [
        "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"
    ]


def test_cidr_to_ips_invalid_notation_returns_empty_list():
    assert dependencies.cidrToIPs("not-a-cidr") == []
    assert dependencies.cidrToIPs("999.999.999.999/24") == []
    assert dependencies.cidrToIPs("") == []


def test_cidr_to_ips_rejects_oversized_cidr_without_expanding():
    # Regression test: cidrToIPs used to have no upper bound, so a wide CIDR
    # (e.g. a malformed/poisoned MISP attribute value) could try to materialize
    # billions of address strings and exhaust memory. Confirm it now bails out
    # cheaply instead, honoring "max_cidr_expansion_addresses" from config.yaml.
    assert dependencies.cidrToIPs("0.0.0.0/0") == []
    assert dependencies.cidrToIPs("10.0.0.0/8") == []


def test_cidr_to_ips_respects_configured_limit(monkeypatch):
    monkeypatch.setitem(dependencies.configCore, 'max_cidr_expansion_addresses', 4)
    assert dependencies.cidrToIPs("192.0.2.0/30") == [
        "192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"
    ]
    assert dependencies.cidrToIPs("192.0.2.0/29") == []  # 8 addresses > configured limit of 4


# --- isTokenExpired ---

def test_is_token_expired_future_date():
    assert dependencies.isTokenExpired("2099-01-01")['status'] is True


def test_is_token_expired_past_date():
    result = dependencies.isTokenExpired("2000-01-01")
    assert result['status'] is False
    assert "expired" in result['detail'].lower()


def test_is_token_expired_invalid_format():
    result = dependencies.isTokenExpired("not-a-date")
    assert result['status'] is False
    assert "invalid" in result['detail'].lower()


# --- ipOnAllowList ---

def test_ip_on_allow_list_testclient_bypass():
    assert dependencies.ipOnAllowList("testclient", [], [])['status'] is True


def test_ip_on_allow_list_in_global_ips():
    result = dependencies.ipOnAllowList("203.0.113.5", ["203.0.113.0/24"], [])
    assert result['status'] is True


def test_ip_on_allow_list_in_org_ips():
    result = dependencies.ipOnAllowList("198.51.100.5", [], ["198.51.100.0/24"])
    assert result['status'] is True


def test_ip_on_allow_list_not_allowed():
    result = dependencies.ipOnAllowList("8.8.8.8", ["203.0.113.0/24"], ["198.51.100.0/24"])
    assert result['status'] is False
    assert "not allowed" in result['detail']


# --- blacklistApiTokenCheck ---

def test_blacklist_check_not_blacklisted():
    result = dependencies.blacklistApiTokenCheck({'blacklisted_api_tokens': []}, "sometoken")
    assert result['status'] is True


def test_blacklist_check_no_blacklist_key():
    result = dependencies.blacklistApiTokenCheck({}, "sometoken")
    assert result['status'] is True


def test_blacklist_check_blacklisted():
    token = "sometoken"
    tokenHash = hashlib.sha256(token.encode()).hexdigest()
    result = dependencies.blacklistApiTokenCheck({'blacklisted_api_tokens': [tokenHash]}, token)
    assert result['status'] is False
    assert "blacklisted" in result['detail'].lower()


# --- validateStringBool ---

@pytest.mark.parametrize("plainText", [
    "https;443;misp.example.net;" + AUTHKEY + ";2030-12-31",
    "http;80;misp.example.net;" + AUTHKEY + ";2030-12-31",
    "https;8080;misp.example.net;" + AUTHKEY + ";2030-12-31",   # regression: ports 1024-65535
    "https;8443;misp.example.net;" + AUTHKEY + ";2030-12-31",   # used to be wrongly rejected
    "https;65535;misp.example.net;" + AUTHKEY + ";2030-12-31",
    "https;1024;misp.example.net;" + AUTHKEY + ";2030-12-31",
])
def test_validate_string_bool_valid(plainText):
    assert dependencies.validateStringBool(plainText) is True


@pytest.mark.parametrize("plainText", [
    "ftp;443;misp.example.net;" + AUTHKEY + ";2030-12-31",        # bad proto
    "https;99999;misp.example.net;" + AUTHKEY + ";2030-12-31",    # bad port
    "https;443;mi/sp.example.net;" + AUTHKEY + ";2030-12-31",     # slash in domain
    "https;443;misp.example.net;tooshortkey;2030-12-31",          # bad auth length
    "https;443;misp.example.net;" + AUTHKEY + ";31-12-2030",      # bad date format
    "https;443;misp.example.net;" + AUTHKEY,                      # missing field
])
def test_validate_string_bool_invalid(plainText):
    assert dependencies.validateStringBool(plainText) is False


# --- encryptString / decryptString roundtrip ---

def test_encrypt_decrypt_roundtrip():
    plainText = f"https;443;misp.example.net;{AUTHKEY};2030-12-31"
    encrypted = dependencies.encryptString(plainText, SALT, PASSWORD)
    assert encrypted['status'] is True

    decrypted = dependencies.decryptString(encrypted['detail'], SALT, PASSWORD)
    assert decrypted['status'] is True
    assert decrypted['detail'] == plainText


def test_encrypt_string_rejects_invalid_format():
    result = dependencies.encryptString("not;a;valid;token", SALT, PASSWORD)
    assert result['status'] is False


# --- orgConfigExtraction: path traversal regression (SECURITY_AUDIT.md CRITICAL finding) ---

def test_org_config_extraction_rejects_backslash_traversal():
    payload = f"https;443;..\\..\\..\\..\\windows\\system32\\config;{AUTHKEY};2099-01-01"
    result = dependencies.orgConfigExtraction(payload)
    assert result['status'] is False


def test_org_config_extraction_rejects_forward_slash_traversal():
    payload = f"https;443;../../../../etc/passwd;{AUTHKEY};2099-01-01"
    result = dependencies.orgConfigExtraction(payload)
    assert result['status'] is False


def test_org_config_extraction_unknown_site_not_found():
    payload = f"https;443;no-such-site-exists.invalid;{AUTHKEY};2099-01-01"
    result = dependencies.orgConfigExtraction(payload)
    assert result['status'] is False
    assert "not found" in result['detail'].lower()


def test_org_config_extraction_expired_token():
    payload = f"https;443;{FIXTURE_FQDN};{AUTHKEY};2000-01-01"
    result = dependencies.orgConfigExtraction(payload)
    assert result['status'] is False
    assert "expired" in result['detail'].lower()


def test_org_config_extraction_valid(fixtureSite):
    payload = f"https;443;{fixtureSite};{AUTHKEY};2099-01-01"
    result = dependencies.orgConfigExtraction(payload)
    assert result['status'] is True
    assert result['config']['tag'] == 'pytestfixture'


# --- checkApiToken: full pipeline ---

def test_check_api_token_valid_allowed_ip(fixtureSite, monkeypatch):
    monkeypatch.setitem(dependencies.configCore, 'allways_allowed_ips', [])
    token = buildToken(domain=fixtureSite)
    result = dependencies.checkApiToken(token, SALT, PASSWORD, "203.0.113.5")
    assert result['status'] is True


def test_check_api_token_ip_not_allowed(fixtureSite, monkeypatch):
    monkeypatch.setitem(dependencies.configCore, 'allways_allowed_ips', [])
    token = buildToken(domain=fixtureSite)
    result = dependencies.checkApiToken(token, SALT, PASSWORD, "8.8.8.8")
    assert result['status'] is False


def test_check_api_token_global_allowlist_grants_access(fixtureSite, monkeypatch):
    monkeypatch.setitem(dependencies.configCore, 'allways_allowed_ips', ["192.0.2.0/24"])
    token = buildToken(domain=fixtureSite)
    result = dependencies.checkApiToken(token, SALT, PASSWORD, "192.0.2.5")
    assert result['status'] is True


def test_check_api_token_expired(fixtureSite, monkeypatch):
    monkeypatch.setitem(dependencies.configCore, 'allways_allowed_ips', [])
    token = buildToken(domain=fixtureSite, expire="2000-01-01")
    result = dependencies.checkApiToken(token, SALT, PASSWORD, "203.0.113.5")
    assert result['status'] is False
    assert "expired" in result['detail'].lower()


def test_check_api_token_blacklisted(monkeypatch):
    monkeypatch.setitem(dependencies.configCore, 'allways_allowed_ips', [])
    token = buildToken()
    tokenHash = dependencies.sha256HashCacheKey(token)
    writeFixtureSite(blacklisted_api_tokens=[tokenHash])
    try:
        result = dependencies.checkApiToken(token, SALT, PASSWORD, "203.0.113.5")
        assert result['status'] is False
        assert "blacklisted" in result['detail'].lower()
    finally:
        os.remove(FIXTURE_SITE_PATH)


def test_check_api_token_not_base64():
    result = dependencies.checkApiToken("not-a-valid-token!!!", SALT, PASSWORD, "203.0.113.5")
    assert result['status'] is False


def test_check_api_token_unknown_site():
    token = buildToken(domain="nosuchsiteexists.invalid")
    result = dependencies.checkApiToken(token, SALT, PASSWORD, "203.0.113.5")
    assert result['status'] is False
