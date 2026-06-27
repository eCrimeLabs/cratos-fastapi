# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

CRATOS is a FastAPI proxy that sits between security infrastructure (SIEM, firewalls, EDR, proxies, etc.) and one or more MISP Threat Sharing Platform instances. It lets consumers pull threat indicators in various structured formats without giving them direct access to MISP or leaking event context. Single-process app (`app/main.py`), no database — config is filesystem YAML, optional caching is via memcached.

## Commands

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run dev server
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

# Run prod server (gunicorn_config.py expects /opt/cratos-fastapi as chdir and a 'fastapi' user — adjust before using locally)
gunicorn app.main:app --config gunicorn_config.py

# Tests — requires test.token (copy from test.token.example, fill with a real MISP-backed Cratos token)
pytest tests/unit/test_api.py
pytest tests/unit/test_api.py --html=report.html   # HTML report
pytest tests/unit/test_api.py -k test_get_feeds_data  # single test / pattern
```

`tests/unit/test_api_external.py` hits a hardcoded external URL (`https://cratos.ecrimelabs.net`) rather than the in-process `TestClient` — it's for live-environment smoke testing, not part of normal local test runs.

There is no linter/formatter configured in this repo.

## Architecture

**Request flow:** route in `app/main.py` → `app/dependencies.getApiToken` (auth) → `app/core/feeds.py` or `app/core/vendors.py` (build MISP search params, normalize/regex-extract output) → `app/core/misp.py` (PyMISP / raw HTTP calls to MISP) → formatted `Response`.

**Multi-tenant config model — this is the core thing to understand:**
- `config/config.yaml` — global app settings (encryption key/salt, memcached connection, reverse proxy trust settings, global allowlisted IPs). Loaded once at import time into `GLOBALCONFIG` (`app/config.py`), validated against `config/config.schema` (yamale).
- `config/mappings.yaml` — static maps of feed-name → MISP attribute types, age-string → relative time, output formats. Merged into `GLOBALCONFIG`.
- `sites/<fqdn-or-ip>.yaml` — one file per MISP instance Cratos is allowed to talk to (company, tag prefix, custom feed→tag mappings, per-site allowed IPs, blacklisted token hashes, MISP connection options). Validated against `sites/sites.schema` at startup (`app/config.validateSiteConfigs`) — **every site file must pass schema validation or the whole app fails to start.**
- The **API token is not a lookup key into a database** — it's a Fernet-encrypted, PBKDF2-derived blob (`app/dependencies.encryptString`/`decryptString`) containing `proto;port;fqdn;misp_auth_key;expiry_date`. Decrypting it yields the FQDN, which is then used to pick which `sites/<fqdn>.yaml` to load (path-sanitized — see Security below). Tokens are minted via `/v1/generate_token_form` (UI) or `/v1/generate_token_json` (API), both go through the same `encryptString`/`validateStringBool` path. `app/dependencies.checkApiToken` is the full validation pipeline: decrypt → load site config → check token blacklist (sha256) → check source IP against global + site allowlists.

**Feed/vendor model:** A "feed" (`ModelFeedName` in `app/models/models.py`) maps to a MISP tag suffix (e.g. `incident` → `<site tag>:incident-classification=incident`); custom per-site feeds (`cust1`..`cust5`) are defined in each site's YAML. A "data type" (`ModelDataType`) maps to one or more MISP attribute types via `config/mappings.yaml`'s `types:` section, and to an extraction regex in `feeds.mispDataParsingSimple` used to pull the actual indicator value back out of whatever MISP returned (defense against malformed/garbage attribute values). `app/core/vendors.py` post-processes the same data for vendor-specific quirks (currently `paloalto`, `cisco`) — adding a vendor means adding to `ModelVendorName` and a branch in the `/v1/vendor/...` route plus a `formatXOutputData` function in `vendors.py`.

**Caching:** memcached is optional/best-effort. Cache key = sha256 of the full request parameter tuple + API token (so cache entries are per-tenant). `app/dependencies.py` holds a single pooled `bmemcached.Client` (`getMemcacheClient`, lazily created, module-level singleton). Any memcache failure degrades to a cache miss rather than an error.

**Models (`app/models/models.py`) are the contract surface**, not internal-only — `ModelFeedName`, `ModelDataType`, `ModelOutputType`, `ModuleOutputAge`, `ModelVendorName` are all `str, Enum` used directly as FastAPI path/query types, so adding a new feed/datatype/output/vendor means updating the enum *and* the corresponding section of `config/mappings.yaml` (for data types) or a site's `custom_feeds` (for feeds) — they have to stay in sync, there's no runtime cross-check forcing it other than the schema validators.

**Middleware stack** (`app/main.py`, applied in declaration order — last declared runs outermost): request logging with IP resolution that respects `reverse_proxy`/`reverse_proxy_header` config (and anonymizes `token=` query values before logging), a memory-usage watchdog that force-GCs above 500MB RSS, and security headers added only to a small allowlist of paths (`/v1/help`, `/redoc`, `/v1/generate_token_form`).

**Error convention:** internal functions return `{'status': bool, 'detail'/'error': str, 'error_num': int, ...}` dicts rather than raising; routes translate `error_num` to HTTP status via the `error_mapping` dict near the top of `app/main.py`. When adding a new failure mode in `core/`, add the numeric code to `error_mapping` too, or it falls through to a generic 500.

## Known open issues

`SECURITY_AUDIT.md` tracks a self-audit with several **OPEN** findings worth checking before touching related code: ReDoS-prone regexes in `app/dependencies.py`/`app/main.py`, no rate limiting, weak token-format validation regex, MD5 cache-key helper still present (deprecated in favor of `sha256HashCacheKey`), and the `srcIP == 'testclient'` bypass in `dependencies.ipOnAllowList` (needed for FastAPI `TestClient`, but worth knowing it exists). One CRITICAL path-traversal finding (site config file resolution from a decrypted token) has already been fixed and is reflected in the current `orgConfigExtraction` code.
