from fastapi.testclient import TestClient
from app.main import app
import pytest
import json
import yaml
import time
import re
import base64
import ipaddress
from defusedxml import ElementTree as DefusedET
from app.models.models import ModelDataType, ModelFeedName, ModelOutputType, ModelVendorName
from itertools import product
import random
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Per-data-type structural validators for live content checks below. Data types not
# listed here are free-form (mutex, snort, yara, sigma, email-subject, email-attachment,
# url, crypto-currency) and only get the format-validity check, not a content shape check.
def _isValidIPv6(value):
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False

CONTENT_VALIDATORS = {
    'ipv4': lambda v: re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v),
    'ipv4ext': lambda v: re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v),
    'cidr4': lambda v: re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', v),
    'ipv6': _isValidIPv6,
    'domain': lambda v: '.' in v and ' ' not in v,
    'hostname': lambda v: '.' in v and ' ' not in v,
    'file-md5': lambda v: re.match(r'^[a-fA-F0-9]{32}$', v),
    'file-sha1': lambda v: re.match(r'^[a-fA-F0-9]{40}$', v),
    'file-sha256': lambda v: re.match(r'^[a-fA-F0-9]{64}$', v),
    'x509-fingerprint-md5': lambda v: re.match(r'^[a-fA-F0-9]{32}$', v),
    'x509-fingerprint-sha1': lambda v: re.match(r'^[a-fA-F0-9]{40}$', v),
    'x509-fingerprint-sha256': lambda v: re.match(r'^[a-fA-F0-9]{64}$', v),
    'email-address': lambda v: '@' in v,
    'vulnerability': lambda v: re.match(r'^cve-\d{4}-\d{4,7}$', v, re.IGNORECASE),
    'ja3': lambda v: re.match(r'^[a-f0-9]{32}$', v),
    'hassh-md5': lambda v: re.match(r'^[a-f0-9]{32}$', v),
    'hasshserver-md5': lambda v: re.match(r'^[a-f0-9]{32}$', v),
    'imphash': lambda v: re.match(r'^[a-f0-9]{32}$', v),
    'chrome-extension-id': lambda v: re.match(r'^[a-p]{32}$', v),
    'edge-extension-id': lambda v: re.match(r'^[a-p]{32}$', v),
}

def decodeOutputToValues(content: bytes, outputType: str) -> list:
    """ Decode a feed/vendor response body back into a list of string values, regardless
    of output format. Returns [] for genuinely empty results (MISP had no matching data) -
    callers should treat an empty list as "nothing to validate", not a failure. """
    text = content.decode('utf-8', errors='replace')
    if outputType == 'json':
        data = json.loads(text)
        return data if isinstance(data, list) else []
    elif outputType == 'yaml':
        data = yaml.safe_load(text)
        return data if isinstance(data, list) else []
    elif outputType == 'xml':
        root = DefusedET.fromstring(text)
        return [child.text for child in root if child.text]
    elif outputType == 'b64':
        return [base64.b64decode(line).decode('utf-8') for line in text.split('\r\n') if line.strip()]
    elif outputType == 'txt':
        return [line for line in text.split('\r\n') if line.strip()]
    return []

def assertContentValidForDataType(content: bytes, outputType: str, dataType: str):
    """ Only enforced when MISP actually returned data for this combination - an empty
    result is a valid outcome (the live instance may simply have no attributes matching
    this feed/type/age right now), not a failure. """
    validator = CONTENT_VALIDATORS.get(dataType)
    if not validator:
        return
    values = decodeOutputToValues(content, outputType)
    if not values:
        return
    invalid = [v for v in values if not validator(v)]
    assert not invalid, f"{dataType} values failing content validation: {invalid[:5]}"

with open('test.token', 'r') as f:
    token = f.read().strip()

PERCENTAGE_DATATYPE = "10%"
TOKEN_HEADER = {"token": token}
MAX_WORKERS = 5
DATAAGE = ["1h", "1w"]
ORGUUID = ['55f6ea5e-2c60-40e5-964f-47a8950d210f', '569b6c1f-bd1c-49c8-9244-0484bce2ab96']

client = TestClient(app)

percentage = int(PERCENTAGE_DATATYPE.rstrip('%')) / 100
# Ensure at least 1 sample to avoid division by zero
sample_size = max(1, int(len(ModelDataType) * percentage))
samplingModelDataTypes = random.sample([e.value for e in ModelDataType], sample_size)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "message" in response.json()
    assert "IP" in response.json()
    assert "User-Agent" in response.json()
    assert "timestamp" in response.json()

def test_favicon():
    response = client.get("/favicon.ico")
    assert response.status_code == 200

def test_status():
    response = client.get("/v1/status")
    assert response.status_code == 200
    assert "ping" in response.json()
    assert "memcachedstatus" in response.json()

def test_generate_token_form():
    response = client.get("/v1/generate_token_form")
    assert response.status_code == 200

def test_generate_token_json():
    response = client.post("/v1/generate_token_json", json={"proto": "https", "port": "443", "domain": "demo.example.net", "auth": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD", "expire": "2030-12-12"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict), "Response is probably not a valid JSON object converted to dictionary"
    assert data['MISP'] == 'https://demo.example.net:443/', "Expected 'MISP URL' value not found in the JSON response"
    assert data['validity'] == '2030-12-12', "Expected 'validity' value not found or incorrect in the JSON response"

def test_openapi():
    response = client.get("/v1/openapi.json")
    assert response.status_code == 200

@pytest.mark.parametrize("feedName,dataType,dataAge,returnedDataType", product([e.value for e in ModelFeedName], samplingModelDataTypes, DATAAGE, [e.value for e in ModelOutputType]))
def test_get_feeds_data(feedName, dataType, dataAge, returnedDataType):
    start_time = time.time()
    response = client.get(f"/v1/feed/{feedName}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", headers=TOKEN_HEADER)
    end_time = time.time()
    logger.info(f"Request and response time: {end_time - start_time:.3f} seconds")
    assert response.status_code == 200

    if returnedDataType == "json":
        try:
            json.loads(response.content)
        except json.JSONDecodeError:
            pytest.fail("Invalid JSON")
    elif returnedDataType == "yaml":
        try:
            yaml.safe_load(response.content)
        except yaml.YAMLError:
            pytest.fail("Invalid YAML")
    elif returnedDataType == "xml":
        try:
            DefusedET.fromstring(response.content)
        except DefusedET.ParseError as e:
            # Print debugging information
            print(f"\n{'='*80}")
            print(f"XML Parse Error for: {feedName}-{dataType}-{dataAge}")
            print(f"Error: {e}")
            print(f"{'='*80}")
            
            # Find and print the problematic character/data
            content = response.content.decode('utf-8', errors='replace')
            
            # Extract error position from the exception message
            import re
            match = re.search(r'line (\d+), column (\d+)', str(e))
            if match:
                line_num = int(match.group(1))
                col_num = int(match.group(2))
                
                lines = content.split('\n')
                if line_num <= len(lines):
                    problem_line = lines[line_num - 1]
                    print(f"\nProblematic line {line_num}:")
                    print(f"{problem_line[:200]}...")  # First 200 chars
                    
                    if col_num < len(problem_line):
                        # Show context around the problematic character
                        start = max(0, col_num - 50)
                        end = min(len(problem_line), col_num + 50)
                        context = problem_line[start:end]
                        
                        print(f"\nContext around column {col_num}:")
                        print(f"{context}")
                        print(f"{' ' * (col_num - start - 1)}^ HERE")
                        
                        # Show character details
                        if col_num - 1 < len(problem_line):
                            bad_char = problem_line[col_num - 1]
                            print(f"\nProblematic character: repr={repr(bad_char)}, ord={ord(bad_char)}, hex=0x{ord(bad_char):04x}")
                            
                            # Try to find the actual entry containing this character
                            entries = re.findall(r'<entry>([^<]*' + re.escape(bad_char) + r'[^<]*)</entry>', problem_line)
                            if entries:
                                print(f"\nProblematic entry(ies):")
                                for i, entry in enumerate(entries[:5], 1):  # Show first 5
                                    print(f"{i}. {entry}")
            
            print(f"{'='*80}\n")
            pytest.fail(f"Invalid XML: {e}")

    assertContentValidForDataType(response.content, returnedDataType, dataType)

@pytest.mark.parametrize("orgUUID,dataType,dataAge,returnedDataType", product(ORGUUID, samplingModelDataTypes, DATAAGE, [e.value for e in ModelOutputType]))
def test_get_org_uuid_data(orgUUID, dataType, dataAge, returnedDataType):
    start_time = time.time()
    response = client.get(f"/v1/uuid/{orgUUID}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", headers=TOKEN_HEADER)
    end_time = time.time()
    logger.info(f"Request and response time: {end_time - start_time:.3f} seconds")
    assert response.status_code == 200

    if returnedDataType == "json":
        try:
            json.loads(response.content)
        except json.JSONDecodeError:
            pytest.fail("Invalid JSON")
    elif returnedDataType == "yaml":
        try:
            yaml.safe_load(response.content)
        except yaml.YAMLError:
            pytest.fail("Invalid YAML")
    elif returnedDataType == "xml":
        try:
            DefusedET.fromstring(response.content)
        except DefusedET.ParseError:
            pytest.fail("Invalid XML")

    assertContentValidForDataType(response.content, returnedDataType, dataType)

@pytest.mark.parametrize("vendorName,feedName,dataType,dataAge", product([e.value for e in ModelVendorName], [e.value for e in ModelFeedName], samplingModelDataTypes, DATAAGE))
def test_get_vendor_feeds_data(vendorName, feedName, dataType, dataAge):
    start_time = time.time()
    response = client.get(f"/v1/vendor/{vendorName}/feed/{feedName}/type/{dataType}/age/{dataAge}", headers=TOKEN_HEADER)
    end_time = time.time()
    logger.info(f"Request and response time: {end_time - start_time:.3f} seconds - /v1/vendor/{vendorName}/feed/{feedName}/type/{dataType}/age/{dataAge}")
    assert response.status_code == 200

    # Vendor output is always plain text regardless of dataType.
    assertContentValidForDataType(response.content, "txt", dataType)

    if dataType == "url" and vendorName == "paloalto":
        # PaloAlto-specific: the *leading* protocol must be stripped from every URL entry
        # (formatPaloaltoOutputData only strips a leading scheme - real-world URLs often
        # contain a second, unrelated "://" later in the string, e.g. a redirect query
        # parameter or a defanged "hxxp://" indicator embedded in the path, which is
        # correctly left untouched - so checking for "://" anywhere would be a false positive).
        values = decodeOutputToValues(response.content, "txt")
        stillHasLeadingProtocol = [v for v in values if re.match(r'^\w+://', v)]
        assert not stillHasLeadingProtocol, f"PaloAlto output retained a leading protocol on: {stillHasLeadingProtocol[:5]}"