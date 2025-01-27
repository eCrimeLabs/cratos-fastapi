from fastapi.testclient import TestClient
from app.main import app
import pytest
import json
import yaml
import time
from defusedxml import ElementTree as DefusedET
from app.models.models import ModelDataType, ModelFeedName, ModelOutputType, ModelVendorName
from concurrent.futures import ThreadPoolExecutor
from itertools import product
import random
import pprint
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

with open('test.token', 'r') as f:
    token = f.read().strip()

PERCENTAGE_DATATYPE = "10%"
TOKEN_HEADER = {"token": token}
MAX_WORKERS = 5
DATAAGE = ["1h", "1w"]
ORGUUID = ['55f6ea5e-2c60-40e5-964f-47a8950d210f', '569b6c1f-bd1c-49c8-9244-0484bce2ab96']

client = TestClient(app)

percentage = int(PERCENTAGE_DATATYPE.rstrip('%')) / 100
sample_size = int(len(ModelDataType) * percentage)
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
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(client.get, f"/v1/feed/{feedName}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", headers=TOKEN_HEADER)]
        for future in futures:
            start_time = time.time()
            response = future.result()
            content = response.content
            end_time = time.time()
            logger.info(f"Request and response time: {end_time - start_time} seconds")
            assert response.status_code == 200

            if returnedDataType == "json":
                try:
                    json.loads(content)
                except json.JSONDecodeError:
                    pytest.fail("Invalid JSON")
            elif returnedDataType == "yaml":
                try:
                    yaml.safe_load(content)
                except yaml.YAMLError:
                    pytest.fail("Invalid YAML")
            elif returnedDataType == "xml":
                try:
                    DefusedET.fromstring(content)
                except DefusedET.ParseError:
                    pytest.fail("Invalid XML")

@pytest.mark.parametrize("orgUUID,dataType,dataAge,returnedDataType", product(ORGUUID, samplingModelDataTypes, DATAAGE, [e.value for e in ModelOutputType]))
def test_get_org_uuid_data(orgUUID, dataType, dataAge, returnedDataType):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(client.get, f"/v1/uuid/{orgUUID}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", headers=TOKEN_HEADER)]
        for future in futures:
            start_time = time.time()
            response = future.result()
            content = response.content
            end_time = time.time()
            logger.info(f"Request and response time: {end_time - start_time} seconds")
            assert response.status_code == 200

            if returnedDataType == "json":
                try:
                    json.loads(content)
                except json.JSONDecodeError:
                    pytest.fail("Invalid JSON")
            elif returnedDataType == "yaml":
                try:
                    yaml.safe_load(content)
                except yaml.YAMLError:
                    pytest.fail("Invalid YAML")
            elif returnedDataType == "xml":
                try:
                    DefusedET.fromstring(content)
                except DefusedET.ParseError:
                    pytest.fail("Invalid XML")

@pytest.mark.parametrize("vendorName,feedName,dataType,dataAge", product([e.value for e in ModelVendorName], [e.value for e in ModelFeedName], samplingModelDataTypes, DATAAGE))
def test_get_vendor_feeds_data(vendorName, feedName, dataType, dataAge):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(client.get, f"/v1/vendor/{vendorName}/feed/{feedName}/type/{dataType}/age/{dataAge}", headers=TOKEN_HEADER)]
        pprint.pprint(futures)
        for future in futures:
            start_time = time.time()
            response = future.result()
            content = response.content
            end_time = time.time()
            logger.info(f"Request and response time: {end_time - start_time} seconds")
            logger.info(f"/v1/vendor/{vendorName}/feed/{feedName}/type/{dataType}/age/{dataAge}")
            assert response.status_code == 200