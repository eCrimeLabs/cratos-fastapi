from fastapi.testclient import TestClient
from app.main import app
import pytest
import json
import yaml
import time
from defusedxml import ElementTree as DefusedET
from app.models.models import ModelDataType, ModelFeedName, ModelOutputType
from concurrent.futures import ThreadPoolExecutor
from itertools import product
import random

with open('test.token', 'r') as f:
    token = f.read().strip()

''' 
   Define the percentage as a string, for how many values to select from Model DataType
   Running the test with 100% of the total values from ModelDataType will take long time
   
   As default we are sampling 10% random values from ModelDataType
'''
PERCENTAGE_DATATYPE = "10%"
TOKEN_HEADER = {"token": token}
MAX_WORKERS = 5
DATAAGE = ["1h", "1w"]

client = TestClient(app)

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




# Convert the percentage string to a decimal
percentage = int(PERCENTAGE_DATATYPE.rstrip('%')) / 100

# Calculate % of the total number of values from ModelDataType
sample_size = int(len(ModelDataType) * percentage)

# Select a random sample of values
samplingModelDataTypes = random.sample([e.value for e in ModelDataType], sample_size)

@pytest.mark.parametrize("feedName,dataType,dataAge,returnedDataType", product([e.value for e in ModelFeedName], samplingModelDataTypes, DATAAGE, [e.value for e in ModelOutputType]))
def test_get_feeds_data(feedName, dataType, dataAge, returnedDataType):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        
        futures = [executor.submit(client.get, f"/v1/feed/{feedName}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", headers=TOKEN_HEADER)]
        
        for future in futures:
            start_time = time.time()
            response = future.result()
            content = response.content
            end_time = time.time()
            print(f"Request and response time: {end_time - start_time} seconds")
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
