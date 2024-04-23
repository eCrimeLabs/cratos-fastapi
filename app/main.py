#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from sys import prefix
from fastapi import Security, Depends, FastAPI, HTTPException, Request, Response, APIRouter, Header, Form, Path, Query
from fastapi.security.api_key import APIKeyQuery, APIKeyCookie, APIKeyHeader, APIKey
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi_versioning import VersionedFastAPI, version
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import FileResponse
from fastapi.encoders import jsonable_encoder
from typing import Union
from typing_extensions import Annotated
from datetime import date, datetime, timezone

from pydantic import BaseModel, Field, create_model
from starlette.status import HTTP_403_FORBIDDEN, HTTP_503_SERVICE_UNAVAILABLE, HTTP_504_GATEWAY_TIMEOUT, HTTP_415_UNSUPPORTED_MEDIA_TYPE, HTTP_500_INTERNAL_SERVER_ERROR
from starlette.responses import RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# Sub elements
from app.core import feeds, misp
from app.config import GLOBALCONFIG
from app import dependencies
from app.models import models
import pprint
import logging

logger = logging.getLogger(__name__)

error_mapping = {
    1: HTTP_403_FORBIDDEN,
    2: HTTP_503_SERVICE_UNAVAILABLE,
    3: HTTP_504_GATEWAY_TIMEOUT,
    4: HTTP_504_GATEWAY_TIMEOUT,
    5: HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    6: HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    10: HTTP_503_SERVICE_UNAVAILABLE,
}

API_KEY_NAME = "token"
CRATOS_VERSION = "1.0.2"

apiKeyQuery = APIKeyQuery(name=API_KEY_NAME, auto_error=False)
apiKeyHeader = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

description = """
CRATOS - FastAPI proxy is your secure and optimized integration between your security infrastructure and your MISP Threat Sharing Platform.

## Feeds

You can in a structured form **custom build** your threat feeds from MISP in the format you need for
integrations into your security components, while also ensuring automated expiration of "old" data.

"""

app = FastAPI(
    title="CRATOS - FastAPI proxy integration for MISP",
    description=description,
    version=CRATOS_VERSION,
    contact={
        "name": "eCrimeLabs ApS",
        "url": "https://github.com/eCrimeLabs/cratos-fastapi"
        },
    docs_url=None, 
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},
    license_info={
        "name": "License: MIT License",
        "url": "https://spdx.org/licenses/MIT.html",
    }
)
app.mount("/img", StaticFiles(directory="img"), name='images')


templates = Jinja2Templates(directory="templates/")
favicon_path = 'templates/favicon.ico'

app.configCore = GLOBALCONFIG
app.password = app.configCore['encryption_key'].encode()
app.salt= app.configCore['salt'].encode()


async def getApiToken(
    apiKeyQuery: str = Security(apiKeyQuery),
    apiKeyHeader: str = Security(apiKeyHeader),
):
    api_key = apiKeyQuery or apiKeyHeader

    if api_key is not None:
        returnValue = dependencies.checkApiToken(api_key, app.salt, app.password, app.ClientIP)
        if returnValue['status']:
            app.configCore['requestConfig'] = returnValue['config']
            return api_key
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail=returnValue['detail']
        )
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN, detail="Could not validate token, or token not set."
    )

@app.on_event("startup")
async def startup_event():
    return

@app.exception_handler(ValueError)
async def value_error_exception_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=400,
        content={"message": str(exc)},
    )

@app.middleware("http")
async def process_proxy_header(request: Request, call_next):
    """ 
    It is essential that the FastAPI gets the real IP address of the visitor in order to validate the IP address
    in the config file it can be set if the application is behind a reverse proxy or not, this is also to ensure that an
    attacker is not able to spoof a header that would be understood by the application as the real IP.
    
    If no reverse proxy is used, the client's IP address is used, else use the header defined in the config file.
        - reverse_proxy: False
        - reverse_proxy_header: "X-Forwarded-For"    
            Known headers are:
            - "X-Real-IP"
            - "X-Forwarded-For"
    """
    boolReverseProxyUsage = app.configCore.get('reverse_proxy')
    strReverseProxyeader = app.configCore.get('reverse_proxy_header')

    if (boolReverseProxyUsage):
        app.ClientIP = request.headers.get(strReverseProxyeader) or request.client.host
    else:
        app.ClientIP = request.client.host
    response = await call_next(request)
    return response

@app.get("/", include_in_schema=False)
async def homepage(user_agent: Annotated[str | None, Header()] = None):
    """
    Default front page of CRATOS FastAPI proxy
    """    
    utcNow = datetime.now(timezone.utc)
    unixtimestamp = int(utcNow.timestamp())
    return {"message": "CRATOS - FastAPI proxy integration for MISP", "IP": app.ClientIP, "User-Agent": user_agent, "timestamp": unixtimestamp}

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    """
    This is the favicon.ico file that is used in the browser.
    """
    return FileResponse(favicon_path)

@app.get("/v1/status", tags=["status"], summary="Used for monitoring Cratos FastAPI and memcached integration avaliability.")
async def pong():
    """ The following route can be used to continually monitor the service is running 
    :param apiKey: apiKey to authenticate the request
    :return: JSON output of the status of the service
    """
    memcachedStatus = ""
    if dependencies.memcacheCheckReadWrite():
        memcachedStatus = "OK"
    else:
        memcachedStatus = "FAIL"
    return {"ping": "pong", "memcachedstatus": memcachedStatus}

@app.get("/v1/generate_token_form", 
         tags=["authentication"],
         summary="UI based access to generate the Auth keys",
         description="This provides a UI interface to generate the auth keys based on information from your MISP instance."         
)
def form_post(request: Request):
    result = "Type a number"
    return templates.TemplateResponse('generate_token_form.html', context={'request': request, 'result': result})

@app.post("/v1/generate_token_form", tags=["authentication"], include_in_schema=False)
def form_post_form(request: Request, expire: str = Form(...), port: str = Form(...), proto: str = Form(...), domain: str = Form(...),  auth: str = Form(...)):
    inputData = str(proto) + ";" + str(port) + ";" + str(domain) + ";" + str(auth) + ";" + str(expire)
    result = dependencies.encryptString(inputData, app.salt, app.password)
    reultLen = str(len(result['detail']))
    return templates.TemplateResponse('generate_token_form.html', context={'request': request, 'result': result['detail'], 'reultLen': reultLen})

@app.post("/v1/generate_token_json", 
          tags=["authentication"]
          )
def form_post_json(
    item: models.formAuthGenItem
    ):
    """ Generate a token based on the input from the form
    :param item: The input from the form
    :return: JSON output of the token
    """
    authKeyToken = {}
    inputData = str(item.proto) + ";" + str(item.port) + ";" + str(item.domain) + ";" + str(item.auth) + ";" + str(item.expire)
    result = dependencies.encryptString(inputData, app.salt, app.password)
    authKeyToken['MISP'] = str(item.proto) + '://' + str(item.domain) + ':' + str(item.port) + '/'
    authKeyToken['validity'] = str(item.expire)
    authKeyToken['token'] = result['detail']
    return authKeyToken

@app.get("/v1/openapi.json", tags=["documentations"])
async def get_open_api_endpoint():
    response = JSONResponse(
        get_openapi(title="CRATOS - FastAPI proxy", version=CRATOS_VERSION, routes=app.routes)
    )
    """ The OpenAPI Specification (OAS) defines a standard, language-agnostic interface to HTTP APIs which allows both humans and computers to discover and understand the capabilities of the service without access to source code, documentation, or through network traffic inspection.
    :param apiKey: apiKey to authenticate the request (Optional)
    :return: JSON output of the OpenAPI specification
    """
    return response


@app.get("/v1/help", tags=["documentations"])
async def get_documentation():
    """ The OpenAPI Specification (OAS) defines a standard, language-agnostic interface to HTTP APIs which allows both humans and computers to discover and understand the capabilities of the service without access to source code, documentation, or through network traffic inspection.
    :param apiKey: apiKey to authenticate the request
    :return: WebUI for documentation and tests    
    """
    response = get_swagger_ui_html(
        openapi_url="/openapi.json", 
        title="CRATOS - FastAPI proxy Documentation",
    )
    return response

@app.get("/v1/check", tags=["status"], summary="Check connection to MISP")
async def check_misp_connection(api_key: APIKey = Depends(getApiToken)):
    """ Check the connection status to the MISP instance
    :param apiKey: apiKey to authenticate the request
    :return: JSON output of the minor information on the MISP instance such as version and pyMISP version
    """       
    mispResponse = {}
    mispURL = ("{}://{}:{}".format(app.configCore['requestConfig']['apiTokenProto'], app.configCore['requestConfig']['apiTokenFQDN'], app.configCore['requestConfig']['apiTokenPort']))
    mispAuthKey = app.configCore['requestConfig']['apiTokenAuthKey']
    mispResponse = misp.mispGetVersion(mispURL, mispAuthKey)

    if not mispResponse['status']:
        error_num = mispResponse['error_num']
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=mispResponse['error'])
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Unknown error")

    mispResponse.pop('status')        
    return mispResponse

@app.get("/v1/statistics", 
         tags=["info"], 
         summary="Get attribute type statistics from the MISP", 
         description="Connects to the MISP instance and returns statistics API and outputs count of attribute types in a JSON format"
)
async def get_misp_statistics(api_key: APIKey = Depends(getApiToken)):
    """ Get statistical data from the MISP instance, related to the attribute types.
    :param apiKey: apiKey to authenticate the request
    :return: JSON output of the statictics
    """    
    mispResponse = {}
    mispURL = ("{}://{}:{}".format(app.configCore['requestConfig']['apiTokenProto'], app.configCore['requestConfig']['apiTokenFQDN'], app.configCore['requestConfig']['apiTokenPort']))
    mispAuthKey = app.configCore['requestConfig']['apiTokenAuthKey']
    mispResponse = misp.mispGetStatistics(mispURL, mispAuthKey)

    if not mispResponse['status']:
        error_num = mispResponse['error_num']
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=mispResponse['error'])
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Unknown error")

    mispResponse.pop('status')        
    return mispResponse

@app.get("/v1/warninglist/id/{warninglistId}/output/{returnedDataType}", 
         tags=["info"], 
         summary="Get lists and content of Warning lists from MISP",
         description="""<b>Connects to the MISP instance for collecting information around Warninglists</b><br><br>
         id 0 returns a list of avaliable warninglists and content around this,
         choosing an id higher than 0 has to be aligned with the MISP warninglist ID.
         """
)
async def get_misp_warninglist(
    *,
    warninglistId: int = Path(title="The ID of the Warninglist to show, 0 lists avaliable Warninglists", ge=0, le=1000),
    returnedDataType: Annotated[models.ModelOutputType, Path(description="Defines the output that the feed will be presented in.")],
    api_key: APIKey = Depends(getApiToken)
    ):
    """ Get content of MISP warninglists or list avaliable MISP warninglists
    :param warninglistId: ID number of warninglist
    :param returnedDataType: What format does the data have to be returned in
    :return: Contant of warninglist of avaliable warninglists in the choosen output format
    """
    mispResponse = {}
    mispURL = ("{}://{}:{}".format(app.configCore['requestConfig']['apiTokenProto'], app.configCore['requestConfig']['apiTokenFQDN'], app.configCore['requestConfig']['apiTokenPort']))
    mispAuthKey = app.configCore['requestConfig']['apiTokenAuthKey']
    mispResponse = misp.mispGetWarninglists(mispURL, mispAuthKey, warninglistId)

    if not mispResponse['status']:
        error_num = mispResponse['error_num']
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=mispResponse['error'])
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Unknown error")

    warninglistResponse = feeds.formatWarninglistOutputData(mispResponse, returnedDataType)    
    return Response(content=warninglistResponse['content'], media_type=warninglistResponse['content_type'])

@app.delete("/v1/clear_cache/feed/{feedName}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", 
         tags=["feed"], 
         summary="Delete cached data related to specific feed",
         description="This deletes the cached data related to specific feed options and Auth Token."
)
async def delete_cached_feeds_data(
    feedName: Annotated[models.ModelFeedName, Path(description="The feed names excl. 'any' and '42' is is mapped to a tag that has been added on either event(s) or attribute(s).")],
    dataType: Annotated[models.ModelDataType, Path(description="Defines the type of data that the feed should consist of.")],
    dataAge: Annotated[models.ModuleOutputAge, Path(description="Expiration of data is essential of any threat feeds, the age is based on the attribute creation or modification data.")],
    returnedDataType: Annotated[models.ModelOutputType, Path(description="Defines the output that the feed will be presented in.")],
    api_key: APIKey = Depends(getApiToken)
    ):
    """ Delete any cached data related to the a specific feed request.
    :param feedName: The predefined feed types that is mapping to a local MISP tag
    :param dataType: The type of data type(s) that the feed should be mapped to
    :param age: The defined age options, on how old an attribute may be
    :param returnedDataType: The output format to deliver the returned data in.
    :param api_key: The authorization token
    :return: Returns data based upon the above parameters in the format specified in returnedDataType
    """
    cachingKeyData = dependencies.md5HashCacheKey(feedName + dataType + dataAge + returnedDataType + api_key)
    cachingKeyFP = dependencies.md5HashCacheKey(dataType + api_key)
    cacheResponse = dependencies.memcacheDeleteData(cachingKeyData)
    cacheResponse = dependencies.memcacheDeleteData(cachingKeyFP)
    return Response(content='{"ok": True}', media_type='application/json')


@app.get("/v1/feed/{feedName}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", 
         tags=["feed"], 
         summary="Retrieve data from MISP composed into a simple return format",
         description="This is the core feature of Cratos to collect data from MISP, normalize and ensure only unique attributes are returned."
)
async def get_feeds_data(
    feedName: Annotated[models.ModelFeedName, Path(description="The feed names excl. 'any' and '42' is is mapped to a tag that has been added on either event(s) or attribute(s).")],
    dataType: Annotated[models.ModelDataType, Path(description="Defines the type of data that the feed should consist of.")],
    dataAge: Annotated[models.ModuleOutputAge, Path(description="Expiration of data is essential of any threat feeds, the age is based on the attribute creation or modification data.")],
    returnedDataType: Annotated[models.ModelOutputType, Path(description="Defines the output that the feed will be presented in.")],
    cache: Annotated[Union[int, None], Query(description="In the event that Memcaching is enabled, this parameter can be used to cache a request for x seconds, to avoid putting load on MISP (max caching 24 hours)", gt=0, le=86400)] = 1,
    api_key: APIKey = Depends(getApiToken)
    ):
    """ Get content of MISP warninglists or list avaliable MISP warninglists
    :param feedName: The predefined feed types that is mapping to a local MISP tag
    :param dataType: The type of data type(s) that the feed should be mapped to
    :param age: The defined age options, on how old an attribute may be
    :param returnedDataType: The output format to deliver the returned data in.
    :param cache: OPTIONAL value used in query of seconds to store the data in memcache 
    :param api_key: The authorization token
    :return: Returns data based upon the above parameters in the format specified in returnedDataType
    """
    cachingKeyData = dependencies.md5HashCacheKey(feedName + dataType + dataAge + returnedDataType + api_key)

    cacheResponseData = dependencies.memcacheGetData(cachingKeyData, returnedDataType)
    if (cacheResponseData['cacheHit']):
        headers = {"X-Cache": "HIT"}
        return Response(content=cacheResponseData['content'], media_type=cacheResponseData['content_type'], headers=headers)
    else:
        cacheResponseData['cacheHit'] = False

    mispResponse = feeds.get_feeds_data(feedName, dataType, dataAge, returnedDataType, app.configCore)

    if not mispResponse['status']:
        error_num = mispResponse['error_num']
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=mispResponse['error'])
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Unknown error")

    # deepcode ignore reDOS: The mitigation for this is located in the models
    mispParsedData = feeds.formatFeedOutputData(mispResponse, returnedDataType, dataType, cache, cachingKeyData)
    headers = {"X-Cache": "MISS"}
    return Response(content=mispParsedData['content'], media_type=mispParsedData['content_type'], headers=headers)


@app.get("/v1/uuid/{orgUUID}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", 
         tags=["feed"], 
         summary="Retrieve data from MISP composed into a simple return format, only related a specific Organization UUID.",
         description="This is the core feature of Cratos to collect data from MISP, normalize and ensure only unique attributes are returned."
)
async def get_organizaiton_data(
    orgUUID: Annotated[str | None, Path(min_length=36, max_length=36, description="MISP Organization UUID", pattern='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')],
    dataType: Annotated[models.ModelDataType, Path(description="Defines the type of data that the feed should consist of.")],
    dataAge: Annotated[models.ModuleOutputAge, Path(description="Expiration of data is essential of any threat feeds, the age is based on the attribute creation or modification data.")],
    returnedDataType: Annotated[models.ModelOutputType, Path(description="Defines the output that the feed will be presented in.")],
    cache: Annotated[Union[int, None], Query(description="In the event that Memcaching is enabled, this parameter can be used to cache a request for x seconds, to avoid putting load on MISP (max caching 24 hours)", gt=0, le=86400)] = 1,
    api_key: APIKey = Depends(getApiToken)
    ):
    """ Get content of MISP warninglists or list avaliable MISP warninglists
    :param uuid: Will extract data from the MISP instance related to the organization UUID
    :param dataType: The type of data type(s) that the feed should be mapped to
    :param age: The defined age options, on how old an attribute may be
    :param returnedDataType: The output format to deliver the returned data in.
    :param cache: OPTIONAL value used in query of seconds to store the data in memcache 
    :param api_key: The authorization token
    :return: Returns data based upon the above parameters in the format specified in returnedDataType
    """
    cachingKeyData = dependencies.md5HashCacheKey(orgUUID + dataType + dataAge + returnedDataType + api_key)

    cacheResponseData = dependencies.memcacheGetData(cachingKeyData, returnedDataType)
    if (cacheResponseData['cacheHit']):
        headers = {"X-Cache": "HIT"}
        return Response(content=cacheResponseData['content'], media_type=cacheResponseData['content_type'], headers=headers)
    else:
        cacheResponseData['cacheHit'] = False

    mispResponse = feeds.get_organization_data(orgUUID, dataType, dataAge, returnedDataType, app.configCore)

    if not mispResponse['status']:
        error_num = mispResponse['error_num']
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=mispResponse['error'])
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Unknown error")

    # deepcode ignore reDOS: The mitigation for this is located in the models
    mispParsedData = feeds.formatFeedOutputData(mispResponse, returnedDataType, dataType, cache, cachingKeyData)
    headers = {"X-Cache": "MISS"}
    return Response(content=mispParsedData['content'], media_type=mispParsedData['content_type'], headers=headers)
