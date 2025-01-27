#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import re
from sys import prefix
from fastapi import Security, Depends, FastAPI, HTTPException, Request, Response, APIRouter, Header, Form, Path, Query
from fastapi.security.api_key import APIKeyQuery, APIKeyHeader, APIKey
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from fastapi_versioning import VersionedFastAPI, version
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.encoders import jsonable_encoder
from typing import Union, Optional
from typing_extensions import Annotated
from datetime import date, datetime, timezone
import asyncio
import base64

from pydantic import BaseModel, Field, create_model
from starlette.status import HTTP_403_FORBIDDEN, HTTP_503_SERVICE_UNAVAILABLE, HTTP_504_GATEWAY_TIMEOUT, HTTP_415_UNSUPPORTED_MEDIA_TYPE, HTTP_500_INTERNAL_SERVER_ERROR
from starlette.responses import RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles

# Sub elements
from app.core import feeds, misp, vendors
from app.config import GLOBALCONFIG
from app import dependencies
from app.models import models
import pprint
import logging
from logging.handlers import RotatingFileHandler
import time

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
CRATOS_VERSION = "1.0.5"



description = """
CRATOS - FastAPI proxy is your secure and optimized integration between your security infrastructure and your MISP Threat Sharing Platform.

## Feeds

You can in a structured form **custom build** your threat feeds from MISP in the format you need for
integrations into your security components, while also ensuring automated expiration of "old" data.

"""

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        RotatingFileHandler(GLOBALCONFIG['access_log'], maxBytes=GLOBALCONFIG['access_log_max_bytes']*1024*1024, backupCount=GLOBALCONFIG['access_log_rotations']),  # Change in config.yaml
        logging.StreamHandler()
    ]

)
logger = logging.getLogger("http_logger")

app = FastAPI(docs_url=None, redoc_url=None)

apiKeyQuery = APIKeyQuery(name=API_KEY_NAME, auto_error=False)
apiKeyHeader = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
security = HTTPBasic(auto_error=False)

async def getApiToken(
    request: Request,
    apiKeyQuery: str = Security(apiKeyQuery),
    apiKeyHeader: str = Security(apiKeyHeader),
    credentials: Optional[HTTPBasicCredentials] = Depends(security)
):
    api_key = apiKeyQuery or apiKeyHeader

    if (credentials):
        """
        The following is a check to see if the username is "cratos" and the password is a base64 encoded string and due to some security products
        fail to accept long passwords the code also supports the option to split the base64 token into username and password and this is then concatenated.
        
        Only related to HTTPBasicCredentials
        """
        concat_user_pass = f"{credentials.username}{credentials.password}"
        if credentials.username == "cratos" and dependencies.isUrlSafeBase64(credentials.password):
            api_key = credentials.password
        elif dependencies.isUrlSafeBase64(concat_user_pass):
            api_key = concat_user_pass
        else:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Could not validate token, or token not set."
            )

    if api_key is not None:
        client_ip = request.client.host
        returnValue = dependencies.checkApiToken(api_key, app.salt, app.password, client_ip)
        if returnValue['status']:
            request.state.configCore = returnValue['config']
            return api_key
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail=returnValue['detail']
        )
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN, detail="Could not validate token, or token not set."
    )

# Serve static files for the logo
app.mount("/static", StaticFiles(directory="static"), name='static')

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """ 
    It is essential that the FastAPI gets the real IP address of the visitor in order to do correct logging and validate the IP address
    in the config file it can be set if the application is behind a reverse proxy or not, this is also to ensure that an
    attacker is not able to spoof a header that would be understood by the application as the real IP.
    
    If no reverse proxy is used, the client's IP address is used, else use the header defined in the config file.
        - reverse_proxy: False
        - reverse_proxy_header: "X-Forwarded-For"    
            Known headers are:
            - "X-Real-IP"
            - "X-Forwarded-For"

    X-Headers containg the Real visitor IP can be a pain since the RFC7239 states that the header can contain multiple IP addresses, but depending on 
    vendor implementation in some cases the real IP is the first and in some cases the last, so the code is written to 
    to use the regex to find the IP address in the header, and the place is used to define what group in the regex to use.
    """    
    start_time = time.time()
    boolReverseProxyUsage = app.configCore.get('reverse_proxy')
    strReverseProxyHeader = app.configCore.get('reverse_proxy_header')
    rexReverseProxyIP = app.configCore.get('reverse_proxy_real_ip_regex')
    rexReverseProxyIPPlace = app.configCore.get('reverse_proxy_regex_place')

    # Log the request and response details
    if boolReverseProxyUsage:
        xHeaderIP = request.headers.get(strReverseProxyHeader)
        if xHeaderIP:
            compiled_regex = re.compile(rexReverseProxyIP)
            match = compiled_regex.search(xHeaderIP)
            if match:
                client_ip = match.group(rexReverseProxyIPPlace)
            else:
                client_ip = request.client.host
        else:
            client_ip = request.client.host
    else:
        client_ip = request.client.host     

    app.ClientIP = client_ip  
    request.state.client_ip = client_ip
 
    # Process the request
    response = await call_next(request)
    
    # Calculate the processing time
    process_time = time.time() - start_time
    
    method = request.method
    request_path = request.url.path
    status_code = response.status_code
    content_length = response.headers.get('content-length', 0)
    http_version = request.scope.get('http_version', '1.1')

    # Regular expression pattern for the URL
    pattern = re.compile(r'^https?:\/\/[^\/]+(\/.*)$')
    match = pattern.match(str(request.url))
    if match:
        url = match.group(1)
    else:
        url = request.url

    # Regular expression to match and anonymize token values, if present
    token_regex = re.compile(r"token=[^&]+")

    # Replace token values with a placeholder
    url = token_regex.sub("token=ANONYMIZED", url)

    try:
        if (request.state.configCore['apiTokenFQDN']):
            apiTokenFQDN = request.state.configCore['apiTokenFQDN']
    except:
        apiTokenFQDN = "No valid token set"

    logger.info(f'{client_ip} - "{apiTokenFQDN}" [{time.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {url} HTTP/{http_version}" {status_code} {content_length} "{request.headers.get("referer", "-")}" "{request.headers.get("user-agent", "-")}" {process_time:.2f}')
    
    return response

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Adding security headers to the response to ensure that the application is not vulnerable to certain types of attacks.
    X-Frame-Options: DENY - This header is used to indicate whether or not a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>.
    """
    response = await call_next(request)
    if request.url.path in ["/v1/help", "/redoc", "/v1/generate_token_form"]:
        # Add security headers
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self';"
            "script-src 'self' 'unsafe-inline';"
            "style-src 'self' 'unsafe-inline';"
            "object-src 'none';"
            "base-uri 'self';"
            "connect-src 'self';"
            "font-src 'self';"
            "frame-src 'self';"
            "img-src 'self' data:;"
            "manifest-src 'self';"
            "media-src 'self';"
            "worker-src blob:;"
                    )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    return response

def custom_openapi():
    """
    Custom OpenAPI schema for the FastAPI application
    """
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="CRATOS - FastAPI proxy integration for MISP",
        version=CRATOS_VERSION,
        description=description,
        contact={
            "name": "eCrimeLabs ApS",
            "url": "https://github.com/eCrimeLabs/cratos-fastapi"
            },
        license_info={
            "name": "License: MIT License",
            "url": "https://spdx.org/licenses/MIT.html",
        },
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "/static/logo.png",  # Ensure this path is correct and the file exists
        "altText": "CRATOS Logo"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

templates = Jinja2Templates(directory="templates/")

app.configCore = GLOBALCONFIG
app.password = app.configCore['encryption_key'].encode()
app.salt= app.configCore['salt'].encode()



@app.on_event("startup")
async def startup_event():
    return

@app.exception_handler(ValueError)
async def value_error_exception_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=400,
        content={"message": str(exc)},
    )


@app.get("/robots.txt", include_in_schema=False)
async def get_robots_txt():
    """
    Generate a robots.txt file to ensure that the application is not indexed by search engines
    """    
    return PlainTextResponse(
        "User-agent: *\nDisallow: /",
        status_code=200
    )

@app.get("/", include_in_schema=False)
async def homepage(request: Request, user_agent: Annotated[str | None, Header()] = None):
    """
    Default front page of CRATOS FastAPI proxy
    """    
    utcNow = datetime.now(timezone.utc)
    unixtimestamp = int(utcNow.timestamp())
    return {
        "message": f"CRATOS - FastAPI proxy v.{CRATOS_VERSION} integration for MISP", 
        "IP": request.state.client_ip, 
        "User-Agent": user_agent, 
        "timestamp": unixtimestamp,
        "date_time": utcNow.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "repository": "https://github.com/eCrimeLabs/cratos-fastapi"
    }

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico")

@app.get("/v1/status", tags=["status"], summary="Used for monitoring Cratos FastAPI and memcached integration avaliability.")
async def pong(request: Request):
    """ 
    The following route can be used to continually monitor the service is running 

    ---

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
    """ 
    Generate a token based on the input from the form

    ---

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
    """ 
    The OpenAPI Specification (OAS) defines a standard, language-agnostic interface to HTTP APIs which allows both humans and computers to discover and understand the capabilities of the service without access to source code, documentation, or through network traffic inspection.

    ---

    :param apiKey: apiKey to authenticate the request (Optional)
    
    :return: JSON output of the OpenAPI specification
    """
    return response


@app.get("/v1/help", 
         tags=["documentations"]
         )
async def get_documentation():
    """ 
    The OpenAPI Specification (OAS) defines a standard, language-agnostic interface to HTTP APIs which allows both humans and computers to discover and understand the capabilities of the service without access to source code, documentation, or through network traffic inspection.

    ---

    :return: WebUI for documentation and tests    
    """
    response = get_swagger_ui_html(
        openapi_url="/openapi.json", 
        title="CRATOS - FastAPI proxy Documentation",
        swagger_favicon_url="/static/favicon.ico",  # Adding  favicon
        swagger_js_url="/static/swagger-ui-dist/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui-dist/swagger-ui.css",
    )
    return response

@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=app.title + " - ReDoc",
        redoc_favicon_url="/static/favicon.ico",  # Adding  favicon
        redoc_js_url="/static/redoc/redoc.standalone.js",
        with_google_fonts=False
    )

@app.get("/v1/check", 
         tags=["status"]
         )
async def check_misp_connection(request: Request, api_key: APIKey = Depends(getApiToken)):
    """ 
    Check the connection status to the MISP instance

    ---

    :param apiKey: apiKey to authenticate the request
    
    :return: JSON output of the minor information on the MISP instance such as version and pyMISP version
    """       
    mispResponse = {}
    mispURL = f"{request.state.configCore['apiTokenProto']}://{request.state.configCore['apiTokenFQDN']}:{request.state.configCore['apiTokenPort']}"
    mispAuthKey = request.state.configCore['apiTokenAuthKey']
    mispResponse = await run_in_threadpool(misp.mispGetVersion, mispURL, mispAuthKey)

    if mispResponse is None or not mispResponse.get('status', False):
        error_num = mispResponse.get('error_num', 0) if mispResponse else 0
        error_detail = mispResponse.get('error', "Unknown error") if mispResponse else "Unknown error"
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=error_detail)
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=error_detail)

    mispResponse.pop('status')        
    return mispResponse

@app.get("/v1/statistics", 
         tags=["info"], 
         summary="Get attribute type statistics from the MISP"
)
async def get_misp_statistics(request: Request, api_key: APIKey = Depends(getApiToken)):
    """ 
    Get statistical data from the MISP instance, related to the numbers based on attribute types.

    ---

    :return: JSON output with the statictic data.
    """    
    mispResponse = {}
    mispURL = f"{request.state.configCore['apiTokenProto']}://{request.state.configCore['apiTokenFQDN']}:{request.state.configCore['apiTokenPort']}"
    mispAuthKey = request.state.configCore['apiTokenAuthKey']
    mispResponse = await run_in_threadpool(misp.mispGetStatistics, mispURL, mispAuthKey)


    if mispResponse is None or not mispResponse.get('status', False):
        error_num = mispResponse.get('error_num', 0) if mispResponse else 0
        error_detail = mispResponse.get('error', "Unknown error") if mispResponse else "Unknown error"
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=error_detail)
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=error_detail)

    mispResponse.pop('status')        
    return mispResponse

@app.get("/v1/warninglist/id/{warninglistId}/output/{returnedDataType}", 
         tags=["info"], 
         summary="Get lists and content of Warning lists from MISP"
)
async def get_misp_warninglist(
    *,
    warninglistId: int = Path(title="The ID of the Warninglist to show, 0 lists avaliable Warninglists", ge=0, le=1000),
    returnedDataType: Annotated[models.ModelOutputWarninglists, Path(description="Defines the output that the feed will be presented in.")],
    request: Request,
    api_key: APIKey = Depends(getApiToken)
    ):
    """
    **Connects to the MISP instance for collecting information around Warninglists**
    
    Setting "warninglistId" to "0" returns a list of avaliable warninglists and content around this, choosing an id higher than 0 has to be aligned with the MISP warninglist ID.
 
    ---

    :param warninglistId: ID number of warninglist

    :param returnedDataType: What format does the data have to be returned in

    :return: Contant of warninglist of avaliable warninglists in the choosen output format
    """
    mispResponse = {}
    mispURL = f"{request.state.configCore['apiTokenProto']}://{request.state.configCore['apiTokenFQDN']}:{request.state.configCore['apiTokenPort']}"
    mispAuthKey = request.state.configCore['apiTokenAuthKey']
    mispResponse = await run_in_threadpool(misp.mispGetWarninglists, mispURL, mispAuthKey, warninglistId)

    if mispResponse is None or not mispResponse.get('status', False):
        error_num = mispResponse.get('error_num', 0) if mispResponse else 0
        error_detail = mispResponse.get('error', "Unknown error") if mispResponse else "Unknown error"
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=error_detail)
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=error_detail)

    warninglistResponse = feeds.formatWarninglistOutputData(mispResponse, returnedDataType)
    return Response(content=warninglistResponse['content'], media_type=warninglistResponse['content_type'])


@app.get("/v1/feedmapping", 
         tags=["info"], 
         summary="Get the mapping of the Cratos feeds to the tags in MISP.",
         response_class=PlainTextResponse
         )
async def check_misp_connection(request: Request, api_key: APIKey = Depends(getApiToken)):
    """ 
    This will display the mapping between the Cratos feeds and to the tags in MISP

    ---
    
    :return: text output of the mapping between the Cratos FastAPI feeds and the MISP tags
    """       
    appConfig = request.state.configCore
    feedsDict = appConfig['config']['custom_feeds']
    tagStr = appConfig['config']['tag']
    standardFeedsDict = {
        "incident": ":incident-classification=incident",
        "block": ":incident-classifition=block",
        "alert": ":incident-classification=alert",
        "hunt": ":incident-classification=hunt"
    }
    standardFeedsDict.update(feedsDict)
    feedMapping = ""
    for feeds in standardFeedsDict:
        feedMapping += ("Feed name: \"" + feeds + "\" is mapped to MISP tag: " + tagStr + standardFeedsDict[feeds] + "\r\n")

    return feedMapping



@app.delete("/v1/clear_cache/feed/{feedName}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", 
         tags=["feed"], 
         summary="Delete cached data related to specific feed"
)
async def delete_cached_feeds_data(
    feedName: Annotated[models.ModelFeedName, Path(description="The feed names excl. 'any' and '42' is is mapped to a tag that has been added on either event(s) or attribute(s).")],
    dataType: Annotated[models.ModelDataType, Path(description="Defines the type of data that the feed should consist of.")],
    dataAge: Annotated[models.ModuleOutputAge, Path(description="Expiration of data is essential of any threat feeds, the age is based on the attribute creation or modification data.")],
    returnedDataType: Annotated[models.ModelOutputType, Path(description="Defines the output that the feed will be presented in.")],
    request: Request,
    api_key: APIKey = Depends(getApiToken)
    ):
    """ 
    Deletes the cached data related to specific feed options and Auth Token.

    ---

    :param feedName: The predefined feed types that is mapping to a local MISP tag

    :param dataType: The type of data type(s) that the feed should be mapped to

    :param age: The defined age options, on how old an attribute may be

    :param returnedDataType: The output format to deliver the returned data in.
    
    :return: Returns data based upon the above parameters in the format specified in returnedDataType
    """
    cachingKeyData = dependencies.md5HashCacheKey(feedName + dataType + dataAge + returnedDataType + api_key)
    cachingKeyFP = dependencies.md5HashCacheKey(dataType + api_key)
    cacheResponse = dependencies.memcacheDeleteData(cachingKeyData)
    cacheResponse = dependencies.memcacheDeleteData(cachingKeyFP)
    return JSONResponse(content={"ok": True})


@app.get("/v1/feed/{feedName}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", 
         tags=["feed"], 
         summary="Gather data from MISP typically based on tags and return in structured formats."
)
async def get_feeds_data(
    request: Request,
    feedName: Annotated[models.ModelFeedName, Path(description="The feed names excl. 'any' and '42' is is mapped to a tag that has been added on either event(s) or attribute(s).")],
    dataType: Annotated[models.ModelDataType, Path(description="Defines the type of data that the feed should consist of.")],
    dataAge: Annotated[models.ModuleOutputAge, Path(description="Expiration of data is essential of any threat feeds, the age is based on the attribute creation or modification data.")],
    returnedDataType: Annotated[models.ModelOutputType, Path(description="Defines the output that the feed will be presented in.")],
    cache: Annotated[Union[int, None], Query(description="In the event that Memcaching is enabled, this parameter can be used to cache a request for XXX seconds, to avoid putting load on MISP (Max caching 86400 seconds (24 hours))", gt=0, le=86400)] = 1,
    api_key: APIKey = Depends(getApiToken)
    ):
    """ 
    Collect data from MISP, normalize and ensure only unique attributes are returned, typically based on MISP tags.

    ---

    :param feedName: The predefined feed types that is mapping to a local MISP tag
    
    :param dataType: The type of data type(s) that the feed should be mapped to
    
    :param age: The defined age options, on how old an attribute may be
    
    :param returnedDataType: The output format to deliver the returned data in.
    
    :param cache: OPTIONAL value used in query of seconds to store the data in memcache 
    
    :return: Returns data based upon the above parameters in the format specified in returnedDataType
    """
    cachingKeyData = dependencies.md5HashCacheKey(feedName + dataType + dataAge + returnedDataType + api_key)

    cacheResponseData = dependencies.memcacheGetData(cachingKeyData, returnedDataType)
    if (cacheResponseData['cacheHit']):
        headers = {"X-Cache": "HIT"}
        return Response(content=cacheResponseData['content'], media_type=cacheResponseData['content_type'], headers=headers)
    else:
        cacheResponseData['cacheHit'] = False

    try:
        mispResponse = await run_in_threadpool(feeds.get_feeds_data, feedName, dataType, dataAge, returnedDataType, request.state.configCore, app.configCore)
    except Exception as e:
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Thread error")


    if mispResponse is None or not mispResponse.get('status', False):
        error_num = mispResponse.get('error_num', 0) if mispResponse else 0
        error_detail = mispResponse.get('error', "Unknown error") if mispResponse else "Unknown error"
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=error_detail)
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=error_detail)

    # deepcode ignore reDOS: The mitigation for this is located in the models
    mispParsedData = feeds.formatFeedOutputData(mispResponse, returnedDataType, dataType, cache, cachingKeyData)
    headers = {"X-Cache": "MISS"}
    return Response(content=mispParsedData['content'], media_type=mispParsedData['content_type'], headers=headers)


@app.get("/v1/vendor/{vendorName}/feed/{feedName}/type/{dataType}/age/{dataAge}", 
         tags=["vendors"], 
         summary="Returns the feed data from MISP in a structured format for a specific vendors.",
)
async def get_vendor_data(
    request: Request,
    vendorName: Annotated[models.ModelVendorName, Path(description="The vendor name will return the output in a specific vendor based format.")],
    feedName: Annotated[models.ModelFeedName, Path(description="The feed names excl. 'any' and '42' is is mapped to a tag that has been added on either event(s) or attribute(s).")],
    dataType: Annotated[models.ModelDataType, Path(description="Defines the type of data that the feed should consist of.")],
    dataAge: Annotated[models.ModuleOutputAge, Path(description="Expiration of data is essential of any threat feeds, the age is based on the attribute creation or modification data.")],
    cache: Annotated[Union[int, None], Query(description="In the event that Memcaching is enabled, this parameter can be used to cache a request for x seconds, to avoid putting load on MISP (max caching 24 hours)", gt=0, le=86400)] = 1,
    api_key: APIKey = Depends(getApiToken)
    ):
    """ 
    Collect data from MISP, normalize and ensure only unique attributes are returned, in a predefined format for a particular vendor requiring custom output.

    ---

    :param vendorName: The vendor name will return the output in a specific vendor based format
    
    :param feedName: The predefined feed types that is mapping to a local MISP tag
    
    :param dataType: The type of data type(s) that the feed should be mapped to
    
    :param age: The defined age options, on how old an attribute may be
    
    :param cache: OPTIONAL value used in query of seconds to store the data in memcache 
    
    :return: Returns data based upon the above parameters in the format specified in returnedDataType
    """
    cachingKeyData = dependencies.md5HashCacheKey(vendorName + feedName + dataType + dataAge + api_key)

    cacheResponseData = dependencies.memcacheGetData(cachingKeyData, 'txt')
    if (cacheResponseData['cacheHit']):
        headers = {"X-Cache": "HIT"}
        return Response(content=cacheResponseData['content'], media_type=cacheResponseData['content_type'], headers=headers)
    else:
        cacheResponseData['cacheHit'] = False

    mispResponse = await run_in_threadpool(feeds.get_feeds_data, feedName, dataType, dataAge, "txt", request.state.configCore, app.configCore)

    if mispResponse is None or not mispResponse.get('status', False):
        error_num = mispResponse.get('error_num', 0) if mispResponse else 0
        error_detail = mispResponse.get('error', "Unknown error") if mispResponse else "Unknown error"
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=error_detail)
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=error_detail)

    if (vendorName == "paloalto"):
        # deepcode ignore reDOS: The mitigation for this is located in the models
        mispParsedData = vendors.formatPaloaltoOutputData(mispResponse, dataType, cache, cachingKeyData)
    elif (vendorName == "cisco"):
        # deepcode ignore reDOS: The mitigation for this is located in the models
        mispParsedData = vendors.formatCiscoOutputData(mispResponse, dataType, cache, cachingKeyData)
    else:
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Vendor not avaliable")

    headers = {"X-Cache": "MISS"}
    return Response(content=mispParsedData['content'], media_type=mispParsedData['content_type'], headers=headers)



@app.get("/v1/uuid/{orgUUID}/type/{dataType}/age/{dataAge}/output/{returnedDataType}", 
         tags=["feed"], 
         summary="Get data related to MISP Organization UUID."
)
async def get_organizaiton_data(
    request: Request,
    orgUUID: Annotated[str | None, Path(min_length=36, max_length=36, description="MISP Organization UUID", pattern='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')],
    dataType: Annotated[models.ModelDataType, Path(description="Defines the type of data that the feed should consist of.")],
    dataAge: Annotated[models.ModuleOutputAge, Path(description="Expiration of data is essential of any threat feeds, the age is based on the attribute creation or modification data.")],
    returnedDataType: Annotated[models.ModelOutputType, Path(description="Defines the output that the feed will be presented in.")],
    cache: Annotated[Union[int, None], Query(description="In the event that Memcaching is enabled, this parameter can be used to cache a request for x seconds, to avoid putting load on MISP (max caching 24 hours)", gt=0, le=86400)] = 1,
    api_key: APIKey = Depends(getApiToken)
    ):
    """ 
    Retrieve data from MISP composed into a simple return format, only related a specific Organization UUID.
    
    ---

    :param uuid: Will extract data from the MISP instance related to the organization UUID
    
    :param dataType: The type of data type(s) that the feed should be mapped to
    
    :param age: The defined age options, on how old an attribute may be
    
    :param returnedDataType: The output format to deliver the returned data in.
    
    :param cache: OPTIONAL value used in query of seconds to store the data in memcache 
    
    :return: Returns data based upon the above parameters in the format specified in returnedDataType
    """
    cachingKeyData = dependencies.md5HashCacheKey(orgUUID + dataType + dataAge + returnedDataType + api_key)

    cacheResponseData = dependencies.memcacheGetData(cachingKeyData, returnedDataType)
    if (cacheResponseData['cacheHit']):
        headers = {"X-Cache": "HIT"}
        return Response(content=cacheResponseData['content'], media_type=cacheResponseData['content_type'], headers=headers)
    else:
        cacheResponseData['cacheHit'] = False

    mispResponse = await run_in_threadpool(feeds.get_organization_data, orgUUID, dataType, dataAge, returnedDataType, request.state.configCore, app.configCore)

    if mispResponse is None or not mispResponse.get('status', False):
        error_num = mispResponse.get('error_num', 0) if mispResponse else 0
        error_detail = mispResponse.get('error', "Unknown error") if mispResponse else "Unknown error"
        if error_num in error_mapping:
            raise HTTPException(status_code=error_mapping[error_num], detail=error_detail)
        else:
            raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=error_detail)

    # deepcode ignore reDOS: The mitigation for this is located in the models
    mispParsedData = feeds.formatFeedOutputData(mispResponse, returnedDataType, dataType, cache, cachingKeyData)
    headers = {"X-Cache": "MISS"}
    return Response(content=mispParsedData['content'], media_type=mispParsedData['content_type'], headers=headers)
