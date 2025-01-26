import requests
from pymisp import PyMISP
from app import dependencies
from datetime import datetime, timezone

class Paths:
    VERSION = '/servers/getVersion.json'
    ATTRIBUTE_STATISTICS = '/attributes/attributeStatistics'

def mispSearchAttributesSimpel(requestData: dict) -> dict:
    requestResponse = {}
    body = requestData['body']
 
    try:
        misp = PyMISP(
            requestData['mispURL'], 
            requestData['mispAuthKey'], 
            requestData['mispVerifyCert'], 
            requestData['mispDebug']
        )
    except Exception as e:
        # PyMISP does not throw an exception for an invalid authkey
        requestResponse = {
            'status': False,
            'content': f'PyMISP exception="{str(e)}"\n',
            'error_num': 10,
            'error': "PyMISP to MISP - Connection error"
        }        
        return(requestResponse)

    try:    
        search_params = {
            'controller': 'attributes',
            'return_format': body['returnFormat'],
            'tags': body['tags'],
            'type_attribute': body['type'],
            'timestamp': body['timestamp'],
            'enforceWarninglist': body['enforceWarninglist'],
            'published': body['published'],
            'metadata': True,
            'pythonify': True
        }

        if body['to_ids']:
            search_params['to_ids'] = body['to_ids']
        if 'org' in body and body['org']:
            search_params['org'] = body['org']

        responseMISP = misp.search(**search_params)   
        requestResponse = {
            'status': True,
            'content': responseMISP
        }
        return(requestResponse)
    except Exception as e:
        # PyMISP catching errors
        requestResponse = {
            'status': False,
            'content': f'PyMISP exception="{str(e)}"\n',
            'error_num': 10,
            'error': "PyMISP to MISP - Search error invalid or missing response"
        }
        return(requestResponse)

def mispGETRequest(url: str, headers: dict, timeout: int, verify: bool) -> dict:
    requestResponse = {}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=verify)
        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        requestResponse['status'] = False
        requestResponse['status_code'] = r.status_code
        requestResponse['encoding'] = r.encoding
        requestResponse['content'] = r.text
        requestResponse['error_num'] = 1
        if ('Authentication failed' in r.text):
            requestResponse['error'] = ("MISP - Authentication failed")
        else:
            requestResponse['error'] = ("MISP - HTTP Error")
        return(requestResponse)
    except requests.exceptions.ConnectionError as errc:
        requestResponse['status'] = False
        requestResponse['error_num'] = 2
        requestResponse['error'] = ("MISP - Connection error")
        return(requestResponse)
    except requests.exceptions.Timeout as errt:
        requestResponse['status'] = False
        requestResponse['error_num'] = 3
        requestResponse['error'] = ("MISP - Connection error, timeout")
        return(requestResponse)
    except requests.exceptions.RequestException as err:
        requestResponse['status'] = False
        requestResponse['error_num'] = 4
        requestResponse['status_code'] = r.status_code
        requestResponse['encoding'] = r.encoding
        requestResponse['content'] = r.text
        requestResponse['error'] = ("MISP - Connection error")
        return(requestResponse) 
    
    try:
        if ('Content-Type' in r.request.headers):
            if (r.request.headers['Content-Type'] == 'application/json'):
                requestResponse['status'] = True
                requestResponse['status_code'] = r.status_code
                requestResponse['encoding'] = r.encoding
                requestResponse['content'] = r.json()
                return(requestResponse) 
            else:
                requestResponse['status'] = True
                requestResponse['status_code'] = r.status_code
                requestResponse['encoding'] = r.encoding
                requestResponse['content'] = r.text
                return(requestResponse)             
        else:
            requestResponse['status'] = True
            requestResponse['status_code'] = r.status_code
            requestResponse['encoding'] = r.encoding
            requestResponse['content'] = r.text
            return(requestResponse)              
    except:
        requestResponse['status'] = False
        requestResponse['error_num'] = 5
        requestResponse['error'] = ("MISP - Parsing error")
        requestResponse['status_code'] = r.status_code
        requestResponse['encoding'] = r.encoding
        requestResponse['content'] = r.text
        return(requestResponse) 

def mispRequestHeader(mispAuthKey):
    """ Generate the MISP request header 
    :param mispAuthKey: The authentication key to the MISP instance
    return: dict: Returns a dict with the header for the MISP request
    """
    mispHeader = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'Authorization': mispAuthKey
    }
    return(mispHeader)


def mispGetVersion(mispURL: str, mispAuthKey: str) -> dict:
    """ Get the MISP version and return the response 
    :param mispURL: The URL to the MISP instance
    :param mispAuthKey: The authentication key to the MISP instance
    return: dict: Returns a dict with the response from the MISP instance
    """
    utcNow = datetime.now(timezone.utc)
    unixtimestamp = int(utcNow.timestamp())
    headers=mispRequestHeader(mispAuthKey)
#    mispResponse = mispGETRequest(mispURL + '/servers/getVersion.json', headers, 5, True)
    mispResponse = mispGETRequest(mispURL + Paths.VERSION, headers, 5, True)
    mispResponse['misp_host'] = mispURL
    mispResponse['unixtimestamp'] = unixtimestamp
    if (mispResponse['status']):
        if (not 'version' in mispResponse['content']):
            mispResponse['status'] = False
            mispResponse['error_num'] = 6
            mispResponse['error'] = ("MISP - None JSON data returned")
            mispResponse['content'] = ""
            return(mispResponse)    
    return(mispResponse)

def mispGetStatistics(mispURL: str, mispAuthKey: str) -> dict:
    headers=mispRequestHeader(mispAuthKey)
    mispResponse = mispGETRequest(mispURL + '/attributes/attributeStatistics', headers, 30, True)
    mispResponse['misp_host'] = mispURL

    if not (isinstance(mispResponse['content'], dict)):
        mispResponse['status'] = False
        mispResponse['error_num'] = 6
        mispResponse['error'] = ("MISP - None JSON data returned")
        mispResponse['content'] = ""
        return(mispResponse)    
    return(mispResponse)    

    
def mispGetWarninglists(mispURL: str, mispAuthKey: str, warninglistId: int) -> dict:
    warninglistURI: str
    if (warninglistId == 0):
        warninglistURI = '/warninglists/index'
    elif (warninglistId > 0):
        warninglistURI = '/warninglists/view/' + str(warninglistId)
    else:
        warninglistURI = '/warninglists/index'
       
    headers=mispRequestHeader(mispAuthKey)
    mispResponse = mispGETRequest(mispURL + warninglistURI, headers, 30, True)
    mispResponse['misp_host'] = mispURL
    
    if not (isinstance(mispResponse['content'], dict)):
        mispResponse['status'] = False
        mispResponse['error_num'] = 6
        mispResponse['error'] = ("MISP - None JSON data returned")
        mispResponse['content'] = ""
        return(mispResponse)    
    return(mispResponse)    