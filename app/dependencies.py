#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import yaml
import base64
import hashlib
import os
import re
from ipaddress import ip_address, ip_network
from datetime import datetime
from dateutil.relativedelta import relativedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bmemcached
import traceback
import asyncio
from app.config import GLOBALCONFIG
configCore = GLOBALCONFIG


def base64List(listData: list) -> list:
    """ Recieves a list of string values converts every entry into base64 and returns this in a list.
    :param listData: This is the list of strings that will be converted.
    :return: list of strings but converted into Base64.
    """
    listOutput = []
    for item in listData:
        encodedItem = base64.b64encode(item.encode('utf-8')).decode('utf-8')
        listOutput.append(encodedItem)
    return (listOutput)


def cidrToIPs(cidr):
    ips = ip_network(cidr)
    return [str(ip) for ip in ips]


def generateUnixTimeStamp(age: str) -> int:
    """ Recieves a rerepresentation of time 1h, 2h, 1d, etc. that is converted into unixtimestamp
    :param age: This is a rerepresentation of time 1h, 2h, 1d, etc.
    :return: Integer of the timestamp.
    """
    now = datetime.now()
    match = re.search("^([0-9]{1,5})([hdwmy]{1})$", age, re.MULTILINE)
    if match:
        ageNumber = match.group(1)
        ageType = match.group(2)
        if (ageType == 'h'):
            searchTime = now - relativedelta(hours=int(ageNumber))
        elif (ageType == 'd'):
            searchTime = now - relativedelta(days=int(ageNumber))
        elif (ageType == 'w'):
            searchTime = now - relativedelta(weeks=int(ageNumber))
        elif (ageType == 'm'):
            searchTime = now - relativedelta(months=int(ageNumber))
        elif (ageType == 'y'):
            searchTime = now - relativedelta(years=int(ageNumber))
        else:
            searchTime = now - relativedelta(hours=1)
        return (int(searchTime.timestamp()))


def isValidJSON(inputJSON: str) -> bool:
    """ Recieves json string as input, and performs initial validation, of the format.
    :param age: Valid JSON string
    :return: Boolean of if the JSON is valid or not
    """
    try:
        json.loads(inputJSON)
    except ValueError:
        return False
    return True


def isTokenExpired(dateString: str) -> dict:
    """ Check if Authentication token provided is valid, expired or incorrect format.
    :param dateString: Date string is expected in %Y-%m-%d format
    :return: Boolean of if token is expired
    """
    returnValue = {}
    try:
        expirationDate = datetime.strptime(dateString, '%Y-%m-%d')
        now = datetime.now()
        if (expirationDate >= now):
            # Token is still valid
            returnValue['status'] = True
            return(returnValue)
        else:
            # Token has expired
            returnValue = {'status': False, 'detail': 'The security token has expired.'}
            return(returnValue)
    except Exception:
        # Token invalid format
        returnValue = {'status': False, 'detail': 'Invalid date in security token (Format: YYYY-MM-DD).'}
        return(returnValue)


def isUrlSafeBase64(securityToken: str) -> dict:
    """ Check if Security Token can be decoded url safe alphabets into normal form of strings.
    :param securityToken: Base64 URLSafe encoded string
    :return: Boolean of if string is URLSafe format.
    """
    returnValue = {}
    try:
        base64.urlsafe_b64decode(securityToken)
        returnValue['status'] = True
        return (returnValue)
    except Exception:
        returnValue = {'status': False, 'detail': 'Invalid Base64 string in use for token.'}
        return (returnValue)


def ipOnAllowList(srcIP: str, globalIPs: list, orgIPs: list) -> dict:
    """ Validates if visiting src IP is in the allowed to access site through the API
    :param srcIP: Src IP of the visiting party
    :param globalIPs: List of core IP's that is allowed for all Sites (config.yaml) - e.g. related to monitoring services
    :param orgIPs: List of IPs allowed related to a specific MISP instance
    :return: Dict with informaiton if the IP is allowed or not
    """
    if srcIP == 'testclient':
        ''' This is a test client that is allowed to access the API
        '''
        return {'status': True}

    ipAddress = ip_address(srcIP)
    cidrs = {ip_network(ip,False) for ip in globalIPs + orgIPs}

    for cidr in cidrs:
        if ipAddress in cidr:
            return {'status': True}

    return {'status': False, 'detail': srcIP + ' are not allowed to access the MISP instance.'}


def checkApiToken(apiToken: str, salt: str, password: str, srcIP: str) -> dict:
    """ Decrypts security token and validates vairous data including the src IP and returns object data from site
        config including url and MISP api token.
    :param apiToken: This is the base64 urlsafe string.
    :param salt: In cryptography, a salt is random data that is used as an additional input to a one-way function
                    that hashes data, a password or passphrase. (stored in config.json)
    :param password: Password for decryption (stored in config.json)
    :param srcIP: Source IP of the visiting client
    :return: Dict with validation of success or fail, and includes the config for further usage.
    """
    returnValue = {}
    try:
        if (type(apiToken) != str):
            returnValue = {'status': False, 'detail': 'Token is not a valid string'}
            return(returnValue)

        base64Validate = isUrlSafeBase64(apiToken)
        if not (base64Validate['status']):
            # Failed Base64 validation
            return(base64Validate)

        decryptedConfigToken = decryptString(apiToken, salt, password)
        if not (decryptedConfigToken['status']):
            # Failed Token decryption
            return (decryptedConfigToken)

        orgConfigData = orgConfigExtraction(decryptedConfigToken['detail'])
        if not (orgConfigData['status']):
            return (orgConfigData)

        allowedIP = ipOnAllowList(srcIP, configCore['allways_allowed_ips'], orgConfigData['config']['allowed_ips'])
        if not (allowedIP['status']):
            return(allowedIP)
    except Exception:
        with open('error_log.txt', 'a') as f:
                traceback.print_exc(file=f)        
                f.write("IP:" + srcIP + '\n')
        returnValue = {'status': False, 'detail': 'Unknown error in CheckApiToken'}
        return(returnValue)
    returnValue = {'status': True, 'config': orgConfigData}
    return(returnValue)


def orgConfigExtraction(decryptedConfigToken: str) -> dict:
    """ Parses the decrypted string and validates the string
    :param decryptedConfigToken: This is the base64 urlsafe decoded string, in a
                                    semicolon-seperated format, composed of 5 elements.
    :return: Dict with structured components of the decrypted string
    """
    try:
        dataList = decryptedConfigToken.split(";")
        configData = {}
        configData['apiTokenProto'] = dataList[0]
        configData['apiTokenPort'] = dataList[1]
        configData['apiTokenFQDN'] = dataList[2]
        configData['apiTokenAuthKey'] = dataList[3]
        configData['apiTokenExpiration'] = dataList[4]

        tokenExpiration = isTokenExpired(configData['apiTokenExpiration'])
        if not (tokenExpiration['status']):
            return(tokenExpiration)

        try:
            keyExists = os.path.exists(os.path.join('sites', str(configData['apiTokenFQDN']) + '.yaml'))
            if (keyExists):
                with open('sites/' + configData['apiTokenFQDN'] + '.yaml', 'r') as f:
                    configData['config'] = yaml.safe_load(f)
                    configData['status'] = True
                    return(configData)
            else:
                returnValue = {'status': False, 'detail': 'Token config file not found'}
            return(returnValue)
        except Exception:
            returnValue = {'status': False, 'detail': 'Configuraiton file was not identified or could not be loaded.'}
    except Exception:
        returnValue = {'status': False, 'detail': 'Error in Token Config extraction.'}
        return(returnValue)


def validateStringBool(plainText: str) -> bool:
    """ Validates a string composed of five elements from a semicolon seperated string, utilizing regex.
    :param plainText: Semicolon-seperated string
    :return: Boolean of string being in expected format
    """
    configData = plainText.split(";")
    if (len(configData) == 5):
        # There has to be excactly 5 parameters
        if not re.search("^(https|http)$", configData[0], re.IGNORECASE):
            return (False)
        if not re.search("^(102[0-3]|10[0-1]\d|[1-9][0-9]{0,2}|0)$", configData[1], re.IGNORECASE):
            return (False)
        if not re.search("^[a-zA-Z0-9\.\:]{4,75}$", configData[2], re.IGNORECASE):
            return (False)
        if not re.search("^[a-zA-Z0-9]{40,72}$", configData[3], re.IGNORECASE):
            return (False)
        if not re.search("^(19|20)[0-9]{2,2}[-](0[1-9]|1[012])[-](0[1-9]|[12][0-9]|3[01])$", configData[4], re.IGNORECASE):
            return (False)
        return (True)
    else:
        return(False)


def setKDF(salt: str, password: str) -> object:
    """ Key derivation functions derive bytes suitable for cryptographic operations from
        passwords or other data sources using a pseudo-random function (PRF)
    :param salt: In cryptography, a salt is random data that is used as an additional input to a
                    one-way function that hashes data, a password or passphrase. (stored in config.yaml)
    :param password: Password for decryption (stored in config.yaml)
    :return: Cryptografic fernet object
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    return(f)


def encryptString(plainText: str, salt: str, password: str) -> dict:
    """ String encryption function using sha256 + PBKDF2HMAC with 600.000 iterations and a salt.
    :param plainText: String content to be encrypted
    :param salt: In cryptography, a salt is random data that is used as an additional input to a
                    one-way function that hashes data, a password or passphrase. (stored in config.yaml)
    :param password: Password for decryption (stored in config.yaml)
    :return: Returns a dict from where the cipher text is stored in base64 url safe format.
    """
    returnData = {}
    if(validateStringBool(plainText)):
        f = setKDF(salt, password)
        token = f.encrypt(plainText.encode())
        returnData['detail'] = token.decode()
        returnData['status'] = True
        return(returnData)
    returnData['status'] = False
    returnData['detail'] = 'Invalid config token format'
    return(returnData)


def decryptString(token: str, salt: str, password: str) -> dict:
    """ String decryption function using sha256 + PBKDF2HMAC with 600.000 iterations and a salt.
    :param token: String content to be decyrpted
    :param salt: In cryptography, a salt is random data that is used as an additional input to
                    a one-way function that hashes data, a password or passphrase. (stored in config.yaml)
    :param password: Password for decryption (stored in config.yaml)
    :return: Returns a dict from where the plaintext is stored.
    """
    returnData = {}
    f = setKDF(salt, password)
    plainText = f.decrypt(token).decode()
    if(validateStringBool(plainText)):
        returnData['detail'] = plainText
        returnData['status'] = True
        return (returnData)
    returnData['status'] = False
    returnData['detail'] = 'Failed decryption of config token'
    return(returnData)


def md5HashCacheKey(inputString: str) -> str:
    """ Generate MD5Hash key based on request data to used in Memcached
    : param inputString: String content related to the requested data
    : return: Returns a string with a MD5 Checksum (32 bytes)
    """
    result = hashlib.md5(inputString.encode())
    # file deepcode ignore InsecureHash: This is used to generate a unique key in the Memcached,
    # and the possibility of a collision on the structured data that is hashed with MD5 is not seen as a risk.
    return(result.hexdigest())


def memcacheCheckReadWrite() -> bool:
    """ Adds data to Memcache for cached responses, and attempts to read from this to validate that connection
        to Memcached is working.
    :return: Returns a boolean based on either success(True) or Failure(False) of the action.
    """
    mcBool = memcacheAddData('CratosTestString', 'CratosTestString', 2)
    if (mcBool):
        returnValue = memcacheGetData('CratosTestString', 'txt')
        if (returnValue['cacheHit']):
            """ Memcached works and it is possible to read and write """
            return(True)
        else:
            return(False)
    else:
        """ There are indications that it was not possible to write to the Memcached. """
        return(False)


def memcacheAddData(dataKey: str, dataValue: str, dataExpire: int) -> bool:
    """ Adds data to Memcache for cached responses, including an automated expiration.
    :param dataKey: String key value
    :param dataValue: String data value
    :param dataExpire: Integer seconds for expiration.
    :return: Returns a boolean based on either success(True) or Failure(False) of the action.
    """
    try:
        mc = bmemcached.Client(configCore['memcached_host'] + ':' + str(configCore['memcached_port']),
                               configCore['memcached_user'],
                               configCore['memcached_pass']
                               )
        mc.enable_retry_delay(False)
        mcBool = mc.set(dataKey, dataValue, dataExpire)
        if (mcBool):
            return(True)
        return(False)
    except Exception:
        return(False)


def memcacheGetData(dataKey: str, outputType: str) -> dict:
    """ Get data to Memcache for cached responses, if avaliable
    :param dataKey: The unique data key (a MD5 checksum of the request and Api Token)
    :param outputType: Define the output type in the event that there is a hit in the caching.
    :return: Dict of data from Memcached database if present.
    """
    returnValue = {}
    contentType = {
        'xml': 'text/xml',
        'yaml': 'text/plain',
        'txt': 'text/plain',
        'json': 'application/json'
    }
    try:
        mc = bmemcached.Client(configCore['memcached_host'] + ':' + str(configCore['memcached_port']),
                               configCore['memcached_user'],
                               configCore['memcached_pass']
                               )
        mc.enable_retry_delay(False)
        dataOutput = mc.get(str(dataKey))
        if dataOutput is None:
            returnValue['cacheHit'] = False
        else:
            returnValue['cacheHit'] = True
            returnValue['status'] = True
            returnValue['content_type'] = contentType[outputType]
            returnValue['content'] = mc.get(str(dataKey))
        return(returnValue)
    except Exception:
        returnValue['cacheHit'] = False
        return(returnValue)


def memcacheDeleteData(dataKey: str) -> bool:
    """ Deletes key, value from Memcache
    :param dataKey: String key value of dataset to delete.
    :return: Returns a boolean based on either success(True) or Failure(False) of the action.
    """
    try:
        mc = bmemcached.Client(configCore['memcached_host'] + ':' + str(configCore['memcached_port']),
                               configCore['memcached_user'],
                               configCore['memcached_pass']
                               )
        mc.enable_retry_delay(False)
        mcBool = mc.delete(dataKey)
        if (mcBool):
            return(True)
        return(False)
    except Exception:
        return(False)


def memcacheFlushAllData() -> bool:
    """ Deletes all cached data in the memcached database
    :return: Returns a boolean based on either success(True) or Failure(False) of the action.
    """
    try:
        mc = bmemcached.Client(configCore['memcached_host'] + ':' + str(configCore['memcached_port']),
                               configCore['memcached_user'],
                               configCore['memcached_pass']
                               )
        mc.enable_retry_delay(False)
        mcBool = mc.flush_all(time=0)
        if (mcBool):
            return(True)
        return(False)
    except Exception:
        return(False)

async def fetch_multiple_feeds_data(
    feedName: models.ModelFeedName,
    dataAge: models.ModuleOutputAge,
    returnedDataType: models.ModelOutputType,
    api_key: str
) -> List[dict]:
    dataTypes = [e.value for e in models.ModelDataType]
    tasks = [
        get_feeds_data(
            feedName=feedName,
            dataType=dataType,
            dataAge=dataAge,
            returnedDataType=returnedDataType,
            api_key=api_key
        ) for dataType in dataTypes
    ]
    responses = await asyncio.gather(*tasks)
    return responses