import json
import xml.etree.ElementTree as ET
import yaml
from app.core import misp
from app import dependencies
import re
import ipaddress
from dicttoxml import dicttoxml

def feedDefineMISPSearch(feed: str, requestData: dict) -> dict:
    definedMISPSearch = {}
    tags = []
    if (feed == 'falsepositive'):
        tags = requestData['tagNames']
    else:
        tags.append(requestData['tagNames'].get('falsepositive'))
        if (requestData['tagNames'].get(feed)):
            tags.append(requestData['tagNames'].get(feed))
    definedMISPSearch['tags'] = tags
    definedMISPSearch['to_ids'] = True
    definedMISPSearch['timestamp'] = requestData['timestamp']
    definedMISPSearch['returnFormat'] = 'json'
    definedMISPSearch['includeEventTags'] = 'yes'    
    definedMISPSearch['enforceWarninglist'] = True
    definedMISPSearch['type'] = requestData['dataTypes']
    definedMISPSearch['withAttachments'] = False
    definedMISPSearch['published'] = True
    if (feed == 'incident' or feed == 'alert' or feed == 'hunt'):
        definedMISPSearch['published'] = False
    elif (feed == '42'):
        definedMISPSearch['enforceWarninglist'] = False    
    elif (feed == 'falsepositive'):
        definedMISPSearch['published'] = False
        definedMISPSearch['enforceWarninglist'] = False
    else:
        pass
    return (definedMISPSearch)

def getFeedNameToTag(prependTag: str, customFeeds: dict) -> dict:
    feedToTagDict = {'falsepositive': '!' + prependTag + ':incident-classification=false-positive'}
    standardFeeds = {
        'incident': ':incident-classification=incident',
        'block': ':incident-classification=block',
        'alert': ':incident-classification=alert',
        'hunt': ':incident-classification=hunt'
    }
    for tagKey in standardFeeds:
        feedToTagDict[tagKey] = prependTag + standardFeeds[tagKey]
    for tagKey in customFeeds:
        feedToTagDict[tagKey] = prependTag + customFeeds[tagKey]
    return (feedToTagDict)

def formatWarninglistOutputData(inputBlob: dict, outputType: str) -> dict:
    returnValue = {}
    contentType = {
        'xml': 'text/xml',
        'yaml': 'text/plain',
        'txt': 'text/plain',
        'json': 'application/json'
    }

    if (outputType.lower() == "xml"):
        if 'Warninglists' in inputBlob['content'].keys():
            xml=dicttoxml(inputBlob['content']['Warninglists'], custom_root='Warninglists', attr_type=False)
            outputContent=xml.decode()
        elif 'Warninglist' in inputBlob['content'].keys():
            xml=dicttoxml(inputBlob['content']['Warninglist']['WarninglistEntry'], custom_root='Warninglists', attr_type=False)
            outputContent=xml.decode()
        else:
            pass
        returnValue['content_type'] = contentType[outputType]
        returnValue['content'] = outputContent
        return(returnValue)
    #--------------------------------------------------------------------
    elif (outputType.lower() == "yaml"):
        if 'Warninglists' in inputBlob['content'].keys():
            outputContent = yaml.dump(inputBlob['content']['Warninglists'], explicit_start=True, default_flow_style=False)
        elif 'Warninglist' in inputBlob['content'].keys():
            outputContentList = []
            for WarninglistEntryDict in inputBlob['content']['Warninglist']['WarninglistEntry']:
                for key, value in WarninglistEntryDict.items():
                    if (key == 'value'):
                        outputContentList.append(str(value))        
            outputContent = yaml.dump(sorted(set(outputContentList)), explicit_start=True, default_flow_style=False)
        else:
            pass        
        returnValue['content_type'] = contentType[outputType]
        returnValue['content'] = outputContent
        return(returnValue)
    #--------------------------------------------------------------------
    elif (outputType.lower() == "txt"):
        outputContent = ''
        if 'Warninglists' in inputBlob['content'].keys():
            for warninglistDict in inputBlob['content']['Warninglists']:
                for key, value in warninglistDict['Warninglist'].items():
                    outputContent += str(key) + ": " + str(value) + "\r\n"
                outputContent += "\r\n"
        elif 'Warninglist' in inputBlob['content'].keys():
            for WarninglistEntryDict in inputBlob['content']['Warninglist']['WarninglistEntry']:
                for key, value in WarninglistEntryDict.items():
                    if (key == 'value'):
                        outputContent += str(value) + "\r\n"          
        else:
            outputContent = 'No warninglist data identified'
        returnValue['content_type'] = contentType[outputType]
        returnValue['content'] = outputContent
        return(returnValue)
    #--------------------------------------------------------------------
    elif (outputType.lower() == "json"):
        if 'Warninglists' in inputBlob['content'].keys():
            outputContent = json.dumps(inputBlob['content']['Warninglists'])
        elif 'Warninglist' in inputBlob['content'].keys():
            outputContentList = []
            for WarninglistEntryDict in inputBlob['content']['Warninglist']['WarninglistEntry']:
                for key, value in WarninglistEntryDict.items():
                    if (key == 'value'):
                        outputContentList.append(str(value))
            outputContent = json.dumps(sorted(set(outputContentList)))
        else:
            pass
        returnValue['content_type'] = contentType[outputType]
        returnValue['content'] = outputContent
        return(returnValue)

def formatFeedOutputData(inputBlob: dict, outputType: str, dataType: str, cachingTime: int, cachingKey: str) -> dict:
    returnValue = {}
    contentType = {
        'xml': 'text/xml',
        'yaml': 'text/plain',
        'txt': 'text/plain',
        'json': 'application/json'
    }

    outputBlob = mispDataParsingSimple(inputBlob, dataType)

    if (outputType.lower() == "xml"):
        root = ET.Element(dataType)
        for item in outputBlob:
            fruit = ET.SubElement(root, 'entry')
            fruit.text = item
        xmlStr = ET.tostring(root, encoding='utf8', method='xml')
        outputContent = xmlStr.decode('utf-8')
        returnValue['content_type'] = contentType[outputType]
        returnValue['content'] = outputContent
        if (cachingTime > 0):
            dependencies.memcacheAddData(cachingKey, outputContent, cachingTime)
        return(returnValue)
    elif (outputType.lower() == "yaml"):
        outputContent = yaml.dump(outputBlob, explicit_start=True, default_flow_style=False)
        returnValue['content_type'] = contentType[outputType]
        returnValue['content'] = outputContent
        if (cachingTime > 0):
            dependencies.memcacheAddData(cachingKey, outputContent, cachingTime)
        return(returnValue)
    elif (outputType.lower() == "txt"):
        outputContent = "\r\n".join(outputBlob)
        returnValue['content_type'] = contentType[outputType]
        returnValue['content'] = outputContent
        if (cachingTime > 0):
            dependencies.memcacheAddData(cachingKey, outputContent, cachingTime)
        return(returnValue)
    elif (outputType.lower() == "json"):
        outputContent = json.dumps(outputBlob)
        returnValue['content_type'] = contentType[outputType]
        returnValue['content'] = outputContent
        if (cachingTime > 0):
            dependencies.memcacheAddData(cachingKey, outputContent, cachingTime)
        return(returnValue)

def mispDataParsingSimple(mispObject: dict, dataType: str) -> list:
    rexDict = {
        'ipv4': r'(\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b)',
        'cidr4': r'(\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))\b)',
        'ipv6': '', # THIS WILL BE MATCHED ELSEWHERE, Due to complexity'
        'domain': r'(\b((xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b)',
        'hostname': r'(\b((xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b)',
        'url': r'^(\w+:(\/?\/?)[^\s]+|[^\s]+)$',
        'file-md5': r'([a-fA-F0-9]{32})',
        'file-sha1': r'([a-fA-F0-9]{40})',
        'file-sha256': r'([a-fA-F0-9]{64})',
        'mutex': r'(^(.+)$)',
        'snort': r'(^(.+)$)',
        'yara': r'(^(.+)$)',
        'sigma': r'(^(.+)$)',
        'ja3': r'([a-f0-9]{32})',
        'x509-fingerprint-md5': r'([a-fA-F0-9]{32})',
        'x509-fingerprint-sha1': r'([a-fA-F0-9]{40})',
        'x509-fingerprint-sha256': r'([a-fA-F0-9]{64})',
        'email-address': r'(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b)',
        'email-subject': r'(^(.+)$)',
        'email-attachment': r'(^(.+)$)',
        'vulnerability': r'(\bcve\-\d{4}-\d{4,7})',
        'hassh-md5': r'([a-f0-9]{32})',
        'hasshserver-md5': r'([a-f0-9]{32})',
        'imphash': r'([a-f0-9]{32})',
        'crypto-currency': r'((^([13][a-km-zA-HJ-NP-Z0-9]{26,33})$)|(^()(4|8)?[0-9A-Z]{1}[0-9a-zA-Z]{93}([0-9a-zA-Z]{11})?)$)'
    }

    returnData = []
    
    for mispAttribute in mispObject['content']:
        valueStr = mispAttribute['value']
        if (dataType == 'ipv6'):
            try:
                addr = ipaddress.IPv6Address(valueStr)
                returnData.append(valueStr) 
            except:
                pass 
        elif (dataType == 'ipv4'):
            regex_pattern_ipv4 = re.compile(rexDict['ipv4'], re.IGNORECASE )
            regex_pattern_cidr4 = re.compile(rexDict['cidr4'], re.IGNORECASE )
            
            # Exclude CIDR IPv4
            match = regex_pattern_cidr4.search(valueStr)
            if match:
                pass
            else:
                # IPv4
                match = regex_pattern_ipv4.search(valueStr)
                if match:
                    resultStr = match.group(1)
                    returnData.append(resultStr)                 

        elif (dataType == 'ipv4ext'):
            regex_pattern_ipv4 = re.compile(rexDict['ipv4'], re.IGNORECASE )
            regex_pattern_cidr4 = re.compile(rexDict['cidr4'], re.IGNORECASE )
            
            # CIDR IPv4
            match = regex_pattern_cidr4.search(valueStr)
            if match:
                resultStr = match.group(1)
                ips = dependencies.cidrToIPs(resultStr)
                for ipv4 in ips:
                    returnData.append(ipv4)
            else:
                # IPv4
                match = regex_pattern_ipv4.search(valueStr)
                if match:
                    resultStr = match.group(1)
                    returnData.append(resultStr)                 
        else:
            regex_pattern = re.compile(rexDict[dataType], re.IGNORECASE )
            match = regex_pattern.search(valueStr)
            if match:
                resultStr = match.group(1)
                returnData.append(resultStr)    
    return sorted(set(returnData))

def getFalsePositiveData(type: str, age: str, configData: dict) -> dict:
    """ The following function fetches a list of attributes of a specific type and age, where there is a <pre tag>:incident-classification=false-positive
    :param type: The attribute type defined in the query
    :param age: The age defined in the query
    :param configData: The config containing data on how to connect to the MISP instance
    :return: Dict of data with the results.    
    """
    requestResponse = {}
    requestData = {}
    requestData['mispURL'] = ("{0}://{1}:{2}".format(configData['requestConfig']['apiTokenProto'], configData['requestConfig']['apiTokenFQDN'], configData['requestConfig']['apiTokenPort']))
    requestData['mispAuthKey'] = configData['requestConfig']['apiTokenAuthKey']
    requestData['timestamp'] = dependencies.generateUnixTimeStamp( age )
    requestData['tagNames'] = [configData['requestConfig']['config']['tag'] + ':incident-classification=false-positive']
    requestData['mispVerifyCert'] = configData['requestConfig']['config']['mispVerifyCert']
    requestData['mispTimeoutSeconds'] = configData['requestConfig']['config']['mispTimeoutSeconds']    
    requestData['mispDebug'] = configData['requestConfig']['config']['mispDebug']
    requestData['dataTypes'] = configData['types'].get(type)
    requestData['body'] = feedDefineMISPSearch('falsepositive', requestData)
    requestResponse = misp.mispSearchAttributesSimpel(requestData)
    return (requestResponse)    

def get_feeds_data(feed: str, type: str, age: str, output: str, configData: dict) -> dict:
    requestResponse = {}
    requestData = {}
    requestData['mispURL'] = ("{0}://{1}:{2}".format(configData['requestConfig']['apiTokenProto'], configData['requestConfig']['apiTokenFQDN'], configData['requestConfig']['apiTokenPort']))
    requestData['mispAuthKey'] = configData['requestConfig']['apiTokenAuthKey']
    requestData['timestamp'] = dependencies.generateUnixTimeStamp( age )
    requestData['tagNames'] = getFeedNameToTag(configData['requestConfig']['config']['tag'], configData['requestConfig']['config']['custom_feeds'])
    requestData['mispVerifyCert'] = configData['requestConfig']['config']['mispVerifyCert']
    requestData['mispTimeoutSeconds'] = configData['requestConfig']['config']['mispTimeoutSeconds']    
    requestData['mispDebug'] = configData['requestConfig']['config']['mispDebug']
    requestData['dataTypes'] = configData['types'].get(type)
    requestData['body'] = feedDefineMISPSearch(feed, requestData)
    requestResponse = misp.mispSearchAttributesSimpel(requestData)
    return (requestResponse)