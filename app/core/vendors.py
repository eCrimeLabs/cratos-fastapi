# This file is related to vendor specific parsing of data
from app import dependencies
from app.core import feeds
import re

def formatPaloaltoOutputData(inputBlob: dict, dataType: str, cachingTime: int, cachingKey: str) -> dict:
    """ The following function formats the output data from the MISP instance, into supported output types.
        https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/configure-the-firewall-to-access-an-external-dynamic-list
        
    :param inputBlob: The input data to be formatted
    :param outputType: The output type to be formatted
    :param cachingTime: The time to cache the data
    :param cachingKey: The key to cache the data
    :return: Dict of data with the results.
    """
    returnValue = {}

    outputBlob =  feeds.mispDataParsingSimple(inputBlob, dataType)
    outputContent = "\r\n".join(outputBlob)
    if (dataType == 'url'): 
        # To prevent commit errors and invalid entries, do not prefix http:// or https:// to any of the entries.....
        outputContent = re.sub(r"^.*?:\/\/", "", outputContent, 0, re.IGNORECASE | re.MULTILINE)
    returnValue['content_type'] = 'text/plain'
    returnValue['content'] = outputContent
    if (cachingTime > 0):
        dependencies.memcacheAddData(cachingKey, outputContent, cachingTime)
    return(returnValue)   


def formatCiscoOutputData(inputBlob: dict, dataType: str, cachingTime: int, cachingKey: str) -> dict:
    """ The following function formats the output data from the MISP instance, into supported output types.
        
    :param inputBlob: The input data to be formatted
    :param outputType: The output type to be formatted
    :param cachingTime: The time to cache the data
    :param cachingKey: The key to cache the data
    :return: Dict of data with the results.
    """
    returnValue = {}

    outputBlob =  feeds.mispDataParsingSimple(inputBlob, dataType)
    outputContent = "\r\n".join(outputBlob)
    returnValue['content_type'] = 'text/plain'
    returnValue['content'] = outputContent
    if (cachingTime > 0):
        dependencies.memcacheAddData(cachingKey, outputContent, cachingTime)
    return(returnValue)   