#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Module documentation
   If this is updated ensure that it aligns with the config/mappings.yaml file
"""
from enum import Enum
from typing import Union
from typing_extensions import Annotated
from pydantic import BaseModel, Field, HttpUrl, validator
from datetime import date
import re


class ModelFeedName(str, Enum):
    incident = "incident"
    block = "block"
    alert = "alert"
    hunt = "hunt"
    cust1 = "cust1"
    cust2 = "cust2"
    cust3 = "cust3"
    cust4 = "cust4"
    cust5 = "cust5"
    any = "any"
    fortyTwo = "42"


class ModelDataType(str, Enum):
    ipvext = "ipv4ext"
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    cird4 = "cidr4"
    domain = "domain"
    hostname = "hostname"
    url = "url"
    md5 = "file-md5"
    sha1 = "file-sha1"
    sha256 = "file-sha256"
    mutex = "mutex"
    snort = "snort"
    yara = "yara"
    sigma = "sigma"
    x509FPMD5 = "x509-fingerprint-md5"
    x509FPSHA1 = "x509-fingerprint-sha1"
    x509FPSHA256 = "x509-fingerprint-sha256"
    emailAddress = "email-address"
    emailSubject = "email-subject"
    emailAttachment = "email-attachment" 
    vulnerability = "vulnerability"
    ja3 = "ja3"
    hasshMD5 = "hassh-md5"
    hashSevrerMD5 = "hasshserver-md5"
    imphash = "imphash"
    cryptoCurr = "crypto-currency"


class ModelOutputType(str, Enum):
    txt = "txt"
    json = "json"
    xml = "xml"
    yaml = "yaml"
    b64 = "b64"


class ModuleOutputAge(str, Enum):
    oneHour = "1h"
    twoHours = "2h"
    sixHours = "6h"
    twelveHours = "12h"
    oneDay = "1d"
    twoDays = "2d"
    threeDays = "3d"
    fourDays = "4d"
    fiveDays = "5d"
    sixDays = "6d"
    oneWeek = "1w"
    twoWeeks = "2w"
    threeWeeks = "3w"
    oneMonth = "1m"
    twoMonths = "2m"
    threeMonths = "3m"
    FourMonths = "4m"
    fiveMonths = "5m"
    sixMonth = "6m"
    nineMonth = "9m"
    oneYear = "1y"
    twoYears = "2y"
    fourYears = "4y"
    tenYears = "10y"

class formAuthGenItem(BaseModel):
    port: int = Field(gt=0, lte=65535, default='443')
    proto: str = Field(default='https')
    domain: str = Field(default='misp.example.net')
    expire: date = Field(default='2023-12-31')
    auth: str = Field(default='aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD')

    @validator('port')
    def validatePortRange(cls, port):
        if port < 1 or port > 65535:
            raise ValueError('Port must be between 1 and 65535')
        return port    
    
    @validator('proto')
    def validateProtoFormat(cls, proto):
        if not re.match(r'^https|http$', str(proto)):
            raise ValueError('Proto has to be either http or https')
        return proto       
    
    @validator('domain')
    def validateDomainFormat(cls, domain):
        if not re.match(r'^[a-zA-Z0-9\.\:]{4,75}$', str(domain)):
            raise ValueError('Proto has to be either http or https')
        return domain    

    @validator('auth')
    def validateAuthFormat(cls, auth):
        if not re.match(r'^[a-zA-Z0-9]{40,40}$', str(auth)):
            raise ValueError('MISP authentication key is invalid length or context')
        return auth        
    
    @validator('expire')
    def validate_expire_format(cls, expire):
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', str(expire)):
            raise ValueError('Expire date must be in YYYY-MM-DD format')
        return expire    
