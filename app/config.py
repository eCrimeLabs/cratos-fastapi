#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os 
import sys

def loadConfig() -> dict:
    try:
        with open(os.path.join('config', 'config.json'), 'r') as f:
            configCore = json.load(f)
    except:
        print ("config.json failed to load")
        sys.exit(1)
    try:
        with open(os.path.join('config', 'mappings.json'), 'r') as f:
            mappingsCore = json.load(f)
    except:
        print ("config.json failed to load")
        sys.exit(1)   

    configCore.update(mappingsCore) 
    return(configCore)

GLOBALCONFIG = loadConfig()