#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import glob
import yaml
import yamale
from yamale.validators import DefaultValidators


def validateSiteConfigs():
    schemaFile = os.path.join('sites', 'sites.schema')
    sitesYaml = glob.glob(os.path.join('sites', "*.yaml"))
    for file in sitesYaml:
        validated = schemaValidator(file, schemaFile)
        if not (validated):
            raise Exception(file + " Schema Validation failed!")


def schemaValidator(yamlFile: str, schemaFile: str) -> bool:
    """ Performs some validation of the schema related to the yaml files
    :param yamlFile: The yaml file to be validated
    :param schemaFile: the schema to validate against
    return: bool: Return True if ok, else return False
    """
    validators = DefaultValidators.copy()
    schema = yamale.make_schema(schemaFile, validators=validators)
    data = yamale.make_data(yamlFile)
    try:
        yamale.validate(schema, data)
        return(True)
    except ValueError as e:
        print('Validation failed!\n%s' % str(e))
        return(False)

def loadConfigYaml() -> dict:
    """ Loading the static config files related to the core Cratos FastAPI
        return: Returns a dict with with content of config.yml and mappings.yml this is a merge of the two files.
    """

    # Handle parsing and error checking of config.yml
    try:
        with open(os.path.join('config', 'config.yaml'), 'r') as f:
            configCore = yaml.safe_load(f)
        validated = schemaValidator(os.path.join('config', 'config.yaml'), os.path.join('config', 'config.schema'))
        if not (validated):
            raise Exception("Schema Validation failed!")
    except Exception as e:
        # Handle other exceptions
        print("An error occurred while attempting to load config.yaml")
        print(f"Error message: {str(e)}")
        sys.exit(1)

    # Handle parsing and error checking of mappings.yml
    try:
        with open(os.path.join('config', 'mappings.yaml'), 'r') as f:
            mappingsCore = yaml.safe_load(f)
        validated = schemaValidator(os.path.join('config', 'mappings.yaml'), os.path.join('config', 'mappings.schema'))
        if not (validated):
            raise Exception("Schema Validation failed!")
    except Exception as e:
        # Handle other exceptions
        print("An error occurred while attempting to load mappings.yaml")
        print(f"Error message: {str(e)}")
        sys.exit(1)

    configCore.update(mappingsCore)
    return(configCore)


GLOBALCONFIG = loadConfigYaml()
validateSiteConfigs()
