#!/usr/bin/env python3
"""
Oracle Identity Cloud Service to Snowflake SCIM Integration Script

This script automates the setup of SCIM provisioning between Oracle Identity Cloud Service
and Snowflake using the GenericScim - Bearer Token template.
"""

import argparse
import logging
import sys
import json
import os
from datetime import datetime

# Import our helper modules
# Assuming the modules are in the same directory as this script
from oracle_scim_client import OracleScimClient
from snowflake_scim_integration import SnowflakeScimIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"oracle-snowflake-integration-{datetime.now().strftime('%Y%m%d%H%M%S')}.log")
    ]
)
logger = logging.getLogger('oracle-snowflake-integration')

def create_snowflake_scim_app(oracle_client, app_name, app_description, 
                             snowflake_account, snowflake_user, snowflake_private_key_path, 
                             snowflake_key_passphrase=None):
    """
    Create a Snowflake SCIM app in Oracle IDCS
    
    Args:
        oracle_client (OracleScimClient): Oracle SCIM client
        app_name (str): Application name
        app_description (str): Application description
        snowflake_account (str): Snowflake account name
        snowflake_user (str): Snowflake username
        snowflake_private_key_path (str): Path to Snowflake private key
        snowflake_key_passphrase (str, optional): Passphrase for the private key
        
    Returns:
        dict: Created application data
    """
    logger.info(f"Creating Snowflake SCIM app '{app_name}' in Oracle IDCS")
    
    # First, test Snowflake connectivity
    snowflake_integration = SnowflakeScimIntegration(
        account_name=snowflake_account,
        user_name=snowflake_user,
        private_key_path=snowflake_private_key_path,
        private_key_passphrase=snowflake_key_passphrase
    )
    
    if not snowflake_integration.test_connectivity():
        logger.error("Failed to connect to Snowflake SCIM API. Please check credentials and try again.")
        sys.exit(1)
    
    # Get Snowflake OAuth token for the app
    access_token = snowflake_integration._get_access_token()
    
    # Snowflake SCIM endpoint
    scim_endpoint = f"https://{snowflake_account}.snowflakecomputing.com/scim/v2"
    
    # Create SCIM app in Oracle IDCS
    try:
        app = oracle_client.create_bearer_token_app(
            app_name=app_name,
            app_description=app_description,
            scim_endpoint=scim_endpoint,
            token_endpoint=f"https://{snowflake_account}.snowflakecomputing.com/oauth/token-request",
            client_id=snowflake_user,
            client_secret="REPLACE_WITH_ACTUAL_SECRET"  # This is placeholder; actual JWT flow is different
        )
        
        logger.info(f"Successfully created app with ID: {app.get('id')}")
        return app
    except Exception as e:
        logger.error(f"Failed to create app: {str(e)}")
        raise

def configure_attribute_mappings(oracle_client, app_id):
    """
    Configure attribute mappings for the Snowflake SCIM app
    
    Args:
        oracle_client (OracleScimClient): Oracle SCIM client
        app_id (str): Application ID
        
    Returns:
        dict: Updated application data
    """
    logger.info(f"Configuring attribute mappings for app ID: {app_id}")
    
    # Default SCIM attribute mappings for Snowflake
    attribute_mappings = [
        {
            "sourceAttribute": "username",
            "targetAttribute": "userName",
            "targetAttributeType": "string"
        },
        {
            "sourceAttribute": "id",
            "targetAttribute": "externalId",
            "targetAttributeType": "string"
        },
        {
            "sourceAttribute": "active",
            "targetAttribute": "active",
            "targetAttributeType": "boolean"
        },
        {
            "sourceAttribute": "name.givenName",
            "targetAttribute": "name.givenName",
            "targetAttributeType": "string"
        },
        {
            "sourceAttribute": "name.familyName",
            "targetAttribute": "name.familyName",
            "targetAttributeType": "string"
        },
        {
            "sourceAttribute": "emails[primary eq true].value",
            "targetAttribute": "emails[type eq \"work\"].value",
            "targetAttributeType": "string"
        }
    ]
    
    try:
        updated_app = oracle_client.configure_app_provisioning(app_id, attribute_mappings)
        logger.info("Successfully configured attribute mappings")
        return updated_app
    except Exception as e:
        logger.error(f"Failed to configure attribute mappings: {str(e)}")
        raise

def test_app_connectivity(oracle_client, app_id):
    """
    Test connectivity for the Snowflake SCIM app
    
    Args:
        oracle_client (OracleScimClient): Oracle SCIM client
        app_id (str): Application ID
        
    Returns:
        bool: True if test is successful, False otherwise
    """
    logger.info(f"Testing connectivity for app ID: {app_id}")
    
    try:
        test_result = oracle_client.test_app_connectivity(app_id)
        if test_result.get('success', False):
            logger.info("Connectivity test successful!")
            return True
        else:
            logger.error(f"Connectivity test failed: {test_result.get('message', 'Unknown error')}")
            return False
    except Exception as e:
        logger.error(f"Failed to test connectivity: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Oracle IDCS to Snowflake SCIM Integration')
    
    # Oracle IDCS parameters
    parser.add_argument('--idcs-url', required=True, help='Oracle IDCS URL (e.g., https://idcs-abcd1234.identity.oraclecloud.com)')
    parser.add_argument('--idcs-client-id', required=True, help='Oracle IDCS client ID')
    parser.add_argument('--idcs-client-secret', required=True, help='Oracle IDCS client secret')
    
    # Snowflake parameters
    parser.add_argument('--snowflake-account', required=True, help='Snowflake account name (without .snowflakecomputing.com)')
    parser.add_argument('--snowflake-user', required=True, help='Snowflake username for JWT authentication')
    parser.add_argument('--snowflake-key', required=True, help='Path to Snowflake private key file')
    parser.add_argument('--snowflake-passphrase', help='Snowflake private key passphrase (if encrypted)')
    
    # App parameters
    parser.add_argument('--app-name', default='Snowflake SCIM', help='Application name in Oracle IDCS')
    parser.add_argument('--app-description', default='Snowflake SCIM integration for user provisioning', help='Application description')
    
    args = parser.parse_args()
    
    try:
        # Initialize Oracle IDCS client
        oracle_client = OracleScimClient(
            idcs_url=args.idcs_url,
            client_id=args.idcs_client_id,
            client_secret=args.idcs_client_secret
        )
        
        # Create Snowflake SCIM app
        app = create_snowflake_scim_app(
            oracle_client=oracle_client,
            app_name=args.app_name,
            app_description=args.app_description,
            snowflake_account=args.snowflake_account,
            snowflake_user=args.snowflake_user,
            snowflake_private_key_path=args.snowflake_key,
            snowflake_key_passphrase=args.snowflake_passphrase
        )
        
        app_id = app.get('id')
        if not app_id:
            logger.error("Failed to get app ID")
            sys.exit(1)
        
        # Configure attribute mappings
        configure_attribute_mappings(oracle_client, app_id)
        
        # Test connectivity
        if test_app_connectivity(oracle_client, app_id):
            logger.info("Integration setup complete and working!")
            
            # Output app