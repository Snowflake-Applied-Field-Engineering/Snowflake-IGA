import requests
import json
import logging
import sys
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('oracle-scim-client')

class OracleScimClient:
    def __init__(self, idcs_url, client_id, client_secret):
        """
        Initialize the Oracle Identity Cloud Service SCIM Client
        
        Args:
            idcs_url (str): Oracle IDCS URL (e.g., https://idcs-abcd1234.identity.oraclecloud.com)
            client_id (str): Client ID for OAuth authentication
            client_secret (str): Client secret for OAuth authentication
        """
        self.idcs_url = idcs_url
        self.client_id = client_id
        self.client_secret = client_secret
        
        self.token_endpoint = f"{self.idcs_url}/oauth2/v1/token"
        self.scim_base_url = f"{self.idcs_url}/admin/v1"
        
        self.access_token = None
    
    def _get_access_token(self):
        """Get OAuth access token from Oracle IDCS"""
        if self.access_token:
            return self.access_token
        
        auth_string = f"{self.client_id}:{self.client_secret}"
        auth_bytes = auth_string.encode('ascii')
        base64_auth = base64.b64encode(auth_bytes).decode('ascii')
        
        headers = {
            'Authorization': f"Basic {base64_auth}",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'client_credentials',
            'scope': 'urn:opc:idm:__myscopes__'
        }
        
        try:
            response = requests.post(self.token_endpoint, headers=headers, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data['access_token']
            logger.info("Successfully obtained IDCS access token")
            return self.access_token
        except Exception as e:
            logger.error(f"Failed to get IDCS access token: {str(e)}")
            if hasattr(response, 'text'):
                logger.error(f"Response: {response.text}")
            raise
    
    def _make_scim_request(self, method, endpoint, data=None, params=None):
        """Make request to Oracle IDCS SCIM API"""
        access_token = self._get_access_token()
        
        headers = {
            'Authorization': f"Bearer {access_token}",
            'Content-Type': 'application/json'
        }
        
        url = f"{self.scim_base_url}/{endpoint}"
        
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                json=data,
                params=params
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"IDCS SCIM API request failed: {str(e)}")
            if hasattr(response, 'text'):
                logger.error(f"Response: {response.text}")
            raise
    
    def get_users(self, start_index=1, count=100, filter_str=None):
        """
        Get users from Oracle IDCS via SCIM API
        
        Args:
            start_index (int): Starting index for pagination
            count (int): Number of users to return per page
            filter_str (str): SCIM filter string
            
        Returns:
            dict: SCIM response containing users
        """
        params = {
            'startIndex': start_index,
            'count': count
        }
        
        if filter_str:
            params['filter'] = filter_str
            
        return self._make_scim_request('GET', 'Users', params=params)
    
    def create_app_from_template(self, app_data):
        """
        Create an application in Oracle IDCS
        
        Args:
            app_data (dict): Application data
            
        Returns:
            dict: Created application data
        """
        return self._make_scim_request('POST', 'Apps', data=app_data)
    
    def create_generic_scim_app(self, app_name, app_description, template_type, scim_endpoint, auth_type, auth_details):
        """
        Create a Generic SCIM application from template
        
        Args:
            app_name (str): Application name
            app_description (str): Application description
            template_type (str): Template type (Basic, BearerToken, ClientCredentials, ResourceOwnerPassword)
            scim_endpoint (str): SCIM endpoint URL
            auth_type (str): Authentication type
            auth_details (dict): Authentication details specific to the auth type
            
        Returns:
            dict: Created application data
        """
        template_id = {
            'Basic': 'GenericScimBasic',
            'BearerToken': 'GenericScimBearerToken',
            'ClientCredentials': 'GenericScimClientCredentials',
            'ResourceOwnerPassword': 'GenericScimResourceOwnerPassword'
        }.get(template_type)
        
        if not template_id:
            raise ValueError(f"Invalid template type: {template_type}")
        
        app_data = {
            "schemas": [
                "urn:ietf:params:scim:schemas:oracle:idcs:App"
            ],
            "displayName": app_name,
            "description": app_description,
            "templateId": template_id,
            "active": True,
            "scimEndpoint": {
                "value": scim_endpoint
            },
            "authType": {
                "value": auth_type
            }
        }
        
        # Add auth-specific details
        app_data.update(auth_details)
        
        return self.create_app_from_template(app_data)
    
    def create_bearer_token_app(self, app_name, app_description, scim_endpoint, token_endpoint, client_id, client_secret):
        """
        Create a Generic SCIM - Bearer Token application
        
        Args:
            app_name (str): Application name
            app_description (str): Application description
            scim_endpoint (str): SCIM endpoint URL
            token_endpoint (str): Token endpoint URL
            client_id (str): Client ID
            client_secret (str): Client secret
            
        Returns:
            dict: Created application data
        """
        auth_details = {
            "tokenEndpoint": {
                "value": token_endpoint
            },
            "clientId": {
                "value": client_id
            },
            "clientSecret": {
                "value": client_secret
            }
        }
        
        return self.create_generic_scim_app(
            app_name=app_name,
            app_description=app_description,
            template_type='BearerToken',
            scim_endpoint=scim_endpoint,
            auth_type='oauth2_client_credentials',
            auth_details=auth_details
        )
    
    def configure_app_provisioning(self, app_id, attribute_mappings):
        """
        Configure provisioning for an application
        
        Args:
            app_id (str): Application ID
            attribute_mappings (list): List of attribute mappings
            
        Returns:
            dict: Updated application data
        """
        app_data = {
            "schemas": [
                "urn:ietf:params:scim:schemas:oracle:idcs:App"
            ],
            "provisioningConfig": {
                "enabled": True,
                "attributeMappings": attribute_mappings
            }
        }
        
        return self._make_scim_request('PATCH', f"Apps/{app_id}", data=app_data)
    
    def get_app(self, app_id):
        """
        Get application by ID
        
        Args:
            app_id (str): Application ID
            
        Returns:
            dict: Application data
        """
        return self._make_scim_request('GET', f"Apps/{app_id}")
    
    def test_app_connectivity(self, app_id):
        """
        Test connectivity for an application
        
        Args:
            app_id (str): Application ID
            
        Returns:
            dict: Test results
        """
        return self._make_scim_request('POST', f"Apps/{app_id}/.test")
