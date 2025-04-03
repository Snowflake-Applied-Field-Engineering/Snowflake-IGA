import requests
import json
import jwt
import datetime
import argparse
import logging
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('snowflake-scim-integration')

class SnowflakeScimIntegration:
    def __init__(self, account_name, user_name, private_key_path, private_key_passphrase=None):
        """
        Initialize the Snowflake SCIM Integration
        
        Args:
            account_name (str): Snowflake account name (without .snowflakecomputing.com)
            user_name (str): Snowflake username for JWT authentication
            private_key_path (str): Path to the private key file for JWT signing
            private_key_passphrase (str, optional): Passphrase for the private key if encrypted
        """
        self.account_name = account_name
        self.user_name = user_name
        self.private_key_path = private_key_path
        self.private_key_passphrase = private_key_passphrase
        
        self.account_url = f"https://{account_name}.snowflakecomputing.com"
        self.token_endpoint = f"{self.account_url}/oauth/token-request"
        self.scim_base_url = f"{self.account_url}/scim/v2"
        
        self.access_token = None
        self.access_token_expiry = None
        
        # Load private key
        self._load_private_key()
    
    def _load_private_key(self):
        """Load private key from file"""
        try:
            with open(self.private_key_path, 'rb') as key_file:
                key_data = key_file.read()
                
            passphrase = None
            if self.private_key_passphrase:
                passphrase = self.private_key_passphrase.encode()
                
            self.private_key = load_pem_private_key(
                key_data,
                password=passphrase,
                backend=default_backend()
            )
            logger.info("Successfully loaded private key")
        except Exception as e:
            logger.error(f"Failed to load private key: {str(e)}")
            raise
    
    def _generate_jwt(self):
        """Generate JWT token for Snowflake authentication"""
        now = datetime.datetime.utcnow()
        expiry = now + datetime.datetime.timedelta(minutes=59)
        
        payload = {
            'iss': f"{self.account_url}/{self.user_name}",
            'sub': f"{self.account_url}/{self.user_name}",
            'iat': now,
            'exp': expiry
        }
        
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm='RS256'
        )
        
        logger.debug("Generated JWT token for authentication")
        return token
    
    def _get_access_token(self):
        """Get OAuth access token from Snowflake using JWT token"""
        if self.access_token and self.access_token_expiry and datetime.datetime.utcnow() < self.access_token_expiry:
            logger.debug("Using existing access token")
            return self.access_token
        
        jwt_token = self._generate_jwt()
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'token': jwt_token
        }
        
        try:
            response = requests.post(self.token_endpoint, headers=headers, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data['access_token']
            
            # Set token expiry to a bit less than the actual expiry to be safe
            expires_in = int(token_data.get('expires_in', 3600)) - 300  # 5 minutes buffer
            self.access_token_expiry = datetime.datetime.utcnow() + datetime.datetime.timedelta(seconds=expires_in)
            
            logger.info("Successfully obtained access token")
            return self.access_token
        except Exception as e:
            logger.error(f"Failed to get access token: {str(e)}")
            if hasattr(response, 'text'):
                logger.error(f"Response: {response.text}")
            raise
    
    def _make_scim_request(self, method, endpoint, data=None, params=None):
        """Make request to Snowflake SCIM API"""
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
            logger.error(f"SCIM API request failed: {str(e)}")
            if hasattr(response, 'text'):
                logger.error(f"Response: {response.text}")
            raise
    
    def get_users(self, start_index=1, count=100, filter_str=None):
        """
        Get users from Snowflake via SCIM API
        
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
    
    def create_user(self, user_data):
        """
        Create a user in Snowflake via SCIM API
        
        Args:
            user_data (dict): User data in SCIM format
            
        Returns:
            dict: Created user data
        """
        return self._make_scim_request('POST', 'Users', data=user_data)
    
    def update_user(self, user_id, user_data):
        """
        Update a user in Snowflake via SCIM API
        
        Args:
            user_id (str): User ID or externalId
            user_data (dict): Updated user data in SCIM format
            
        Returns:
            dict: Updated user data
        """
        return self._make_scim_request('PUT', f"Users/{user_id}", data=user_data)
    
    def delete_user(self, user_id):
        """
        Delete a user in Snowflake via SCIM API
        
        Args:
            user_id (str): User ID or externalId
        """
        return self._make_scim_request('DELETE', f"Users/{user_id}")
    
    def get_groups(self, start_index=1, count=100, filter_str=None):
        """
        Get groups from Snowflake via SCIM API
        
        Args:
            start_index (int): Starting index for pagination
            count (int): Number of groups to return per page
            filter_str (str): SCIM filter string
            
        Returns:
            dict: SCIM response containing groups
        """
        params = {
            'startIndex': start_index,
            'count': count
        }
        
        if filter_str:
            params['filter'] = filter_str
            
        return self._make_scim_request('GET', 'Groups', params=params)
    
    def create_group(self, group_data):
        """
        Create a group in Snowflake via SCIM API
        
        Args:
            group_data (dict): Group data in SCIM format
            
        Returns:
            dict: Created group data
        """
        return self._make_scim_request('POST', 'Groups', data=group_data)
    
    def update_group(self, group_id, group_data):
        """
        Update a group in Snowflake via SCIM API
        
        Args:
            group_id (str): Group ID
            group_data (dict): Updated group data in SCIM format
            
        Returns:
            dict: Updated group data
        """
        return self._make_scim_request('PUT', f"Groups/{group_id}", data=group_data)
    
    def delete_group(self, group_id):
        """
        Delete a group in Snowflake via SCIM API
        
        Args:
            group_id (str): Group ID
        """
        return self._make_scim_request('DELETE', f"Groups/{group_id}")

    def test_connectivity(self):
        """Test connectivity to Snowflake SCIM API"""
        try:
            # Try to get a token
            self._get_access_token()
            
            # Try to get users (limited to 1)
            users = self.get_users(count=1)
            
            logger.info(f"Successfully connected to Snowflake SCIM API. Found {users.get('totalResults', 0)} users.")
            return True
        except Exception as e:
            logger.error(f"Connectivity test failed: {str(e)}")
            return False

# Example Oracle to Snowflake user mapping function
def map_oracle_to_snowflake_user(oracle_user):
    """
    Map Oracle Identity Cloud Service user to Snowflake SCIM user format
    
    Args:
        oracle_user (dict): Oracle user data
        
    Returns:
        dict: Snowflake SCIM user data
    """
    snowflake_user = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": oracle_user.get('userName'),
        "active": oracle_user.get('active', True),
        "name": {
            "givenName": oracle_user.get('name', {}).get('givenName', ''),
            "familyName": oracle_user.get('name', {}).get('familyName', '')
        },
        "emails": [
            {
                "primary": True,
                "value": oracle_user.get('emails', [{}])[0].get('value', '')
            }
        ],
        "externalId": oracle_user.get('id')
    }
    
    return snowflake_user

def main():
    parser = argparse.ArgumentParser(description='Snowflake SCIM Integration Tool')
    parser.add_argument('--account', required=True, help='Snowflake account name (without .snowflakecomputing.com)')
    parser.add_argument('--user', required=True, help='Snowflake username for JWT authentication')
    parser.add_argument('--key', required=True, help='Path to private key file')
    parser.add_argument('--passphrase', help='Private key passphrase (if encrypted)')
    parser.add_argument('--test', action='store_true', help='Test connectivity')
    parser.add_argument('--list-users', action='store_true', help='List users')
    parser.add_argument('--list-groups', action='store_true', help='List groups')
    
    args = parser.parse_args()
    
    integration = SnowflakeScimIntegration(
        account_name=args.account,
        user_name=args.user,
        private_key_path=args.key,
        private_key_passphrase=args.passphrase
    )
    
    if args.test:
        success = integration.test_connectivity()
        sys.exit(0 if success else 1)
        
    if args.list_users:
        users = integration.get_users()
        print(json.dumps(users, indent=2))
        
    if args.list_groups:
        groups = integration.get_groups()
        print(json.dumps(groups, indent=2))

if __name__ == "__main__":
    main()
