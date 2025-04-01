import requests
import snowflake.connector
import yaml
import logging
from scripts.common.snowflake_connector import get_snowflake_connection

logging.basicConfig(level=logging.INFO)

# Load config
with open("../common/config.yaml", "r") as file:
    config = yaml.safe_load(file)

SAVIYNT_API_URL = "https://saviynt.example.com/api/users"
SAVIYNT_API_KEY = "your_saviynt_api_key"

def fetch_saviynt_users():
    """Fetches user details from Saviynt API."""
    headers = {"Authorization": f"Bearer {SAVIYNT_API_KEY}"}
    response = requests.get(SAVIYNT_API_URL, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        logging.error(f"❌ Failed to fetch users from Saviynt: {response.text}")
        return []

def provision_users():
    """Creates users in Snowflake based on Saviynt data."""
    users = fetch_saviynt_users()
    if not users:
        logging.info("No new users to provision.")
        return

    conn = get_snowflake_connection()
    if not conn:
        logging.error("Failed to establish Snowflake connection.")
        return

    try:
        with conn.cursor() as cur:
            for user in users:
                username = user["username"]
                role = user.get("role", "PUBLIC")

                # Check if user exists
                cur.execute(f"SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE NAME = '{username}'")
                exists = cur.fetchone()[0]

                if exists:
                    logging.info(f"User {username} already exists. Skipping.")
                else:
                    cur.execute(f"CREATE USER {username} PASSWORD = 'TempPass123'")
                    cur.execute(f"GRANT ROLE {role} TO USER {username}")
                    logging.info(f"✅ Created user {username} with role {role}")

    except Exception as e:
        logging.error(f"❌ Provisioning failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    provision_users()
