import requests
import snowflake.connector
import yaml
import logging
from scripts.common.snowflake_connector import get_snowflake_connection

logging.basicConfig(level=logging.INFO)

SAVIYNT_ROLE_API = "https://saviynt.example.com/api/roles"

def fetch_saviynt_roles():
    """Fetches role mappings from Saviynt API."""
    headers = {"Authorization": f"Bearer {SAVIYNT_API_KEY}"}
    response = requests.get(SAVIYNT_ROLE_API, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        logging.error(f"❌ Failed to fetch roles from Saviynt: {response.text}")
        return []

def sync_roles():
    """Syncs Saviynt role assignments with Snowflake."""
    roles = fetch_saviynt_roles()
    if not roles:
        logging.info("No roles to sync.")
        return

    conn = get_snowflake_connection()
    if not conn:
        logging.error("Failed to establish Snowflake connection.")
        return

    try:
        with conn.cursor() as cur:
            for role_data in roles:
                role = role_data["role"]
                users = role_data["users"]

                # Ensure role exists in Snowflake
                cur.execute(f"CREATE ROLE IF NOT EXISTS {role}")

                # Assign users to role
                for user in users:
                    cur.execute(f"GRANT ROLE {role} TO USER {user}")
                    logging.info(f"✅ Assigned role {role} to user {user}")

    except Exception as e:
        logging.error(f"❌ Role sync failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    sync_roles()
