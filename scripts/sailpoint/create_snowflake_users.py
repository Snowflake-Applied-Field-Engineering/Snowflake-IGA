import snowflake.connector
import yaml
import logging
from scripts.common.snowflake_connector import get_snowflake_connection

# Load config
with open("../common/config.yaml", "r") as file:
    config = yaml.safe_load(file)

logging.basicConfig(level=logging.INFO)

def create_user(username, role="PUBLIC"):
    """Creates a new Snowflake user and assigns a default role."""
    conn = get_snowflake_connection()
    if not conn:
        logging.error("Failed to establish Snowflake connection.")
        return

    try:
        with conn.cursor() as cur:
            cur.execute(f"CREATE USER IF NOT EXISTS {username} PASSWORD = 'TempPass123'")
            cur.execute(f"GRANT ROLE {role} TO USER {username}")
            logging.info(f"✅ Successfully created user: {username} with role: {role}")
    except Exception as e:
        logging.error(f"❌ Failed to create user {username}: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    # Example usage
    create_user("john.doe", "IGA_ADMIN")
