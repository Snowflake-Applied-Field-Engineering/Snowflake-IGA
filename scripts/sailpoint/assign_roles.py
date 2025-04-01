import snowflake.connector
import yaml
import logging
from scripts.common.snowflake_connector import get_snowflake_connection

logging.basicConfig(level=logging.INFO)

def assign_role(username, role):
    """Assigns a Snowflake role to an existing user."""
    conn = get_snowflake_connection()
    if not conn:
        logging.error("Failed to establish Snowflake connection.")
        return

    try:
        with conn.cursor() as cur:
            cur.execute(f"GRANT ROLE {role} TO USER {username}")
            logging.info(f"✅ Successfully assigned role {role} to user {username}")
    except Exception as e:
        logging.error(f"❌ Failed to assign role {role} to user {username}: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    # Example usage
    assign_role("john.doe", "IGA_ADMIN")
