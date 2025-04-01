import snowflake.connector
import yaml
import logging
from scripts.common.snowflake_connector import get_snowflake_connection

logging.basicConfig(level=logging.INFO)

def revoke_user(username):
    """Revokes all roles from a Snowflake user and disables the account."""
    conn = get_snowflake_connection()
    if not conn:
        logging.error("Failed to establish Snowflake connection.")
        return

    try:
        with conn.cursor() as cur:
            cur.execute(f"REVOKE ALL PRIVILEGES ON ACCOUNT FROM USER {username}")
            cur.execute(f"ALTER USER {username} SET DISABLED = TRUE")
            logging.info(f"✅ Successfully revoked access and disabled user: {username}")
    except Exception as e:
        logging.error(f"❌ Failed to revoke access for {username}: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    # Example usage
    revoke_user("john.doe")
