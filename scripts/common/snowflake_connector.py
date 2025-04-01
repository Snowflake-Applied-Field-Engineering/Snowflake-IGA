import snowflake.connector
import yaml
import os
from snowflake.connector.errors import DatabaseError

# Load configuration from config.yaml
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

def load_config():
    """Loads configuration from a YAML file."""
    with open(CONFIG_PATH, "r") as file:
        return yaml.safe_load(file)

config = load_config()

def get_snowflake_connection():
    """
    Establishes a Snowflake connection based on the selected authentication method.
    Returns an active Snowflake connection object.
    """
    try:
        auth_type = config.get("auth_type", "password")  # Default to password-based auth

        if auth_type == "password":
            conn = snowflake.connector.connect(
                user=config["snowflake"]["user"],
                password=config["snowflake"]["password"],
                account=config["snowflake"]["account"],
                warehouse=config["snowflake"].get("warehouse", ""),
                database=config["snowflake"].get("database", ""),
                schema=config["snowflake"].get("schema", "")
            )

        elif auth_type == "oauth":
            conn = snowflake.connector.connect(
                user=config["snowflake"]["user"],
                account=config["snowflake"]["account"],
                authenticator="oauth",
                token=config["snowflake"]["oauth_token"]
            )

        elif auth_type == "keypair":
            conn = snowflake.connector.connect(
                user=config["snowflake"]["user"],
                account=config["snowflake"]["account"],
                private_key=config["snowflake"]["private_key"]
            )

        else:
            raise ValueError(f"Unsupported auth_type: {auth_type}")

        print("✅ Snowflake connection successful!")
        return conn

    except DatabaseError as e:
        print(f"❌ Snowflake connection failed: {e}")
        return None

# Test the connection
if __name__ == "__main__":
    conn = get_snowflake_connection()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT CURRENT_VERSION()")
        print(f"Snowflake Version: {cur.fetchone()[0]}")
        cur.close()
        conn.close()
