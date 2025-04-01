import snowflake.connector
import yaml
import logging
import pandas as pd
from scripts.common.snowflake_connector import get_snowflake_connection

logging.basicConfig(level=logging.INFO)

def generate_access_report():
    """Generates a report of all users and roles in Snowflake."""
    conn = get_snowflake_connection()
    if not conn:
        logging.error("Failed to establish Snowflake connection.")
        return

    try:
        query = """
        SELECT u.name AS username, r.name AS role
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.id = g.grantee_id
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.ROLES r ON g.role_id = r.id
        """
        df = pd.read_sql(query, conn)

        # Save to CSV
        df.to_csv("snowflake_access_report.csv", index=False)
        logging.info("✅ Access report generated: snowflake_access_report.csv")

    except Exception as e:
        logging.error(f"❌ Failed to generate access report: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    generate_access_report()
