# Airflow connection configuration for Snowflake
# To add this connection via Airflow UI:
# Admin -> Connections -> Add a new record

# Connection ID: snowflake_default
# Connection Type: Snowflake
# Host: your_account.snowflakecomputing.com
# Schema: your_database
# Login: your_username
# Password: your_password
# Account: your_account
# Database: your_database
# Region: your_region
# Role: ACCOUNTADMIN
# Warehouse: COMPUTE_WH

# Alternative: Add connection via Airflow CLI
# airflow connections add 'snowflake_default' \
#     --conn-type 'snowflake' \
#     --conn-host 'your_account.snowflakecomputing.com' \
#     --conn-login 'your_username' \
#     --conn-password 'your_password' \
#     --conn-schema 'your_database' \
#     --conn-extra '{"account": "your_account", "warehouse": "COMPUTE_WH", "database": "your_database", "role": "ACCOUNTADMIN", "authenticator": "snowflake"}'

# If using OAuth instead of password authentication:
# airflow connections add 'snowflake_default' \
#     --conn-type 'snowflake' \
#     --conn-host 'your_account.snowflakecomputing.com' \
#     --conn-login 'your_username' \
#     --conn-schema 'your_database' \
#     --conn-extra '{"account": "your_account", "warehouse": "COMPUTE_WH", "database": "your_database", "role": "ACCOUNTADMIN", "authenticator": "oauth", "token": "your_oauth_token"}'

# Example CSV format for new_users.csv:
# username,first_name,last_name,email,role,warehouse,additional_roles
# jdoe,John,Doe,john.doe@example.com,ANALYST_ROLE,COMPUTE_WH,MARKETING_ROLE,REPORTING_ROLE
# msmith,Mary,Smith,mary.smith@example.com,DEVELOPER_ROLE,COMPUTE_WH,
# rjones,Robert,Jones,robert.jones@example.com,ADMIN_ROLE,ADMIN_WH,SECURITY_ROLE
