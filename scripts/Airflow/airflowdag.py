from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.snowflake.operators.snowflake import SnowflakeOperator
from airflow.providers.snowflake.hooks.snowflake import SnowflakeHook
import pandas as pd
import logging

# Default arguments for the DAG
default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email_on_failure': True,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}

# Create a DAG instance
dag = DAG(
    'snowflake_user_provisioning',
    default_args=default_args,
    description='A DAG to automate Snowflake user provisioning',
    schedule_interval=timedelta(days=1),
    start_date=datetime(2025, 3, 1),
    catchup=False,
    tags=['snowflake', 'user_provisioning'],
)

# Function to fetch user data from source system
# This could be CSV, API call, database, etc.
def fetch_user_data(**context):
    # Example: Read from CSV
    # In a real scenario, this could be an API call to an HR system or LDAP
    try:
        df = pd.read_csv('/path/to/new_users.csv')
        
        # Basic validation
        required_cols = ['username', 'first_name', 'last_name', 'email', 'role', 'warehouse']
        for col in required_cols:
            if col not in df.columns:
                raise ValueError(f"Required column {col} missing from input data")
        
        # Filter out invalid records
        df = df[df['username'].notna() & df['email'].notna()]
        
        # Push the DataFrame to XCom for next task
        users_to_create = df.to_dict('records')
        logging.info(f"Found {len(users_to_create)} users to provision in Snowflake")
        
        return users_to_create
    
    except Exception as e:
        logging.error(f"Error fetching user data: {str(e)}")
        raise

# Function to generate SQL for user creation
def generate_user_creation_sql(**context):
    # Pull the user data from XCom
    users = context['ti'].xcom_pull(task_ids='fetch_user_data')
    
    if not users:
        logging.info("No users to provision")
        return []
    
    sql_statements = []
    
    # Generate SQL for each user
    for user in users:
        # Generate a secure password (in production, consider integration with a password manager)
        # or use SSO instead of password authentication
        default_password = f"ChangeMe123!"  # In production, generate secure random passwords
        
        # Create user SQL
        sql = f"""
        CREATE USER IF NOT EXISTS {user['username']} 
        PASSWORD = '{default_password}'
        DISPLAY_NAME = '{user['first_name']} {user['last_name']}'
        EMAIL = '{user['email']}'
        DEFAULT_WAREHOUSE = {user['warehouse']}
        DEFAULT_ROLE = {user['role']}
        MUST_CHANGE_PASSWORD = TRUE;
        """
        
        sql_statements.append({"username": user['username'], "sql": sql})
    
    logging.info(f"Generated SQL statements for {len(sql_statements)} users")
    return sql_statements

# Function to execute user creation
def execute_user_creation(**context):
    # Pull the SQL statements from XCom
    sql_statements = context['ti'].xcom_pull(task_ids='generate_user_creation_sql')
    
    if not sql_statements:
        logging.info("No SQL statements to execute")
        return
    
    # Get Snowflake connection
    snowflake_hook = SnowflakeHook(snowflake_conn_id='snowflake_default')
    
    results = []
    
    # Execute each SQL statement
    for statement in sql_statements:
        try:
            snowflake_hook.run(statement['sql'])
            results.append({
                "username": statement['username'],
                "status": "SUCCESS",
                "message": "User created successfully"
            })
            logging.info(f"Successfully created user {statement['username']}")
        except Exception as e:
            error_message = str(e)
            results.append({
                "username": statement['username'],
                "status": "ERROR",
                "message": error_message
            })
            logging.error(f"Error creating user {statement['username']}: {error_message}")
    
    return results

# Function to grant roles to users
def grant_roles_to_users(**context):
    # Pull user data and results from previous tasks
    users = context['ti'].xcom_pull(task_ids='fetch_user_data')
    creation_results = context['ti'].xcom_pull(task_ids='execute_user_creation')
    
    if not users or not creation_results:
        logging.info("No users to grant roles to")
        return
    
    # Filter for successfully created users
    successful_users = [result['username'] for result in creation_results 
                        if result['status'] == 'SUCCESS']
    
    if not successful_users:
        logging.info("No successfully created users to grant roles to")
        return
    
    # Get Snowflake connection
    snowflake_hook = SnowflakeHook(snowflake_conn_id='snowflake_default')
    
    # Create a map of usernames to their data
    user_map = {user['username']: user for user in users}
    
    grant_results = []
    
    # Grant roles to each user
    for username in successful_users:
        user = user_map.get(username)
        if not user:
            continue
        
        # The role specified in the input file
        primary_role = user['role']
        
        # Additional roles (if specified in input)
        additional_roles = user.get('additional_roles', '').split(',') if user.get('additional_roles') else []
        
        try:
            # Grant each role
            for role in [primary_role] + additional_roles:
                if role and role.strip():
                    sql = f"GRANT ROLE {role.strip()} TO USER {username};"
                    snowflake_hook.run(sql)
            
            grant_results.append({
                "username": username,
                "status": "SUCCESS",
                "message": f"Granted roles to {username}"
            })
            logging.info(f"Successfully granted roles to user {username}")
        except Exception as e:
            error_message = str(e)
            grant_results.append({
                "username": username,
                "status": "ERROR",
                "message": error_message
            })
            logging.error(f"Error granting roles to user {username}: {error_message}")
    
    return grant_results

# Function to notify about the provisioning results
def send_notification(**context):
    # Pull results from previous tasks
    creation_results = context['ti'].xcom_pull(task_ids='execute_user_creation')
    grant_results = context['ti'].xcom_pull(task_ids='grant_roles_to_users')
    
    if not creation_results:
        message = "No user creation results available"
        logging.info(message)
        return message
    
    # Count successes and failures
    creation_success = sum(1 for result in creation_results if result['status'] == 'SUCCESS')
    creation_failure = len(creation_results) - creation_success
    
    grant_success = sum(1 for result in grant_results if result['status'] == 'SUCCESS') if grant_results else 0
    grant_failure = len(grant_results) - grant_success if grant_results else 0
    
    # Build summary message
    message = f"""
    Snowflake User Provisioning Summary:
    
    User Creation:
    - Success: {creation_success}
    - Failure: {creation_failure}
    
    Role Assignments:
    - Success: {grant_success}
    - Failure: {grant_failure}
    
    Details:
    """
    
    # Add details for each user
    for result in creation_results:
        message += f"\n{result['username']}: {result['status']} - {result['message']}"
    
    # In a real implementation, you would send this via email, Slack, etc.
    # For example with Airflow's email operator or Slack operator
    logging.info(f"Sending notification: {message}")
    
    # You could also update a dashboard or logging system
    
    return message

# Define the task dependencies
fetch_task = PythonOperator(
    task_id='fetch_user_data',
    python_callable=fetch_user_data,
    provide_context=True,
    dag=dag,
)

generate_sql_task = PythonOperator(
    task_id='generate_user_creation_sql',
    python_callable=generate_user_creation_sql,
    provide_context=True,
    dag=dag,
)

execute_creation_task = PythonOperator(
    task_id='execute_user_creation',
    python_callable=execute_user_creation,
    provide_context=True,
    dag=dag,
)

grant_roles_task = PythonOperator(
    task_id='grant_roles_to_users',
    python_callable=grant_roles_to_users,
    provide_context=True,
    dag=dag,
)

notification_task = PythonOperator(
    task_id='send_notification',
    python_callable=send_notification,
    provide_context=True,
    dag=dag,
)

# Set the task dependency chain
fetch_task >> generate_sql_task >> execute_creation_task >> grant_roles_task >> notification_task
