```markdown
# Common Utilities for Snowflake IGA

This directory contains shared utility scripts used across the Snowflake IGA project. 
These scripts help with authentication, logging, configuration, and other common tasks.

## Files in This Directory

### snowflake_connector.py
Purpose: Handles authentication and connection to Snowflake.  
Usage:
```python
from snowflake_connector import get_snowflake_connection
conn = get_snowflake_connection()

### config.yaml

Purpose: Stores configuration settings for Snowflake, SailPoint, and Saviynt.  
Usage:

```plaintext
- Defines authentication type (password, oauth, or keypair).
- Stores API credentials for SailPoint and Saviynt.
- Should not be committed to GitHub (add to .gitignore).


### logging_setup.py

Purpose: Provides consistent logging across all scripts.  
Usage:

```python
from logging_setup import logger
logger.info("This is an info message")


### utils.py

Purpose: Contains helper functions used across multiple scripts.  
Examples:

```plaintext
- Formatting timestamps
- Validating user input
- Fetching API responses


## How to Use These Utilities

```plaintext
1. Ensure you have config.yaml set up.
2. Import the required modules in your script.
3. Use them to simplify Snowflake IGA automation.
