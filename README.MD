
# Snowflake IGA Toolkit

**Snowflake IGA terraform and scripts**  
This project provides a **collection of automation scripts** designed to **integrate Snowflake with IGA (Identity Governance and Administration) tools**, such as **SailPoint** and **Saviynt** and also some terraform for automation.

## Features
- Automates **user provisioning & deprovisioning** in Snowflake.  
- **Synchronizes roles** between IGA tools and Snowflake.  
- Supports **OAuth, Key Pair, and Password authentication** for Snowflake.  
- Provides **audit logs & reporting** for access governance.  
- Built-in **GitHub Actions CI/CD** for automated testing.

---

## 📂 Repository Structure
```
snowIGA
├── scripts/
│   ├── common/          #  Shared utilities for Snowflake authentication & logging
│   │   ├── snowflake_connector.py
│   │   ├── config.yaml
│   │   ├── logging_setup.py
│   │   ├── utils.py
│   ├── sailpoint/       #  SailPoint-specific automation scripts
│   │   ├── create_snowflake_users.py
│   │   ├── assign_roles.py
│   │   ├── revoke_access.py
│   │   ├── sync_sailpoint_snowflake.py
│   ├── saviynt/         #  Saviynt-specific automation scripts
│   │   ├── provision_users.py
│   │   ├── sync_roles.py
│   │   ├── generate_access_reports.py
├── terraform/           #  New Terraform module for Snowflake IGA automation
│   ├── main.tf              # Main Terraform configuration
│   ├── providers.tf         # Snowflake provider setup
│   ├── variables.tf         # Variables for flexibility
│   ├── outputs.tf           # Terraform outputs
│   ├── modules/
│   │   ├── users/           # User provisioning module
│   │   │   ├── users.tf
│   │   │   ├── variables.tf
│   │   │   ├── outputs.tf
│   │   ├── roles/           # Role management module
│   │   │   ├── roles.tf
│   │   │   ├── variables.tf
│   │   │   ├── outputs.tf
│   │   ├── policies/        # Network security policies
│   │   │   ├── policies.tf
│   │   │   ├── variables.tf
│   │   │   ├── outputs.tf
│   ├── terraform.tfvars     # User-specific values
│   ├── README.md            # Documentation for Terraform
├── docs/
│   ├── setup_guide.md
│   ├── API_reference.md
│   ├── integration_steps.md
│   ├── troubleshooting.md
├── tests/
│   ├── test_snowflake_connection.py
│   ├── test_provisioning.py
│   ├── test_role_sync.py
├── .github/workflows/
│   ├── ci.yml  #  CI/CD pipeline for automated testing
├── .gitignore
├── LICENSE
├── README.md  #  You are here! 
```
---

## Terraform Implementation

### Overview
The Terraform module provides Infrastructure as Code (IaC) capabilities for automating Snowflake identity governance. It enables consistent, version-controlled deployment of user accounts, role assignments, and security policies that align with your organization's IGA requirements.

### Key Components

#### Main Configuration (`main.tf`)
Orchestrates the entire Terraform deployment by calling the specialized modules for users, roles, and policies. It defines the high-level architecture of your Snowflake IGA implementation.

#### Provider Setup (`providers.tf`)
Configures the Snowflake provider with authentication details and connection parameters. Supports multiple authentication methods including OAuth, username/password, and key pair authentication.

#### Modules
The Terraform implementation is organized into three core modules:

##### 1. Users Module
- **Purpose**: Automates the creation, management, and deprovisioning of Snowflake users
- **Key Features**:
  - Bulk user provisioning from CSV or JSON sources
  - Customizable user properties (default roles, warehouses)
  - Automatic user deactivation based on IGA signals

##### 2. Roles Module
- **Purpose**: Manages role hierarchies and assignments in Snowflake
- **Key Features**:
  - Role-based access control (RBAC) implementation
  - Automated role assignments based on IGA group mappings
  - Support for custom role hierarchies and inheritance

##### 3. Policies Module
- **Purpose**: Implements network security policies and access controls
- **Key Features**:
  - IP allowlisting for secure access
  - Session policy management
  - Password policy enforcement

### Using the Terraform Module

1. **Initialize the Terraform configuration**:
   ```bash
   cd terraform
   terraform init
   ```

2. **Customize variables in `terraform.tfvars`**:
   ```hcl
   snowflake_account    = "your-account"
   snowflake_region     = "us-east-1"
   snowflake_username   = "terraform_user"
   snowflake_private_key_path = "/path/to/key.p8"
   
   # User configuration
   user_file_path = "./users.json"
   
   # Role configuration
   custom_role_hierarchy = true
   role_mapping_source = "sailpoint"
   ```

3. **Plan your changes**:
   ```bash
   terraform plan -out=snowflake_iga.plan
   ```

4. **Apply the configuration**:
   ```bash
   terraform apply snowflake_iga.plan
   ```

5. **For automated workflows, use the module outputs**:
   ```hcl
   # Example outputs
   provisioned_users = module.users.user_list
   role_assignments = module.roles.role_mappings
   ```

---

## Getting Started

### 🔹 **1. Clone the Repository**
```bash
git clone https://github.com/bbhorrigan/snowIGA.git
cd snowIGA
```

### 🔹 **2. Configure Snowflake Credentials**
- Edit the `scripts/common/config.yaml` file:
```yaml
auth_type: "password"  # Options: password, oauth, keypair

snowflake:
  user: "your_user"
  password: "your_password"
  account: "your_snowflake_account"
  warehouse: "COMPUTE_WH"
  database: "MY_DATABASE"
  schema: "PUBLIC"
```
- If using **OAuth**, update the `oauth_token` field.
- If using **Key Pair Authentication**, provide the `private_key` path.

### 🔹 **3. Test the Snowflake Connection**
```bash
python scripts/common/snowflake_connector.py
```
If successful, you'll see:
```
✅ Snowflake connection successful!
Snowflake Version: X.X.X
```

---

## Scripts Overview
### Common Utilities
| Script                    | Purpose |
|---------------------------|---------|
| `snowflake_connector.py`  | Establishes connection to Snowflake |
| `config.yaml`             | Stores authentication credentials |
| `logging_setup.py`        | Provides logging functions |
| `utils.py`                | Helper functions for various tasks |

### SailPoint Integration
| Script                         | Purpose |
|---------------------------------|---------|
| `create_snowflake_users.py`     | Automates user creation in Snowflake |
| `assign_roles.py`               | Assigns roles based on SailPoint mappings |
| `revoke_access.py`              | Removes user access as per governance rules |
| `sync_sailpoint_snowflake.py`   | Syncs SailPoint role assignments to Snowflake |

### Saviynt Integration
| Script                      | Purpose |
|------------------------------|---------|
| `provision_users.py`         | Manages user provisioning via Saviynt |
| `sync_roles.py`              | Ensures Snowflake roles match Saviynt roles |
| `generate_access_reports.py` | Generates user access & audit reports |

---
