variable "snowflake_account" {
  description = "Snowflake account identifier"
  type        = string
}

variable "snowflake_user" {
  description = "Snowflake admin user"
  type        = string
}

variable "snowflake_password" {
  description = "Password for the Snowflake admin user"
  type        = string
  sensitive   = true
}

variable "default_warehouse" {
  description = "Default Snowflake warehouse"
  type        = string
  default     = "COMPUTE_WH"
}

variable "default_database" {
  description = "Default Snowflake database"
  type        = string
  default     = "MY_DATABASE"
}
