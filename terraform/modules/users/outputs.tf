# terraform/modules/users/outputs.tf
output "provisioned_users" {
  description = "List of provisioned users"
  value       = snowflake_user.users[*].name
}
