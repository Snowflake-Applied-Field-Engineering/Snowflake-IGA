# terraform/modules/roles/outputs.tf
output "created_role" {
  description = "The Snowflake role that was created"
  value       = snowflake_role.iga_admin.name
}
