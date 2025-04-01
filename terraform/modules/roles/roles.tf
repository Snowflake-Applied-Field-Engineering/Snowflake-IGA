# terraform/modules/roles/roles.tf
resource "snowflake_role" "iga_admin" {
  name    = var.role_name
  comment = "IGA Role for managing user provisioning"
}

resource "snowflake_role_grants" "iga_admin_grants" {
  role_name = snowflake_role.iga_admin.name
  users     = var.assigned_users
}
