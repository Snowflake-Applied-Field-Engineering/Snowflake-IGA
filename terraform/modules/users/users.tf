# terraform/modules/users/users.tf
resource "snowflake_user" "users" {
  for_each    = toset(var.user_list)
  name        = each.value
  login_name  = each.value
  comment     = "Provisioned via Terraform"
  default_role = var.default_role
  disabled    = false
}
