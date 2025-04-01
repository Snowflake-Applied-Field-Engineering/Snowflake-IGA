# terraform/modules/roles/variables.tf
variable "role_name" {
  description = "Role name to create"
  type        = string
}

variable "assigned_users" {
  description = "List of users to assign to this role"
  type        = list(string)
}
