# terraform/modules/users/variables.tf
variable "user_list" {
  description = "List of users to be provisioned"
  type        = list(string)
}

variable "default_role" {
  description = "Default role for new users"
  type        = string
}
