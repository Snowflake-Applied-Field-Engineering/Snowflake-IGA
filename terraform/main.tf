module "users" {
  source        = "./modules/users"
  user_list     = ["john.doe", "jane.smith"]
  default_role  = "PUBLIC"
}

module "roles" {
  source         = "./modules/roles"
  role_name      = "IGA_ADMIN"
  assigned_users = module.users.provisioned_users
}

module "policies" {
  source          = "./modules/policies"
  allowed_ip_list = ["192.168.1.0/24"]
}
