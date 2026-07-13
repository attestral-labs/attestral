# Nothing in this file carries a risky literal. Every finding requires
# resolving a variable, a tfvars override, a local, or a module input -
# exactly what real Terraform looks like.

variable "log_acl" {
  type    = string
  default = "private" # safe default; terraform.tfvars flips it
}

variable "db_backups" {
  default = 0
}

locals {
  encrypt_db = false
}

resource "aws_s3_bucket" "logs" {
  acl = var.log_acl
}

resource "aws_rds_cluster" "events" {
  storage_encrypted       = local.encrypt_db
  backup_retention_period = var.db_backups
}

module "edge" {
  source    = "./modules/edge"
  open_cidr = "0.0.0.0/0" # overrides the module's safe default
}
