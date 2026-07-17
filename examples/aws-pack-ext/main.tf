# Service-coverage expansion fixtures (ATL-055..ATL-067). Each resource is
# misconfigured on exactly one attribute and hardened on the rest, so it fires
# only its own rule. Do not use as a template for real infrastructure.

# ATL-055: public function URL.
resource "aws_lambda_function_url" "public" {
  function_name      = "handler"
  authorization_type = "NONE"
}

# ATL-056: no IAM database auth (hardened elsewhere).
resource "aws_db_instance" "app" {
  identifier                          = "app"
  storage_encrypted                   = true
  publicly_accessible                 = false
  deletion_protection                 = true
  auto_minor_version_upgrade          = true
  iam_database_authentication_enabled = false
}

# ATL-057: no enhanced VPC routing (encrypted + private).
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier  = "warehouse"
  encrypted           = true
  publicly_accessible = false
  enhanced_vpc_routing = false
}

# ATL-058: no at-rest encryption (transit on).
resource "aws_elasticache_replication_group" "cache_a" {
  replication_group_id       = "cache-a"
  transit_encryption_enabled = true
  at_rest_encryption_enabled = false
}

# ATL-059: no in-transit encryption (at-rest on).
resource "aws_elasticache_replication_group" "cache_b" {
  replication_group_id       = "cache-b"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = false
}

# ATL-060: unencrypted DocumentDB.
resource "aws_docdb_cluster" "docs" {
  cluster_identifier = "docs"
  storage_encrypted  = false
}

# ATL-061: direct internet access (root off).
resource "aws_sagemaker_notebook_instance" "nb_net" {
  name                   = "nb-net"
  instance_type          = "ml.t3.medium"
  root_access            = "Disabled"
  direct_internet_access = "Enabled"
}

# ATL-062: root access (internet off).
resource "aws_sagemaker_notebook_instance" "nb_root" {
  name                   = "nb-root"
  instance_type          = "ml.t3.medium"
  direct_internet_access = "Disabled"
  root_access            = "Enabled"
}

# ATL-063: no deletion protection (drops invalid headers).
resource "aws_lb" "lb_del" {
  name                       = "lb-del"
  drop_invalid_header_fields = true
  enable_deletion_protection = false
}

# ATL-064: forwards invalid headers (deletion protected).
resource "aws_lb" "lb_hdr" {
  name                       = "lb-hdr"
  enable_deletion_protection = true
  drop_invalid_header_fields = false
}

# ATL-065: unencrypted Kinesis stream.
resource "aws_kinesis_stream" "events" {
  name            = "events"
  shard_count     = 1
  encryption_type = "NONE"
}

# ATL-066: unauthenticated API method.
resource "aws_api_gateway_method" "open" {
  rest_api_id   = "abc123"
  resource_id   = "res1"
  http_method   = "GET"
  authorization = "NONE"
}

# ATL-067: trail configured but logging switched off. Multi-region, log-file
# validation, and a KMS key are all set so only ATL-067 fires (ATL-019/020/054
# stay quiet).
resource "aws_cloudtrail" "disabled" {
  name                       = "acme-disabled"
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
  enable_logging             = false
}

# ATL-068: GuardDuty detector present but disabled.
resource "aws_guardduty_detector" "main" {
  enable = false
}
