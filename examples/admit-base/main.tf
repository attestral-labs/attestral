resource "aws_s3_bucket" "customer_data" { bucket = "acme-customer-data" }
resource "aws_iam_role" "deployer" {
  name               = "agent-deployer"
  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
}
resource "aws_dynamodb_table" "sessions" {
  name = "agent-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"
  attribute { name = "id"  type = "S" }
}
