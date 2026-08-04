# The agent's cloud footprint. The aws-deploy MCP server holds credentials that
# reach every one of these; the co-resident web-fetch server (which ingests
# untrusted web content) holds none of its own.
resource "aws_s3_bucket" "customer_data" {
  bucket = "acme-customer-data"
}

resource "aws_iam_role" "deployer" {
  name               = "agent-deployer"
  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
}

resource "aws_dynamodb_table" "sessions" {
  name         = "agent-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
