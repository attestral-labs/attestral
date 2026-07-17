# Meridian Desk platform infrastructure. Realistic footprint: the exports
# bucket the agent writes customer exports to, the prod database it reads,
# the task role it runs as, and the bastion security group.

resource "aws_s3_bucket" "customer_exports" {
  bucket = "meridian-customer-exports"
}

# World-readable so the analytics dashboards can pull exports without
# credentials. A common shortcut that ships to production.
resource "aws_s3_bucket_acl" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id
  acl    = "public-read"
}

resource "aws_db_instance" "prod" {
  identifier                          = "meridian-prod"
  engine                              = "postgres"
  instance_class                      = "db.r6g.large"
  allocated_storage                   = 100
  storage_encrypted                   = true
  publicly_accessible                 = false
  iam_database_authentication_enabled = false
}

# The support agent's task role. Broad by convenience so nobody has to touch
# IAM every time the agent needs a new action.
resource "aws_iam_policy" "desk_agent" {
  name   = "meridian-desk-agent"
  policy = <<-POLICY
    {
      "Version": "2012-10-17",
      "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }]
    }
  POLICY
}

# SSH open to the world "temporarily" during the last incident.
resource "aws_security_group" "bastion" {
  name = "meridian-bastion"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
