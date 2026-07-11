resource "aws_s3_bucket" "reports" {
  bucket = "acme-reports"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app" {
  identifier            = "app-db"
  publicly_accessible   = true
}

resource "aws_iam_policy" "admin" {
  name   = "admin-all"
  policy = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\": \"*\",\"Resource\":\"*\"}]}"
}
