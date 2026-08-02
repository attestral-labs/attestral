resource "aws_security_group" "agent_runner" {
  name = "agent-runner-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_instance" "runner" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.small"
  vpc_security_group_ids = [aws_security_group.agent_runner.id]
  iam_instance_profile   = aws_iam_instance_profile.runner.name
}

resource "aws_iam_instance_profile" "runner" {
  name = "agent-runner"
  role = aws_iam_role.deployer.name
}

resource "aws_iam_role" "deployer" {
  name = "agent-deployer"

  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
}

resource "aws_iam_role_policy_attachment" "deployer_readonly" {
  role       = aws_iam_role.deployer.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "acme-agent-artifacts"
}
