# EKS/ASG launch template metadata hardening (ATL-069).
# `workers` leaves IMDSv1 answerable; `workers_hardened` enforces IMDSv2.

resource "aws_launch_template" "workers" {
  name_prefix   = "eks-workers"
  image_id      = "ami-0abcd1234ef567890"
  instance_type = "t3.medium"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}

resource "aws_launch_template" "workers_hardened" {
  name_prefix   = "eks-workers-hardened"
  image_id      = "ami-0abcd1234ef567890"
  instance_type = "t3.medium"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
