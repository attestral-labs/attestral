variable "open_cidr" {
  type    = string
  default = "10.0.0.0/8" # safe on its own; the caller passes 0.0.0.0/0
}

resource "aws_security_group" "gateway" {
  name = "edge-gateway"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.open_cidr]
  }
}
