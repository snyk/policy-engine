locals {
  ports = [
    443, 80, 22
  ]
}

resource "aws_vpc" "example" {
  cidr_block = "11.0.0.0/16"
}

resource "aws_security_group" "example" {
  name   = "example"
  vpc_id = aws_vpc.example.id

  dynamic "ingress" {
    for_each = local.ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  # non-default iterator name example
  dynamic "egress" {
    for_each = local.ports
    iterator = each
    content {
      from_port   = each.value
      to_port     = each.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
