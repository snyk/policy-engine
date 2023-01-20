provider "aws" {
    region = "us-east-2"
}

variable "settings" {
    type = list(object({
        port = number
        cidr = string
    }))
    default = [
        {"port": 22, "cidr": "192.168.1.0/32"},
        {"port": 80, "cidr": "0.0.0.0/0"},
    ]
}

resource "aws_security_group" "example1" {
    dynamic "ingress" {
        for_each = var.settings
        content {
            protocol = "tcp"
            from_port = ingress.value["port"]
            to_port = ingress.value["port"]
            cidr_blocks = [ingress.value["cidr"]]
        }
    }
}
