# © 2023 Snyk Limited All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
