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

data "aws_msk_broker_nodes" "msk_nodes" {
  cluster_arn = "cluster-arn"
}

resource "aws_lb" "msk" {
  name               = "msk-private-link-ingress"
  load_balancer_type = "network"
  internal           = true
  subnets            =  ["subnet-000000", "subnet-111111", "subnet-222222"]
}

resource "aws_lb_target_group" "msk_nlb_target_groups" {
  count       = 3
  name        = "msk-dynamic-broker${count.index}"
  port        = 1234
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = "vpc-0123456789"
}

resource "aws_lb_target_group_attachment" "msk_tgr_attachment" {
  for_each = {
    for i, k in aws_lb_target_group.msk_nlb_target_groups :
    i => {
      target_group = aws_lb_target_group.msk_nlb_target_groups[i]

      # These two lines cause the error
      instance_ip  = data.aws_msk_broker_nodes.msk_nodes.node_info_list[i].client_vpc_ip_address
      broker_id    = data.aws_msk_broker_nodes.msk_nodes.node_info_list[i].broker_id
    }
  }
  target_group_arn = each.value.target_group.arn
  target_id        = each.value.instance_ip
} 