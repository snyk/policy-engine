# Copyright 2022-2023 Snyk Ltd
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

variable "using_default" {
    type = string
    default = "default_value"
}

variable "in_terraform_tfvars" {
    type = string
    default = "default_value"
}

variable "in_terraform_tfvars_json" {
    type = string
    default = "default_value"
}

variable "in_aaa_auto_tfvars" {
    type = string
    default = "default_value"
}

variable "in_bbb_auto_tfvars_json" {
    type = string
    default = "default_value"
}

variable "in_ccc_auto_tfvars" {
    type = string
    default = "default_value"
}

resource "aws_s3_bucket" "bucket" {
    tags = {
        var_1 = var.using_default
        var_2 = var.in_terraform_tfvars
        var_3 = var.in_terraform_tfvars_json
        var_4 = var.in_aaa_auto_tfvars
        var_5 = var.in_bbb_auto_tfvars_json
        var_6 = var.in_ccc_auto_tfvars
    }
}
