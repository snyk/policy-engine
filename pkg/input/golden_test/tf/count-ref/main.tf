# Copyright 2022 Snyk Ltd
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

variable "aws_region" {
  default = "eu-west-1"
}

provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "not_working_1" {
  count  = var.aws_region == "eu-west-1" ? 1 : 0
  bucket = "not-working-1-random-string"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "not_working_1_block" {
  count                   = var.aws_region == "eu-west-1" ? 1 : 0
  bucket                  = aws_s3_bucket.not_working_1[count.index].id
  block_public_acls       = aws_s3_bucket.not_working_1[count.index].acl == "private" ? true : false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
