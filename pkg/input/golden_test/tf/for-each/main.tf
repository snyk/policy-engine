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

variable "buckets" {
  type    = map
  default = {"prod": "abc123", "dev": "ced456"}
}

variable "users" {
  type    = list(string)
  default = ["Todd", "James", "Alice", "Dottie"]
}

resource "aws_s3_bucket" "mybuckets" {
  for_each      = var.buckets
  bucket_prefix = "${each.key}${each.value}"
  tags          = {"env": each.key}
}

resource "aws_iam_user" "myusers" {
  for_each = toset(var.users)
  name     = each.key
}

# These resources read a property from mybuckets.
resource "aws_s3_bucket" "read_mybuckets" {
  for_each      = var.buckets
  tags          = {"read_prefix": aws_s3_bucket.mybuckets[each.key].bucket_prefix}
}

# These resources read a non-existing property ("phantom attribute") from
# mybuckets.
resource "aws_s3_bucket" "phantom_mybuckets" {
  for_each      = var.buckets
  tags          = {"backup": aws_s3_bucket.mybuckets[each.key].id}
}
