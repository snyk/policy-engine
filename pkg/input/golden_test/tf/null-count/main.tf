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

# In this file, `count` is set to `null` which is undefined behavior in
# terraform.  We interpret this as `count = 1`.
#
# This lets us include some resources in terraform modules with required
# arguments that we can't determine a value for.  While those resources may end
# up not existing, usually you'd still want to be warned about unsafe
# configurations detected by rules.

variable "foo_count" {
  type = number
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "foo" {
  bucket = "mybucket-${count.index}"
  count = var.foo_count ? 10 : null
}
