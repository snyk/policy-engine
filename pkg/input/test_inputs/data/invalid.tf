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

resource "aws_s3_bucket" "exposedbucket" {
  bucket = "${var.victim_company}accidentlyexposed"

  tags = {
    Name        = "Exposed Bucket"
    env = "Dev"
  }
}

resource "aws_s3_bucket_acl" "exposedbucket_acl" {
  bucket = aws_s3_bucket.exposedbucket.id
  acl    = "public-read"

}

}
resource "aws_s3_bucket_public_access_block" "private" {
  bucket                  = aws_s3_bucket.exposedbucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_account_public_access_block" "main" {
  restrict_public_buckets     = true
}

resource "aws_s3_account_public_access_block" "main" {
  ignore_public_acls     = true
}

resource "aws_s3_account_public_access_block" "main" {
  block_public_policy     = true
}
