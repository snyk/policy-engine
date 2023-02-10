# See <https://github.com/fugue/regula/issues/389>
variable "team" {
  type = string
}
variable "service" {
  type = string
}
variable "type" {
  type = string
}

locals {
  default_tags = [
    "owner:tf",
    "service:${var.service}",
    "team:${var.team}",
    "region:*",
    "geo:*",
    "env:*"
  ]
  tags = concat(local.default_tags, ["test"])
}

resource "aws_s3_bucket" "test" {
  bucket_prefix = "testytest"
  tags = local.tags
}
