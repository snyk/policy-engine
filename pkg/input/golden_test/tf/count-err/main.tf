resource "aws_s3_bucket" "count_bucket" {
  count         = var.create_bucket
  bucket_prefix = "some_count"
}

resource "aws_s3_bucket" "for_each_bucket" {
  for_each      = var.create_bucket ? {} : {"key": "value"}
  bucket_prefix = "some_for_each"
}
