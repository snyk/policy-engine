provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias = "west"
  region = "us-west-1"
}

terraform {
  required_providers {
    aws = {
      version = "~> 4.0.0"
    }
  }
}

resource "aws_kms_key" "key" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_s3_bucket" "bucket1" {
}

resource "aws_s3_bucket" "bucket2" {
  provider = aws.west
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket2" {
  provider = aws.west
  bucket = aws_s3_bucket.bucket2.bucket

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
