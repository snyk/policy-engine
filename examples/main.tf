provider "aws" {
    region = "us-east-1"
}

resource "aws_s3_bucket" "example" {
    bucket = "dumb-bucket"
}

resource "aws_s3_bucket" "valid" {
    bucket = "dumb"
}
