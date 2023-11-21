resource "aws_s3_bucket" "nativebucket" {
    count = 1
    bucket = "test"
}

resource "aws_s3_bucket_versioning" "nativebucket" {
    count = 1
    bucket = aws_s3_bucket.nativebucket[0].id
    versioning_configuration {
      status = "Enabled"
    }
}

resource "aws_s3_bucket" "febucket" {
    for_each = {"one": "one"}
    bucket = "test"
}

resource "aws_s3_bucket_versioning" "febucket" {
    for_each = {"one": "one"}
    bucket = aws_s3_bucket.febucket["one"].id
    versioning_configuration {
      status = "Enabled"
    }
}
