# What we expect to see after a plan
resource "aws_s3_bucket" "one" {
  bucket = "one"
}

resource "aws_s3_bucket_lifecycle_configuration" "one" {
  bucket = aws_s3_bucket.one.id

  rule {
    id     = "foo"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }

    expiration {
      days = 90
    }
  }

  rule {
    id     = "bar"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

# Now with dynamic blocks
resource "aws_s3_bucket" "two" {
  bucket = "two"
}

resource "aws_s3_bucket_lifecycle_configuration" "two" {
  bucket = aws_s3_bucket.two.id

  dynamic "rule" {
    for_each = var.lifecycle_rules

    content {
      id     = try(rule.value.id, null)
      status = try(rule.value.enabled ? "Enabled" : "Disabled", null)

      # Max 1 block - expiration
      dynamic "expiration" {
        for_each = try(flatten([rule.value.expiration]), [])

        content {
          date                         = try(expiration.value.date, null)
          days                         = try(expiration.value.days, null)
          expired_object_delete_marker = try(expiration.value.expired_object_delete_marker, null)
        }
      }

      # Several blocks - transition
      dynamic "transition" {
        for_each = try(flatten([rule.value.transition]), [])

        content {
          date          = try(transition.value.date, null)
          days          = try(transition.value.days, null)
          storage_class = transition.value.storage_class
        }
      }
    }
  }
}
