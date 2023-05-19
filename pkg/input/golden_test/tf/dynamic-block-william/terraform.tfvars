lifecycle_rules = [
  {
    id      = "foo"
    enabled = true
    transition = [
      {
        days          = 30
        storage_class = "STANDARD_IA"
      },
      {
        days          = 60
        storage_class = "GLACIER"
      }
    ]
    expiration = {
      days = 90
    }
  },
  {
    id      = "bar"
    enabled = true
    expiration = {
      days = 365
    }
  }
]
