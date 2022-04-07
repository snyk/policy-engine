package rules.snyk_001.tf

resource_type = "aws_s3_bucket"

has_bucket_name {
	contains(input.bucket, "bucket")
}

has_bucket_name {
	contains(input.bucket_prefix, "bucket")
}

deny[info] {
	has_bucket_name
	info := {"message": "Buckets should not contain bucket, its implied duh"}
}
