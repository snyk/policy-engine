package rules.snyk_002

resource_type = "MULTIPLE"

buckets = snyk.resources("aws_s3_bucket")

has_bucket_name {
	contains(input.bucket, "bucket")
}

has_bucket_name {
	contains(input.bucket_prefix, "bucket")
}

policy[info] {
	bucket := buckets[_]
	info := {
		"message": "Buckets should not contain bucket, its implied duh",
		"resource": bucket,
	}
}
