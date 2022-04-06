package rules.snyk_003

resource_type = "MULTIPLE"

buckets = snyk.resources("aws_s3_bucket")

has_bucket_name(bucket) {
	contains(bucket.bucket, "bucket")
}

has_bucket_name(bucket) {
	contains(bucket.bucket_prefix, "bucket")
}

deny[info] {
	bucket := buckets[_]
	has_bucket_name(bucket)
	info := {
		"message": "Buckets should not contain bucket, its implied duh",
		"resource": bucket,
	}
}

locations[info] {
	bucket := buckets[_]
	info := {"resource": bucket}
}
