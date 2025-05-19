package rules.fugue_simple_deny_info

resource_type := "aws_s3_bucket"

has_bucket_name if {
	is_string(input.bucket)
	contains(input.bucket, "bucket")
}

has_bucket_name if {
	is_string(input.bucket_prefix)
	contains(input.bucket_prefix, "bucket")
}

deny contains info if {
	has_bucket_name
	info := {"message": "bucket should not contain the word bucket, it's implied"}
}
