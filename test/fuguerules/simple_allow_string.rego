package rules.fugue_simple_allow_string

resource_type = "aws_s3_bucket"

has_bucket_name {
	is_string(input.bucket)
	contains(input.bucket, "bucket")
}

has_bucket_name {
	is_string(input.bucket_prefix)
	contains(input.bucket_prefix, "bucket")
}

allow[msg] {
	not has_bucket_name
	msg := "this bucket is okay folks"
}
