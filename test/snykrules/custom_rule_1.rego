package rules

has_bucket_name(bucket) if {
	is_string(bucket.bucket)
	contains(bucket.bucket, "bucket")
}

has_bucket_name(bucket) if {
	is_string(bucket.bucket_prefix)
	contains(bucket.bucket_prefix, "bucket")
}

deny contains msg if {
	bucket := input.resource.aws_s3_bucket[name]

	has_bucket_name(bucket)

	msg := {
		"publicId": "CUSTOM-RULE-1",
		"title": "Has bucket in bucket name",
		"severity": "medium",
		"msg": sprintf("input.resource.aws_s3_bucket[%v]", [name]),
		"issue": "",
		"impact": "",
		"remediation": "",
		"references": [],
	}
}
