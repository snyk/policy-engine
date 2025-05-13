# This example showcases the use of the `context` field in the `info` object to
# provide user-defined policy output.

# The `context` field is a dictionary of values that can be used to provide
# additional information about the policy.

# Here the context is used in single-resource policy, but it can be used
# in multi-resource policies as well.
package rules.snyk_012.tf

resource_type := "aws_s3_bucket"

has_bucket_name if {
	is_string(input.bucket)
	contains(input.bucket, "bucket")
}

deny contains info if {
	has_bucket_name
	info := {"message": "Bucket names should not contain the word bucket, it's implied"}
}

# The `context` field is provided via the `info` object returned by the
# (optional) `resources` rule.
resources contains info if {
	info := {"context": {"bucket_name": input.bucket}}
}
