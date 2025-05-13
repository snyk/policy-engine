# This example extends the simple rule with attributes.
#
# Attributes allow us to point to specific parts of the resource.  They are
# represented using an array of strings or integers; consistent with usage
# in `opa.walk()` and other OPA functions.
#
# Considering the following JSON attributes:
#
#     "ingress": [
#       {
#         "from_port": 22,
#         "to_port": 22
#       }
#     ]
#
# Then the `from_port` path would be `["ingress", 0, "from_port"]`.
package rules.snyk_002.tf

resource_type := "aws_s3_bucket"

# We now populate the attributes so we can use them in `deny`.
bucket_name_paths contains ["bucket"] if {
	is_string(input.bucket)
	contains(input.bucket, "bucket")
}

bucket_name_paths contains ["bucket_prefix"] if {
	is_string(input.bucket_prefix)
	contains(input.bucket_prefix, "bucket")
}

deny contains info if {
	count(bucket_name_paths) > 0
	info := {
		"message": "Bucket names should not contain the word bucket, it's implied",
		"attributes": bucket_name_paths,
	}
}
