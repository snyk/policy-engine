# The package name must match a specific format, so the policy engine can
# discover rules.  We use:
#
#     rules.RULE_ID.INPUT_TYPE
#
package rules.snyk_001.tf

# Rules can set metadata in the `metadata` assignment.  This is typically
# imported from a JSON file, like here:
metadata := data.rules.snyk_001.metadata

# Simple rules must assign `resource_type`.  All resources of this type will
# be subject to this rule.
resource_type := "aws_s3_bucket"

# A simple rule can refer to the resource directly as `input`:
has_bucket_name if {
	is_string(input.bucket)
	contains(input.bucket, "bucket")
}

has_bucket_name if {
	is_string(input.bucket_prefix)
	contains(input.bucket_prefix, "bucket")
}

# Simple rules must contain a `deny` set.  This set must consist of info
# objects, which are documented in the reference.
#
# In simple rules, these must at least include a `message`.
deny contains info if {
	has_bucket_name
	info := {"message": "Bucket names should not contain the word bucket, it's implied"}
}
