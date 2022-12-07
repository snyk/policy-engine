# Relationships must always be defined in the `relations` package so the policy
# engine knows where to find them.
package relations

import data.snyk

# Relationships can be added by extending the `relations` set with an object.
relations[info] {
	buckets := snyk.resources("aws_s3_bucket")
	encryption_configs := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")
	info := {
		# The name of the relationship is required.
		"name": "aws_s3_bucket_server_side_encryption_configuration",
		# Relationships can be constructed multiple ways, but `keys` is
		# recommended in almost all cases.
		#
		# `keys` requires `left` and `right` fields, both of which must contain
		# `[resource, key]` pairs.  The relationships direction is left to
		# right, meaning that the left resources are the first argument of
		# `snyk.relates`, and that the right resources are the second argument
		# of `snyk.back_relates`.
		#
		# Relationships are constructed whenever matching key pairs are found on
		# the left and right.
		"keys": {
			# We use the `bucket` fields from encryption configurations.
			"right": [[ec, ec.bucket] | ec := encryption_configs[_]],
			# This is an example of using multiple fields.
			"left": [[b, attr] |
				b := buckets[_]
				attr := b[{"id", "bucket"}[_]]
			],
		},
	}
}
