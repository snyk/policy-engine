# In certain situations it can be complex or annoying to obtain the
# `primary_resource`.  In those cases you can manually correlate `resources`
# and `deny`s using `correlation`.
#
# The code of this rule is mostly the same as the last one.
package rules.snyk_006.tf

import data.snyk

buckets := snyk.resources("aws_s3_bucket")

is_encrypted(bucket) if {
	_ = bucket.server_side_encryption_configuration[_].rule[_][_][_].sse_algorithm
}

is_encrypted(bucket) if {
	encryption_configs := snyk.relates(bucket, "aws_s3_bucket.server_side_encryption_configuration")
	_ := encryption_configs[_]
}

# In `deny`, we set `correlation` to a string value.  This can be any string,
# as long as related resources are able to produce the same string for the same
# issue.
deny contains info if {
	bucket = buckets[_]
	not is_encrypted(bucket)
	info := {
		"correlation": bucket.id,
		"resource": bucket,
		"message": "Bucket does not specify encryption",
	}
}

# We must produce the same `correlation` here.  Rather than just setting
# `resource`, we may set `primary_resource` so the engine can associate the
# issue with the right primary resource.
resources contains info if {
	bucket := buckets[_]
	info := {
		"correlation": bucket.id,
		"primary_resource": bucket,
	}
}

# Here, we produce a consistent `correlation` so the engine can link the
# encryption configurations with the corresponding buckets.
resources contains info if {
	bucket := buckets[_]
	encryption_configs := snyk.relates(bucket, "aws_s3_bucket.server_side_encryption_configuration")
	ec = encryption_configs[_]
	info := {
		"correlation": bucket.id,
		"resource": ec,
	}
}
