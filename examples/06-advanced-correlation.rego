# In certain situations it can be complex or annoying to obtain the
# `primary_resource`.  In those cases you can manually correlate `resources`
# and `deny`s using `correlation`.
#
# The code of this rule is mostly the same as the last one.
package rules.snyk_006.tf

import data.snyk

buckets := snyk.resources("aws_s3_bucket")

encryption_configs := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")

to_bucket_id := ret {
	ret := object.union({b.id: b.id | b := buckets[_]}, {b.bucket: b.id | b := buckets[_]})
}

is_encrypted(bucket) {
	_ = bucket.server_side_encryption_configuration[_].rule[_][_][_].sse_algorithm
}

is_encrypted(bucket) {
	ec := encryption_configs[_]
	to_bucket_id[ec.bucket] == bucket.id
}

# In `deny`, we set `correlation` to a string value.  This can be any string,
# as long as related resources are able to produce the same string for the same
# issue.
deny[info] {
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
resources[info] {
	bucket := buckets[_]
	info := {
		"correlation": bucket.id,
		"primary_resource": bucket,
	}
}

# Here, we produce a consistent `correlation` so the engine can link the
# encryption configurations with the corresponding buckets.
resources[info] {
	ec = encryption_configs[_]
	info := {
		"correlation": to_bucket_id[ec.bucket],
		"resource": ec,
	}
}
