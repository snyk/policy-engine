package rules.snyk_004.tf

resource_type := "MULTIPLE"

encryption_paths(bucket) = paths {
	paths := [path |
		algorithm = bucket.server_side_encryption_configuration[config_index].rule[rule_index][attr_name][attr_index].sse_algorithm
		path := ["server_side_encryption_configuration", config_index, "rule", rule_index, attr_name, attr_index, "sse_algorithm"]
	]
}

buckets := snyk.resources("aws_s3_bucket")

encryption_configs := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")

# The `bucket` argument in encryption_configs can refer to a bucket ID, or the
# name of the bucket.  This rule adds a map so we can get the canonical version.
# This could be part of an S3 library.
to_bucket_id := ret {
	ret := object.union({b.id: b.id | b := buckets[_]}, {b.bucket: b.id | b := buckets[_]})
}

is_encrypted(bucket) {
	count(encryption_paths(bucket)) > 0
}

is_encrypted(bucket) {
	ec := encryption_configs[_]
	to_bucket_id[ec.bucket] == bucket.id
}

deny[info] {
	bucket = buckets[_]
	not is_encrypted(bucket)
	info := {
		"correlation": bucket.id,
		"message": "Bucket does not specify encryption",
	}
}

location[info] {
	bucket := buckets[_]
	info := {
		"correlation": bucket.id,
		"resource": bucket,
		"attributes": encryption_paths(bucket),
	}
}

location[info] {
	ec = encryption_configs[_]
	correlation = ec.bucket
	info := {
		"correlation": to_bucket_id[ec.bucket],
		"resource": ec,
	}
}
