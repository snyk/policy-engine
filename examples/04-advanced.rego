# This is a more complex rule, in which we look both at S3 buckets and an
# auxiliary IaC resource type for encrypting them.
#
# We want to check both resources, and report both of them if compliant or
# noncompliant.
#
# We can do this by associating the auxiliary resource types using a
# `correlation`.  You can see how this is used in `location` below.
package rules.snyk_004.tf

buckets := snyk.resources("aws_s3_bucket")

encryption_configs := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")

# The `bucket` argument in encryption_configs can refer to a bucket ID, or the
# name of the bucket.  This rule adds a map so we can get the canonical version.
# This could be part of an S3 library and is really an implementation detail.
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

deny[info] {
	bucket = buckets[_]
	not is_encrypted(bucket)
	info := {
		"resource": bucket,
		"message": "Bucket does not specify encryption",
	}
}

# Like in the previous example, we include resource information about the
# buckets so we can get full compliance results.
location[info] {
	bucket := buckets[_]
	info := {"resource": bucket}
}

# We want to relate the encryption configs that we examined to their
# corresponding buckets, so the policy engine knows these are not separate
# issues.
#
# The policy engine tracks different issues using correlations.
#
# `correlation` is an opaque identifier that defaults to `.resource.id`.  This
# is why did not have to set `correlation` before, it was simply using the ID
# of the S3 bucket.
#
# But in this case, we do want to explicitly set it to the bucket ID, to
# associate the encryption config with it, and indicate that this is not a
# separate issue.
location[info] {
	ec = encryption_configs[_]
	correlation = ec.bucket
	info := {
		"correlation": to_bucket_id[ec.bucket],
		"resource": ec,
	}
}
