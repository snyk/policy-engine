# This is a more complex rule, in which we look both at S3 buckets and an
# auxiliary IaC resource type for encrypting them.
#
# We want to check both resources, and report both of them if compliant or
# noncompliant.
#
# We can do this by associating the auxiliary resource types using a
# `primary_resource`.  You can see how this is used in `resources` below.
package rules.snyk_005.tf

import data.snyk

buckets := snyk.resources("aws_s3_bucket")

encryption_configs := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")

# The `bucket` argument in encryption_configs can refer to a bucket ID, or the
# name of the bucket.  This rule adds a map so we can get the canonical version.
# This could be part of an S3 library and is really an implementation detail.
to_bucket_id := ret if {
	ret := object.union({b.id: b.id | b := buckets[_]}, {b.bucket: b.id | b := buckets[_]})
}

# This allows us to look up a bucket by its ID.
bucket_by_id[id] := bucket if {
	bucket := buckets[_]
	id := bucket.id
}

is_encrypted(bucket) if {
	_ = bucket.server_side_encryption_configuration[_].rule[_][_][_].sse_algorithm
}

is_encrypted(bucket) if {
	ec := encryption_configs[_]
	to_bucket_id[ec.bucket] == bucket.id
}

deny contains info if {
	bucket = buckets[_]
	not is_encrypted(bucket)
	info := {
		"resource": bucket,
		"message": "Bucket does not specify encryption",
	}
}

# Like in the previous example, we include resource information about the
# buckets so we can get full compliance results.
resources contains info if {
	bucket := buckets[_]
	info := {"resource": bucket}
}

# We want to relate the encryption configs that we examined to their
# corresponding buckets, so the policy engine knows these are not separate
# issues.
#
# We can do this by indicating that this resource belongs to a
# different `primary_resource`.
resources contains info if {
	ec = encryption_configs[_]
	info := {
		"primary_resource": bucket_by_id[to_bucket_id[ec.bucket]],
		"resource": ec,
	}
}
