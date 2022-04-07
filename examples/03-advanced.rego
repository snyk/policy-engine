# This rule is identical to the previous example, but extends it with
# optional location metadata.
#
# By adding this metadata, the policy engine can derive which resources were
# examined.  This way, we can infer which resources were compliant for this
# rule, in addition to the noncompliant ones.
package rules.snyk_003.tf

buckets = snyk.resources("aws_s3_bucket")

has_bucket_name(bucket) {
	contains(bucket.bucket, "bucket")
}

has_bucket_name(bucket) {
	contains(bucket.bucket_prefix, "bucket")
}

deny[info] {
	bucket := buckets[_]
	has_bucket_name(bucket)
	info := {
		"message": "Buckets should not contain bucket, its implied duh",
		"resource": bucket,
	}
}

# If present, `location` must be a set of info objects.
location[info] {
	bucket := buckets[_]
	info := {"resource": bucket}
}
