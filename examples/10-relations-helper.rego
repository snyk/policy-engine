# This rule uses a relationship that was defined using the
# snyk.relation_from_fields helper function. See <relations.rego> for the
# definition of the "aws_s3_bucket.ownership_controls" relation that we use
# below.
package rules.snyk_010.tf

import data.snyk

buckets := snyk.resources("aws_s3_bucket")

# This deny rule captures buckets that have no ownership controls defined.
deny contains info if {
	bucket := buckets[_]
	controls := snyk.relates(bucket, "aws_s3_bucket.ownership_controls")
	count(controls) < 1
	info := {"resource": bucket}
}

# This deny rule captures buckets that have misconfigured ownership controls
deny contains info if {
	bucket := buckets[_]
	controls := snyk.relates(bucket, "aws_s3_bucket.ownership_controls")
	control := controls[_]
	control.rule[_].object_ownership != "BucketOwnerEnforced"
	info := {
		"primary_resource": bucket,
		"resource": control,
	}
}

resources contains info if {
	bucket := buckets[_]
	info := {"resource": bucket}
}

resources contains info if {
	bucket := buckets[_]
	control := snyk.relates(bucket, "aws_s3_bucket.ownership_controls")[_]
	info := {
		"primary_resource": bucket,
		"resource": control,
	}
}
