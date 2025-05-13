# As we saw in the previous file (<05-advanced-primary-resource.rego>),
# it can be quite annoying to correlate resources with one another.
#
# In order to make that easier, the policy engine provides the concept of
# _resource relationships.  You can read about the design in detail in
# <../docs/design/resource-relations.md>, this example will just cover the
# actual usage.
package rules.snyk_005b.tf

import data.snyk

buckets := snyk.resources("aws_s3_bucket")

# Note that we don't actually need this except to illustrate back_relates
# further below.  Exercise for the reader: replace `back_relates` by `relates`
# in `resources[info]` rule without affecting the result.
encryption_configs := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")

is_encrypted(bucket) if {
	_ = bucket.server_side_encryption_configuration[_].rule[_][_][_].sse_algorithm
}

is_encrypted(bucket) if {
	# `snyk.relates` can be used to query for a list of relating resources
	# based on a relationship name.  In this case, the relationship name is
	# the same as the resource type of the related resource, but that's not
	# always the case.
	#
	# Relationships are declared in separate files, so they can be shared by
	# rules.  In <relations.rego>, you can see how this relationship is defined
	# in Rego.
	encryption_configs := snyk.relates(bucket, "aws_s3_bucket.server_side_encryption_configuration")
	_ := encryption_configs[_]
}

deny contains info if {
	bucket = buckets[_]
	not is_encrypted(bucket)
	info := {
		"resource": bucket,
		"message": "Bucket does not specify encryption",
	}
}

resources contains info if {
	bucket := buckets[_]
	info := {"resource": bucket}
}

# In addition to `snyk.relates`, you can use `back_relates` to reverse any
# relationship.  This can be useful in certain rules, in places where you
# you already have the secondary resource defined, and want to retrieve the
# primary one.  Notes that this also returns a list, as relations are always
# many-to-many.
resources contains info if {
	ec := encryption_configs[_]
	bucket := snyk.back_relates("aws_s3_bucket.server_side_encryption_configuration", ec)[_]
	info := {
		"primary_resource": bucket,
		"resource": ec,
	}
}
