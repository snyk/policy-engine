# Relationships must always be defined in the `relations` package so the policy
# engine knows where to find them.
package relations

import data.snyk

# Relationships can be added by extending the `relations` set with an object.
relations contains info if {
	buckets := snyk.resources("aws_s3_bucket")
	encryption_configs := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")
	info := {
		# The name of the relationship is required.
		"name": "aws_s3_bucket.server_side_encryption_configuration",
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

# The snyk library provides a helper function to define the most common type of
# relation where we're simly checking that a field on one resource is equal to
# a field on another resource.
relations contains info if {
	info := snyk.relation_from_fields(
		# Just like above, this is the name of the relation:
		"aws_s3_bucket.ownership_controls",
		# This is the "left" resource. We can provide multiple field names here like
		# in the above example:
		{"aws_s3_bucket": ["id", "bucket"]},
		# Finally, we specify the "right" resource:
		{"aws_s3_bucket_ownership_controls": ["bucket"]},
	)
}

relations contains info if {
	pods := snyk.resources("kubernetes_pod")
	services := snyk.resources("kubernetes_service_v1")
	info := {
		"name": "kubernetes_pod.service",
		"keys": {
			"left": [[p, label] |
				p := pods[_]
				v := p.metadata[_].labels[k]
				label := concat("=", [k, v])
			],
			"right": [[s, label] |
				s := services[_]
				v := s.spec[_].selector[k]
				label := concat("=", [k, v])
			],
		},
	}
}

relations contains info if {
	services := snyk.resources("kubernetes_service_v1")
	ingresses := snyk.resources("kubernetes_ingress")
	info := {
		"name": "kubernetes_service_v1.ingress",
		"keys": {
			"left": [[s, name] |
				s := services[_]
				name := s.metadata[_].name
			],
			"right": [[i, backend] |
				i := ingresses[_]
				backend := i.spec[_].backend[_].service_name
			],
		},
	}
}
