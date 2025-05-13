# Advanced rules can do more than marking resources as compliant or
# noncompliant: we can also check for the presence of certain required
# resources.
#
# In this example, we verify that at least one cloudtrail is present that has
# `include_global_service_events` set to true.
package rules.snyk_008.tf

import data.snyk

metadata := data.rules.snyk_007.metadata

# Not all cloudtrails are relevant for this validation.  If a specific trail
# doesn't have this set, it is not necessarily noncompliant: it could be
# unrelated.  This is why we just grab the relevant ones here.
global_cloudtrails := [cloudtrail |
	cloudtrail := snyk.resources("aws_cloudtrail")[_]
	cloudtrail.include_global_service_events == true
]

# We cannot pass a `resource` to the deny (since we don't have one!).  But we
# can specify a `resource_type` as metadata, to indicate what sort of resource
# was missing.
deny contains info if {
	count(global_cloudtrails) == 0
	info := {
		"message": "At least one aws_cloudtrail must have include_global_service_events configured",
		"resource_type": "aws_cloudtrail",
	}
}

# We include the valid trails so they can be marked compliant.
resources contains info if {
	cloudtrail := global_cloudtrails[_]
	info := {"resource": cloudtrail}
}
