# Sometimes we want to write a policy that says:
# "This primary resource is vulnerable, because of this secondary resource"
# This example demonstrates that concept by using the primary_resource attribute
# in its deny rule.
package rules.snyk_009.tf

import data.snyk

buckets := snyk.resources("aws_s3_bucket")
encryption_configs := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")

belongs_to_bucket(config, bucket) {
  config.bucket == bucket.bucket
}

belongs_to_bucket(config, bucket) {
  config.bucket == bucket.id
}

# Here we're building a map of bucket -> all of its encryption configuration
# resources. Note that Rego lets you use an object as a key in another object.
configs_by_bucket := {bucket: configs |
  bucket := buckets[_]
  configs := [config | 
    config := encryption_configs[_]
    belongs_to_bucket(config, bucket)
  ]
}

# This function returns the paths to any SSE algorithm in this encryptiong
# configuration that's not KMS.
bad_attrs(config) = ret {
  ret := [["rule", j, "apply_server_side_encryption_by_default", k] |
    config.rule[j].apply_server_side_encryption_by_default[k].sse_algorithm != "aws:kms"
  ]
}

# Here we're demonstrating a deny on a secondary resource. You can think of this
# rule as saying:
# "This bucket is invalid because of this config, and these attributes of the 
# config explain why."
deny[info] {
  config := configs_by_bucket[bucket][_]
  bad := bad_attrs(config)
  count(bad) > 0
  info := {
    "primary_resource": bucket,
    "resource": config,
    # These are attributes from the encryption configuration (i.e. the secondary
    # resource), and not the bucket.
    "attributes": bad
  }
}

# Our resources rule is written to return _all_ resources and attributes that
# this policy inspected. The Policy Engine uses these results to know which
# resources were note failed by this policy, as well as which attributes
# factored into that decision.
resources[info] {
  config := configs_by_bucket[bucket][_]
  info := {
    "primary_resource": bucket,
    "resource": config,
    "attributes": [["rule", j, "apply_server_side_encryption_by_default", k] |
      _ = config.rule[j].apply_server_side_encryption_by_default[k].sse_algorithm
    ]
  }
}
