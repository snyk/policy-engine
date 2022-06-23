# Enhancement to the single-resource policy archetype

[Single-resource policies](../policy_spec.md#single-resource-policy) have the advantage
over multi-resource policies that they require less boilerplate code. But, they're only
suitable for very a simple use-case, i.e. to enforce some properties on every resource
of a particular type. From the policy author's perspective, the main functional
differences between single-resource policies and multi-resource policies are:

* The `input` document for single-resource policies is a single resource of the type
  specified in the `resource_type` rule.
* The policy cannot access any other resources via `snyk.resources()` or `snyk.query()`

This document is a proposal to eliminate that second bullet point in order to expand the
uses for single-resource policies.

## Rationale

There is no technical limitation that forces us to restrict access to other resources in
single-resource policies. If we enable that access via the `snyk` Rego API functions,
many multi-resource policies could be rewritten as simpler, single-resource policies.

## Example

This example is a modification of
[05-advanced-primary-resource.rego](../../examples/05-advanced-primary-resource.rego)
that demonstrates how some policy engine features are simpler to use when there is an
implicit primary resource:

```open-policy-agent
package rules.snyk_005.tf

import data.snyk

resource_type := "aws_s3_bucket"

matches_bucket_or_id(val) {
    val == input.id
}

matches_bucket_or_id(val) {
    val == input.bucket
}

# We only need to enumerate encryption configurations for the current input.
encryption_configs := [ec |
    ec := snyk.resources("aws_s3_bucket_server_side_encryption_configuration")[_]
    matches_bucket_or_id(ec.bucket)
]

# This rule is reused in the resources rule below
inline_config_paths := [
    ["server_side_encryption_configuration", i, "rule", j, k, l, "sse_algorithm"] |
    _ = input.server_side_encryption_configuration[i].rule[j][k][l].sse_algorithm
]

is_encrypted {
    count(inline_config_paths) > 0
}

is_encrypted {
    count(encryption_configs) > 0
}

# There are no mandatory info fields for single-resource policies, because the resource
# can be inferred. This style of rule isn't currently supported, but it would be trivial
# to implement.
deny {
    not is_encrypted
}

# Just like in the deny rule, the resource for this rule can be inferred.
resources[info] {
    count(inline_config_paths) > 0
    info := {
        "attributes": inline_config_paths
    }
}

# Notice that we don't need to specify the primary resource here.
resources[info] {
    ec := encryption_configs[_]
    info := {
        "resource": ec,
        "attributes": [["bucket"]]
    }
}
```

## When would multi-resource policies still be necessary?

This enhancement does not completely replace the need for multi-resource policies for
these use-cases:

* [Missing-resource policies](../policy_spec.md#missing-resource-policy)
* Policies that don't apply to every resource of a given type
  * An example of this is a policy that enforces rotation on AWS KMS keys. Rotation is
    only supported for symmetric keys, so this policy should not produce any results for
    asymmetric keys. We can use a multi-resource policy to exclude asymmetric keys from
    the output of the `deny` and `resources` rules.
* Policies that apply to multiple types of primary resources
  * An example of this is a rule that enforces tags on all taggable resource types.
