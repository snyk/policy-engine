# Policy result identity

- [Policy result identity](#policy-result-identity)
  - [Background](#background)
  - [Suggested change](#suggested-change)
  - [The `result_tag` attribute](#the-result_tag-attribute)
  - [Potential risk](#potential-risk)

We have identified a need for some policies to produce multiple, distinct
results for a single resource. This document is a proposal for an enhancement to
an existing mechanism in Policy Engine that achieves this.

## Background

Policy Engine currently combines `deny` and `resources` results together based
on a ["correlation ID"](https://github.com/snyk/policy-engine/blob/5e55e9bc644c35aebaf82defd84abf7cb7f97f92/docs/policy_spec.md#correlation-ids).
The default correlation ID is based on the primary resource's namespace, type,
and ID. This produces a single result per resource, per policy.

Policy authors are able to supply their own correlation ID in order to change
the way that results are grouped. This mechanism is very flexible and enables
policies to produce multiple results for a single resource or a single result
for multiple resources.

The drawback to this mechanism is that it's not communicated to or understood by
our downstream consumers, which are built for a handful of known use-cases:

- A single primary resource
- A missing resource
- A failing attribute within a resource

## Suggested change

Because a single result for multiple resources isn't a current use-case, we
propose to:

- Remove `correlation` from our Rego API
  - Policy Engine will still use this mechanism internally, but it shouldn't be
    exposed to policy authors.
- Add a `result_tag` attribute which can be used to uniquely identify a result
  when multiple results are produced for a single resource.
- Include the `result_tag` attribute in our output format

This accomplishes three goals:

- Removes the ability to produce a single result for multiple resources, because
  it's not a core use-case, and it's not a case that our consumers are built
  for.
- Retains the ability to produce multiple results for a single resource, which 
  is required for the "failing attribute within a resource" use-case.
- Communicates a way to distinguish those policy results to downstream
  consumers.

## The `result_tag` attribute

`result_tag` is an additional attribute in the `deny` and `resources` return
objects:

```open-policy-agent
deny[info] {
	deployment := deployments[_]
  container := deployment.containers[idx]
  is_invalid(container)

	info := {
		"resource": deployment,
		"result_tag": sprintf("container[%s]", container.name),
		"attributes": [["containers", idx]],
	}
}

resources[info] {
  deployment := deployments[_]
  container := deployment.containers[idx]

  info := {
    "resource": deployment
    "result_tag": sprintf("container[%s]", container.name),
    "attributes": [["containers", idx]],
  }
}
```

It is intended to be a human-readable identifier that Policy Engine will use to
distinguish results that are otherwise for the same policy and resource.
Internally, it is a new addition to the correlation ID:

```
correlation_id = resource_namespace + resource_type + resource_id + result_tag
```

In the above example, one result is produced per container in the deployment.
Furthermore, the identity of the result is not dependent on the order of the
containers `array`.

`result_tag` will be included in the output alongside the resource ID,
namespace, and type:

```javascript
{
  "passed": false,
  "ignored": false,
  "resource_id": "some-s3-bucket",
  "resource_namespace": "us-east-1",
  "resource_type": "aws_s3_bucket",
  "result_tag": "sid[Allow Public access]",
  "severity": "high",
  "resources": [ /* ... */ ]
}
```

## Potential risk

Policies that use this feature will require some additional scrutiny during
review, because changing the format of a `result_tag` will disrupt downstream
consumers. Issues, Ignores, and their consumers all depend on the stability of
policy result identity.

For that reason, `result_tag` should be considered unchangeable once it's
defined, unless there is a major bug with the `result_tag` itself.
