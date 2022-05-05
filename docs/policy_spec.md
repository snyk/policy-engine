# Policies specification

This document describes the contract and API for policies that run in the Unified Policy
Engine (UPE).

- [Policies specification](#policies-specification)
  - [Conventions in this document](#conventions-in-this-document)
    - [Policy vs. rule](#policy-vs-rule)
  - [Policy requirements](#policy-requirements)
    - [`deny[info]`](#denyinfo)
      - [`info` object properties](#info-object-properties)
  - [Optional rules](#optional-rules)
    - [`resource_type`](#resource_type)
    - [`input_type`](#input_type)
    - [`metadata`](#metadata)
      - [Supported fields](#supported-fields)
    - [`resources[info]`](#resourcesinfo)
      - [`info` object properties](#info-object-properties-1)
      - [Correlation IDs](#correlation-ids)
      - [Examples](#examples)
  - [Policy archetypes](#policy-archetypes)
    - [Single-resource policy](#single-resource-policy)
      - [Single-resource policy examples](#single-resource-policy-examples)
    - [Multi-resource policy](#multi-resource-policy)
      - [Multi-resource policy examples](#multi-resource-policy-examples)
    - [Missing-resource policy](#missing-resource-policy)
      - [Missing-resource policy examples](#missing-resource-policy-examples)
  - [The `snyk` API](#the-snyk-api)
    - [`snyk.resources(<resource type>)`](#snykresourcesresource-type)
      - [Example `snyk.resources` call and output](#example-snykresources-call-and-output)
  - [Types reference](#types-reference)
    - [State object](#state-object)
    - [Resource objects](#resource-objects)
      - [Obtaining resource objects](#obtaining-resource-objects)
    - [Attribute paths](#attribute-paths)

## Conventions in this document

### Policy vs. rule

This document uses the term "policy" to refer to a rego file that UPE queries in order
to evaluate some input. This is mainly done to disambiguate "rules" in the Open Policy
Agent terminology (which is used extensively throughout this document) from what Snyk
refers to as a rule elsewhere.

## Policy requirements

1. Policies must be in a sub-package of `rules`. Examples of valid package declarations:
    - `package rules.my_rule`
    - `package rules.snyk_007.tf`

2. Policies must contain a `deny[info]` "judgement rule", where `info` is assigned to
   an object (described in the next section). It's assumed that the `deny[info]` rule
   is written to match failing resources or conditions.
    * The required fields in the `info` object will depend on which
      [archetype](#policy-archetypes) the policy conforms to.

### `deny[info]`

#### `info` object properties

This table lists each supported property of the `info` object along with which policy
archetypes would use it.

| Field           |  Type  | Description                                                    | Single-resource | Multi-resource | Missing-resource |
| :-------------- | :----: | :------------------------------------------------------------- | :-------------: | :------------: | :--------------: |
| `resource`      | object | A [resource object](#resource-objects)                         |                 |       ✓        |                  |
| `message`       | string | A message that is specific to this result                      |        ✓        |       ✓        |        ✓         |
| `resource_type` | string | The type of resource that is missing                           |                 |                |        ✓         |
| `remediation`   | string | Remediation steps for the issue identified by this `deny` rule |        ✓        |       ✓        |        ✓         |
| `severity`      | string | The severity of the issue identified by this `deny` rule       |        ✓        |       ✓        |        ✓         |
| `attributes`    | array  | An array of [attribute paths](#attribute-paths)                |        ✓        |       ✓        |                  |
| `correlation`   | string | A manually-specified [correlation ID](#correlation-ids)        |                 |       ✓        |        ✓         |

## Optional rules

### `resource_type`

When `resource_type` is set to `MULTIPLE`, the `input` document will be set to the
[State object](#state-object) that is currently being processed by the engine. 

When `resource_type` is set to a specific resource type (e.g. `aws_s3_bucket`), UPE will
set the `input` document to the `attributes` map of a single resource state. 

When `resource_type` is unspecified, it defaults to `MULTIPLE`.

Examples:

```open-policy-agent
resource_type := "MULTIPLE"
```

```open-policy-agent
resource_type := "aws_s3_bucket"
```

### `input_type`

The `input_type` rule defines defines which input types a rule applies to. The current
list of supported input types are:

* `cfn` (CloudFormation template)
* `tf` (Terraform HCL)
* `tf_plan` (Terraform plan file)
* `tf_runtime` (Runtime state from Snyk Cloud)
* `k8s` (Kubernetes manifest)
* `arm` (Azure ARM template)

When `input_type` is unspecified, it defaults to `tf`.

**NOTE** The current behavior is that UPE will treat `tf`, `tf_plan`, and `tf_runtime`
as equal, i.e. policies that specify any of these input types will run for all inputs.
This could be subject to change in future versions of UPE.

### `metadata`

The `metadata` rule defines static metadata associated with the policy. See the
[`deny` rule section](#denyinfo) for result-specific metadata.

#### Supported fields

**NOTE** that `unified-policy-engine` by itself does not enforce any restrictions on
metadata fields apart from their data type. The descriptions below are mostly intended
to clarify the intent of each field.

| Field           |  Type  | Description                                                                                                      |
| :-------------- | :----: | :--------------------------------------------------------------------------------------------------------------- |
| `id`            | string | A short identifier for the policy. The same ID can be shared across different implementations of the same policy |
| `title`         | string | A short description of the policy                                                                                |
| `description`   | string | A longer description of the policy                                                                               |
| `remediation`   | string | Remediation steps for the issue identified by the policy                                                         |
| `references`    | string | Links to additional information about the issue identified by the policy                                         |
| `category`      | string | The category of the policy                                                                                       |
| `tags`          | array  | An array of tag strings associated with this policy                                                              |
| `service_group` | string | The service group of the primary resource associated with this policy (e.g. "EBS", "EC2")                        |
| `controls`      | object | A map of rule set ID to an array of control tags                                                                 |
| `rule_sets`     | array  | An array of rule set IDs                                                                                         |
| `severity`      | string | The severity of the issue identified by this policy                                                              |

Example with all fields populated:

```open-policy-agent
metadata := {
    "id": "COMPANY_0001",
    "title": "S3 bucket name contains the word 'bucket'",
    "description": "It is unnecessary for resource names to contain their type.",
    "remediation": "1. Go to the AWS console\n2. Navigate to the S3 service page\n3. ...",
    "references": "[Some blog post](https://example.com/bucket-naming-conventions)",
    "category": "Best Practices",
    "tags": [
        "Naming Conventions",
        "Pet Peeves"
    ],
    "service_group": "S3",
    "controls": {
        "CIS-AWS_v1.3.0": [
            "CIS-AWS_v1.3.0_5.1",
            "CIS-AWS_v1.3.0_5.2"
        ],
        "CIS-AWS_v1.4.0": [
            "CIS-AWS_v1.4.0_6.7"
        ]
    },
    "rule_sets": [
        "CIS-AWS_v1.3.0",
        "CIS-AWS_v1.4.0",
        "2931f772-5599-4aed-9e2d-b5ed9a2d7aa3"
    ],
    "severity": "Critical"
}
```

### `resources[info]`

The `resources` rule is used to define which resources which contributed to a result.
For the multi-resource and missing-resource policy archetypes, UPE uses `resources`
results to mark resources as passing. For this reason, resources should be written to
return results regardless of whether the policy as a whole would pass or fail a specific
resource.

The `info` return value is set to an object that describes a single resource and
optionally:
* Its attributes that contributed to the policy result
* Its relation to the primary resource associated with the policy result

#### `info` object properties

| Field              |  Type  | Description                                                                                  |
| :----------------- | :----: | :------------------------------------------------------------------------------------------- |
| `resource`         | object | A [resource object](#resource-objects) to associate with a policy result                      |
| `primary_resource` | object | The primary [resource object](#resource-objects) associated with a policy result              |
| `attributes`       | array  | An array of [attribute paths](#attribute-paths) from the resource in the `resource` property |
| `correlation`      | string | A manually-specified [correlation ID](#correlation-ids)                                      |

#### Correlation IDs

Internally, each `deny[info]` result has an identifier associated with it. That
identifier can be manually specified by setting the `correlation` property in the info
object. Otherwise, it's calculated from the resource's type, identifier, and namespace.


Similarly, `resources[info]` results have an associated identifier that can be set
manually via a `correlation` property. Otherwise it will be calculated from the resource
in the `primary_resource` attribute (if specified) or the `resource` attribute.

UPE will relate `resources` results with `deny` results that have the same identifier.

#### Examples

* [examples/05-advanced-primary-resource.rego](../examples/05-advanced-primary-resource.rego)
  demonstrates using the `primary_resource` attribute to specify that a
  `resources[info]` result is related to a specific deny result. Note that the deny
  result's correlation ID is calculated by default in this usage.
* [examples/06-advanced-correlation.rego](../examples/06-advanced-correlation.rego)
  demonstrates using a manually-specified correlation ID to relate a `resources[info]`
  result to a `deny[info]` result.
* [examples/04-advanced-resources.rego](../examples/04-advanced-resources.rego)
  demonstrates using the `resource` property on the info `object` when the `resources`
  rule is returning the primary resource. In this example, the `resources` rule only
  serves to enable UPE to identify passing resources.
## Policy archetypes

### Single-resource policy

Single-resource policies are distinguished by setting the
[`resource_type` rule](#resource_type) to a single resource type. UPE evaluates
single-resource policies by querying the `deny[info]` rule with the `input` document
set to a single [resource object](#resource-object)

By definition, single resource policies only interact with a single resource. Therefore,
the `snyk.resources()` function is not useable in single-resource policies.

#### Single-resource policy examples

* [examples/01-simple.rego](../examples/01-simple.rego)
* [examples/02-simple-attributes.rego](../examples/02-simple-attributes.rego)

### Multi-resource policy

Multi-resource policies are distinguished by setting the
[`resource_type` rule](#resource_type) to `"MULTIPLE"`. UPE evaluates multi-resource
policies by querying the `deny[info]` rule with the `input` document set to the entire
`State` object being evaluated. Although multi-resource policies can access individual
resources via the `input` document, they should use the `snyk.resources()` function to
retrieve resources from the input by resource type.

#### Multi-resource policy examples

* [examples/03-advanced.rego](../examples/03-advanced.rego)
* [examples/04-advanced-resources.rego](../examples/04-advanced-resources.rego)
* [examples/05-advanced-primary-resource.rego](../examples/05-advanced-primary-resource.rego)
* [examples/06-advanced-correlation.rego](../examples/06-advanced-correlation.rego)

### Missing-resource policy

Missing-resource policies are an extension of the Multi-resource policy archetype that
has at least one `deny[info]` rule that sets the `resource_type` field on the `info`
object instead of `resource`, e.g.:

```open-policy-agent
# We cannot pass a `resource` to the deny (since we don't have one!).  But we
# can specify a `resource_type` as metadata, to indicate what sort of resource
# was missing.
deny[info] {
	count(global_cloudtrails) == 0
	info := {
		"message": "At least one aws_cloudtrail must have include_global_service_events configured",
		"resource_type": "aws_cloudtrail",
	}
}
```

#### Missing-resource policy examples

* [examples/08-missing.rego](../examples/08-missing.rego)

## The `snyk` API

UPE provides a set of functions under the `snyk` namespace that can be used by policies.
To use them, policies should `import data.snyk`, like is shown in the
[multi-resource policy examples](#multi-resource-policy-examples).

### `snyk.resources(<resource type>)`

The `snyk.resources` function takes in a single resource type string and returns an
array of [resource objects](#resource-objects) of that type from the current `State`
being evaluated.

Internally, UPE tracks calls to `snyk.resources` to produce the `resource_types` array
in the results output.

#### Example `snyk.resources` call and output

This example demonstrates the `snyk.resources` input and output in a REPL session:

```sh
$ ./unified-policy-engine repl examples/main.tf
> import data.snyk
> snyk.resources("aws_cloudtrail")
[
  {
    "_filepath": "examples/main.tf",
    "_meta": {},
    "_namespace": "examples/main.tf",
    "_provider": "aws",
    "_tags": {},
    "_type": "aws_cloudtrail",
    "id": "aws_cloudtrail.cloudtrail1",
    "include_global_service_events": true,
    "name": "cloudtrail1",
    "s3_bucket_name": "aws_s3_bucket.bucket1",
    "s3_key_prefix": "prefix"
  }
]
> 
```

## Types reference

This section describes some of the types referred to in the other sections of this
document.

### State object

"State object" refers to the input to UPE's policy evaluation. The state object is
defined in the [`swagger.yaml` file](../swagger.yaml), which is then used to generate
[a model struct](../pkg/models/model_state.go).

In general, policies should not interact with the state object directly and should
instead use [the `snyk` API](#the-snyk-api).

### Resource objects

Resource objects are a map of resource property name to property value. Policy authors
can expect that resource objects are close or identical to how the resources are defined
in IaC code with some additional properties added by UPE.

For example, the following Terraform resource:

```hcl
resource "aws_cloudtrail" "cloudtrail1" {
  name                          = "cloudtrail1"
  s3_bucket_name                = aws_s3_bucket.bucket1.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
}
```

would become the following resource object:

```json
{
  "_filepath": "examples/main.tf",
  "_meta": {},
  "_namespace": "examples/main.tf",
  "_provider": "aws",
  "_tags": {},
  "_type": "aws_cloudtrail",
  "id": "aws_cloudtrail.cloudtrail1",
  "include_global_service_events": true,
  "name": "cloudtrail1",
  "s3_bucket_name": "aws_s3_bucket.bucket1",
  "s3_key_prefix": "prefix"
}
```

In general, policies will not need to interact with the added properties.

#### Obtaining resource objects

In [single-resource policies](#single-resource-policy), the `input` document will be
set to a single resource object of the type specified in the
[`resource_type` rule](#resource_type).

In [multi-resource policies](#multi-resource-policy) and
[missing-resource policies](#missing-resource-policy), resource objects should be
obtained via the [`snyk.resources`](#snykresourcesresource-type) function.

### Attribute paths

Attribute paths are arrays of strings and integers that describe the location of a
particular attribute within a resource. The `attributes` properties that you see in
the [`deny`](#denyinfo) and [`resources`](#resourcesinfo) definitions are arrays of
attribute paths, e.g:

```open-policy-agent
[
    [
        "spec",
        0,
        "container",
        1,
        "security_context",
        0,
        "privileged"
    ],
    [
        "spec",
        0,
        "container",
        3,
        "security_context",
        0,
        "privileged"
    ]
]
```

The following examples demonstrate how `attributes` can be used in practice:

* [`examples/02-simple-attributes.rego`](../examples/02-simple-attributes.rego)
* [`examples/07-advanced-attributes.rego`](../examples/07-advanced-attributes.rego)
