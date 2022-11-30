# Resource Relations

When writing a policy, it is common to correlate resources to one another.

This is typically done either by building objects:

```rego
topic_policies_by_topic := ret {
	ret := {policy.arn: policy | policy := policies[_]}
}
```

Or by writing functions that match on attributes:

```rego
matches_bucket_or_id(value, bucket) {
	value == bucket.id
}

matches_bucket_or_id(value, bucket) {
	value == bucket.arn
}
```

Writing these joins is a burden on the policy author.  It is harder to do this
correctly that it seems.  Here are some common problems:

1.  **Performance**: by using a function like `matches_bucket_or_id`, we often
    need to test each bucket against each other resource, resulting in O(n^2)
    performance which is problematic on big accounts.

2.  **Robustness**: writing the join as an object is also problematic.  The
    evaluation for the rule `topic_policies_by_topic` will crash if `policy.arn`
    is the same for different policies (e.g. if it is `null` or `""`).

3.  **Correctness**: we often want to use multiple attributes (e.g. `arn` and
    `id`).  It is tricky to write and debug this in Rego and ensure that the
    query still benefits from [comprehension indexing].

4.  **Duplication**: these rules often get duplicated across rules, or within the
    same rule.  This is not great since, as demonstrated above, they can
    actually be tricky to write.  Having a single place for them speeds up
    policy development.

This proposal lays out better way for dealing with this.

## Resource Graph Model

We can think of the relations between the resources as a graph, and we'd like
to establish a common model for these rather than doing them ad-hoc in rules
and libraries.

The resource graph has resources as nodes, and **labeled**, **directed** edges.
We can represent it as a list of `(resource, relation, resource)` triples:

    (my_cloudtrail, "logs_to_bucket",               my_bucket)
    (my_bucket,     "has_encryption_configuration", my_bucket_encryption_configuration)

The **labeling** is important as one resource type may relate to another
resource type in several different ways:

    (my_cloudtrail, "logs_to_bucket",     my_bucket)
    (my_cloudtrail, "has_event_selector", my_sensitive_bucket)

The **direction** is important as knowing which side the resource is on may be
important to determine compliance:

    (my_security_group, "allows_ingress_from", my_other_security_group)

This is not a new idea -- it is heavily inspired by [RDF stores].

## Querying the Resource Graph

In policies, we're interested in asking which resources relate to one another.
This can be useful to determine compliance, and to write the `resources[info]`
rule.

We can think of queries to the resource graph as triplets with one resource
left blank:

    (my_cloudtrail, "logs_to_bucket", ?)

In Rego, this is implemented by the `snyk.relates("relation_name", resource)`
function:

```rego
cloudtrail := snyk.resources("aws_cloudtrail")[_]
bucket := snyk.relates(cloudtrail, "logs_to_bucket")[_]
```

By having a common model, we can also provide the backward relation.  That way
policy authors can pick whichever is more useful in their policy.  In addition
to `relates`, a policy author can use `back_relates` to look for the
corresponding triple `(?, "logs_to_bucket", bucket)`:

```rego
bucket := snyk.resources("aws_s3_bucket")[_]
cloudtrail := snyk.back_relates("logs_to_bucket", bucket)[_]
```

## Building the Resource Graph

We've explained what the resource graph model is, and how to query it, but in
the end it's just a model -- the implementation is different, as storing triples
would degrade performance.

In practice, we want to use objects that store the the corresponding resources
in a way that we can access them cheaply.  But as we've explained before, having
the policy engine authors implement these objects in each rule causes some
problems.

Instead, we'll ask the policy authors for a declarative description of the
relationships between objects.  This is done by placing objects describing
the relationships in the `data.relations.relations` set.

This is what that looks like:

```rego
package relations

import data.snyk

relations[info] {
	info := {
		"name": "logging",
		"keys": {
			"left": [[b, b.id] | b := snyk.resources("aws_s3_bucket")[_]],
			"right": [[l, l.bucket] | l := snyk.resources("aws_s3_bucket_logging")[_]],
		},
	}
}
```

Let's unpack that a bit:

```rego
package relations
```

Since these relations are decoupled from rules, it is recommended to store these
in separate files per service group, for example `lib/tf/aws/s3/relations.rego`.
However, the package name is fixed, so the policy engine knows where to find
them.

```rego
import data.snyk
```

We still use the `snyk.resources` (or `query`) to obtain the resources we want
to relate.

```rego
relations[info] {
```

We use an incremental definition for the `relations` rule so it can be extended
from multiple files.

```rego
	info := {
		"name": "logging",
```

The `"name"` is required and determines the middle element of the triple.
See also [naming relationships](#naming-relationships)

```rego
		"keys": {
			"left": [[b, b.id] | b := snyk.resources("aws_s3_bucket")[_]],
			"right": [[l, l.bucket] | l := snyk.resources("aws_s3_bucket_logging")[_]],
		},
	}
}
```

We can think of several ways to do the join in a declarative way.  By far the
most common is matching some set of attributes across the resources.  This can
be done by setting `keys`. `left` and `right` must be set to pairs of resources
together with their keys -- a list comprehension is usually useful to implement
this.

### Non-key joins

In our example, we used `keys` to correlate resources.  In general, we recommend
using `keys`, since it is fast and can handle multiple keys or fields per
resource.

We can add support for other joins as well.  In particular, it seems nice to at
least support `explicit` joins as well (called this way since the user gives an
"explicit" list of pairs of resources to be joined).

```rego
"explicit": [[b, l] |
	b := snyk.resources("aws_s3_bucket")[_]
	l := snyk.resources("aws_s3_bucket_logging")[_]
	b.id == l.bucket
],
```

This is very flexible (since any Rego code can be used to build the list of
pairs) but is somewhat similar to the ad-hoc way we used to do joins.
Hence, we do not recommend this as it can lead to the performance or correctness
issues discussed in earlier in this document.

### Naming Relationships

Part of the advantage in adopting this proposal originate from converging
towards a common format for relationships.  An important part of that is
establishing a convention for naming relationships, so they are predictable,
easy to understand and don't conflict.

There are three rules:

1.  If a resource type is meaningless on its own and always meant to be attached
    to a primary resource, you can use the name of that resource type.
    Example: `aws_s3_bucket_server_side_encryption_configuration`.

2.  If resource type X refers to resource type Y using some attribute A,
    use some variation of `X_A`, possibly dropping `id` or `name` from A if it
    makes sense.  Example: `aws_cloudtrail` refers to `aws_s3_bucket` using the
    attribute `s3_bucket_name`, so we use `aws_cloudtrail_s3_bucket`.

3.  If none of the above apply, use something that follows the convention of
    `<resource_type>_<attribute_name>` in spirit.

### Listing relationships

One can get a list of defined relationships by using regular OPA queries.  The
following example lists all relationships by name:

```
policy-engine -d rego
> {i.name | data.relations.relations[i]}
```

## Benefits

This proposal has three distinct benefits:

1.  It makes policy authoring easier when you need to join resources.
2.  It puts us a step closer to being to automatically generate
    `resources[info]` rules, as we can inspect the relations.
3.  Exporting the relationships between resources in a human-readable format
    is useful to other components -- for example the Viz currently has a
    hand-rolled version of this.

[comprehension indexing]: https://www.openpolicyagent.org/docs/latest/policy-performance/#comprehension-indexing
[RDF stores]: https://en.wikipedia.org/wiki/Triplestore
