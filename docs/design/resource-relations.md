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
    performance which is problematic on big Cloud environments.  At Fugue, rules
    timing out because of this reason was a common occurrence once `n` is around
    a few thousand.

2.  **Robustness**: writing the join as an object is also problematic.  The
    evaluation for the rule `topic_policies_by_topic` will crash if `policy.arn`
    is the same for different policies (e.g. if it is `null` or `""`).  The
    `null` or `""` case is likely to happen when we fail to evaluate some part
    of an IaC configuration.

3.  **Correctness**: we often want to use multiple attributes (e.g. `arn` and
    `id`).  It is quite tricky to write and debug this in Rego and ensure that
    the query still benefits from [comprehension indexing].  This optimisation
    is absolutely essential in avoiding the O(n^2) problem.

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
We can represent it as a list of `(resource, relation, resource)` triples.  Some
examples:

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

Now that we've established the idea of having a "graph of relations", let's see
what it looks like for policies to use this.

In policies, we're interested in asking which resources relate to one another.
This can be useful both to determine compliance, as well as writing the
`resources[info]` rule.

We can think of queries to the resource graph as triplets with one resource
left blank:

    (my_cloudtrail, "logs_to_bucket", ?)

In Rego, this is implemented by the `snyk.relates("relation_name", resource)`
function:

```rego
cloudtrail := snyk.resources("aws_cloudtrail")[_]
bucket := snyk.relates(cloudtrail, "logs_to_bucket")[_]
```

By virtue of having a common model and having this implemented in a library, we
can also provide the backward relation.  That way policy authors can pick
whichever is more useful in their policy.  In addition to `relates`, a policy
author can use `back_relates` to look for the corresponding triple
`(?, "logs_to_bucket", bucket)`:

```rego
bucket := snyk.resources("aws_s3_bucket")[_]
cloudtrail := snyk.back_relates("logs_to_bucket", bucket)[_]
```

Note the reverse order of the arguments which feels more natural to the author
of this proposal but is up for discussion.

## Building the Resource Graph

We've explained what the resource graph model is, and how to query it, but in
the end it's just a model -- the implementation is different, as literally
storing triples would result in horrible performance.

In practice, we want to use objects that store the the corresponding resources
in a way that we can access them cheaply.  But as we've explained before, having
the policy engine authors implement these objects in each rule causes some
problems.

Instead, we'll ask the policy authors for a declarative description of the
relationships between objects.  This is done by placing objects describing
the relationships in the `data.relations.relations` set.

This is an example of what that looks like:

```rego
package relations

import data.snyk

relations[info] {
	info := {
		"name": "logging",
		"keys": {
			"right": [[logging, logging.bucket] | logging := snyk.resources("aws_s3_bucket_logging")[_]],
			"left": [[bucket, k] |
				bucket := snyk.resources("bucket")[_]
				attr := {"id", "bucket"}[_]
				k := bucket[attr]
			],
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
			"right": [[logging, logging.bucket] |
				logging := snyk.resources("aws_s3_bucket_logging")[_]
			],
			"left": [[bucket, k] |
				bucket := snyk.resources("bucket")[_]
				attr := {"id", "bucket"}[_]
				k := bucket[attr]
			],
		},
	}
}
```

We can think of several ways to do the join in a declarative way.  By far the
most common is matching some set of attributes across the resources.  This
can be done by setting `keys`. `left` and `right` must be set to **pairs of
[resource, key]** -- a list comprehension is usually useful to implement
this.  Note that resources may appear multiple time in this list of pairs, with
different keys.  This is illustrated in `left` above, where we want to extract
two attributes.

### Non-key joins

In our example, we used `keys` to correlate resources.  In general, we recommend
using `keys` in all cases, since it is fast and can handle multiple keys or
fields per resource.

We can, if necessary, add support for other joins as well.  In particular, it
seems nice to at least support `explicit` joins as well (called this way since
the user gives an "explicit" list of pairs of resources to be joined).

```rego
"explicit": [[bucket, logging] |
	bucket := snyk.resources("aws_s3_bucket")[_]
	logging := snyk.resources("aws_s3_bucket_logging")[_]
	bucket.id == logging.bucket
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
    to a primary resource, very much like a property, you can use the name of
    that resource type and property, concatenated with a `.`.
    Example: `aws_s3_bucket.server_side_encryption_configuration`.

2.  If resource type X refers to resource type Y using some attribute A,
    use some variation of `X.A`, possibly dropping `id` or `name` from A if it
    makes sense.  Example: `aws_cloudtrail` refers to `aws_s3_bucket` using the
    attribute `s3_bucket_name`, so we use `aws_cloudtrail.s3_bucket`.

3.  There are some rare cases in which many different types of resources can be
    associated with a specific resource X.  In that case you can use just `X`.
    Examples include `aws_security_group` (you could associate instances,
    autoscaling groups, clusters...) and `data.iam_policy_document`.

4.  If none of the above apply, use something that follows the convention of
    `<resource_type>.<attribute_name>` in spirit.

### Listing relationships

One can get a list of defined relationships by using regular OPA queries.  The
following example lists all relationships by name:

```
policy-engine -d rego
> {i.name | data.relations.relations[i]}
```

### Helper function

Many relationships are defined by a simple equality between a field on one
resource with a field on another resource. For example, an `aws_s3_bucket`
resource is related to an `aws_s3_bucket_logging` resource when the bucket's
`id` or `bucket` property is equal to the logging resource's `bucket` property.
We provide a helper function that makes it much easier to write `relations`
rules for these types of relationships:

```open-policy-agent
# Note that the list of properties for both the left and right resource can
# contain any number of properties to compare. As long as at least one left
# property is equal to a right property, we'll consider those resources to be
# related.
relations[info] {
	info := snyk.relation_from_fields(
		"<relation name>",
		{"<left resource>": ["<left property 1>", "<left property 2>"]},
		{"<right resource>": ["<right property 1>", "<right property 2>"]},
	)
}
```

Using this function, we could define the `aws_s3_bucket_logging` relationship
like so:

```open-policy-agent
relations[info] {
	info := snyk.relation_from_fields(
		"aws_s3_bucket.logging",
		{"aws_s3_bucket": ["id", "bucket"]},
		{"aws_s3_bucket_logging": ["bucket"]},
	)
}
```

## Benefits

This proposal has three distinct benefits:

1.  It makes policy authoring easier when you need to join resources.
2.  It puts us a step closer to being to automatically generate
    `resources[info]` rules, as we can inspect the relations.
3.  Exporting the relationships between resources in a human-readable format
    is useful to other components -- for example the Viz currently has a
    hand-rolled version of this.

## Performance considerations

**Memory**:

 -  The resources are represented as objects in the OPA runtime "heap".  Our
    additional tables store additional pointers to these objects, not additional
    objects.

 -  Most resource attributes do not map out relations.  In this sense, we
    can think of this is as only a change in constant factors rather than
    complexity.

**Time**:

 -  The key-based queries are carefully written to make use of
    [comprehension indexing].  A test for this is included.

[comprehension indexing]: https://www.openpolicyagent.org/docs/latest/policy-performance/#comprehension-indexing
[RDF stores]: https://en.wikipedia.org/wiki/Triplestore

## Extension: annotated relationships

### Problem statement

Even though relations can be named, and thus multiple relations between two
resources can exist, this is sometimes not enough.  Consider the following
example using a hypothetical cloud service provider:

```
load_balancer "my_loadbalancer" {
    action {
        port       = 22
        forward_to = application_1
    }

    action {
        port       = 80
        forward_to = application_2
    }

    ...
}

application "my_application_1" {
    ...
}

application "my_application_2" {
    ...
}
```

We can construct the following triplets:

    (my_loadbalancer, "forwards_to", my_application_1)
    (my_loadbalancer, "forwards_to", my_application_2)

However, all additional information (in this case, which port we're talking
about) is not stored in the relation.

If some policy needs this data, it needs to recover that data by first querying
for relations, and then matching the the results of that query against the
`forward_to` field.  This is a lot of work and breaks many benefits we gained
from using relations in the first place (convenience, performance, having a
single way to query these).

### Solution

In order to support these scenarios, all relations can be _annotated_ with some
additional data.  This data can be any Rego value, defaulting to `null` in case
no annotations are specified.

In the example above, we could annotate the relations with a single integer
representing the port number, but to be a bit more self-explanatory and
future-compatible we'll use an object instead, e.g. `{"port": 80}`.

### Building relations

Adding annotations is simple: they can be added as a third, optional element
for the entries in either the `"left"` or `"right"` parts of the relation.
Continuing with the example above, we get:

```rego
relations[info] {
	info := {
		"name": "forwards_to",
		"keys": {
			"left": [[r, forward.forward_to, ann] |
				r := snyk.resources("load_balancer")[_]
				forward := r.forward_to[_]
				ann := {"port": forward.port}
			],
			"right": [[r, r.id] |
				r := snyk.resources("load_balancer")[_]
			],
		},
	}
}
```

If annotations are specified in both the `left` and `right` properties, the
`right` one takes precedence.

For `"explicit"`-ly defined relations, you also the annotation as a third
element in each entry:

```rego
"explicit": [[bucket, logging, annotation] |
	bucket := snyk.resources("aws_s3_bucket")[_]
	logging := snyk.resources("aws_s3_bucket_logging")[_]
	bucket.id == logging.bucket
	annotation := ...
],
```

### Querying relations

Once the relation is defined, it still can be queried using the regular
`snyk.relates` and `snyk.back_relates`, which do not return the annotations:

```rego
lb := snyk.resources("load_balancer")[_]
app := snyk.relates(lb, "forward_to")[_]
```

If the annotations are desired, instead use `snyk.relates_with` and
`snyk.back_relates_with` instead, which each return the annotations in addition
to the resources:

```rego
lb := snyk.resources("load_balancer")[_]
[app, ann] := snyk.relates(lb, "forward_to")[_]
ann.port == 80
```
