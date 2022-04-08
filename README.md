# Unified Policy Engine

## Tutorial & Examples

We will walk through the rules in the examples directory, starting out with
simple rules and gradually adding concepts.

### Simple rules

[examples/01-simple.rego](examples/01-simple.rego)

### Returning attributes

[examples/02-simple-attributes.rego](examples/02-simple=attributes.rego)

### Advanced rules part 1

[examples/02-advanced.rego](examples/02-advanced.rego)

### Advanced rules part 2

[examples/03-advanced.rego](examples/03-advanced.rego)

### Advanced rules part 3

[examples/04-advanced.rego](examples/04-advanced.rego)

### Advanced rules part 4

[examples/06-advanced.rego](examples/06-advanced.rego)


### Missing resources

[examples/05-missing.rego](examples/05-missing.rego)

## Reference

### Info objects

Info objects have different fields depending in which context they occur.

`deny[info]` fields:

 -  `message`: Message string detailing the issue.  **Required.**
 -  `resource`: Resource associated with the issue.
 -  `resource_type`: May be used to indicate the resource type in case of a
    missing resource.
 -  `correlation`: May be used to override the correlation the policy engine
    uses to relate issues.  Defaults to `.resource.id`.

`resources[info]` fields:

 -  `resource`: Resource associated with the issue.  **Required.**
 -  `correlation`: May be used to override the correlation the policy engine
    uses to relate issues.  Defaults to `.resource.id`.

### snyk API

 -  `snyk.resources(resource_type)`:
    Returns a object of resource IDs to resources of the requested type.
