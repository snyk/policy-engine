# Unified Policy Engine

## Tutorial & Examples

We will walk through the rules in the examples directory, starting out with
simple rules and gradually adding concepts.

### Simple rules

<examples/01-simple.rego>

### Advanced rules part 1

<examples/02-advanced.rego>

### Advanced rules part 2

<examples/03-advanced.rego>

### Advanced rules part 3

<examples/03-advanced.rego>

## Reference

### Info objects

Fields:

 -  `message`: Message string detailing the issue.
 -  `resource`: Resource associated with the issue.

### snyk API

 -  `snyk.resources(resource_type)`

    Returns a object of resource IDs to resources of the requested type.
