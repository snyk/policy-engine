# schemas

This library provides a common way of providing a schema for an input format.
It currently supports type (coercions) and sensitive attributes.

The common interface is defined in [schemas.go](schemas.go).

How these are generated per platform and provider wildly differs.

## CloudFormation

A zip archive made available at
<https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-type-sc
hemas.html> is embedded in the executable.  We load and parse this archive
when the first schema is requested.

## AWS

We cannot easily import providers using the SDK V2 as Go libraries.
Furthermore, these have huge and complex dependency footprints, so we would not
want to embed these or include these dependencies within our own `go.mod`.

Instead, we have a script in [tf/generate/generate.sh](tf/generate/generate.sh)
that clones each provider and replaces its main function by one that extracts
the schemas.  This way the providers can each have there own set of dependencies
(as clashes seem to occur).

The resulting schemas are stored in `.json.gz` files per provider.  These
fortunately do not need to be regenerated very frequently.

On the policy engine, these `.json.gz` files are embedded.  The first time
a schema is requested, we load all of these into memory.
