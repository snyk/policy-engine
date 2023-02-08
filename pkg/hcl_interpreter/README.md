# hcl_interpreter

This package supports loading HCL configurations.  Since it is a bit more
complex than the other loaders, it has it's own package.  What follows is
a brief but complete overview of how it works.

It tries to mimic terraform behavior as much as possible by using terraform
as a library.  Since some packages inside terraform are in an `/internal`
package, we vendor in terraform and rename the packages to make them
accessible from our code.  This is automated in the top-level Makefile.

## names.go

[names.go] holds some utilities to work with names, for example parsing them
from strings and rendering them back to strings.  A name consists of two parts:

 -  A module part (e.g. `module.child1.`).  This is empty for the root module.
 -  A local part (e.g. `aws_s3_bucket.my_bucket` or `var.my_var`).

Importantly, there are a number of `AsXYZ()` methods, for example
`AsModuleOutput()`.  These manipulate the names to point to their "real"
location: for example, if you use `module.child1.my_output` in the root
module, the "real" location is the output inside the child module, so
`module.child1.outputs.my_output`.  These methods form a big part of the logic
and having it here allows us to keep the code in other files relatively clean.

## moduletree.go

[moduletree.go] is responsible for parsing a directory of terraform files,
including children (submodules).  We end up with a hierarchical structure:

 -  root module
     *  child 1
     *  child 2
         -  grandchild

We can "walk" this tree using a visitor pattern and visit every _term_.

A term can be a simple expression or a block with attributes and sub-blocks.
Each resource forms a term, and so does each other "entity" in the input,
like a a local variable or a module output.  For more details, see [term.go].

For example:

  -  `aws_security_group.invalid_sg_1`
  -  `module.child1.output.bucket`

Because we pass in both the full name (see above) as well as the term, a visitor
can store these in a flat rather than hierarchical map, which is more convenient
to work with in Go.

This file uses an additional file [moduleregister.go] to deal with the locations
of remote (downloaded) terraform modules.

## valtree.go

Once expressions are evaluated, they become values of the type `cty.Value`.
This module has a number of utilities to construct and merge Values.

## phantom_attrs.go

In IaC files, it is common to depend on values which are not filled in:

```
resource "aws_kms_key" "rds-db-instance-kms" {
  deletion_window_in_days = 10
}

resource "aws_db_instance" "default" {
  kms_key_id = "${aws_kms_key.rds-db-instance-kms.arn}"
  ...
}

```

`rds-db-instance-kms` does not have an `.arn` attribute, but evaluating
`kms_key_id` needs one.  We solve this by collecting all references to unknown
attributes in the expressions, and setting these as "phantom attributes" on the
resources.  They are not included in the output.

## hcl_interpreter.go

Finally, using these foundations, [hcl_interpreter.go] implements the main
logic.  This happens in the following imperative steps:

1.  We use the visitor from [moduletree.go] to obtain a full list of everything
    in the module and its children.

2.  For every term, we can compute its dependencies (possibly renaming
    some using the logic in [names.go]).  This gives us enough info to run a
    [topological sort](https://en.wikipedia.org/wiki/Topological_sorting);
    which tells us the exact order in which all terms should be evaluated.

3.  We run through and evaluate each expression.

     -  We have a single big `cty.Value` that holds **everything** we have
        evaluated so far per module.

     -  Before evaluating, we add extra dependencies to this `cty.Value` scope
        based on the code in `dependencies()` and `prepareVariables()`.  This
        is used to e.g. get outputs from other modules.

     -  After evaluating, we merge the result back into the `cty.Value` for that
        module.

4.  We convert the individual `cty.Value`s for the resources into the resources
    view (this involves only some minor bookkeeping like adding the `id` and
    `_provider` fields).

[moduleregister.go]: moduleregister.go
[moduletree.go]: moduletree.go
[names.go]: names.go
[hcl_interpreter.go]: hcl_interpreter.go
[valtree.go]: valtree.go
[term.go]: term.go
