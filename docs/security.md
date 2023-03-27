# Security

Running policy engine may involve running untrusted, user-supplied code on
user-supplied inputs.  This document describes the security aspects that
come into play.

This is less of a concern if you are only using policy-engine to test your own
infrastructure against your own set of rules.

- [General recommendation](#general-recommendation)
- [Running Rego](#running-rego)
- [Loading Inputs](#loading-inputs)
  - [`.tf` files](#tf-files)

## General Recommendation

Even though security is important to us (given policy-engine originated at a
security-focused company), it's not impossible to rule out bugs that would allow
some sort of escalation.

Therefore, if you are using user-supplied Rego code or user-supplied inputs,
we strongly recommend to run using policy-engine in an isolated environment,
which typically means at least:

 -  No filesystem access
 -  No environment variable propagation
 -  No network access
 -  Strict limits on memory & time consumption

## Running Rego

We use [OPA]'s topdown Rego evaluator, written in Go.  We have disabled the
following functionality:

 -  `http.send()`: can send arbitrary HTTP calls
 -  `opa.runtime()`: includes environment variables; this returns an empty
    object in policy-engine.

[OPA]: https://www.openpolicyagent.org

## Loading Inputs

### `.tf` files

Passing resource information from `.tf` files involves evaluating HCL.
The [hcl_interpreter README](../pkg/hcl_interpreter/README.md) contains more
information on how this works: but what's relevant here is that we mix our
own evaluation logic with reusing bits of the hashicorp's HCL package.

Some functions in `HCL` allow reading information from the filesystem.
An classic example of this is something like:

```hcl
resource "aws_instance" "my_instance" {
   user_data = file("${path.module}/startup_script.sh")
}
```

This would allow users to gain information about the server-side environment.
To this purpose, we've modified the following functions to use the
[Afero](https://github.com/spf13/afero) filesystem library rather than the
physical one.

 -  Filesystem functions:
     *  `abspath`
     *  `dirname`
     *  `pathexpand`
     *  `basename`
     *  `file`
     *  `fileexists`
     *  `fileset`
     *  `filebase64`
     *  `templatefile`
 -  Crypto functions:
     *  `filebase64sha256`
     *  `filebase64sha512`
     *  `filemd5`
     *  `filesha1`
     *  `filesha256`
     *  `filesha512`
