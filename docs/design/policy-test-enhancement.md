# Snapshot testing for policies

Policy tests can be tedious to write and maintain. We currently write the expected
output of the `deny` and `resources` rules, which can be quite large or complex, by
hand. Any time we make updates, for example to reword the message returned by a rule, we
need to make the same update repeatedly in the expected output in our tests.

This document is a proposal for a new `snyk.matches_snapshot` builtin which can
alleviate some of that burden.

## Background on snapshot testing

Snapshot testing (or golden testing) works by evaluating some code, saving a "snapshot"
of the output, and then asserting that the output has not changed on subsequent runs. If
the output does change, some manual intervention is required to update the snapshot.
Snapshots are committed alongside the code.

In practice, snapshot tests are typically very easy to write and also very helpful for
reviewers, because they make it easy to see the output of whatever they're testing.
They also enforce that output does not change unintentionally.

More information on snapshot / golden tests:

* Introduction to golden testing:
  * https://ro-che.info/articles/2017-12-04-golden-tests
* Jest (a JavaScript test framework) docs on their implementation of snapshot testing:
  * https://jestjs.io/docs/snapshot-testing

## Proposed interface

Similar to the Jest implementation, our snapshot tests should just be another assertion
that you can make alongside your other tests:

```open-policy-agent
snyk.matches_snapshot(some_variable, "some_snapshot_name")
```

* This function will assert that the value of `some_variable` matches the contents of
  the file `snapshots/some_snapshot_name.json` relative to the file that contains the
  function call.
    * Ideally, this function should be called directly within a test file rather than in
      some library code that is used across tests. That way, the snapshots will be
      created alongside their test files rather than in some central location.
* If the file does not exist, it will be created and the function will return `true`.
* If the file does exist and the contents do not match, this function will return an
  error with its message set to the diff.
* If `policy-engine test` is run with the `--update-snapshots` option, this function will update
  any existing snapshots.

## Example

This is an existing test from `SNYK-CC-00107`:

```open-policy-agent
check_invalid_via_multiple(mock_input) {
        denies := rule_tests.by_correlation_id(deny) with input as mock_input
        denies == {
                "aws_s3_bucket.public1": {
                        {
                                "attributes": [["acl"]],
                                "message": "An ACL allows public access to the bucket",
                                "resource": "aws_s3_bucket.public1",
                        },
                        {
                                "message": "A bucket policy allows public access to the bucket",
                                "resource": "aws_s3_bucket.public1",
                        },
                },
                "aws_s3_bucket.public2": {
                        {
                                "attributes": [["grant"]],
                                "message": "A grant allows public access to the bucket",
                                "resource": "aws_s3_bucket.public2",
                        },
                        {
                                "message": "A bucket policy allows public access to the bucket",
                                "resource": "aws_s3_bucket.public2",
                        },
                },
                "aws_s3_bucket.public3": {
                        {
                                "attributes": [["grant"]],
                                "message": "A grant allows public access to the bucket",
                                "resource": "aws_s3_bucket.public3",
                        },
                        {
                                "message": "A bucket policy allows public access to the bucket",
                                "resource": "aws_s3_bucket.public3",
                        },
                },
                "aws_s3_bucket.public4": {
                        {
                                "attributes": [["grant"]],
                                "message": "A grant allows public access to the bucket",
                                "resource": "aws_s3_bucket.public4",
                        },
                        {
                                "message": "A bucket policy allows public access to the bucket",
                                "resource": "aws_s3_bucket.public4",
                        },
                },
                "aws_s3_bucket.public5": {
                        {
                                "attributes": [["grant"]],
                                "message": "A grant allows public access to the bucket",
                                "resource": "aws_s3_bucket.public5",
                        },
                        {
                                "message": "A bucket policy allows public access to the bucket",
                                "resource": "aws_s3_bucket.public5",
                        },
                },
        }

        rs := rule_tests.by_correlation_id(resources) with input as mock_input
        rs == {
                "aws_s3_bucket.public1": {
                        {
                                "attributes": [["Statement", 0]],
                                "resource": "aws_s3_bucket_policy.policy1",
                        },
                        {"resource": "aws_s3_bucket.public1"},
                },
                "aws_s3_bucket.public2": {
                        {
                                "attributes": [["Statement", 0]],
                                "resource": "aws_s3_bucket_policy.policy2",
                        },
                        {"resource": "aws_s3_bucket.public2"},
                },
                "aws_s3_bucket.public3": {
                        {
                                "attributes": [["Statement", 0]],
                                "resource": "aws_s3_bucket_policy.policy3",
                        },
                        {"resource": "aws_s3_bucket.public3"},
                },
                "aws_s3_bucket.public4": {
                        {
                                "attributes": [["Statement", 0]],
                                "resource": "aws_s3_bucket_policy.policy4",
                        },
                        {"resource": "aws_s3_bucket.public4"},
                },
                "aws_s3_bucket.public5": {
                        {
                                "attributes": [["Statement", 0]],
                                "resource": "aws_s3_bucket_policy.policy5",
                        },
                        {"resource": "aws_s3_bucket.public5"},
                },
        }
}

test_invalid_via_multiple {
        check_invalid_via_multiple(terraform.invalid_via_multiple.config.mock_input)
        check_invalid_via_multiple(terraform.invalid_via_multiple.plan.mock_input)
}
```

And rewritten using the proposed function:

```open-policy-agent
check_invalid_via_multiple(mock_input) {
        denies := rule_tests.by_correlation_id(deny) with input as mock_input
        snyk.matches_snapshot(denies, "snapshots/invalid_via_multiple_denies.json")

        rs := rule_tests.by_correlation_id(resources) with input as mock_input
        snyk.matches_snapshot(rs, "invalid_via_multiple_rs")
}

test_invalid_via_multiple {
        check_invalid_via_multiple(terraform.invalid_via_multiple.config.mock_input)
        check_invalid_via_multiple(terraform.invalid_via_multiple.plan.mock_input)
}
```

Note that we're still able to assert that we get the same output from both the `config`
and `plan` inputs like before.
