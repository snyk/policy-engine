# The package name for tests is arbitrary but should not start with `rules.`
# just to avoid confusion.
package rules.snyk_003.tf

# We need to import the fixture we generated.
import data.examples.main

test_policy if {
	# We run the `deny` part of the rule using our fixture.
	denies := deny with input as main.mock_input

	# The actual testing is rule-specific.
	count(denies) == 2
	denies[_].resource.id == "aws_s3_bucket.bucket1"
	denies[_].resource.id == "aws_s3_bucket.bucket3"
}
