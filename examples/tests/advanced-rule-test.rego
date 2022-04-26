# The package name for tests is arbitrary but should not start with `rules.`
# just to avoid confusion.
package data.tests.rules.snyk_003.tf

# We need to import the fixture we generated.
import data.examples.main

# We import the actual rule as well, so we can test it.
import data.rules.snyk_003.tf as policy

test_policy {
	# We run the `deny` part of the rule using our fixture.
	denies := policy.deny with input as main.mock_input

	# The actual testing is rule-specific.
	count(denies) == 2
	denies[_].resource.id == "aws_s3_bucket.bucket1"
	denies[_].resource.id == "aws_s3_bucket.bucket3"
}
