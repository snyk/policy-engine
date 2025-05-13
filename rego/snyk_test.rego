# © 2022-2023 Snyk Limited All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package snyk_test

import data.snyk

test_resource_id if {
	# Test that we set id and _id in the same way as the Go code. For id, that's:
	#		* use the physical ID if one is defined
	#		* otherwise use the logical ID
	# And _id should always be set to the logical ID.
	mock_input := {"resources": {"aws_s3_bucket": {
		"aws_s3_bucket.foo": {
			"id": "aws_s3_bucket.foo",
			"namespace": "test.plan",
			"attributes": {"id": "bar"},
		},
		"aws_s3_bucket.baz": {
			"id": "aws_s3_bucket.baz",
			"namespace": "test.plan",
			"attributes": {"id": null},
		},
		"aws_s3_bucket.qux": {
			"id": "aws_s3_bucket.qux",
			"namespace": "test.plan",
			"attributes": {},
		},
	}}}

	buckets_by_logical_id := {id: bucket |
		bucket := snyk.resources("aws_s3_bucket")[_]
		id := bucket._id
	} with input as mock_input

	buckets_by_logical_id["aws_s3_bucket.foo"].id == "bar"
	buckets_by_logical_id["aws_s3_bucket.baz"].id == "aws_s3_bucket.baz"
	buckets_by_logical_id["aws_s3_bucket.qux"].id == "aws_s3_bucket.qux"
}
