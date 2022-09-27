# Copyright 2022 Snyk Ltd
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

test_resource_id {
	# Test that we override any "id" set in the attributes, which is how the
	# Go code behaves.
	mock_input := {"resources": {"aws_s3_bucket": {"aws_s3_bucket.foo": {
		"id": "aws_s3_bucket.foo",
		"namespace": "test.plan",
		"attributes": {"id": "bar"},
	}}}}
	buckets = snyk.resources("aws_s3_bucket") with input as mock_input
	buckets[_].id == "aws_s3_bucket.foo"
}
