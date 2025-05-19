# © 2023 Snyk Limited All rights reserved.
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

package rules.EXAMPLE_01.terraform

import data.lib.utils
import data.snyk

input_type := "tf"

resource_type := "MULTIPLE"

metadata := data.rules.EXAMPLE_01.metadata

buckets := snyk.resources("aws_s3_bucket")

deny contains info if {
	bucket := buckets[_]
	utils.bucket_name_contains(bucket, "bucket")
	info := {"resource": bucket}
}

resources contains info if {
	bucket := buckets[_]
	info := {"resource": bucket}
}
