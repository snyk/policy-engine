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

package relations

import data.snyk

# Relations for unit tests.
relations[info] {
	# Only include these relations when this input flag is specified as a safety
	# measure.
	input.snyk_relations_test
	info := {
		"name": "bucket_settings",
		"keys": {
			"left": [[b, b.id] | b := snyk.resources("bucket")[_]],
			"right": [[l, l.bucket] | l := snyk.resources("bucket_settings")[_]],
		},
	}
}

# Relations for unit tests.
relations[info] {
	# Only include these relations when this input flag is specified as a safety
	# measure.
	input.snyk_relations_test
	info := {
		"name": "bucket_logging",
		"explicit": [[b, l] |
			b := snyk.resources("bucket")[_]
			l := snyk.resources("bucket_logging")[_]
			l.bucket == b.id
		],
	}
}

# Relations for unit tests.
relations[info] {
	# Only include these relations when this input flag is specified as a safety
	# measure.
	input.snyk_relations_test
	info := {
		"name": "bucket_acl",
		"keys": {
			"left": [[b, k] |
				b := snyk.resources("bucket")[_]
				k := b[{"id", "bucket"}[_]]
			],
			"right": [[l, l.bucket] | l := snyk.resources("bucket_acl")[_]],
		},
	}
}
