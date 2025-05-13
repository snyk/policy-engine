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
relations contains info if {
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
relations contains info if {
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
relations contains info if {
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

# Relations for unit tests.
# This relation is annotated on the edges.
relations contains info if {
	# Only include these relations when this input flag is specified as a safety
	# measure.
	input.snyk_relations_test
	info := {
		"name": "security_group",
		"keys": {
			"left": array.concat(
				[[r, egress.security_group_id, ann] |
					r := snyk.resources("security_group")[_]
					egress := r.egress[_]
					ann := {"type": "egress", "port": egress.port}
				],
				[[r, ingress.security_group_id, ann] |
					r := snyk.resources("security_group")[_]
					ingress := r.ingress[_]
					ann := {"type": "ingress", "port": ingress.port}
				],
			),
			"right": [[r, r.id] | r := snyk.resources("security_group")[_]],
		},
	}
}

# Relations for unit tests.
# This tests annotated explicit relations
relations contains info if {
	# Only include these relations when this input flag is specified as a safety
	# measure.
	input.snyk_relations_test
	info := {
		"name": "forwards_to",
		"explicit": [[l, r, ann] |
			l := snyk.resources("load_balancer")[_]
			forward := l.forward[_]
			r := snyk.resources("application")[_]
			forward.application == r.id
			ann := {"port": forward.port}
		],
	}
}
