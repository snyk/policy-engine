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

package snyk

import data.snyk.internal.relations
import data.snyk

relates(resource, name) = ret {
	ret := relations.forward[[name, relations.make_resource_key(resource)]]
} else = [] {
	true
}

back_relates(name, resource) = ret {
	ret := relations.backward[[name, relations.make_resource_key(resource)]]
} else = [] {
	true
}

relation_from_fields(name, left, right) = info {
	info := {
		"name": name,
		"keys": {
			"left": [[resource, resource[field]] |
				fields := left[resource_type]
				resource := snyk.resources(resource_type)[_]
				field := fields[_]
			],
			"right": [[resource, resource[field]] |
				fields := right[resource_type]
				resource := snyk.resources(resource_type)[_]
				field := fields[_]
			],
		},
	}
}
