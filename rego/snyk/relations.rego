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

import data.snyk
import data.snyk.internal.relations
import data.snyk.internal.relations.cache

relates(resource, name) := ret if {
	ret := [right_resource |
		[right_resource, _] := cache.forward[[name, relations.make_resource_key(resource)]][_]
	]
}

relates_with(resource, name) := ret if {
	ret := cache.forward[[name, relations.make_resource_key(resource)]]
} else := []

back_relates(name, resource) := ret if {
	ret := [left_resource |
		[left_resource, _] := cache.backward[[name, relations.make_resource_key(resource)]][_]
	]
}

back_relates_with(name, resource) := ret if {
	ret := cache.backward[[name, relations.make_resource_key(resource)]]
} else := []

relation_from_fields(name, left, right) := info if {
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
