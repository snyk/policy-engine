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

package snyk

__physical_or_logical_id(resource) := ret if {
	is_string(resource.attributes.id)
	not resource.attributes.id == ""
	ret := resource.attributes.id
} else := ret if {
	ret := resource.id
}

resources(resource_type) := ret if {
	ret := [obj |
		resource := input.resources[resource_type][_]
		obj := object.union(
			resource.attributes,
			{
				"id": __physical_or_logical_id(resource),
				"_id": resource.id,
				"_type": resource_type,
				"_namespace": resource.namespace,
				"_meta": object.get(resource, "meta", {}),
				"_tags": object.get(resource, "tags", {}),
			},
		)
	]
}

input_type := input.input_type

input_resource_types := {rt | input.resources[rt]}

# Stubbable query() implementation for tests.
# If resources are not found in the input, return a previously-configured stub
# value.
# rule_tests.query_returns in https://github.com/snyk/opa-rules configures stub
# values in the way that this function expects.
query(q) := ret if {
	from_input := resources(q.resource_type)
	count(from_input) > 0
	ret := from_input
}

query(q) := ret if {
	from_input := resources(q.resource_type)
	count(from_input) == 0
	query_str := json.marshal(q)
	ret := input._query[query_str]
}
