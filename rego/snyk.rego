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

package snyk

resources(resource_type) = ret {
	ret := [obj |
		resource := input.resources[resource_type][_]
		obj := object.union(
			{
				"id": resource.id,
				"_type": resource_type,
				"_namespace": resource.namespace,
				"_meta": object.get(resource, "meta", {}),
			},
			resource.attributes,
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
query(q) = ret {
	from_input := resources(q.resource_type)
	count(from_input) > 0
	ret := from_input
}

query(q) = ret {
	from_input := resources(q.resource_type)
	count(from_input) == 0
	query_str := json.marshal(q)
	ret := input._query[query_str]
}
