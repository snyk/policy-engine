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
