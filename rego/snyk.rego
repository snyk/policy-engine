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
