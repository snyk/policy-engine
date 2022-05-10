package snyk

resources(resource_type) = ret {
	ret := [obj |
		resource := input.resources[resource_type][_]
		obj := object.union({
			"id": resource.id,
			"_type": resource_type,
			"_namespace": resource.namespace,
		}, resource.attributes)
	]
}
