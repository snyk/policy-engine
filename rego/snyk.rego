package snyk

resources(resource_type) = ret {
	ret := [obj |
		resource := input.resources[resource_type][_]
		obj := object.union({
			"id": resource.id,
			"_type": resource_type,
			"_namespace": resource.namespace,
			"_meta": object.get(resource, "meta", {}),
			"_uid": crypto.sha256(concat(":", [
				crypto.sha256(resource.namespace),
				crypto.sha256(resource_type),
				crypto.sha256(resource.id),
			])),
		}, resource.attributes)
	]
}
