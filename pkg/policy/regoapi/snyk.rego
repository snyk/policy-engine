package snyk

resources(resource_type) = ret {
	ret := __query({"resource_type": resource_type, "scope": {}})
}

input_type := __current_input_type()

input_resource_types := __input_resource_types()

query(scope) = ret {
	ret := __query(scope)
}
