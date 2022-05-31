package snyk

resources(resource_type) = ret {
  obj := __resources_by_type(resource_type)
  ret := [resource | resource := obj[_]]
}

input_type := __current_input_type()

input_resource_types := __input_resource_types()
