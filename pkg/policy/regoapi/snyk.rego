package snyk

resources(resource_type) = ret {
  obj := __resources_by_type(resource_type)
  ret := [resource | resource := obj[_]]
}

cloud_resources(resource_type) = ret {
	ret := __cloud_resources(resource_type)
}
