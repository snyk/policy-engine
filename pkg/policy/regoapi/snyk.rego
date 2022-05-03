package snyk

resources(resource_type) = ret {
  obj := __resources_by_type(resource_type)
  ret := [resource | resource := obj[_]]
}
