package snyk

resources(resource_type) = ret {
    ret := [resource |
        resource := input[_].resources[resource_type][_].attributes
	]
}
