package snyk

import data.snyk.internal.relations

relates(resource, name) := ret {
	ret := relations.forward[[name, relations.make_resource_key(resource)]]
}
