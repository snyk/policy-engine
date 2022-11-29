package snyk.internal.relations

make_resource_key(resource) := ret {
	ret := [resource._namespace, resource._type, resource._id]
}

forward_resource_key_keys := {name: ret |
	relation := data.relations.relations[_]
	name := relation.name
	ret := {resource_key: keys |
		relation := data.relations.relations[_]
		relation.name == name
		[left_resource, key] := relation.keys.left[_]
		resource_key := make_resource_key(left_resource)
		keys := [k |
			[left_resource, k] := relation.keys.left[_]
			resource_key == make_resource_key(left_resource)
		]
	}
}

# NOTE: comprehension idx triggers here, this is important.
forward_left_foreign_keys := {idx: ret |
	relation := data.relations.relations[_]
	[left_resource, _] := relation.keys.left[_]
	idx := [relation.name, make_resource_key(left_resource)]
	ret := {k |
		relation := data.relations.relations[_]
		[left_resource, k] := relation.keys.left[_]
		idx == [relation.name, make_resource_key(left_resource)]
	}
}

# NOTE: comprehension idx triggers here, this is important.
forward_right_foreign_keys := {idx: ret |
	relation := data.relations.relations[_]
	[_, key] := relation.keys.right[_]
	idx := [relation.name, key]
	ret := {right_resource |
		relation := data.relations.relations[_]
		[right_resource, k] := relation.keys.right[_]
		idx == [relation.name, k]
	}
}

# NOTE: comprehension idx not strictly necessary here.
forward := {idx: right_resources |
	[name, _] := idx
	keys := forward_left_foreign_keys[idx]
	right_resources := [right_resource |
		k := keys[_]
		right_resource := forward_right_foreign_keys[[name, k]][_]
	]
}
