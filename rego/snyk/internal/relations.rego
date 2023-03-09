# © 2023 Snyk Limited All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package snyk.internal.relations

make_resource_key(resource) = ret {
	ret := [resource._namespace, resource._type, resource._id]
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
forward_keys := {idx: right_resources |
	keys := forward_left_foreign_keys[idx]
	right_resources := [right_resource |
		k := keys[_]
		[name, _] := idx
		right_resource := forward_right_foreign_keys[[name, k]][_]
	]
}

forward_explicit := {idx: right_resources |
	relation := data.relations.relations[_]
	pairs := object.get(relation, "explicit", [])
	[left_resource, _] := pairs[_]
	idx := [relation.name, make_resource_key(left_resource)]
	right_resources := {right_resource |
		relation := data.relations.relations[_]
		pairs := object.get(relation, "explicit", [])
		[l, right_resource] := pairs[_]
		idx == [relation.name, make_resource_key(l)]
	}
}

forward := {idx: right_resources |
	idxs := {k | _ := forward_keys[k]} | {k | _ := forward_explicit[k]}
	idx := idxs[_]
	right_resources := array.concat(
		[r | r := forward_keys[idx][_]],
		[r | r := forward_explicit[idx][_]],
	)
}

# NOTE: comprehension idx triggers here, this is important.
backward_right_foreign_keys := {idx: ret |
	relation := data.relations.relations[_]
	[right_resource, _] := relation.keys.right[_]
	idx := [relation.name, make_resource_key(right_resource)]
	ret := {k |
		relation := data.relations.relations[_]
		[right_resource, k] := relation.keys.right[_]
		idx == [relation.name, make_resource_key(right_resource)]
	}
}

# NOTE: comprehension idx triggers here, this is important.
backward_left_foreign_keys := {idx: ret |
	relation := data.relations.relations[_]
	[_, key] := relation.keys.left[_]
	idx := [relation.name, key]
	ret := {left_resource |
		relation := data.relations.relations[_]
		[left_resource, k] := relation.keys.left[_]
		idx == [relation.name, k]
	}
}

# NOTE: comprehension idx not strictly necessary here.
backward_keys := {idx: left_resources |
	keys := backward_right_foreign_keys[idx]
	left_resources := [left_resource |
		k := keys[_]
		[name, _] := idx
		left_resource := backward_left_foreign_keys[[name, k]][_]
	]
}

backward_explicit := {idx: left_resources |
	relation := data.relations.relations[_]
	pairs := object.get(relation, "explicit", [])
	[_, right_resource] := pairs[_]
	idx := [relation.name, make_resource_key(right_resource)]
	left_resources := {left_resource |
		relation := data.relations.relations[_]
		pairs := object.get(relation, "explicit", [])
		[left_resource, r] := pairs[_]
		idx == [relation.name, make_resource_key(r)]
	}
}

backward := {idx: left_resources |
	idxs := {k | _ := backward_keys[k]} | {k | _ := backward_explicit[k]}
	idx := idxs[_]
	left_resources := array.concat(
		[r | r := backward_keys[idx][_]],
		[r | r := backward_explicit[idx][_]],
	)
}
