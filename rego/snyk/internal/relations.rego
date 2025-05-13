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

make_resource_key(resource) := ret if {
	ret := [resource._namespace, resource._type, resource._id]
}

# Turns a (resource, user_key) into (resource, user_key, user_annotation).
make_annotated(val) := ret if {
	count(val) == 2
	ret := [val[0], val[1], null]
}

make_annotated(val) := ret if {
	count(val) == 3
	ret := val
}

merge_annotations(left, right) := null if {
	left == null
	right == null
} else := left if {
	right == null
} else := right

# NOTE: comprehension idx triggers here, this is important.
forward_left_foreign_keys := {idx: ret |
	relation := data.relations.relations[_]
	[left_resource, _, _] := make_annotated(relation.keys.left[_])
	idx := [relation.name, make_resource_key(left_resource)]
	ret := {[k, ann] |
		relation := data.relations.relations[_]
		[left_resource, k, ann] := make_annotated(relation.keys.left[_])
		idx == [relation.name, make_resource_key(left_resource)]
	}
}

# NOTE: comprehension idx triggers here, this is important.
forward_right_foreign_keys := {idx: ret |
	relation := data.relations.relations[_]
	[_, key, _] := make_annotated(relation.keys.right[_])
	idx := [relation.name, key]
	ret := {[right_resource, ann] |
		relation := data.relations.relations[_]
		[right_resource, k, ann] := make_annotated(relation.keys.right[_])
		idx == [relation.name, k]
	}
}

# NOTE: comprehension idx not strictly necessary here.
forward_keys := {idx: right_resource_ann_tuples |
	keys := forward_left_foreign_keys[idx]
	right_resource_ann_tuples := [[right_resource, ann] |
		[k, ann1] := keys[_]
		[name, _] := idx
		[right_resource, ann2] := forward_right_foreign_keys[[name, k]][_]
		ann := merge_annotations(ann1, ann2)
	]
}

forward_explicit := {idx: right_resource_ann_tuples |
	relation := data.relations.relations[_]
	pairs := object.get(relation, "explicit", [])
	[left_resource, _, _] := make_annotated(pairs[_])
	idx := [relation.name, make_resource_key(left_resource)]
	right_resource_ann_tuples := {[right_resource, ann] |
		relation := data.relations.relations[_]
		pairs := object.get(relation, "explicit", [])
		[l, right_resource, ann] := make_annotated(pairs[_])
		idx == [relation.name, make_resource_key(l)]
	}
}

forward := {idx: right_resource_ann_tuples |
	idxs := {k | _ := forward_keys[k]} | {k | _ := forward_explicit[k]}
	idx := idxs[_]
	right_resource_ann_tuples := array.concat(
		[r | r := forward_keys[idx][_]],
		[r | r := forward_explicit[idx][_]],
	)
}

# NOTE: comprehension idx triggers here, this is important.
backward_right_foreign_keys := {idx: ret |
	relation := data.relations.relations[_]
	[right_resource, _, _] := make_annotated(relation.keys.right[_])
	idx := [relation.name, make_resource_key(right_resource)]
	ret := {[k, ann] |
		relation := data.relations.relations[_]
		[right_resource, k, ann] := make_annotated(relation.keys.right[_])
		idx == [relation.name, make_resource_key(right_resource)]
	}
}

# NOTE: comprehension idx triggers here, this is important.
backward_left_foreign_keys := {idx: ret |
	relation := data.relations.relations[_]
	[_, key, _] := make_annotated(relation.keys.left[_])
	idx := [relation.name, key]
	ret := {[left_resource, ann] |
		relation := data.relations.relations[_]
		[left_resource, k, ann] := make_annotated(relation.keys.left[_])
		idx == [relation.name, k]
	}
}

# NOTE: comprehension idx not strictly necessary here.
backward_keys := {idx: left_resource_ann_tuples |
	keys := backward_right_foreign_keys[idx]
	left_resource_ann_tuples := [[left_resource, ann] |
		[k, ann1] := keys[_]
		[name, _] := idx
		[left_resource, ann2] := backward_left_foreign_keys[[name, k]][_]
		ann := merge_annotations(ann2, ann1)
	]
}

backward_explicit := {idx: left_resource_ann_tuples |
	relation := data.relations.relations[_]
	pairs := object.get(relation, "explicit", [])
	[_, right_resource] := pairs[_]
	idx := [relation.name, make_resource_key(right_resource)]
	left_resource_ann_tuples := {[left_resource, null] |
		relation := data.relations.relations[_]
		pairs := object.get(relation, "explicit", [])
		[left_resource, r] := pairs[_]
		idx == [relation.name, make_resource_key(r)]
	}
}

backward := {idx: left_resource_ann_tuples |
	idxs := {k | _ := backward_keys[k]} | {k | _ := backward_explicit[k]}
	idx := idxs[_]
	left_resource_ann_tuples := array.concat(
		[r | r := backward_keys[idx][_]],
		[r | r := backward_explicit[idx][_]],
	)
}
