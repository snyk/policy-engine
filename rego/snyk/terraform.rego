# © 2022-2023 Snyk Limited All rights reserved.
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

package snyk.terraform

# Checks if the provider used for the resource is compatible with the given
# constraint.
#
# See <https://www.terraform.io/language/expressions/version-constraints>.
resource_provider_version_constraint(resource, constraints) if {
	meta := object.get(resource, "_meta", {})
	terraform := object.get(meta, "terraform", {})
	resource_constraints := object.get(terraform, "provider_version_constraint", "")
	semver_constraints_intersect(resource_constraints, constraints)
}

semver_constraints_intersect(constraints1, constraints2) if {
	lhs_constraints := parse_semver_constraints(constraints1)
	rhs_constraints := parse_semver_constraints(constraints2)
	count([true |
		[lop, lhs] = lhs_constraints[_]
		[rop, rhs] = rhs_constraints[_]
		not semver_constraints_intersect_4(lop, lhs, rop, rhs)
	]) == 0
}

semver_constraints_intersect_4("=", lhs, rop, rhs) if {
	rop == "="
	lhs == rhs
} else if {
	rop == "!="
	lhs != rhs
} else if {
	rop == ">"
	lhs > rhs
} else if {
	rop == ">="
	lhs >= rhs
} else if {
	rop == "<"
	lhs < rhs
} else if {
	rop == "<="
	lhs <= rhs
} else if {
	rop == "~>"
	[major, minor, _] = rhs
	lhs >= rhs
	lhs < [major, minor + 1, 0]
}

semver_constraints_intersect_4("!=", lhs, rop, rhs) if {
	rop == "="
	lhs != rhs
} else if {
	rop == "!="
} else if {
	rop == ">"
} else if {
	rop == ">="
} else if {
	rop == "<"
} else if {
	rop == "<="
} else if {
	rop == "~>"
}

semver_constraints_intersect_4(">", lhs, rop, rhs) if {
	rop == "="
	lhs < rhs
} else if {
	rop == "!="
} else if {
	rop == ">"
} else if {
	rop == ">="
} else if {
	rop == "<"
	lhs < rhs
} else if {
	rop == "<="
	lhs < rhs
} else if {
	rop == "~>"
	lhs < rhs
}

semver_constraints_intersect_4(">=", lhs, rop, rhs) if {
	rop == "="
	lhs <= rhs
} else if {
	rop == "!="
} else if {
	rop == ">"
} else if {
	rop == ">="
} else if {
	rop == "<"
	lhs < rhs
} else if {
	rop == "<="
	lhs <= rhs
} else if {
	rop == "~>"
	lhs <= rhs
}

semver_constraints_intersect_4("<", lhs, rop, rhs) if {
	rop == "="
	lhs > rhs
} else if {
	rop == "!="
} else if {
	rop == ">"
	lhs > rhs
} else if {
	rop == ">="
	lhs > rhs
} else if {
	rop == "<"
} else if {
	rop == "<="
} else if {
	rop == "~>"
	lhs > rhs
}

semver_constraints_intersect_4("<=", lhs, rop, rhs) if {
	rop == "="
	lhs >= rhs
} else if {
	rop == "!="
} else if {
	rop == ">"
	lhs > rhs
} else if {
	rop == ">="
	lhs >= rhs
} else if {
	rop == "<"
} else if {
	rop == "<="
} else if {
	rop == "~>"
	lhs >= rhs
}

semver_constraints_intersect_4("~>", lhs, rop, rhs) if {
	rop == "="
	[lhs_major, lhs_minor, _] = lhs
	lhs <= rhs
	[lhs_major, lhs_minor + 1, 0] > rhs
} else if {
	rop == "!="
} else if {
	rop == ">"
	lhs > rhs
} else if {
	rop == ">="
	lhs >= rhs
} else if {
	rop == "<"
	lhs < rhs
} else if {
	rop == "<="
	lhs <= rhs
} else if {
	rop == "~>"
	[lhs_major, lhs_minor, _] = lhs
	[rhs_major, rhs_minor, _] = rhs
	[lhs_major, lhs_minor] == [rhs_major, rhs_minor]
}

# Parse semver, padding with "0"
parse_semver(str) := ret if {
	[major, minor, patch] = split(str, ".")
	ret = [to_number(major), to_number(minor), to_number(patch)]
} else := ret if {
	[major, minor] = split(str, ".")
	ret = [to_number(major), to_number(minor), 0]
} else := ret if {
	[major] = split(str, ".")
	ret = [to_number(major), 0, 0]
}

parse_semver_constraints(str) := ret if {
	tokens := split(str, ",")
	ret := {[operator, semver] |
		token := tokens[_]
		not regex.match(`^\s*$`, token)
		[[_, operator, semver_str]] = regex.find_all_string_submatch_n(`^\s*([=!<>~]+)\s*([\d\.]*)\s*$`, token, -1)
		semver := parse_semver(semver_str)
	}
}
