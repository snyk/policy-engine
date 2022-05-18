package snyk.terraform

# Checks if the provider used for the resource is compatible with the given
# constraint.
#
# See <https://www.terraform.io/language/expressions/version-constraints>.
resource_provider_version_constraint(resource, constraints) {
	meta := object.get(resource, "_meta", {})
	terraform := object.get(meta, "terraform", {})
	resource_constraints := object.get(terraform, "provider_version_constraint", "")
	semver_constraints_intersect(resource_constraints, constraints)
}

semver_constraints_intersect(constraints1, constraints2) {
	lhs_constraints := parse_semver_constraints(constraints1)
	rhs_constraints := parse_semver_constraints(constraints2)
	count([true |
		[lop, lhs] = lhs_constraints[_]
		[rop, rhs] = rhs_constraints[_]
		not semver_constraints_intersect_4(lop, lhs, rop, rhs)
	]) == 0
}

semver_constraints_intersect_4("=", lhs, rop, rhs) {
	rop == "="
	lhs == rhs
} else {
	rop == "!="
	lhs != rhs
} else {
	rop == ">"
	lhs > rhs
} else {
	rop == ">="
	lhs >= rhs
} else {
	rop == "<"
	lhs < rhs
} else {
	rop == "<="
	lhs <= rhs
} else {
	rop == "~>"
	[major, minor, _] = rhs
	lhs >= rhs
	lhs < [major, minor + 1, 0]
}

semver_constraints_intersect_4("!=", lhs, rop, rhs) {
	rop == "="
	lhs != rhs
} else {
	rop == "!="
} else {
	rop == ">"
} else {
	rop == ">="
} else {
	rop == "<"
} else {
	rop == "<="
} else {
	rop == "~>"
}

semver_constraints_intersect_4(">", lhs, rop, rhs) {
	rop == "="
	lhs < rhs
} else {
	rop == "!="
} else {
	rop == ">"
} else {
	rop == ">="
} else {
	rop == "<"
	lhs < rhs
} else {
	rop == "<="
	lhs < rhs
} else {
	rop == "~>"
	lhs < rhs
}

semver_constraints_intersect_4(">=", lhs, rop, rhs) {
	rop == "="
	lhs <= rhs
} else {
	rop == "!="
} else {
	rop == ">"
} else {
	rop == ">="
} else {
	rop == "<"
	lhs < rhs
} else {
	rop == "<="
	lhs <= rhs
} else {
	rop == "~>"
	lhs <= rhs
}

semver_constraints_intersect_4("<", lhs, rop, rhs) {
	rop == "="
	lhs > rhs
} else {
	rop == "!="
} else {
	rop == ">"
	lhs > rhs
} else {
	rop == ">="
	lhs > rhs
} else {
	rop == "<"
} else {
	rop == "<="
} else {
	rop == "~>"
	lhs > rhs
}

semver_constraints_intersect_4("<=", lhs, rop, rhs) {
	rop == "="
	lhs >= rhs
} else {
	rop == "!="
} else {
	rop == ">"
	lhs > rhs
} else {
	rop == ">="
	lhs >= rhs
} else {
	rop == "<"
} else {
	rop == "<="
} else {
	rop == "~>"
	lhs >= rhs
}

semver_constraints_intersect_4("~>", lhs, rop, rhs) {
	rop == "="
	[lhs_major, lhs_minor, _] = lhs
	lhs <= rhs
	[lhs_major, lhs_minor + 1, 0] > rhs
} else {
	rop == "!="
} else {
	rop == ">"
	lhs > rhs
} else {
	rop == ">="
	lhs >= rhs
} else {
	rop == "<"
	lhs < rhs
} else {
	rop == "<="
	lhs <= rhs
} else {
	rop == "~>"
	[lhs_major, lhs_minor, _] = lhs
	[rhs_major, rhs_minor, _] = rhs
	[lhs_major, lhs_minor] == [rhs_major, rhs_minor]
}

# Parse semver, padding with "0"
parse_semver(str) = ret {
	[major, minor, patch] = split(str, ".")
	ret = [to_number(major), to_number(minor), to_number(patch)]
} else = ret {
	[major, minor] = split(str, ".")
	ret = [to_number(major), to_number(minor), 0]
} else = ret {
	[major] = split(str, ".")
	ret = [to_number(major), 0, 0]
}

parse_semver_constraints(str) = ret {
	tokens := split(str, ",")
	ret := {[operator, semver] |
		token := tokens[_]
		not regex.match(`^\s*$`, token)
		[[_, operator, semver_str]] = regex.find_all_string_submatch_n(`^\s*([=!<>~]+)\s*([\d\.]*)\s*$`, token, -1)
		semver := parse_semver(semver_str)
	}
}
