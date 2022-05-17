package snyk.terraform

# Verifies that a semver satisfies a constraint.
# See <https://www.terraform.io/language/expressions/version-constraints>.
semver_constraints_ok(semver, constraints) {
	not semver_constraints_fail(semver, constraints)
}

semver_constraints_fail(semver, constraints) {
	constraint = split(constraints, ",")[_]
	semver_constraint_fail(semver, constraint)
}

semver_constraint_fail(semver, constraint) {
	not semver_constraint_ok(semver, constraint)
}

semver_constraint_ok(semver, constraint) {
	lhs = parse_semver(semver)
	[[_, operator, rhs_str]] = regex.find_all_string_submatch_n(`^\s*([=!<>~]+)\s*([\d\.]*)\s*$`, constraint, -1)
	rhs = parse_semver(rhs_str)
	semver_constraint_operator(lhs, operator, rhs)
}

semver_constraint_operator(lhs, "=", rhs) {
	lhs == rhs
}

semver_constraint_operator(lhs, "!=", rhs) {
	lhs != rhs
}

semver_constraint_operator(lhs, ">", rhs) {
	lhs > rhs
}

semver_constraint_operator(lhs, ">=", rhs) {
	lhs >= rhs
}

semver_constraint_operator(lhs, "<", rhs) {
	lhs < rhs
}

semver_constraint_operator(lhs, "<=", rhs) {
	lhs <= rhs
}

semver_constraint_operator(lhs, "~>", rhs) {
	[major, minor, _] = rhs
	lhs >= rhs
	lhs < [major, minor + 1, 0]
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
