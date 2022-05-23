package snyk.terraform

test_resource_provider_version_constraint {
	resource_provider_version_constraint({}, ">=3")
	resource_provider_version_constraint({"_meta": {"terraform": {"provider_version_constraint": "~> 3.0"}}}, ">=3")
	not resource_provider_version_constraint({"_meta": {"terraform": {"provider_version_constraint": "~> 3.0"}}}, ">=4")
}

test_semver_constraints_intersect {
	do_intersect("=2.4", ">= 2.2, <2.5")
	dont_intersect("=2.5", ">= 2.2, <2.5")

	do_intersect("=2.4", ">= 0.0, <7.0, !=6.6.6")
	dont_intersect("=6.6.6", ">= 0.0, <7.0, !=6.6.6")

	do_intersect("~>2.4", "= 2.4.0")
	dont_intersect("~>2.4", "= 3")

	do_intersect("~>2.4", "> 2.3")
	do_intersect("~>2.4", "< 3")

	do_intersect("= 1.2.3", "~> 1.2.3")
	do_intersect("= 1.2.4", "~> 1.2.3")
	dont_intersect("= 1.3.0", "~> 1.2.3")
	dont_intersect("= 1.2.2", "~> 1.2.3")

	do_intersect("=1", "=1")
	do_intersect("=1", "")
	do_intersect("", "=1")
	do_intersect(">=3, <4", "~>3.0.0")
	dont_intersect(">=3, <4", "~>4.0.0")
	do_intersect(">=3, <4", "!=3.0.0")
	dont_intersect(">=3, <4", "<2.0.0")
	do_intersect("~>3.0.0", ">=3")

	do_intersect("<= 2", "~>1.0.0")
	dont_intersect("<= 2", "~>3.0.0")

	do_intersect("~>1.0.1", "~>1.0.0")
	dont_intersect("~1.1.0", "~>1.0.0")
	do_intersect("~>1.0.1", "!=1.0.1")

	do_intersect("=1.0.0", "<=1.0.0")
	do_intersect("!=1.0.0", "<=1.0.0")
	dont_intersect(">1.0.0", "<=1.0.0")
	dont_intersect("<=1.0.0", ">1.0.0")
	# do_intersect(">1.0.0", "<=1.2.3")
	do_intersect(">=1.0.0", "<=1.0.0")
	do_intersect("<1.0.0", "<=1.0.0")
	do_intersect("<=2.0.0", "<=1.0.0")
}

# Intersection of constraints commutes, so it's useful to check it in both
# directions to get better test coverage.  This is a utility for that.
do_intersect(l, r) {
    semver_constraints_intersect(l, r)
    semver_constraints_intersect(r, l)
}

# See `do_intersect`.
dont_intersect(l, r) {
    not semver_constraints_intersect(l, r)
    not semver_constraints_intersect(r, l)
}
