package snyk.terraform

test_resource_provider_version_constraint {
	resource_provider_version_constraint({}, ">=3")
	resource_provider_version_constraint({"_meta": {"terraform": {"provider_version_constraint": "~> 3.0"}}}, ">=3")
	not resource_provider_version_constraint({"_meta": {"terraform": {"provider_version_constraint": "~> 3.0"}}}, ">=4")
}

test_semver_constraints_intersect {
	semver_constraints_intersect("=2.4", ">= 2.2, <2.5")
	not semver_constraints_intersect("=2.5", ">= 2.2, <2.5")

	semver_constraints_intersect("=2.4", ">= 0.0, <7.0, !=6.6.6")
	not semver_constraints_intersect("=6.6.6", ">= 0.0, <7.0, !=6.6.6")

	semver_constraints_intersect("~>2.4", "= 2.4.0")
	not semver_constraints_intersect("~>2.4", "= 3")

	semver_constraints_intersect("~>2.4", "> 2.3")
	semver_constraints_intersect("~>2.4", "< 3")

	semver_constraints_intersect("= 1.2.3", "~> 1.2.3")
	semver_constraints_intersect("= 1.2.4", "~> 1.2.3")
	not semver_constraints_intersect("= 1.3.0", "~> 1.2.3")
	not semver_constraints_intersect("= 1.2.2", "~> 1.2.3")

	semver_constraints_intersect("=1", "=1")
	semver_constraints_intersect("=1", "")
	semver_constraints_intersect("", "=1")
	semver_constraints_intersect(">=3, <4", "~>3.0.0")
	not semver_constraints_intersect(">=3, <4", "~>4.0.0")
	semver_constraints_intersect(">=3, <4", "!=3.0.0")
	not semver_constraints_intersect(">=3, <4", "<2.0.0")
	semver_constraints_intersect("~>3.0.0", ">=3")
}
