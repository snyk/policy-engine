package snyk.terraform

test_semver_constraints {
	semver_constraints_ok("2.4", ">= 2.2, <2.5")
	not semver_constraints_ok("2.5", ">= 2.2, <2.5")

	semver_constraints_ok("2.4", ">= 0.0, <7.0, !=6.6.6")
	not semver_constraints_ok("6.6.6", ">= 0.0, <7.0, !=6.6.6")
}

test_semver_constraint {
	semver_constraint_ok("2.4", "= 2.4.0")
	not semver_constraint_ok("2.4", "= 3")

	semver_constraint_ok("2.4", "> 2.3")
	semver_constraint_ok("2.4", "< 3")

	semver_constraint_ok("1.2.3", "~> 1.2.3")
	semver_constraint_ok("1.2.4", "~> 1.2.3")
	not semver_constraint_ok("1.3.0", "~> 1.2.3")
	not semver_constraint_ok("1.2.2", "~> 1.2.3")
}
