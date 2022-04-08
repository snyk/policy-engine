# Just like in simple rules, we can return attribute metadata so the users
# of this policy know where the problem is.
#
# This advanced rule checks for privileged mode in containers, and as such may
# return multiple attributes, as multiple containers may be in violation.
package rules.snyk_006.tf

pods := snyk.resources("kubernetes_pod")

is_privileged(container) {
	container.security_context[0].privileged == true
} else {
	container.security_context[0].privileged == "true"
} else = false {
	true
}

privileged_paths(pod) = paths {
	paths := [path |
		is_privileged(pod.spec[0].container[i])
		path := ["spec", "container", i, "security_context", 0, "privileged"]
	]
}

# We can write an issue without worrying about the specific paths.
deny[info] {
	pod := pods[_]
	count(privileged_paths(pod)) > 0
	info := {
		"resource": pod,
		"message": "Pod contains container running in privileged mode",
	}
}

# We can include the failing paths in the resource locations.
resources[info] {
	pod := pods[_]
	info := {"resource": pod, "attributes": privileged_paths(pod)}
}
