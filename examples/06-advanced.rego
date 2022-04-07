package rules.snyk_006.tf

pods := snyk.resources("kubernetes_pod")

is_privileged_paths(pod) = paths {
	paths := [path |
		is_privileged(pod.spec[0].container[i])
		path := ["spec", "container", i, "security_context", 0, "privileged"]
	]
}

is_privileged(container) {
	container.security_context[0].privileged == true
} else {
	container.security_context[0].privileged == "true"
} else = false {
	true
}

# We can write an issue without worrying about the specific paths
deny[info] {
	pod := pods[_]
	is_privileged(pod.spec[0].container[_])
	info := {
		"resource": pod,
		"message": "Pod contains container running in privileged mode",
	}
}

# We can include the failing paths in the resource locations
location[info] {
	pod := pods[_]
	info := {"resource": pod, "attributes": is_privileged_paths(pod)}
}
