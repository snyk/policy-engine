package rules.snyk_011.tf

import data.snyk

metadata := {
	"id": "EXAMPLE-011",
	"title": "Kubernetes pod is connected to ingress",
	"kind": "finding",
	"category": "public_exposure",
}

pods := snyk.resources("kubernetes_pod")

deny contains info if {
	pod := pods[_]
	service := snyk.relates(pod, "kubernetes_pod.service")[_]
	ingress := snyk.relates(service, "kubernetes_service_v1.ingress")[_]

	info := {
		"resource": pod,
		"graph": [
			{
				"source": ingress,
				"label": "exposes",
				"target": service,
			},
			{
				"source": service,
				"label": "exposes",
				"target": pod,
			},
		],
	}
}
