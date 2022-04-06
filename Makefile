demo:
	go build
	./unified-policy-engine \
		-d examples/rule.rego \
		-d examples/advanced.rego \
		-d examples/advanced2.rego \
		examples/main.tf
