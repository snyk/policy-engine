demo:
	go build
	./unified-policy-engine \
		-d examples/01-simple.rego \
		-d examples/02-simple-attributes.rego \
		-d examples/03-advanced.rego \
		-d examples/04-advanced.rego \
		-d examples/05-advanced.rego \
		-d examples/06-missing.rego \
		examples/main.tf
