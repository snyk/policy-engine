demo:
	go build
	./upe \
		-d examples/rule.rego \
		-d examples/advanced.rego \
		-d examples/advanced2.rego \
		examples/main.tf
