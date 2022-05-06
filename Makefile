MODELS_DIR="pkg/models"

demo:
	go build
	./unified-policy-engine run \
		-d examples/metadata \
		-d examples/01-simple.rego \
		-d examples/02-simple-attributes.rego \
		-d examples/03-advanced.rego \
		-d examples/04-advanced-resources.rego \
		-d examples/05-advanced-primary-resource.rego \
		-d examples/06-advanced-attributes.rego \
		-d examples/07-missing.rego \
		examples/main.tf

swagger:
	rm -rf $(MODELS_DIR)
	docker run --rm -it \
		--volume $(shell pwd):/workspace \
		--user $(shell id -u):$(shell id -g) \
		--workdir /workspace \
		swaggerapi/swagger-codegen-cli-v3 \
		generate \
		-i swagger.yaml \
		-l go \
		-o $(MODELS_DIR) \
		--model-package models \
		-D packageName=models
	sed -i.bak \
		-e 's/Object/interface\{\}/g' \
		-e 's/OneOfRuleResultResourceAttributePathItems/interface\{\}/g' \
		-e 's/int32/int/g' \
		-e 's/\*State /State /g' \
		-e 's/Type_ /Type /g' \
		$(MODELS_DIR)/*.go
	rm -rf \
		$(MODELS_DIR)/*.bak \
		$(MODELS_DIR)/.swagger-codegen \
		$(MODELS_DIR)/api \
		$(MODELS_DIR)/docs \
		$(MODELS_DIR)/.gitignore \
		$(MODELS_DIR)/.swagger-codegen-ignore \
		$(MODELS_DIR)/.travis.yml \
		$(MODELS_DIR)/api_default.go \
		$(MODELS_DIR)/client.go \
		$(MODELS_DIR)/configuration.go \
		$(MODELS_DIR)/git_push.sh \
		$(MODELS_DIR)/model_one_of_rule_result_resource_attribute_path_items.go \
		$(MODELS_DIR)/README.md \
		$(MODELS_DIR)/response.go
	gofmt -w $(MODELS_DIR)/*.go
