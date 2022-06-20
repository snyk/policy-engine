MODELS_DIR="pkg/models"

demo:
	go build
	./policy-engine run \
		-d examples/metadata \
		-d examples/01-simple.rego \
		-d examples/02-simple-attributes.rego \
		-d examples/03-advanced.rego \
		-d examples/04-advanced-resources.rego \
		-d examples/05-advanced-primary-resource.rego \
		-d examples/06-advanced-correlation.rego \
		-d examples/07-advanced-attributes.rego \
		-d examples/08-missing.rego \
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
		-e 's/\*\[]SourceLocation /[]SourceLocation /g' \
		-e 's/\tResources \[]RuleResultResource /\tResources []*RuleResultResource /g' \
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

.PHONY: install_tools
install_tools:
	go install github.com/golang/mock/mockgen@v1.6.0
	go install github.com/goreleaser/goreleaser@v1.9.2
	go install github.com/miniscruff/changie@v1.7.0

ifndef VERSION
$(error VERSION should be set to vX.Y.Z)
endif

.PHONY: release
release:
	changie batch $(VERSION)
	change merge
	git add changes/$(VERSION).md CHANGELOG.md
	git commit -m "Bump version to $(VERSION)"
	git tag -a -F changes/$(VERSION).md $(VERSION)
	git push origin main $(VERSION)
