MODELS_DIR="pkg/models"

GO_SOURCE = $(shell find cmd pkg rego -type f -name '*.go') $(shell find pkg rego -type f -name '*.rego')
CLI_SOURCE = $(GO_SOURCE) go.mod go.sum
CURRENT_VERSION=$(shell awk '/^\#\# v[0-9]/ { print $$2 }' CHANGELOG.md | head -n 1 | sed 's/^v//')
GITCOMMIT=$(shell git rev-parse --short HEAD 2> /dev/null || true)

# Hardcoding -dev here to make it easier to distinguish between ad-hoc builds
# and goreleaser builds.
define LDFLAGS
	-X \"github.com/snyk/policy-engine/pkg/version.Version=$(CURRENT_VERSION)-dev\"
endef

policy-engine: $(CLI_SOURCE)
	go build -ldflags="$(LDFLAGS)"

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
	rm -f $(MODELS_DIR)/model_*.go
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

PLAIN_VERSION := $(VERSION:v%=%)

.PHONY: release
release:
	@echo "Testing if $(VERSION) is set..."
	test $(VERSION)
	changie batch $(VERSION)
	changie merge
	git checkout -b release/$(PLAIN_VERSION)
	git add changes CHANGELOG.md
	git diff --staged
	@echo -n "Are you sure? [y/N] " && read ans && [ $${ans:-N} == y ]
	git commit -m "Bump version to $(VERSION)"
	git push origin release/$(PLAIN_VERSION)
	@echo "Go to https://github.com/snyk/policy-engine/compare/release/$(PLAIN_VERSION)?expand=1"

TERRAFORM_VERSION=1.0.10

.PHONY: vendor_terraform
vendor_terraform:
	curl -Lo terraform.zip https://github.com/hashicorp/terraform/archive/refs/tags/v$(TERRAFORM_VERSION).zip
	unzip -o terraform.zip
	mkdir -p pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/addrs pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/configs pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/didyoumean pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/experiments pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/getproviders pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/httpclient pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/instances pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/lang pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/logging pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/modsdir pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/registry pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/tfdiags pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/internal/typeexpr pkg/internal/terraform
	cp -r terraform-$(TERRAFORM_VERSION)/version pkg/internal/terraform
	cp terraform-$(TERRAFORM_VERSION)/LICENSE pkg/internal/terraform
	find pkg/internal/terraform/ -name '*.go' \
		-exec sed -i".bak" 's#github\.com/hashicorp/terraform/internal/#github.com/snyk/policy-engine/pkg/internal/terraform/#' '{}' \;
	find pkg/internal/terraform/ -name '*.go' \
		-exec sed -i".bak" 's#github\.com/hashicorp/terraform/version#github.com/snyk/policy-engine/pkg/internal/terraform/version#' '{}' \;
	find pkg/internal/terraform/ -name '*.bak' -delete
	find pkg/internal/terraform/ -name '*_test.go' -delete
	git apply patches/terraform.patch
	rm -rf terraform.zip terraform-$(TERRAFORM_VERSION)
