.PHONY: sync lint format format-check typecheck test check run-mock clean docker-build docker-push deploy-trust gcp-release enclave-go-build

ENCLAVE_DIR  := enclave-go
PARENT_DIR   := parent
REGISTRY     := 330422590279.dkr.ecr.us-east-1.amazonaws.com
REPO         := quill-cloud-proxy
TRUST_BUCKET := trust.quill.lorehex.co
GOLANGCI_LINT_VERSION := v1.64.8
GOLANGCI_LINT_MODULE := github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GO_TAGS := cloud_aws,llm_bedrock cloud_aws,llm_openrouter cloud_gcp,llm_vertex cloud_gcp,llm_openrouter

# ---- Go enclave -----------------------------------------------------------

enclave-go-build:
	cd $(ENCLAVE_DIR) && for tags in $(GO_TAGS); do go build -tags "$$tags" ./...; done

enclave-go-test:
	cd $(ENCLAVE_DIR) && for tags in $(GO_TAGS); do go test -tags "$$tags" ./...; done

enclave-go-vet:
	cd $(ENCLAVE_DIR) && for tags in $(GO_TAGS); do go vet -tags "$$tags" ./...; done

enclave-go-lint:
	cd $(ENCLAVE_DIR) && for tags in $(GO_TAGS); do \
		if command -v golangci-lint >/dev/null 2>&1; then \
			golangci-lint run --build-tags "$$tags"; \
		else \
			go run $(GOLANGCI_LINT_MODULE) run --build-tags "$$tags"; \
		fi; \
	done

# ---- Python parent --------------------------------------------------------

sync:
	cd $(PARENT_DIR) && uv sync

lint:
	cd $(PARENT_DIR) && uv run ruff check src tests

format:
	cd $(PARENT_DIR) && uv run ruff format src tests

format-check:
	cd $(PARENT_DIR) && uv run ruff format --check src tests

typecheck:
	cd $(PARENT_DIR) && uv run mypy --strict --python-version 3.11 src tests

test:
	cd $(PARENT_DIR) && uv run pytest

check: lint format-check typecheck test enclave-go-build enclave-go-lint enclave-go-test

run-mock:
	cd $(PARENT_DIR) && QUILL_TRANSPORT=unix-socket uv run uvicorn quill_parent.main:app --host 127.0.0.1 --port 8443

# ---- Docker images (multi-arch) -------------------------------------------

docker-build:
	docker buildx build --platform linux/arm64 -t $(REGISTRY)/$(REPO):enclave-latest -f $(ENCLAVE_DIR)/Dockerfile.enclave $(ENCLAVE_DIR)
	docker buildx build --platform linux/arm64 -t $(REGISTRY)/$(REPO):parent-latest  -f $(PARENT_DIR)/Dockerfile.parent $(PARENT_DIR)

docker-push:
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $(REGISTRY)
	docker buildx build --platform linux/arm64 --push -t $(REGISTRY)/$(REPO):enclave-latest -f $(ENCLAVE_DIR)/Dockerfile.enclave $(ENCLAVE_DIR)
	docker buildx build --platform linux/arm64 --push -t $(REGISTRY)/$(REPO):parent-latest  -f $(PARENT_DIR)/Dockerfile.parent $(PARENT_DIR)

# ---- Trust page -----------------------------------------------------------

deploy-trust:
	aws s3 sync trust-page/ s3://$(TRUST_BUCKET)/ --exclude "build.sh" --cache-control "max-age=60, public" --content-type "text/html; charset=utf-8"
	aws s3 cp trust-page/pcr0.txt s3://$(TRUST_BUCKET)/pcr0.txt --cache-control "max-age=60, public" --content-type "text/plain; charset=utf-8"
	aws s3 cp trust-page/image-digest-gcp.txt s3://$(TRUST_BUCKET)/image-digest-gcp.txt --cache-control "max-age=60, public" --content-type "text/plain; charset=utf-8"
	aws s3 cp trust-page/image-reference-gcp.txt s3://$(TRUST_BUCKET)/image-reference-gcp.txt --cache-control "max-age=60, public" --content-type "text/plain; charset=utf-8"
	aws s3 cp trust-page/gcp-release.json s3://$(TRUST_BUCKET)/gcp-release.json --cache-control "max-age=60, public" --content-type "application/json"

gcp-release:
	./tools/release-gcp.sh

# ---- Clean ---------------------------------------------------------------

clean:
	find . -type d \( -name __pycache__ -o -name .mypy_cache -o -name .ruff_cache -o -name .pytest_cache \) -exec rm -rf {} +
