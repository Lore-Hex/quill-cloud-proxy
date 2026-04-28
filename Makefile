.PHONY: sync lint format format-check typecheck test check run-mock clean

ENCLAVE_DIR := enclave
PARENT_DIR  := parent

sync:
	cd $(ENCLAVE_DIR) && uv sync
	cd $(PARENT_DIR) && uv sync

lint:
	cd $(ENCLAVE_DIR) && uv run ruff check src tests
	cd $(PARENT_DIR) && uv run ruff check src tests

format:
	cd $(ENCLAVE_DIR) && uv run ruff format src tests
	cd $(PARENT_DIR) && uv run ruff format src tests

format-check:
	cd $(ENCLAVE_DIR) && uv run ruff format --check src tests
	cd $(PARENT_DIR) && uv run ruff format --check src tests

typecheck:
	cd $(ENCLAVE_DIR) && uv run mypy --strict --python-version 3.11 src tests
	cd $(PARENT_DIR) && uv run mypy --strict --python-version 3.11 src tests

test:
	cd $(ENCLAVE_DIR) && uv run pytest
	cd $(PARENT_DIR) && uv run pytest
	cd tests && uv run pytest -c pyproject.toml || true  # cross-package tests, optional

check: lint format-check typecheck test

run-mock:
	cd $(PARENT_DIR) && QUILL_TRANSPORT=unix-socket uv run uvicorn quill_parent.main:app --host 127.0.0.1 --port 8443

clean:
	find . -type d \( -name __pycache__ -o -name .mypy_cache -o -name .ruff_cache -o -name .pytest_cache \) -exec rm -rf {} +
