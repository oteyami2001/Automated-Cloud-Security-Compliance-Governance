# Offline developer checks (the same steps as .github/workflows/ci.yml). None of these call AWS.
PYTHON ?= python3

.PHONY: check catalog test lint sast docs docs-check suppressions package terraform

check: lint sast catalog docs-check suppressions test

catalog:
	$(PYTHON) scripts/validate_catalog.py

test:
	$(PYTHON) -m pytest --cov=src/acscg --cov-report=term-missing --cov-fail-under=90

lint:
	ruff check .
	ruff format --check .

sast:
	bandit -q -r src scripts -c pyproject.toml

docs:
	$(PYTHON) scripts/render_control_tables.py
	$(PYTHON) scripts/sync_diagrams.py
	$(PYTHON) scripts/build_lambda.py --catalog-only

docs-check:
	$(PYTHON) scripts/render_control_tables.py --check
	$(PYTHON) scripts/sync_diagrams.py --check
	$(PYTHON) scripts/build_lambda.py --check

suppressions:
	$(PYTHON) scripts/check_suppressions.py

package:
	$(PYTHON) scripts/build_lambda.py

terraform:
	terraform fmt -check -recursive terraform
	for d in terraform/modules/* terraform/bootstrap; do \
	  terraform -chdir=$$d init -backend=false -input=false >/dev/null && \
	  terraform -chdir=$$d validate && terraform -chdir=$$d test || exit 1; done
	terraform -chdir=terraform/stack init -backend=false -input=false >/dev/null
	terraform -chdir=terraform/stack validate
	terraform -chdir=terraform/stack test -filter=tests/stack.tftest.hcl
	for e in dev staging prod; do \
	  terraform -chdir=terraform/stack test -filter=tests/environments.tftest.hcl -var-file=../envs/$$e/terraform.tfvars || exit 1; done
