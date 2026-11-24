# Offline developer checks. None of these targets call AWS.
PYTHON ?= python3

.PHONY: check catalog test lint docs docs-check

check: catalog test lint docs-check

catalog:
	$(PYTHON) scripts/validate_catalog.py

test:
	$(PYTHON) -m pytest

lint:
	ruff check .
	ruff format --check .

docs:
	$(PYTHON) scripts/render_control_tables.py
	$(PYTHON) scripts/sync_diagrams.py

docs-check:
	$(PYTHON) scripts/render_control_tables.py --check
	$(PYTHON) scripts/sync_diagrams.py --check
