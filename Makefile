.PHONY: dev lint test build clean

dev:
	pip install -e ".[dev]"

lint:
	ruff check src/
	ruff format --check src/
	mypy src/ --strict

test:
	pytest tests/ -v --cov=src/ --cov-report=term-missing

build:
	python -m build

clean:
	rm -rf dist/ build/ *.egg-info
