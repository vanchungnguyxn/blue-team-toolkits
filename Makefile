.PHONY: install lint test run demo clean help

# Default target
help:
	@echo "Blue Team Toolkit - Available commands:"
	@echo "  install     Install package and dependencies"
	@echo "  lint        Run code linting (ruff + black)"
	@echo "  test        Run test suite"
	@echo "  run         Run bluetool with default config"
	@echo "  demo        Run demo with sample PCAP"
	@echo "  clean       Clean build artifacts"
	@echo "  init        Initialize config and database"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,geoip,performance]"

lint:
	ruff check src/ tests/
	black --check src/ tests/

lint-fix:
	ruff check --fix src/ tests/
	black src/ tests/

test:
	pytest tests/ -v

run:
	bluetool start --config examples/config.yaml

demo:
	bluetool demo

init:
	bluetool init

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
