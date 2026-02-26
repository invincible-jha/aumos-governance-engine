.PHONY: install test test-quick lint format typecheck clean all migrate docker-build docker-run docker-down

all: lint typecheck test

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=aumos_governance_engine --cov-report=term-missing

test-quick:
	pytest tests/ -x -q --no-header

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

typecheck:
	mypy src/aumos_governance_engine/

migrate:
	alembic -c src/aumos_governance_engine/migrations/alembic.ini upgrade head

migrate-audit:
	@echo "Run migrations on audit DB separately using AUMOS_GOVERNANCE_AUDIT_DB_URL"
	AUMOS_DATABASE_URL=$${AUMOS_GOVERNANCE_AUDIT_DB_URL} alembic -c src/aumos_governance_engine/migrations/alembic.ini upgrade head

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .mypy_cache -exec rm -rf {} +
	rm -rf dist/ build/ *.egg-info

docker-build:
	docker build -t aumos/governance-engine:dev .

docker-run:
	docker compose -f docker-compose.dev.yml up -d

docker-down:
	docker compose -f docker-compose.dev.yml down

docker-logs:
	docker compose -f docker-compose.dev.yml logs -f app

opa-check:
	curl -s http://localhost:8181/health | python -m json.tool
