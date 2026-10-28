.PHONY: install data data-local test ml eval api setup deploy lint fmt check clean

install:
	uv sync

data:
	uv run python -m data.pipeline

data-local:
	uv run python -m data.pipeline --local

test:
	uv run pytest

ml:
	uv run python -m data.build_features
	uv run python -m data.train_ml

eval:
	uv run python -m evals.run_eval

api:
	uv run uvicorn api.main:app --reload --port 8080

setup:
	./infra/setup.sh

deploy:
	./infra/deploy.sh

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

check: lint test

clean:
	rm -rf data/raw data/clean .pytest_cache .ruff_cache
