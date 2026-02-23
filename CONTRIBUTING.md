# Contributing

## Scope
- This repository is for educational/research cyber risk analysis workflows.
- It is not a production security product.

## Setup
1. `py -3 -m pip install -e ".[dev]"`
2. `pre-commit install`
3. `pytest`

## Required checks
- `ruff check .`
- `ruff format --check .`
- `mypy`
- `pytest`

## Rules for contributions
- Keep behavior stable unless fixing a clear bug.
- Add deterministic tests for functional changes.
- Never commit secrets, API keys, or sensitive data.
