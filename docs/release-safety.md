# Release Safety Notes

This portfolio repository should ship sanitized code and examples only.

Do not redistribute:
- `.env` with local secrets
- local DB files (`*.db`, `*.db-*`)
- generated exports (`exports/*.json`, `exports/*.pdf`, `exports/rag_indexes/*`)
- local virtual environments (`.venv`)

Before publishing:
1. Run `release-safety-check.cmd`.
2. Keep `exports/` placeholder-only.
3. Verify examples contain sanitized data only.
