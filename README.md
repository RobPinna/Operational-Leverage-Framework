# Operational Leverage Framework

Operational Leverage Framework is an evidence-first CTI/cyber risk assessment project that maps public exposure signals into actionable confidence outputs.

## Prerequisites
- Python `>=3.11` (from `pyproject.toml`).
- Optional: `OPENAI_API_KEY` only if you want OpenAI-backed reasoning features.

## Quickstart (One Command)
From repository root:

```bash
python scripts/run.py web
```

This command will:
- create `.venv` if missing (or fall back to your current Python if `.venv` creation is blocked),
- install dependencies (`pip install -e ".[dev]"` when supported, otherwise `requirements.txt`),
- start FastAPI on `http://127.0.0.1:56461`,
- open the browser automatically.

No manual `.env` setup is required for local UI startup.
If `.env` is missing, runtime-safe local defaults are generated for `SECRET_KEY`, `PASSWORD_PEPPER`, and `API_KEY_PEPPER`.

Run without auto-opening the browser:

```bash
python scripts/run.py web --no-browser
```

## Cross-Platform Commands
- Setup: `python scripts/run.py setup --venv`
- Test: `python scripts/run.py test`
- CLI default scenario: `python scripts/run.py cli`
- CLI custom args: `python scripts/run.py cli -- examples/scenario_hospitality/input.json --out examples/output/hospitality.json --risk-type impersonation`
- Web app: `python scripts/run.py web`
- Safety checks: `python scripts/run.py safety`

## Advanced Configuration (`.env` Optional)
For stable secrets or custom runtime settings, create `.env` from `.env.example`.

```bash
cp .env.example .env
```

Windows CMD:

```bat
copy .env.example .env
```

Replace placeholders in `.env`:
- `SECRET_KEY=change-me-exposuremapper-secret`
- `PASSWORD_PEPPER=change-me-password-pepper`
- `API_KEY_PEPPER=change-me-api-key-pepper`
- `DEFAULT_ADMIN_PASSWORD=change-me-admin-password`
- `OPENAI_API_KEY=` (optional, leave empty for local/offline mode)

## Legacy Windows Shortcut (Optional)
`start-dev.cmd` is kept as a legacy helper and simply forwards to:

```bat
python scripts\run.py web
```

Use the Python command above as the primary startup path.

## Expected CLI Output
For `python scripts/run.py cli`, output is written to:
- `examples/output/hospitality.json`

The command also prints:
- `confidence=<value>`
- `wrote=<absolute-path-to-output-file>`

## Troubleshooting
- `ModuleNotFoundError`: run `python scripts/run.py setup --venv` first.
- Browser does not open automatically: run `python scripts/run.py web --no-browser` and open `http://127.0.0.1:56461`.
- OpenAI-related errors: leave `OPENAI_API_KEY=` empty for offline mode, or set a valid key in `.env`.
- Safety failures on runtime artifacts: remove generated DB/export artifacts, then rerun `python scripts/run.py safety`.
