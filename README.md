# Operational Leverage Framework

Operational Leverage Framework is an evidence-first CTI/cyber risk assessment project that maps public exposure signals into actionable confidence outputs.

## Prerequisites
- Python `>=3.11` (from `pyproject.toml`).
- Optional: `OPENAI_API_KEY` only if you want OpenAI-backed reasoning features.

## Quickstart (3 commands)
From repository root:

```bash
python scripts/run.py setup --venv
python scripts/run.py test
python scripts/run.py cli
```

## Come usare il progetto (release GitHub)
1. Clona il repository.
2. Crea `.env` partendo da `.env.example`:
```bat
copy .env.example .env
```
```bash
cp .env.example .env
```
3. Sostituisci i placeholder in `.env`:
- `SECRET_KEY=change-me-exposuremapper-secret`
- `PASSWORD_PEPPER=change-me-password-pepper`
- `API_KEY_PEPPER=change-me-api-key-pepper`
- `DEFAULT_ADMIN_PASSWORD=change-me-admin-password`
- `OPENAI_API_KEY=` (opzionale, lascia vuoto per modalita local/offline)
4. Avvio web app:
```bash
python scripts/run.py web
```
5. Avvio web app senza apertura browser:
```bash
python scripts/run.py web --no-browser
```
6. Verifica release-safety prima della pubblicazione:
```bash
python scripts/run.py safety
```

## Cross-Platform Commands
- Setup: `python scripts/run.py setup --venv`
- Test: `python scripts/run.py test`
- CLI default scenario: `python scripts/run.py cli`
- CLI custom args: `python scripts/run.py cli -- examples/scenario_hospitality/input.json --out examples/output/hospitality.json --risk-type impersonation`
- Web app: `python scripts/run.py web`
- Safety checks: `python scripts/run.py safety`

## Expected output
For the default CLI command (`python scripts/run.py cli`), output is written to:
- `examples/output/hospitality.json`

The command also prints:
- `confidence=<value>`
- `wrote=<absolute-path-to-output-file>`

## Troubleshooting
- `ModuleNotFoundError`: run `python scripts/run.py setup --venv` first.
- Browser does not open automatically: run `python scripts/run.py web --no-browser` and open `http://127.0.0.1:56461`.
- OpenAI-related errors: leave `OPENAI_API_KEY=` empty for offline mode, or set a valid key in `.env`.
- Safety failures on runtime artifacts: remove generated DB/export artifacts, then rerun `python scripts/run.py safety`.
