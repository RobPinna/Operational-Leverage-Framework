# Operational Leverage Framework

Operational Leverage Framework is a defensive, evidence-first CTI/cyber risk assessment project that maps public exposure signals into actionable risk narratives.

## Disclaimer
- Educational/research repository.
- Not a security product.
- No guarantees of completeness, correctness, or fitness for operational decisions.

## What / Why / Output
- What: ingest and score public-facing evidence signals (contact channels, workflows, vendor cues, org cues).
- Why: convert noisy exposure evidence into structured confidence and risk-to-action communication.
- Output:
  - confidence + signal metadata
  - assessment narratives (UI)
  - exported JSON/PDF reports

## Quickstart (3 commands)
```bash
py -3 -m pip install -e ".[dev]"
pytest
py -3 -m operational_leverage_framework.cli.main examples/scenario_hospitality/input.json --out examples/output/hospitality.json --risk-type impersonation
```

## Come usare il progetto (release GitHub)
1. Clona il repository.
2. Crea il file locale di configurazione:
```bat
copy .env.example .env
```
3. Sostituisci i placeholder in `.env`:
- File: `.env`
  Placeholder: `SECRET_KEY=change-me-exposuremapper-secret`
  Cosa mettere: una stringa casuale lunga per sessioni/app.
- File: `.env`
  Placeholder: `PASSWORD_PEPPER=change-me-password-pepper`
  Cosa mettere: pepper privato usato per hashing password.
- File: `.env`
  Placeholder: `API_KEY_PEPPER=change-me-api-key-pepper`
  Cosa mettere: pepper privato per cifratura/obfuscation chiavi.
- File: `.env`
  Placeholder: `DEFAULT_ADMIN_PASSWORD=change-me-admin-password`
  Cosa mettere: password admin locale forte.
- File: `.env`
  Placeholder: `OPENAI_API_KEY=`
  Cosa mettere: opzionale. Lascia vuoto per modalità local/offline.
4. Avvio web app:
```bat
start-dev.cmd
```
5. Verifica release-safety prima della pubblicazione:
```bat
release-safety-check.cmd
```

## Full web app shortcut
From the repository root on Windows:
```bat
start-dev.cmd
```

What it does:
- creates `.venv` if missing
- installs backend dependencies from `requirements.txt`
- starts FastAPI app on `http://127.0.0.1:56461`
- opens homepage automatically at `http://127.0.0.1:56461`
- keeps `exports/` as runtime folder (placeholder-only in public release)

Optional:
```bat
start-dev.cmd --no-browser
```

## Real example (local run)
Command:
```bash
py -3 -m operational_leverage_framework.cli.main examples/scenario_hospitality/input.json --out examples/output/hospitality.json --risk-type impersonation
```

Observed output:
```text
confidence=67
wrote=D:\Rob Pinna\Tech\Cybersec\ExposureMapper\examples\output\hospitality.json
```

Observed result snippet:
```json
{
  "confidence": 67,
  "meta": {
    "signal_diversity_count": 3,
    "has_critical_signal": true
  }
}
```

## Project layout
- `start-dev.cmd` one-command launcher (setup + run + open homepage)
- `ExposureMapperTI.cmd` backward-compatible wrapper to `start-dev.cmd`
- `app/` FastAPI web app (routers, services, connectors)
- `src/operational_leverage_framework/` typed public package (`core`, `io`, `models`, `cli`)
- `src/rag/` local retrieval pipeline
- `src/reasoner/` hypothesis generation logic
- `tests/` deterministic offline tests
- `examples/` runnable evidence scenarios

## Limits and assumptions
- Confidence scores are heuristic and evidence-quality dependent.
- Public-source coverage is partial by definition.
- Optional API connectors may be unavailable in fully offline mode.

## Security notes
- No telemetry.
- No hardcoded API keys.
- Demo examples use sanitized synthetic data.

## Portfolio note
This repository demonstrates:
- CTI rigor through evidence-quality weighting and explicit signal coverage.
- Risk-to-action framing with deterministic confidence computation.
- Maintainable engineering practice: typed boundaries, tests, CI, and release hygiene.

## Commands
- Lint: `ruff check .`
- Format: `ruff format .`
- Typecheck: `mypy`
- Test: `pytest`
- Web app (existing behavior): `uvicorn app.main:app --reload`
