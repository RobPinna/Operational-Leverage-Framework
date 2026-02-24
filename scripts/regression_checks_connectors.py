from __future__ import annotations

"""
Lightweight regression checks for modular connector patch.

What it validates:
1) Disabled connectors do not produce evidence rows.
2) Enabling a connector allows evidence ingestion through the existing pipeline.
3) Collection stage does not create hypotheses directly (no risk-engine side effects here).

Run:
  .\\.venv\\Scripts\\python.exe scripts\\regression_checks_connectors.py
"""

import os
import sys
from datetime import datetime, timezone

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sqlalchemy import select  # noqa: E402

import app.services.assessment_service as svc  # noqa: E402
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload  # noqa: E402
from app.db import Base, SessionLocal, engine, ensure_runtime_schema  # noqa: E402
from app.models import Assessment, ConnectorSetting, Evidence, Hypothesis  # noqa: E402
from app.utils.jsonx import to_json  # noqa: E402


class _StubConnector(ConnectorBase):
    def __init__(self, name: str):
        self.name = name
        self.description = f"stub:{name}"
        self.requires_api_key = False

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        return [
            EvidencePayload(
                connector=self.name,
                category="exposure",
                title=f"stub evidence {self.name}",
                snippet=f"stub signal from {self.name}",
                source_url=f"connector://{self.name}",
                confidence=60,
                raw={"signal_type": "CHANNEL_AMBIGUITY_SIGNAL"},
            )
        ]


def main() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_runtime_schema()
    with SessionLocal() as db:
        assessment = Assessment(
            company_name="Regression Co",
            domain="example.com",
            sector="technology",
            regions="EU",
            demo_mode=False,
            status="draft",
            selected_sources_json=to_json(["email_posture_analyzer", "dns_footprint"]),
            collect_log_json="[]",
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        # Explicitly disable one connector and enable the other.
        db.add(ConnectorSetting(name="email_posture_analyzer", enabled=False, api_key_obfuscated=""))
        db.add(ConnectorSetting(name="dns_footprint", enabled=True, api_key_obfuscated=""))
        db.commit()

        original_map = svc.connector_map
        try:
            svc.connector_map = lambda: {
                "email_posture_analyzer": _StubConnector("email_posture_analyzer"),
                "dns_footprint": _StubConnector("dns_footprint"),
            }
            logs = svc.run_collection(db, assessment)
            assert isinstance(logs, list)
        finally:
            svc.connector_map = original_map

        rows = db.execute(select(Evidence).where(Evidence.assessment_id == assessment.id)).scalars().all()
        names = [r.connector for r in rows]
        assert "email_posture_analyzer" not in names, "Disabled connector must not write evidence."
        assert "dns_footprint" in names, "Enabled connector should still run."

        hypothesis_count = (
            db.execute(select(Hypothesis).where(Hypothesis.assessment_id == assessment.id)).scalars().all()
        )
        assert len(hypothesis_count) == 0, "Collection stage must not modify risk engine outputs directly."

    print("regression_checks_connectors: OK")


if __name__ == "__main__":
    main()
