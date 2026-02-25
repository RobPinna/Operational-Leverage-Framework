from __future__ import annotations

import tempfile
from pathlib import Path

import app.db as app_db
from app.models import Assessment, Hypothesis
from app.services.risk_story import _elevated_sort_tuple, get_ranked_risks


def _init_test_db(db_path: Path) -> None:
    app_db.configure_database(f"sqlite:///{db_path.as_posix()}")
    assert app_db.engine is not None
    app_db.Base.metadata.drop_all(bind=app_db.engine)
    app_db.Base.metadata.create_all(bind=app_db.engine)


def test_get_ranked_risks_has_no_db_side_effects() -> None:
    with tempfile.TemporaryDirectory(prefix="olf-risk-ranking-") as temp_dir:
        db_path = Path(temp_dir) / "risk_ranking.db"
        _init_test_db(db_path)

        with app_db.SessionLocal() as db:
            assessment = Assessment(company_name="ACME", domain="acme.test", sector="Hospitality", regions="EU")
            db.add(assessment)
            db.flush()

            hypothesis = Hypothesis(
                assessment_id=int(assessment.id),
                title="Synthetic risk",
                description="No evidence attached",
                status="ELEVATED",
                plausibility_score=95,
                potential_impact_score=90,
                likelihood="high",
                severity=5,
                confidence=90,
                evidence_refs_json="[]",
                signal_counts_json="{}",
            )
            db.add(hypothesis)
            db.commit()

            before = {
                "status": hypothesis.status,
                "plausibility_score": int(hypothesis.plausibility_score or 0),
                "potential_impact_score": int(hypothesis.potential_impact_score or 0),
                "likelihood": str(hypothesis.likelihood or ""),
                "severity": int(hypothesis.severity or 0),
            }

            get_ranked_risks(db, assessment)
            db.refresh(hypothesis)

            after = {
                "status": hypothesis.status,
                "plausibility_score": int(hypothesis.plausibility_score or 0),
                "potential_impact_score": int(hypothesis.potential_impact_score or 0),
                "likelihood": str(hypothesis.likelihood or ""),
                "severity": int(hypothesis.severity or 0),
            }
            assert after == before
        if app_db.engine is not None:
            app_db.engine.dispose()
        app_db.configure_database("sqlite:///:memory:")


def test_elevated_sort_prefers_visible_badges() -> None:
    lower_visible = {
        "id": 11,
        "impact_band": "MED",
        "likelihood": "med",
        "confidence": 65,
        "plausibility_score": 99,
        "signal_coverage": 3,
        "evidence_refs_count": 3,
    }
    higher_visible = {
        "id": 12,
        "impact_band": "HIGH",
        "likelihood": "high",
        "confidence": 80,
        "plausibility_score": 70,
        "signal_coverage": 2,
        "evidence_refs_count": 2,
    }

    ordered = sorted([lower_visible, higher_visible], key=_elevated_sort_tuple, reverse=True)
    assert ordered[0]["id"] == 12
