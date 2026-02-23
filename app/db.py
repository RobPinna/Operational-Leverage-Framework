from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from pathlib import Path
from urllib.parse import unquote

from app.config import get_settings

settings = get_settings()

if settings.database_url.startswith("sqlite:///"):
    raw = unquote(settings.database_url[len("sqlite:///") :])
    try:
        Path(raw).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If the parent dir can't be created, SQLite will fail later with a clearer error.
        pass

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def ensure_runtime_schema() -> None:
    """Apply lightweight runtime schema safety for SQLite deployments."""
    if not settings.database_url.startswith("sqlite"):
        return
    with engine.begin() as conn:
        # Dedupe legacy rows in connector_settings (unique constraint is not retroactive).
        try:
            conn.exec_driver_sql(
                "DELETE FROM connector_settings "
                "WHERE id NOT IN (SELECT MAX(id) FROM connector_settings GROUP BY name)"
            )
        except Exception:
            pass
        try:
            conn.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_connector_settings_name ON connector_settings (name)"
            )
        except Exception:
            # If duplicates still exist or table missing, ignore (handled in application reads).
            pass

        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_examination_logs_assessment_content_hash "
            "ON examination_logs (assessment_id, content_hash)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_documents_assessment_content_hash "
            "ON documents (assessment_id, content_hash)"
        )
        # Evidence quality layer columns and indexes.
        ecols = {
            row[1]
            for row in conn.exec_driver_sql("PRAGMA table_info(evidences)").fetchall()
            if row and len(row) > 1
        }
        if "evidence_kind" not in ecols:
            conn.exec_driver_sql("ALTER TABLE evidences ADD COLUMN evidence_kind TEXT")
        if "quality_tier" not in ecols:
            conn.exec_driver_sql("ALTER TABLE evidences ADD COLUMN quality_tier TEXT")
        if "quality_weight" not in ecols:
            conn.exec_driver_sql("ALTER TABLE evidences ADD COLUMN quality_weight REAL")
        if "is_boilerplate" not in ecols:
            conn.exec_driver_sql("ALTER TABLE evidences ADD COLUMN is_boilerplate INTEGER")
        if "rationale" not in ecols:
            conn.exec_driver_sql("ALTER TABLE evidences ADD COLUMN rationale TEXT")
        try:
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_evidences_assessment_kind ON evidences (assessment_id, evidence_kind)"
            )
        except Exception:
            pass
        try:
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_evidences_assessment_boilerplate ON evidences (assessment_id, is_boilerplate)"
            )
        except Exception:
            pass
        columns = {
            row[1]
            for row in conn.exec_driver_sql("PRAGMA table_info(examination_logs)").fetchall()
            if row and len(row) > 1
        }
        if "was_rendered" not in columns:
            conn.exec_driver_sql("ALTER TABLE examination_logs ADD COLUMN was_rendered INTEGER")
        if "extracted_chars" not in columns:
            conn.exec_driver_sql("ALTER TABLE examination_logs ADD COLUMN extracted_chars INTEGER")
        if "pdf_pages" not in columns:
            conn.exec_driver_sql("ALTER TABLE examination_logs ADD COLUMN pdf_pages INTEGER")
        if "pdf_text_chars" not in columns:
            conn.exec_driver_sql("ALTER TABLE examination_logs ADD COLUMN pdf_text_chars INTEGER")

        # Hypotheses quality metadata (added without Alembic).
        hcols = {
            row[1]
            for row in conn.exec_driver_sql("PRAGMA table_info(hypotheses)").fetchall()
            if row and len(row) > 1
        }
        if "confidence" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN confidence INTEGER")
        if "signal_diversity" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN signal_diversity INTEGER")
        if "signal_counts_json" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN signal_counts_json TEXT")
        if "missing_signals_json" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN missing_signals_json TEXT")
        if "timeline_json" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN timeline_json TEXT")
        if "primary_risk_type" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN primary_risk_type TEXT")
        if "risk_vector_summary" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN risk_vector_summary TEXT")
        if "baseline_tag" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN baseline_tag INTEGER")
        if "integrity_flags_json" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN integrity_flags_json TEXT")
        if "status" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN status TEXT")
        if "plausibility_score" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN plausibility_score INTEGER")
        if "potential_impact_score" not in hcols:
            conn.exec_driver_sql("ALTER TABLE hypotheses ADD COLUMN potential_impact_score INTEGER")

        try:
            conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_hypotheses_assessment_primary_risk_type ON hypotheses (assessment_id, primary_risk_type)")
        except Exception:
            pass
        try:
            conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_hypotheses_assessment_status ON hypotheses (assessment_id, status)")
        except Exception:
            pass
        try:
            conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_hypotheses_assessment_plausibility ON hypotheses (assessment_id, plausibility_score)")
        except Exception:
            pass
        try:
            conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_hypotheses_assessment_potential_impact ON hypotheses (assessment_id, potential_impact_score)")
        except Exception:
            pass

        # Backfill NULLs for newly added columns (SQLite ALTER TABLE adds NULL by default).
        try:
            conn.exec_driver_sql(
                "UPDATE evidences SET evidence_kind='UNKNOWN' "
                "WHERE evidence_kind IS NULL OR TRIM(evidence_kind)=''"
            )
            conn.exec_driver_sql(
                "UPDATE evidences SET quality_tier='LOW' "
                "WHERE quality_tier IS NULL OR TRIM(quality_tier)=''"
            )
            conn.exec_driver_sql("UPDATE evidences SET quality_weight=0.5 WHERE quality_weight IS NULL")
            conn.exec_driver_sql("UPDATE evidences SET is_boilerplate=0 WHERE is_boilerplate IS NULL")
            conn.exec_driver_sql("UPDATE evidences SET rationale='' WHERE rationale IS NULL")

            conn.exec_driver_sql(
                "UPDATE hypotheses SET primary_risk_type='Channel ambiguity exploitation' "
                "WHERE primary_risk_type IS NULL OR TRIM(primary_risk_type)=''"
            )
            conn.exec_driver_sql("UPDATE hypotheses SET risk_vector_summary='' WHERE risk_vector_summary IS NULL")
            conn.exec_driver_sql("UPDATE hypotheses SET baseline_tag=0 WHERE baseline_tag IS NULL")
            conn.exec_driver_sql("UPDATE hypotheses SET integrity_flags_json='{}' WHERE integrity_flags_json IS NULL")
            conn.exec_driver_sql("UPDATE hypotheses SET status='WATCHLIST' WHERE status IS NULL OR TRIM(status)=''")
            conn.exec_driver_sql("UPDATE hypotheses SET status='BASELINE' WHERE baseline_tag=1")
            conn.exec_driver_sql("UPDATE hypotheses SET plausibility_score=0 WHERE plausibility_score IS NULL")
            conn.exec_driver_sql("UPDATE hypotheses SET potential_impact_score=0 WHERE potential_impact_score IS NULL")
        except Exception:
            pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
