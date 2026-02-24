from pathlib import Path
from urllib.parse import unquote

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings

Base = declarative_base()
SessionLocal = sessionmaker(autoflush=False, autocommit=False, future=True)
engine: Engine | None = None
_current_database_url: str | None = None


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    if not database_url.startswith("sqlite:///"):
        return
    raw = unquote(database_url[len("sqlite:///") :])
    try:
        Path(raw).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If the parent dir can't be created, SQLite will fail later with a clearer error.
        pass


def _connect_args(database_url: str) -> dict[str, bool]:
    return {"check_same_thread": False} if database_url.startswith("sqlite") else {}


def configure_database(database_url: str | None = None) -> Engine:
    global _current_database_url, engine

    resolved_url = (database_url or get_settings().database_url).strip()
    if engine is not None and _current_database_url == resolved_url:
        return engine

    _ensure_sqlite_parent_dir(resolved_url)
    engine_kwargs: dict[str, object] = {
        "connect_args": _connect_args(resolved_url),
        "future": True,
    }
    if resolved_url.startswith("sqlite:///:memory:"):
        engine_kwargs["poolclass"] = StaticPool

    next_engine = create_engine(resolved_url, **engine_kwargs)

    if engine is not None:
        try:
            engine.dispose()
        except Exception:
            pass

    engine = next_engine
    _current_database_url = resolved_url
    SessionLocal.configure(bind=engine)
    return engine


def get_database_url() -> str:
    return (_current_database_url or get_settings().database_url).strip()


def ensure_runtime_schema() -> None:
    """Apply lightweight runtime schema safety for SQLite deployments."""
    active_engine = configure_database()
    if not get_database_url().startswith("sqlite"):
        return
    with active_engine.begin() as conn:
        tables = {
            row[0]
            for row in conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if row and row[0]
        }

        # Dedupe legacy rows in connector_settings (unique constraint is not retroactive).
        if "connector_settings" in tables:
            try:
                conn.exec_driver_sql(
                    "DELETE FROM connector_settings WHERE id NOT IN (SELECT MAX(id) FROM connector_settings GROUP BY name)"
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

        if "examination_logs" in tables:
            try:
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_examination_logs_assessment_content_hash "
                    "ON examination_logs (assessment_id, content_hash)"
                )
            except Exception:
                pass
        if "documents" in tables:
            try:
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_documents_assessment_content_hash ON documents (assessment_id, content_hash)"
                )
            except Exception:
                pass
        # Evidence quality layer columns and indexes.
        if "evidences" in tables:
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

        if "examination_logs" in tables:
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
        if "hypotheses" in tables:
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
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_hypotheses_assessment_primary_risk_type ON hypotheses (assessment_id, primary_risk_type)"
                )
            except Exception:
                pass
            try:
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_hypotheses_assessment_status ON hypotheses (assessment_id, status)"
                )
            except Exception:
                pass
            try:
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_hypotheses_assessment_plausibility ON hypotheses (assessment_id, plausibility_score)"
                )
            except Exception:
                pass
            try:
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_hypotheses_assessment_potential_impact ON hypotheses (assessment_id, potential_impact_score)"
                )
            except Exception:
                pass

        # Backfill NULLs for newly added columns (SQLite ALTER TABLE adds NULL by default).
        try:
            if "evidences" in tables:
                conn.exec_driver_sql(
                    "UPDATE evidences SET evidence_kind='UNKNOWN' WHERE evidence_kind IS NULL OR TRIM(evidence_kind)=''"
                )
                conn.exec_driver_sql(
                    "UPDATE evidences SET quality_tier='LOW' WHERE quality_tier IS NULL OR TRIM(quality_tier)=''"
                )
                conn.exec_driver_sql("UPDATE evidences SET quality_weight=0.5 WHERE quality_weight IS NULL")
                conn.exec_driver_sql("UPDATE evidences SET is_boilerplate=0 WHERE is_boilerplate IS NULL")
                conn.exec_driver_sql("UPDATE evidences SET rationale='' WHERE rationale IS NULL")

            if "hypotheses" in tables:
                conn.exec_driver_sql(
                    "UPDATE hypotheses SET primary_risk_type='Channel ambiguity exploitation' "
                    "WHERE primary_risk_type IS NULL OR TRIM(primary_risk_type)=''"
                )
                conn.exec_driver_sql("UPDATE hypotheses SET risk_vector_summary='' WHERE risk_vector_summary IS NULL")
                conn.exec_driver_sql("UPDATE hypotheses SET baseline_tag=0 WHERE baseline_tag IS NULL")
                conn.exec_driver_sql(
                    "UPDATE hypotheses SET integrity_flags_json='{}' WHERE integrity_flags_json IS NULL"
                )
                conn.exec_driver_sql("UPDATE hypotheses SET status='WATCHLIST' WHERE status IS NULL OR TRIM(status)=''")
                conn.exec_driver_sql("UPDATE hypotheses SET status='BASELINE' WHERE baseline_tag=1")
                conn.exec_driver_sql("UPDATE hypotheses SET plausibility_score=0 WHERE plausibility_score IS NULL")
                conn.exec_driver_sql(
                    "UPDATE hypotheses SET potential_impact_score=0 WHERE potential_impact_score IS NULL"
                )
        except Exception:
            pass


def get_db():
    configure_database()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


configure_database()
