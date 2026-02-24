import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.exc import OperationalError

from app.bootstrap import ensure_default_admin
from app.config import BASE_DIR, get_settings
from app.db import Base, SessionLocal, engine, ensure_runtime_schema
from app.routers import api, assessments, auth, correlations, dashboard, findings, hypotheses, mitigations, reports, risks, settings as settings_router, trust_workflows
from src.operational_leverage_framework import get_runtime_version


def _sqlite_path_from_url(database_url: str) -> Path | None:
    url = (database_url or "").strip()
    if not url.startswith("sqlite:///"):
        return None
    raw = url[len("sqlite:///") :]
    return Path(raw)


def _backup_sqlite_files(db_path: Path, *, reason: str, include_db: bool) -> None:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_dir = get_settings().runtime_dir / "db_recovery"
    backup_dir.mkdir(parents=True, exist_ok=True)
    suffix = f".{reason}.{ts}"
    journal = Path(str(db_path) + "-journal")
    wal = Path(str(db_path) + "-wal")

    targets = [journal, wal]
    if include_db:
        targets.append(db_path)

    for p in targets:
        if p.exists():
            try:
                os.replace(str(p), str(backup_dir / (p.name + suffix)))
            except Exception:
                logging.getLogger(__name__).exception("Failed to backup sqlite file: %s", p)


def _init_db_with_recovery(settings) -> None:
    """
    Create tables + apply runtime schema, with a pragmatic recovery path for corrupted SQLite files.
    """
    logger = logging.getLogger(__name__)
    try:
        Base.metadata.create_all(bind=engine)
        ensure_runtime_schema()
        with SessionLocal() as db:
            ensure_default_admin(db)
        return
    except OperationalError as e:
        msg = str(e).lower()
        if "disk i/o error" not in msg:
            raise

        db_path = _sqlite_path_from_url(settings.database_url)
        if not db_path:
            raise

        # First attempt: stale/corrupt journal files can trigger disk I/O errors.
        journal = Path(str(db_path) + "-journal")
        if journal.exists():
            logger.warning("SQLite disk I/O error detected. Attempting journal recovery: %s", journal)
            _backup_sqlite_files(db_path, reason="journal_recovery", include_db=False)
            try:
                engine.dispose()
            except Exception:
                pass
            Base.metadata.create_all(bind=engine)
            ensure_runtime_schema()
            with SessionLocal() as db:
                ensure_default_admin(db)
            return

        # Last resort: backup DB and start a fresh one.
        logger.warning("SQLite disk I/O error detected. Backing up DB and creating a fresh database: %s", db_path)
        _backup_sqlite_files(db_path, reason="db_recreate", include_db=True)
        try:
            engine.dispose()
        except Exception:
            pass
        Base.metadata.create_all(bind=engine)
        ensure_runtime_schema()
        with SessionLocal() as db:
            ensure_default_admin(db)
        return


def create_app() -> FastAPI:
    settings = get_settings()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    app = FastAPI(title=settings.app_name)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie=settings.session_cookie_name,
        same_site="lax",
        https_only=False,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    bundle_dir = Path(getattr(sys, "_MEIPASS", str(BASE_DIR)))
    static_dir = bundle_dir / "static"
    templates_dir = bundle_dir / "templates"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    # Disable template caching and enable auto reload so UI changes are visible immediately in dev.
    # This also prevents confusing "old template still rendering" issues when iterating quickly.
    app.state.templates = Jinja2Templates(directory=str(templates_dir), auto_reload=True, cache_size=0)
    def _static_v(rel_path: str) -> int:
        # Cache-busting for static assets without requiring app restarts.
        # Uses file mtime for stable, deterministic versions.
        try:
            p = static_dir / rel_path
            return int(p.stat().st_mtime)
        except Exception:
            return int(time.time())

    app.state.templates.env.globals["static_v"] = _static_v

    _init_db_with_recovery(settings)

    app.include_router(auth.router)
    app.include_router(api.router)
    app.include_router(dashboard.router)
    app.include_router(assessments.router)
    app.include_router(findings.router)
    app.include_router(correlations.router)
    app.include_router(risks.router)
    app.include_router(hypotheses.router)
    app.include_router(mitigations.router)
    app.include_router(reports.router)
    app.include_router(trust_workflows.router)
    app.include_router(settings_router.router)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/api/health")
    def api_health():
        return {"status": "ok", "version": get_runtime_version()}

    return app


app = create_app()
