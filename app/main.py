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
from sqlalchemy.exc import OperationalError
from starlette.middleware.sessions import SessionMiddleware

from app import db as app_db
from app import models as _models  # noqa: F401 - register SQLAlchemy models before create_all
from app.bootstrap import ensure_default_admin
from app.config import BASE_DIR, get_settings
from app.routers import (
    api,
    assessments,
    auth,
    correlations,
    dashboard,
    findings,
    hypotheses,
    mitigations,
    reports,
    risks,
    trust_workflows,
)
from app.routers import (
    settings as settings_router,
)

try:
    from operational_leverage_framework import get_runtime_version
except ModuleNotFoundError:  # pragma: no cover - compatibility for non-editable local runs
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


def _fresh_sqlite_fallback_url(settings, reason: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    fallback_dir = settings.runtime_dir / "db_recovery"
    fallback_dir.mkdir(parents=True, exist_ok=True)
    fallback_db = fallback_dir / f"exposuremapper_{reason}_{ts}.db"
    return f"sqlite:///{fallback_db.as_posix()}"


def _initialize_db_schema(database_url: str) -> None:
    active_engine = app_db.configure_database(database_url)
    app_db.Base.metadata.create_all(bind=active_engine)
    app_db.ensure_runtime_schema()
    with app_db.SessionLocal() as db:
        ensure_default_admin(db)


def _init_db_with_recovery(settings) -> None:
    """
    Create tables + apply runtime schema, with a pragmatic recovery path for corrupted SQLite files.
    """
    logger = logging.getLogger(__name__)
    try:
        _initialize_db_schema(settings.database_url)
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
                app_db.configure_database(settings.database_url).dispose()
            except Exception:
                pass
            try:
                _initialize_db_schema(settings.database_url)
                return
            except OperationalError:
                fallback_url = _fresh_sqlite_fallback_url(settings, reason="journal_fallback")
                logger.warning("Journal recovery failed. Falling back to fresh SQLite database: %s", fallback_url)
                os.environ["DATABASE_URL"] = fallback_url
                get_settings.cache_clear()
                _initialize_db_schema(fallback_url)
                return

        # Last resort: backup DB and start a fresh one.
        logger.warning("SQLite disk I/O error detected. Backing up DB and creating a fresh database: %s", db_path)
        _backup_sqlite_files(db_path, reason="db_recreate", include_db=True)
        try:
            app_db.configure_database(settings.database_url).dispose()
        except Exception:
            pass
        try:
            _initialize_db_schema(settings.database_url)
            return
        except OperationalError:
            fallback_url = _fresh_sqlite_fallback_url(settings, reason="db_recreate_fallback")
            logger.warning("DB recreate recovery failed. Falling back to fresh SQLite database: %s", fallback_url)
            os.environ["DATABASE_URL"] = fallback_url
            get_settings.cache_clear()
            _initialize_db_schema(fallback_url)
            return


def create_app() -> FastAPI:
    # Respect runtime env overrides (tests, packaged launcher, temporary runs).
    get_settings.cache_clear()
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
        allow_origins=settings.cors_allowed_origins or ["http://127.0.0.1", "http://localhost"],
        allow_origin_regex=settings.cors_allow_origin_regex,
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
