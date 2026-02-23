from functools import lru_cache
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    app_name: str = os.getenv("APP_NAME", "ExposureMapper TI")
    app_env: str = os.getenv("APP_ENV", "dev")
    secret_key: str = os.getenv("SECRET_KEY", "change-me-exposuremapper-secret")
    password_pepper: str = os.getenv("PASSWORD_PEPPER", "local-pepper")
    api_key_pepper: str = os.getenv("API_KEY_PEPPER", "local-api-pepper")
    session_cookie_name: str = os.getenv("SESSION_COOKIE_NAME", "exposuremapper_session")
    # Default DB path: Windows environments can intermittently block SQLite journaling in source folders.
    # We default to a per-user TEMP directory for reliability; override with DATABASE_URL for persistence.
    _default_db_path: Path = BASE_DIR / "exposuremapper.db"
    if os.name == "nt":
        _tmp = os.getenv("TEMP", "").strip()
        if _tmp:
            _default_db_path = Path(_tmp) / "ExposureMapperTI" / "exposuremapper.db"
    database_url: str = os.getenv("DATABASE_URL", f"sqlite:///{_default_db_path.as_posix()}")
    request_timeout_seconds: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "8"))
    website_user_agent: str = os.getenv(
        "WEBSITE_USER_AGENT", "ExposureMapperTI/1.0 (+local-assessment)"
    )
    default_admin_user: str = os.getenv("DEFAULT_ADMIN_USER", "admin")
    default_admin_password: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123!")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_reasoner_model: str = os.getenv("OPENAI_REASONER_MODEL", "gpt-4.1")
    openai_hypothesis_confidence_threshold: int = int(os.getenv("OPENAI_HYPOTHESIS_CONFIDENCE_THRESHOLD", "55"))
    # Admin-only debug toggles (UI may display additional validator details).
    admin_debug_risk: bool = os.getenv("ADMIN_DEBUG_RISK", "0").strip() == "1"


@lru_cache
def get_settings() -> Settings:
    return Settings()
