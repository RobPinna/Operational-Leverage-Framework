from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import User
from app.security import hash_password


def ensure_default_admin(db: Session) -> None:
    settings = get_settings()
    user = (
        db.execute(select(User).where(User.username == settings.default_admin_user).order_by(User.id.desc()).limit(1))
        .scalars()
        .first()
    )
    if user:
        return
    db.add(
        User(
            username=settings.default_admin_user,
            password_hash=hash_password(settings.default_admin_password),
        )
    )
    db.commit()
