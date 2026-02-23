from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.security import verify_password

router = APIRouter(tags=["auth"])


@router.get("/login")
def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/assessments", status_code=302)
    return request.app.state.templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None},
    )


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = (
        db.execute(
            select(User)
            .where(User.username == username.strip())
            .order_by(User.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if not user or not verify_password(password, user.password_hash):
        return request.app.state.templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password"},
            status_code=400,
        )

    request.session["user_id"] = user.id
    request.session["username"] = user.username
    return RedirectResponse(url="/assessments", status_code=302)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
