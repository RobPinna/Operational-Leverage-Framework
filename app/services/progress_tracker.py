from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any


@dataclass
class _ProgressState:
    assessment_id: int
    mode: str
    message: str
    done: bool = False
    success: bool = True
    error: str = ""
    updated_at: datetime = field(default_factory=datetime.utcnow)


_LOCK = Lock()
_STATES: dict[tuple[int, str], _ProgressState] = {}


def _key(assessment_id: int, mode: str) -> tuple[int, str]:
    return (int(assessment_id), str(mode or "").strip().lower() or "default")


def start_progress(assessment_id: int, mode: str, message: str) -> None:
    with _LOCK:
        _STATES[_key(assessment_id, mode)] = _ProgressState(
            assessment_id=int(assessment_id),
            mode=str(mode or "").strip().lower() or "default",
            message=str(message or "").strip() or "Starting...",
            done=False,
            success=True,
            error="",
            updated_at=datetime.utcnow(),
        )


def update_progress(assessment_id: int, mode: str, message: str) -> None:
    with _LOCK:
        k = _key(assessment_id, mode)
        state = _STATES.get(k)
        if state is None:
            _STATES[k] = _ProgressState(
                assessment_id=int(assessment_id),
                mode=str(mode or "").strip().lower() or "default",
                message=str(message or "").strip() or "Working...",
                done=False,
                success=True,
                error="",
                updated_at=datetime.utcnow(),
            )
            return
        state.message = str(message or "").strip() or state.message
        state.updated_at = datetime.utcnow()
        state.done = False


def finish_progress(assessment_id: int, mode: str, message: str = "Completed.") -> None:
    with _LOCK:
        k = _key(assessment_id, mode)
        state = _STATES.get(k)
        if state is None:
            _STATES[k] = _ProgressState(
                assessment_id=int(assessment_id),
                mode=str(mode or "").strip().lower() or "default",
                message=str(message or "").strip() or "Completed.",
                done=True,
                success=True,
                error="",
                updated_at=datetime.utcnow(),
            )
            return
        state.message = str(message or "").strip() or "Completed."
        state.done = True
        state.success = True
        state.error = ""
        state.updated_at = datetime.utcnow()


def fail_progress(assessment_id: int, mode: str, error: str) -> None:
    with _LOCK:
        k = _key(assessment_id, mode)
        state = _STATES.get(k)
        if state is None:
            _STATES[k] = _ProgressState(
                assessment_id=int(assessment_id),
                mode=str(mode or "").strip().lower() or "default",
                message="Failed.",
                done=True,
                success=False,
                error=str(error or "").strip()[:300],
                updated_at=datetime.utcnow(),
            )
            return
        state.message = "Failed."
        state.done = True
        state.success = False
        state.error = str(error or "").strip()[:300]
        state.updated_at = datetime.utcnow()


def get_progress(assessment_id: int, mode: str) -> dict[str, Any]:
    with _LOCK:
        state = _STATES.get(_key(assessment_id, mode))
        if state is None:
            return {
                "assessment_id": int(assessment_id),
                "mode": str(mode or "").strip().lower() or "default",
                "message": "",
                "done": False,
                "success": True,
                "error": "",
                "updated_at": "",
            }
        return {
            "assessment_id": int(state.assessment_id),
            "mode": str(state.mode),
            "message": str(state.message),
            "done": bool(state.done),
            "success": bool(state.success),
            "error": str(state.error),
            "updated_at": state.updated_at.isoformat() + "Z",
        }
