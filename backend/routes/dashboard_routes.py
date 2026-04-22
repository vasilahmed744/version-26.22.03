from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from backend.analytics import build_dashboard_summary
from backend.auth import get_user_from_token, require_roles
from backend.database import get_db
from backend.dependencies import get_services
from backend.models import User
from backend.reporting import generate_dashboard_report_html


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(
    services=Depends(get_services),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    return build_dashboard_summary(db, services.traffic_monitor.runtime_mode)


@router.get("/status")
def monitor_status(
    request: Request,
    services=Depends(get_services),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    status_snapshot = services.traffic_monitor.get_status_snapshot()
    return {
        **status_snapshot,
        "clients": services.websocket_manager.connection_count,
        "path": str(request.url_for("websocket_stream")),
    }


async def _broadcast_monitor_status(services, db: Session) -> dict:
    summary = build_dashboard_summary(db, services.traffic_monitor.runtime_mode)
    status_snapshot = services.traffic_monitor.get_status_snapshot()
    payload = {
        "state": status_snapshot["state"],
        "mode": status_snapshot["mode"],
        "note": status_snapshot["note"],
        "summary": summary,
    }
    await services.websocket_manager.broadcast_json(
        {
            "type": "monitor_status",
            "payload": payload,
        }
    )
    return payload


@router.post("/start")
async def start_monitoring(
    services=Depends(get_services),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    status_snapshot = services.traffic_monitor.resume_monitoring()
    payload = await _broadcast_monitor_status(services, db)
    return {
        "message": "Monitoring resumed",
        "status": status_snapshot,
        "summary": payload["summary"],
    }


@router.post("/stop")
async def stop_monitoring(
    services=Depends(get_services),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    status_snapshot = services.traffic_monitor.pause_monitoring()
    payload = await _broadcast_monitor_status(services, db)
    return {
        "message": "Monitoring paused",
        "status": status_snapshot,
        "summary": payload["summary"],
    }


@router.get("/report", response_class=HTMLResponse)
def dashboard_report(
    token: str = Query(...),
    services=Depends(get_services),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    try:
        current_user = get_user_from_token(db, token)
    except HTTPException as exc:
        raise exc

    if current_user.role not in {"admin", "analyst"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to generate this report",
        )

    session_started_at = services.traffic_monitor.current_session_started_at or services.traffic_monitor.last_session_started_at
    session_ended_at = services.traffic_monitor.last_session_ended_at
    runtime_status = services.traffic_monitor.get_status_snapshot()
    html = generate_dashboard_report_html(
        db=db,
        current_user=current_user,
        session_started_at=session_started_at,
        session_ended_at=session_ended_at if runtime_status["state"] == "paused" else None,
        runtime_status=runtime_status,
    )
    return HTMLResponse(content=html)
