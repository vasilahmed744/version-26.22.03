from datetime import datetime
from io import BytesIO

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, joinedload

from backend.analytics import export_logs_to_csv, serialize_log
from backend.auth import require_roles
from backend.database import get_db
from backend.models import AttackLog, User


router = APIRouter(prefix="/logs", tags=["logs"])


def _apply_filters(query, source_ip, severity, detection_type, protocol, date_from, date_to):
    if source_ip:
        query = query.filter(AttackLog.source_ip.contains(source_ip))
    if severity:
        query = query.filter(AttackLog.severity == severity)
    if detection_type:
        query = query.filter(AttackLog.detection_type.contains(detection_type))
    if protocol:
        query = query.filter(AttackLog.protocol == protocol)
    if date_from:
        query = query.filter(AttackLog.timestamp >= datetime.fromisoformat(date_from))
    if date_to:
        query = query.filter(AttackLog.timestamp <= datetime.fromisoformat(date_to))
    return query


@router.get("")
def list_logs(
    source_ip: str | None = None,
    severity: str | None = None,
    detection_type: str | None = None,
    protocol: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = Query(default=250, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    query = db.query(AttackLog).options(joinedload(AttackLog.payload_findings)).order_by(AttackLog.timestamp.desc())
    query = _apply_filters(query, source_ip, severity, detection_type, protocol, date_from, date_to)
    logs = query.limit(limit).all()
    return {"items": [serialize_log(log) for log in logs]}


@router.get("/export")
def export_logs(
    source_ip: str | None = None,
    severity: str | None = None,
    detection_type: str | None = None,
    protocol: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
) -> StreamingResponse:
    query = db.query(AttackLog).options(joinedload(AttackLog.payload_findings)).order_by(AttackLog.timestamp.desc())
    query = _apply_filters(query, source_ip, severity, detection_type, protocol, date_from, date_to)
    csv_content = export_logs_to_csv(query.limit(1000).all())
    return StreamingResponse(
        BytesIO(csv_content.encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinel_logs.csv"},
    )
