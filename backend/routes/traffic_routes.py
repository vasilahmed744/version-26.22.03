from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session, joinedload

from backend.analytics import serialize_log
from backend.auth import require_roles
from backend.database import get_db
from backend.models import AttackLog, User


router = APIRouter(prefix="/traffic", tags=["traffic"])


@router.get("")
def recent_traffic(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    logs = (
        db.query(AttackLog)
        .options(joinedload(AttackLog.payload_findings))
        .order_by(AttackLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return {"items": [serialize_log(log) for log in logs]}
