from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload

from backend.analytics import serialize_alert
from backend.auth import get_current_user, require_roles
from backend.database import get_db
from backend.dependencies import get_services
from backend.models import Alert, AttackLog, User


router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    alerts = (
        db.query(Alert)
        .options(joinedload(Alert.attack_log).joinedload(AttackLog.payload_findings))
        .order_by(Alert.created_at.desc())
        .limit(200)
        .all()
    )
    return {"items": [serialize_alert(alert) for alert in alerts]}


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    services=Depends(get_services),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    alert.status = "acknowledged"
    alert.acknowledged_by_id = current_user.id
    alert.acknowledged_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)

    await services.websocket_manager.broadcast_json(
        {
            "type": "alert_acknowledged",
            "payload": serialize_alert(alert),
        }
    )
    return {"message": "Alert acknowledged"}
