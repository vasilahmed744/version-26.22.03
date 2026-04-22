from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.auth import require_roles
from backend.database import get_db
from backend.dependencies import get_services
from backend.models import Setting, User
from backend.schemas import SettingsUpdate


router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("")
def get_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    settings = db.query(Setting).first()
    return {
        "settings": {
            "demo_mode": settings.demo_mode,
            "live_mode": settings.live_mode,
            "payload_inspection_enabled": settings.payload_inspection_enabled,
            "firewall_simulation_enabled": settings.firewall_simulation_enabled,
            "geoip_enabled": settings.geoip_enabled,
            "auto_block_high_risk": settings.auto_block_high_risk,
            "alert_on_medium": settings.alert_on_medium,
            "alert_on_high": settings.alert_on_high,
            "detection_threshold": settings.detection_threshold,
            "max_events_per_minute": settings.max_events_per_minute,
            "live_capture_interface": settings.live_capture_interface,
            "updated_at": settings.updated_at.isoformat(),
        }
    }


@router.put("")
async def update_settings(
    payload: SettingsUpdate,
    services=Depends(get_services),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> dict:
    settings = db.query(Setting).first()
    settings.demo_mode = payload.demo_mode
    settings.live_mode = payload.live_mode
    if settings.demo_mode and settings.live_mode:
        settings.demo_mode = False
    settings.payload_inspection_enabled = payload.payload_inspection_enabled
    settings.firewall_simulation_enabled = payload.firewall_simulation_enabled
    settings.geoip_enabled = payload.geoip_enabled
    settings.auto_block_high_risk = payload.auto_block_high_risk
    settings.alert_on_medium = payload.alert_on_medium
    settings.alert_on_high = payload.alert_on_high
    settings.detection_threshold = payload.detection_threshold
    settings.max_events_per_minute = payload.max_events_per_minute
    settings.live_capture_interface = payload.live_capture_interface
    db.commit()
    db.refresh(settings)

    await services.websocket_manager.broadcast_json(
        {
            "type": "settings_updated",
            "payload": {
                "demo_mode": settings.demo_mode,
                "live_mode": settings.live_mode,
                "payload_inspection_enabled": settings.payload_inspection_enabled,
                "firewall_simulation_enabled": settings.firewall_simulation_enabled,
                "geoip_enabled": settings.geoip_enabled,
                "auto_block_high_risk": settings.auto_block_high_risk,
                "alert_on_medium": settings.alert_on_medium,
                "alert_on_high": settings.alert_on_high,
                "detection_threshold": settings.detection_threshold,
                "max_events_per_minute": settings.max_events_per_minute,
                "live_capture_interface": settings.live_capture_interface,
            },
        }
    )
    return {"message": "Settings updated"}
