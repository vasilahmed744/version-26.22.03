from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.auth import require_roles
from backend.database import get_db
from backend.dependencies import get_services
from backend.models import User
from backend.schemas import FirewallBlockCreate


router = APIRouter(prefix="/firewall", tags=["firewall"])


@router.get("/blocks")
def list_blocks(
    services=Depends(get_services),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    blocks = services.blocker.list_blocks(db)
    return {
        "items": [
            {
                "id": block.id,
                "ip_address": block.ip_address,
                "reason": block.reason,
                "status": block.status,
                "mode": block.mode,
                "blocked_at": block.blocked_at.isoformat(),
                "expires_at": block.expires_at.isoformat() if block.expires_at else None,
                "is_active": block.is_active,
            }
            for block in blocks
        ]
    }


@router.post("/blocks")
async def add_block(
    payload: FirewallBlockCreate,
    services=Depends(get_services),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    block = services.blocker.block_ip(
        db,
        ip_address=payload.ip_address,
        reason=payload.reason,
        duration_minutes=payload.duration_minutes,
        permanent=payload.permanent,
        requested_by=current_user,
    )
    await services.websocket_manager.broadcast_json(
        {
            "type": "blocklist_update",
            "payload": {"action": "blocked", "ip_address": block.ip_address},
        }
    )
    return {"message": "IP blocked", "id": block.id}


@router.delete("/blocks/{block_id}")
async def remove_block(
    block_id: int,
    services=Depends(get_services),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    block = services.blocker.unblock_ip(db, block_id)
    if not block:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Block entry not found")

    await services.websocket_manager.broadcast_json(
        {
            "type": "blocklist_update",
            "payload": {"action": "unblocked", "ip_address": block.ip_address},
        }
    )
    return {"message": "IP unblocked"}
