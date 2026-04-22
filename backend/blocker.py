from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress
import platform
import subprocess

from sqlalchemy.orm import Session

from backend.models import BlockedIP, Setting, User


class FirewallBlocker:
    def _expire_old_blocks(self, db: Session) -> None:
        now = datetime.utcnow()
        expired_blocks = (
            db.query(BlockedIP)
            .filter(BlockedIP.is_active.is_(True), BlockedIP.expires_at.is_not(None), BlockedIP.expires_at < now)
            .all()
        )
        for block in expired_blocks:
            block.is_active = False
            block.status = "expired"
        if expired_blocks:
            db.commit()

    def list_blocks(self, db: Session) -> list[BlockedIP]:
        self._expire_old_blocks(db)
        return db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()

    def is_ip_blocked(self, db: Session, ip_address: str) -> bool:
        self._expire_old_blocks(db)
        return (
            db.query(BlockedIP)
            .filter(BlockedIP.ip_address == ip_address, BlockedIP.is_active.is_(True))
            .first()
            is not None
        )

    def block_ip(
        self,
        db: Session,
        ip_address: str,
        reason: str,
        duration_minutes: int | None,
        permanent: bool,
        requested_by: User | None = None,
        simulation_override: bool | None = None,
    ) -> BlockedIP:
        ipaddress.ip_address(ip_address)
        self._expire_old_blocks(db)

        existing = (
            db.query(BlockedIP)
            .filter(BlockedIP.ip_address == ip_address, BlockedIP.is_active.is_(True))
            .first()
        )
        if existing:
            return existing

        settings = db.query(Setting).first()
        simulation_enabled = settings.firewall_simulation_enabled if settings else True
        if simulation_override is not None:
            simulation_enabled = simulation_override

        mode = "simulation"
        status = "active"
        expires_at = None if permanent else datetime.utcnow() + timedelta(minutes=duration_minutes or 60)

        if not simulation_enabled:
            mode = self._apply_system_block(ip_address)

        block = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            status=status,
            mode=mode,
            expires_at=expires_at,
            created_by_id=requested_by.id if requested_by else None,
        )
        db.add(block)
        db.commit()
        db.refresh(block)
        return block

    def unblock_ip(self, db: Session, block_id: int) -> BlockedIP | None:
        block = db.query(BlockedIP).filter(BlockedIP.id == block_id).first()
        if not block:
            return None

        if block.is_active and block.mode != "simulation":
            self._remove_system_block(block.ip_address, block.mode)

        block.is_active = False
        block.status = "removed"
        db.commit()
        db.refresh(block)
        return block

    def _apply_system_block(self, ip_address: str) -> str:
        system_name = platform.system().lower()
        if "windows" in system_name:
            rule_name = f"Sentinel Block {ip_address}"
            subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip_address}",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule_name} Out",
                    "dir=out",
                    "action=block",
                    f"remoteip={ip_address}",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            return "windows-firewall"

        if "linux" in system_name:
            subprocess.run(["ufw", "deny", "from", ip_address], check=True, capture_output=True, text=True)
            return "ufw"

        return "simulation"

    def _remove_system_block(self, ip_address: str, mode: str) -> None:
        try:
            if mode == "windows-firewall":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Sentinel Block {ip_address}"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Sentinel Block {ip_address} Out"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            elif mode == "ufw":
                subprocess.run(["ufw", "delete", "deny", "from", ip_address], check=True, capture_output=True, text=True)
        except Exception:
            return
