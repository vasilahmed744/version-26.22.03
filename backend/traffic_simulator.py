from __future__ import annotations

import asyncio
from datetime import datetime
import random
from typing import Any

from sqlalchemy.orm import sessionmaker

from backend.analytics import build_dashboard_summary
from backend.models import Setting


class TrafficMonitorService:
    def __init__(self, session_factory: sessionmaker, detector, websocket_manager) -> None:
        self.session_factory = session_factory
        self.detector = detector
        self.websocket_manager = websocket_manager
        self._task: asyncio.Task | None = None
        self._running = False
        self._monitoring_active = False
        self.runtime_state = "stopped"
        self.runtime_mode = "demo"
        self.runtime_note = "Monitor is starting"
        self.current_session_started_at: datetime | None = None
        self.last_session_started_at: datetime | None = None
        self.last_session_ended_at: datetime | None = None

        self.protocols = ["TCP", "TCP", "TCP", "UDP", "ICMP"]
        self.internal_sources = ["10.0.0.15", "10.0.0.22", "10.0.1.8", "172.16.5.9", "192.168.1.44"]
        self.public_sources = ["45.67.23.90", "185.143.223.11", "103.77.21.44", "91.214.124.7", "198.51.100.18"]
        self.destinations = ["10.0.0.10", "10.0.0.11", "10.0.0.20", "192.168.1.10", "172.16.5.20"]
        self.normal_payloads = [
            "GET /status HTTP/1.1",
            "TLS ClientHello",
            "DNS Query internal-api.local",
            "POST /api/login payload=user=demo",
            "Heartbeat packet",
        ]
        self.suspicious_payloads = [
            "GET /search?q=' OR 1=1 --",
            "<script>alert('xss')</script>",
            "cmd.exe /c whoami && net user",
            "../../../../../etc/passwd",
            "powershell -enc SQBFAFgA",
        ]

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._running = True
        self._monitoring_active = True
        self.runtime_state = "running"
        self.current_session_started_at = datetime.utcnow()
        self.last_session_started_at = self.current_session_started_at
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        self._running = False
        self._monitoring_active = False
        self.runtime_state = "stopped"
        self.last_session_ended_at = datetime.utcnow()
        self.runtime_mode = "idle"
        self.runtime_note = "Monitoring service stopped"
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def pause_monitoring(self) -> dict[str, Any]:
        self._monitoring_active = False
        self.runtime_state = "paused"
        self.runtime_mode = "idle"
        self.runtime_note = "Monitoring paused by operator"
        self.last_session_ended_at = datetime.utcnow()
        return self.get_status_snapshot()

    def resume_monitoring(self) -> dict[str, Any]:
        self._monitoring_active = True
        self.runtime_state = "running"
        self.current_session_started_at = datetime.utcnow()
        self.last_session_started_at = self.current_session_started_at
        self.last_session_ended_at = None
        with self.session_factory() as db:
            settings = db.query(Setting).first()
            _, mode, note = self._next_event(settings, preview_only=True) if settings else (None, "demo", "Demo traffic simulation active")
        self.runtime_mode = mode
        self.runtime_note = note
        return self.get_status_snapshot()

    def get_status_snapshot(self) -> dict[str, Any]:
        return {
            "state": self.runtime_state,
            "mode": self.runtime_mode,
            "note": self.runtime_note,
            "session_started_at": self.current_session_started_at.isoformat() if self.current_session_started_at else None,
            "last_session_started_at": self.last_session_started_at.isoformat() if self.last_session_started_at else None,
            "last_session_ended_at": self.last_session_ended_at.isoformat() if self.last_session_ended_at else None,
        }

    async def _run_loop(self) -> None:
        while self._running:
            if not self._monitoring_active:
                await asyncio.sleep(0.5)
                continue
            with self.session_factory() as db:
                settings = db.query(Setting).first()
                if not settings:
                    await asyncio.sleep(1.0)
                    continue

                event, mode, note = self._next_event(settings)
                self.runtime_mode = mode
                self.runtime_note = note
                if event:
                    processed = self.detector.process_event(db, event)
                    summary = build_dashboard_summary(db, self.runtime_mode)
                    await self.websocket_manager.broadcast_json(
                        {
                            "type": "traffic_event",
                            "payload": processed["traffic"],
                            "summary": summary,
                            "mode": self.runtime_mode,
                            "note": self.runtime_note,
                        }
                    )
                    if processed["alert"]:
                        await self.websocket_manager.broadcast_json(
                            {
                                "type": "alert_event",
                                "payload": processed["alert"],
                            }
                        )
                else:
                    await self.websocket_manager.broadcast_json(
                        {
                            "type": "monitor_status",
                            "payload": {
                                "state": self.runtime_state,
                                "mode": self.runtime_mode,
                                "note": self.runtime_note,
                            },
                        }
                    )
            await asyncio.sleep(random.uniform(0.8, 1.6))

    def _next_event(self, settings: Setting, preview_only: bool = False) -> tuple[dict[str, Any] | None, str, str]:
        if settings.live_mode:
            live_event = None if preview_only else self._try_live_capture(settings.live_capture_interface or None)
            if live_event:
                return live_event, "live", "Optional live packet capture active"
            fallback_event = None if preview_only else self._generate_demo_event(fallback_tag="live-fallback")
            return fallback_event, "live-fallback", (
                "Live capture unavailable or idle; demo-safe fallback traffic is active"
            )

        if settings.demo_mode:
            demo_event = None if preview_only else self._generate_demo_event()
            return demo_event, "demo", "Demo traffic simulation active"

        return None, "idle", "Monitoring is enabled but traffic generation is paused"

    def _generate_demo_event(self, fallback_tag: str | None = None) -> dict[str, Any]:
        suspicious = random.random() < 0.28
        source_ip = random.choice(self.public_sources if suspicious else self.internal_sources)
        destination_ip = random.choice(self.destinations)
        protocol = random.choice(self.protocols)
        destination_port = random.choice(
            [80, 443, 53, 8080, 445, 3389, 22, 3306] if suspicious else [80, 443, 53, 8080, 8443]
        )
        source_port = random.randint(1024, 65535)
        packet_size = random.randint(64, 1800 if suspicious else 1200)
        payload = random.choice(self.suspicious_payloads if suspicious else self.normal_payloads)
        return {
            "timestamp": datetime.utcnow(),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_size": packet_size,
            "payload": payload,
            "ingest_source": fallback_tag or "demo",
        }

    def _try_live_capture(self, interface_name: str | None) -> dict[str, Any] | None:
        try:
            from scapy.all import IP, TCP, UDP, sniff

            packets = sniff(count=1, timeout=1, iface=interface_name, store=True)
            if not packets:
                return None
            packet = packets[0]
            if IP not in packet:
                return None

            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else packet[IP].proto
            source_port = packet.sport if hasattr(packet, "sport") else 0
            destination_port = packet.dport if hasattr(packet, "dport") else 0
            payload = bytes(packet.payload).decode("utf-8", errors="ignore")[:255]
            return {
                "timestamp": datetime.utcnow(),
                "source_ip": packet[IP].src,
                "destination_ip": packet[IP].dst,
                "protocol": str(protocol),
                "source_port": int(source_port),
                "destination_port": int(destination_port),
                "packet_size": len(packet),
                "payload": payload,
                "ingest_source": "live",
            }
        except Exception:
            return None
