from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from backend.analytics import serialize_alert, serialize_log
from backend.blocker import FirewallBlocker
from backend.geoip import GeoIPService
from backend.models import Alert, AttackLog, PayloadFinding, Setting
from backend.payload_inspector import PayloadInspector


class DetectionEngine:
    def __init__(
        self,
        payload_inspector: PayloadInspector,
        geoip_service: GeoIPService,
        blocker: FirewallBlocker,
    ) -> None:
        self.payload_inspector = payload_inspector
        self.geoip_service = geoip_service
        self.blocker = blocker
        self.recent_activity: dict[str, deque] = defaultdict(deque)

    def process_event(self, db: Session, event: dict[str, Any]) -> dict[str, Any]:
        settings = db.query(Setting).first()
        if not settings:
            raise RuntimeError("Application settings are not initialized")

        risk_score, severity, verdict, detection_type, summary, action = self._score_event(
            db,
            event,
            settings,
        )
        geo_data = self.geoip_service.lookup_ip(
            db,
            event["source_ip"],
            allow_external=settings.geoip_enabled,
        ) if settings.geoip_enabled else {}

        log = AttackLog(
            timestamp=event["timestamp"],
            source_ip=event["source_ip"],
            destination_ip=event["destination_ip"],
            protocol=event["protocol"],
            source_port=event["source_port"],
            destination_port=event["destination_port"],
            packet_size=event["packet_size"],
            verdict=verdict,
            severity=severity,
            risk_score=risk_score,
            detection_type=detection_type,
            summary=summary,
            payload_sample=event.get("payload"),
            geo_country=geo_data.get("country"),
            geo_region=geo_data.get("region"),
            geo_city=geo_data.get("city"),
            geo_isp=geo_data.get("isp"),
            recommended_action=action,
            raw_event=self._serialize_event(event),
            is_blocked=self.blocker.is_ip_blocked(db, event["source_ip"]),
        )
        db.add(log)
        db.flush()

        payload_result = self.payload_inspector.inspect(
            event.get("payload"),
            enabled=settings.payload_inspection_enabled,
        )
        for finding in payload_result["findings"]:
            db.add(
                PayloadFinding(
                    attack_log_id=log.id,
                    rule_name=finding["rule_name"],
                    category=finding["category"],
                    matched_fragment=finding["matched_fragment"],
                    risk_score=finding["risk_score"],
                    details=finding["details"],
                )
            )
        db.flush()

        created_alert = None
        should_create_alert = (
            verdict in {"suspicious", "attack"}
            and ((severity == "medium" and settings.alert_on_medium) or severity in {"high", "critical"})
            and (severity != "high" or settings.alert_on_high or severity == "critical")
        )
        if should_create_alert:
            created_alert = Alert(
                attack_log_id=log.id,
                severity=severity,
                alert_type=detection_type,
                title=f"{severity.title()} {detection_type}",
                description=summary,
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                recommended_action=action,
            )
            db.add(created_alert)
            db.flush()

        if settings.auto_block_high_risk and risk_score >= 88 and not self.blocker.is_ip_blocked(db, log.source_ip):
            blocked = self.blocker.block_ip(
                db,
                ip_address=log.source_ip,
                reason=f"Auto-blocked after {detection_type}",
                duration_minutes=120,
                permanent=False,
            )
            log.is_blocked = blocked.is_active

        db.commit()
        db.refresh(log)
        if created_alert:
            db.refresh(created_alert)

        return {
            "traffic": serialize_log(log),
            "alert": serialize_alert(created_alert) if created_alert else None,
        }

    def _score_event(self, db: Session, event: dict[str, Any], settings: Setting) -> tuple[float, str, str, str, str, str]:
        score = 5.0
        indicators: list[str] = []

        suspicious_ports = {22, 23, 53, 135, 139, 445, 1433, 3306, 3389, 4444, 5900, 8080}
        if event["destination_port"] in suspicious_ports:
            score += 18
            indicators.append("suspicious port scan target")

        if event["protocol"] in {"ICMP", "UDP"}:
            score += 6
            indicators.append(f"atypical {event['protocol']} activity")

        if event["packet_size"] > 1400:
            score += 9
            indicators.append("oversized packet profile")

        recent_events = self.recent_activity[event["source_ip"]]
        now = event["timestamp"]
        recent_events.append(now)
        while recent_events and recent_events[0] < now - timedelta(seconds=45):
            recent_events.popleft()
        if len(recent_events) >= 10:
            score += 28
            indicators.append("burst activity from a single source")
        elif len(recent_events) >= 5:
            score += 14
            indicators.append("elevated event rate")

        payload_result = self.payload_inspector.inspect(
            event.get("payload"),
            enabled=settings.payload_inspection_enabled,
        )
        if payload_result["findings"]:
            score += payload_result["total_score"] * 0.7
            categories = {finding["category"] for finding in payload_result["findings"]}
            indicators.extend(sorted(category.replace("_", " ") for category in categories))

        if self.blocker.is_ip_blocked(db, event["source_ip"]):
            score = max(score, 95.0)
            indicators.append("traffic from blocked source")

        score = min(score, 100.0)

        if score >= 90:
            severity = "critical"
            verdict = "attack"
        elif score >= 75:
            severity = "high"
            verdict = "attack"
        elif score >= settings.detection_threshold:
            severity = "medium"
            verdict = "suspicious"
        elif score >= 35:
            severity = "low"
            verdict = "suspicious"
        else:
            severity = "info"
            verdict = "normal"

        if payload_result["findings"]:
            detection_type = payload_result["findings"][0]["category"].replace("_", " ").title()
        elif "burst activity from a single source" in indicators:
            detection_type = "Network Scan"
        elif event["destination_port"] in suspicious_ports:
            detection_type = "Reconnaissance"
        else:
            detection_type = "Anomalous Traffic"

        summary = (
            f"{event['protocol']} traffic from {event['source_ip']} to {event['destination_ip']} "
            f"was classified as {verdict} because of {', '.join(indicators[:3]) or 'baseline-safe behaviour'}."
        )
        action = (
            "Block source IP and investigate endpoint"
            if severity in {"high", "critical"}
            else "Review traffic context and continue monitoring"
        )
        return score, severity, verdict, detection_type, summary, action

    @staticmethod
    def _serialize_event(event: dict[str, Any]) -> dict[str, Any]:
        serialized: dict[str, Any] = {}
        for key, value in event.items():
            if isinstance(value, datetime):
                serialized[key] = value.isoformat()
            else:
                serialized[key] = value
        return serialized
