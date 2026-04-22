from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from io import StringIO
import csv

from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.models import Alert, AttackLog, BlockedIP


def serialize_payload_findings(log: AttackLog) -> list[dict]:
    return [
        {
            "id": finding.id,
            "rule_name": finding.rule_name,
            "category": finding.category,
            "matched_fragment": finding.matched_fragment,
            "risk_score": finding.risk_score,
            "details": finding.details,
        }
        for finding in log.payload_findings
    ]


def serialize_log(log: AttackLog) -> dict:
    return {
        "id": log.id,
        "timestamp": log.timestamp.isoformat(),
        "source_ip": log.source_ip,
        "destination_ip": log.destination_ip,
        "protocol": log.protocol,
        "source_port": log.source_port,
        "destination_port": log.destination_port,
        "packet_size": log.packet_size,
        "verdict": log.verdict,
        "severity": log.severity,
        "risk_score": round(log.risk_score, 2),
        "detection_type": log.detection_type,
        "summary": log.summary,
        "payload_sample": log.payload_sample,
        "geo_country": log.geo_country,
        "geo_region": log.geo_region,
        "geo_city": log.geo_city,
        "geo_isp": log.geo_isp,
        "recommended_action": log.recommended_action,
        "is_blocked": log.is_blocked,
        "payload_findings": serialize_payload_findings(log),
    }


def serialize_alert(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "attack_log_id": alert.attack_log_id,
        "severity": alert.severity,
        "alert_type": alert.alert_type,
        "title": alert.title,
        "description": alert.description,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "recommended_action": alert.recommended_action,
        "status": alert.status,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "created_at": alert.created_at.isoformat(),
        "attack_log": serialize_log(alert.attack_log) if alert.attack_log else None,
    }


def build_dashboard_summary(db: Session, monitoring_mode: str) -> dict:
    logs = db.query(AttackLog).order_by(desc(AttackLog.timestamp)).limit(500).all()
    alerts = db.query(Alert).filter(Alert.status == "open").count()
    blocked_ips = db.query(BlockedIP).filter(BlockedIP.is_active.is_(True)).count()

    total_packets = len(logs)
    normal_traffic = sum(1 for log in logs if log.verdict == "normal")
    suspicious_traffic = sum(1 for log in logs if log.verdict == "suspicious")
    attack_count = sum(1 for log in logs if log.verdict == "attack")
    risk_percentage = round(
        (sum(log.risk_score for log in logs) / max(total_packets, 1)),
        2,
    )

    top_counter = Counter(log.source_ip for log in logs if log.verdict != "normal")
    top_suspicious_ips = [
        {"ip": ip, "count": count}
        for ip, count in top_counter.most_common(5)
    ]

    geo_counter = Counter(
        log.geo_country or "Unknown"
        for log in logs
        if log.verdict != "normal"
    )
    geo_summary = [
        {"country": country, "count": count}
        for country, count in geo_counter.most_common(5)
    ]

    protocol_counter = Counter(log.protocol for log in logs)
    protocol_distribution = [
        {"protocol": protocol, "count": count}
        for protocol, count in protocol_counter.items()
    ]

    bucket_start = datetime.utcnow() - timedelta(minutes=9)
    trend_buckets: dict[str, int] = defaultdict(int)
    for log in logs:
        if log.timestamp >= bucket_start:
            bucket_key = log.timestamp.replace(second=0, microsecond=0).strftime("%H:%M")
            trend_buckets[bucket_key] += 1
    traffic_trend = [
        {"minute": minute, "count": count}
        for minute, count in sorted(trend_buckets.items())
    ]

    return {
        "total_packets": total_packets,
        "normal_traffic": normal_traffic,
        "suspicious_traffic": suspicious_traffic,
        "attack_count": attack_count,
        "risk_percentage": risk_percentage,
        "active_alerts": alerts,
        "blocked_ips": blocked_ips,
        "monitoring_mode": monitoring_mode,
        "top_suspicious_ips": top_suspicious_ips,
        "geo_summary": geo_summary,
        "protocol_distribution": protocol_distribution,
        "traffic_trend": traffic_trend,
    }


def export_logs_to_csv(logs: list[AttackLog]) -> str:
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "packet_size",
            "verdict",
            "severity",
            "risk_score",
            "detection_type",
            "summary",
            "geo_country",
            "geo_region",
            "geo_city",
            "geo_isp",
            "payload_findings",
        ]
    )
    for log in logs:
        finding_text = "; ".join(
            f"{finding.category}:{finding.matched_fragment}"
            for finding in log.payload_findings
        )
        writer.writerow(
            [
                log.timestamp.isoformat(),
                log.source_ip,
                log.destination_ip,
                log.protocol,
                log.source_port,
                log.destination_port,
                log.packet_size,
                log.verdict,
                log.severity,
                round(log.risk_score, 2),
                log.detection_type,
                log.summary,
                log.geo_country or "",
                log.geo_region or "",
                log.geo_city or "",
                log.geo_isp or "",
                finding_text,
            ]
        )
    return buffer.getvalue()
