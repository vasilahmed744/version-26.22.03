from __future__ import annotations

from collections import Counter
from datetime import datetime
from html import escape

from sqlalchemy import desc
from sqlalchemy.orm import Session, joinedload

from backend.models import Alert, AttackLog, Setting, User


def _severity_color(severity: str) -> str:
    palette = {
        "critical": "#ff5978",
        "high": "#ff7a59",
        "medium": "#ffb84d",
        "low": "#34e7a0",
        "info": "#39d5ff",
    }
    return palette.get((severity or "info").lower(), "#39d5ff")


def _impact_label(attack_ratio: float) -> tuple[str, str]:
    if attack_ratio >= 35:
        return "HIGH", "#ff7a59"
    if attack_ratio >= 15:
        return "MEDIUM", "#ffb84d"
    return "LOW", "#34e7a0"


def _safe(value: str | None) -> str:
    return escape(str(value or "-"))


def _build_rows(logs: list[AttackLog]) -> str:
    if not logs:
        return "<tr><td colspan='11'>No telemetry is available for this report window.</td></tr>"

    rows = []
    for log in logs:
        findings = ", ".join(
            f"{finding.category}: {finding.matched_fragment}"
            for finding in log.payload_findings[:3]
        ) or "-"
        verdict_color = "#ff7a59" if log.verdict == "attack" else "#ffb84d" if log.verdict == "suspicious" else "#34e7a0"
        rows.append(
            "<tr>"
            f"<td>{_safe(log.timestamp.isoformat())}</td>"
            f"<td>{_safe(log.source_ip)}</td>"
            f"<td>{_safe(log.destination_ip)}</td>"
            f"<td>{_safe(log.protocol)}</td>"
            f"<td>{log.source_port}</td>"
            f"<td>{log.destination_port}</td>"
            f"<td>{log.packet_size}</td>"
            f"<td style='color:{verdict_color};font-weight:700'>{_safe(log.verdict.title())}</td>"
            f"<td>{round(log.risk_score, 2)}%</td>"
            f"<td>{_safe(log.detection_type)}</td>"
            f"<td>{_safe(findings)}</td>"
            "</tr>"
        )
    return "".join(rows)


def _build_alert_rows(alerts: list[Alert]) -> str:
    if not alerts:
        return "<tr><td colspan='6'>No alerts recorded in this session window.</td></tr>"

    rows = []
    for alert in alerts:
        rows.append(
            "<tr>"
            f"<td>{_safe(alert.created_at.isoformat())}</td>"
            f"<td>{_safe(alert.title)}</td>"
            f"<td>{_safe(alert.source_ip)}</td>"
            f"<td>{_safe(alert.alert_type)}</td>"
            f"<td>{_safe(alert.severity.title())}</td>"
            f"<td>{_safe(alert.status.title())}</td>"
            "</tr>"
        )
    return "".join(rows)


def generate_dashboard_report_html(
    db: Session,
    current_user: User,
    session_started_at: datetime | None,
    session_ended_at: datetime | None,
    runtime_status: dict,
) -> str:
    settings = db.query(Setting).first()

    log_query = db.query(AttackLog).options(joinedload(AttackLog.payload_findings))
    if session_started_at:
        log_query = log_query.filter(AttackLog.timestamp >= session_started_at)
    if session_ended_at:
        log_query = log_query.filter(AttackLog.timestamp <= session_ended_at)

    logs = log_query.order_by(desc(AttackLog.timestamp)).limit(200).all()
    if not logs:
        logs = (
            db.query(AttackLog)
            .options(joinedload(AttackLog.payload_findings))
            .order_by(desc(AttackLog.timestamp))
            .limit(200)
            .all()
        )

    earliest_log = logs[-1] if logs else None
    latest_log = logs[0] if logs else None
    time_window_start = session_started_at or (earliest_log.timestamp if earliest_log else None)
    time_window_end = session_ended_at or datetime.utcnow()

    alert_query = db.query(Alert)
    if time_window_start:
        alert_query = alert_query.filter(Alert.created_at >= time_window_start)
    if time_window_end:
        alert_query = alert_query.filter(Alert.created_at <= time_window_end)
    alerts = alert_query.order_by(desc(Alert.created_at)).limit(50).all()

    total_packets = len(logs)
    normal_count = sum(1 for log in logs if log.verdict == "normal")
    suspicious_count = sum(1 for log in logs if log.verdict == "suspicious")
    attack_count = sum(1 for log in logs if log.verdict == "attack")
    attack_ratio = round((attack_count / total_packets) * 100, 1) if total_packets else 0.0
    impact_label, impact_color = _impact_label(attack_ratio)

    top_source = Counter(log.source_ip for log in logs).most_common(1)
    top_destination = Counter(log.destination_ip for log in logs).most_common(1)
    top_protocol = Counter(log.protocol for log in logs).most_common(1)
    top_severity_log = max(logs, key=lambda item: item.risk_score, default=None)
    top_attack_log = max(
        [log for log in logs if log.verdict != "normal"],
        key=lambda item: item.risk_score,
        default=top_severity_log,
    )

    distinct_ports = len({log.destination_port for log in logs if log.verdict != "normal"})
    recent_findings = [
        finding
        for log in logs[:25]
        for finding in log.payload_findings
    ]
    finding_counter = Counter(finding.category.replace("_", " ") for finding in recent_findings)
    dominant_finding = finding_counter.most_common(1)[0][0].title() if finding_counter else "Anomalous Traffic"

    open_alerts = sum(1 for alert in alerts if alert.status == "open")
    max_risk = max((log.risk_score for log in logs), default=0.0)
    report_generated_at = datetime.utcnow()

    if top_attack_log and top_attack_log.verdict == "attack":
        root_cause = (
            f"The session is dominated by {escape(top_attack_log.detection_type)} traffic from "
            f"{escape(top_attack_log.source_ip)} toward {escape(top_attack_log.destination_ip)} "
            f"with a peak observed risk score of {round(top_attack_log.risk_score, 2)}%."
        )
    elif top_attack_log:
        root_cause = (
            f"The session shows elevated {escape(top_attack_log.detection_type)} behavior requiring analyst review, "
            f"primarily associated with {escape(top_attack_log.source_ip)}."
        )
    else:
        root_cause = "No high-confidence hostile pattern dominated this session window."

    recommendations = [
        "Review the most recent suspicious flows and confirm whether they match known maintenance activity.",
        "Block or rate-limit the top suspicious source if repeated hostile traffic continues.",
        "Inspect impacted hosts for exposed services on the most targeted destination ports.",
        "Tune firewall and IDS thresholds if the current pattern represents repeated benign noise.",
        "Export and retain the evidence table for forensic follow-up and audit history.",
    ]

    note_text = runtime_status.get("note") or "Telemetry status unavailable."
    mode_text = runtime_status.get("mode") or "unknown"
    state_text = runtime_status.get("state") or "unknown"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel Session Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: "Segoe UI", Arial, sans-serif;
      background:
        radial-gradient(circle at top right, rgba(57,213,255,0.12), transparent 28%),
        linear-gradient(180deg, #050d18 0%, #07111f 58%, #091425 100%);
      color: #e6f7ff;
      padding: 28px 18px;
    }}
    .page {{
      max-width: 1120px;
      margin: 0 auto;
      border-radius: 22px;
      overflow: hidden;
      border: 1px solid rgba(57,213,255,0.16);
      box-shadow: 0 24px 80px rgba(0,0,0,0.42);
      background: rgba(6, 18, 33, 0.96);
    }}
    .cover {{
      padding: 42px 40px 34px;
      background:
        linear-gradient(135deg, rgba(7,17,31,0.98) 0%, rgba(11,28,51,0.96) 50%, rgba(255,122,89,0.92) 120%);
      border-bottom: 1px solid rgba(57,213,255,0.14);
    }}
    .sub {{
      font-size: 12px;
      letter-spacing: 0.24em;
      text-transform: uppercase;
      color: #92a8c4;
      margin-bottom: 14px;
    }}
    h1 {{
      font-size: 31px;
      margin-bottom: 10px;
    }}
    .cover p {{
      color: #d2e8f8;
      max-width: 760px;
      line-height: 1.7;
    }}
    .badge {{
      display: inline-block;
      margin-top: 18px;
      padding: 7px 16px;
      border-radius: 999px;
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.12);
      color: #fff;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }}
    .cover-grid, .info-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
      margin-top: 22px;
    }}
    .cover-item, .card {{
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(57,213,255,0.14);
      border-radius: 16px;
      padding: 14px 16px;
    }}
    .cover-item label, .lbl {{
      display: block;
      font-size: 10px;
      color: #92a8c4;
      text-transform: uppercase;
      letter-spacing: 0.16em;
      margin-bottom: 6px;
    }}
    .cover-item p, .val {{
      font-size: 14px;
      font-weight: 700;
    }}
    .body {{ padding: 34px 40px 38px; }}
    h2 {{
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: #39d5ff;
      border-left: 4px solid #39d5ff;
      padding-left: 12px;
      margin: 30px 0 14px;
    }}
    h2:first-of-type {{ margin-top: 0; }}
    p, li {{
      line-height: 1.8;
      color: #c6dbeb;
      font-size: 14px;
    }}
    ul, ol {{ padding-left: 20px; }}
    .card.full {{ grid-column: 1 / -1; }}
    .alert-card {{
      border-left: 4px solid {impact_color};
      background: rgba(255,255,255,0.04);
    }}
    .tbl {{
      width: 100%;
      overflow: auto;
      border: 1px solid rgba(57,213,255,0.12);
      border-radius: 16px;
      background: rgba(2, 10, 18, 0.7);
      margin-top: 12px;
    }}
    table {{
      width: max-content;
      min-width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }}
    thead th {{
      position: sticky;
      top: 0;
      background: #081527;
      color: #e6f7ff;
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid rgba(57,213,255,0.14);
      white-space: nowrap;
    }}
    td {{
      padding: 9px 12px;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      color: #d2e8f8;
      white-space: nowrap;
      vertical-align: top;
    }}
    tr:nth-child(even) {{ background: rgba(255,255,255,0.025); }}
    .timeline {{
      display: grid;
      gap: 14px;
      margin-top: 8px;
    }}
    .tl-item {{
      display: flex;
      gap: 14px;
      align-items: flex-start;
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(57,213,255,0.1);
    }}
    .tl-dot {{
      width: 12px;
      height: 12px;
      border-radius: 50%;
      margin-top: 4px;
      background: #39d5ff;
      box-shadow: 0 0 16px rgba(57,213,255,0.55);
      flex-shrink: 0;
    }}
    .footer {{
      padding: 16px 24px;
      text-align: center;
      color: #92a8c4;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      font-size: 11px;
      border-top: 1px solid rgba(57,213,255,0.12);
      background: rgba(4, 14, 25, 0.96);
    }}
    @media (max-width: 820px) {{
      .cover-grid, .info-grid {{ grid-template-columns: 1fr; }}
      .body, .cover {{ padding-left: 22px; padding-right: 22px; }}
    }}
    @media print {{
      body {{ background: #050d18; padding: 0; }}
      .page {{ box-shadow: none; border-radius: 0; max-width: none; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="cover">
      <div class="sub">Sentinel SOC Console • Session Report</div>
      <h1>Network Intrusion Detection Report</h1>
      <p>This report summarizes the latest Sentinel monitoring session, including telemetry volume, suspicious activity, alerts, evidence, and operator-ready recommendations.</p>
      <span class="badge">Impact: {impact_label}</span>
      <div class="cover-grid">
        <div class="cover-item"><label>Generated At</label><p>{report_generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")}</p></div>
        <div class="cover-item"><label>Analyst</label><p>{_safe(current_user.username)}</p></div>
        <div class="cover-item"><label>Monitor State</label><p>{_safe(state_text.title())}</p></div>
        <div class="cover-item"><label>Monitor Mode</label><p>{_safe(mode_text.title())}</p></div>
      </div>
    </div>
    <div class="body">
      <h2>Executive Summary</h2>
      <p>Sentinel analysed <strong>{total_packets}</strong> recent packet records in the selected session window. The platform observed <strong style="color:#34e7a0">{normal_count}</strong> normal events, <strong style="color:#ffb84d">{suspicious_count}</strong> suspicious events, and <strong style="color:#ff7a59">{attack_count}</strong> attack events. A total of <strong>{len(alerts)}</strong> alerts were generated, with <strong>{open_alerts}</strong> still open. Current runtime note: <strong>{_safe(note_text)}</strong>.</p>

      <h2>Incident Details</h2>
      <div class="info-grid">
        <div class="card"><div class="lbl">Total Packets</div><div class="val">{total_packets}</div></div>
        <div class="card"><div class="lbl">Attack Traffic</div><div class="val" style="color:#ff7a59">{attack_count} ({attack_ratio}%)</div></div>
        <div class="card"><div class="lbl">Suspicious Traffic</div><div class="val" style="color:#ffb84d">{suspicious_count}</div></div>
        <div class="card"><div class="lbl">Open Alerts</div><div class="val">{open_alerts}</div></div>
        <div class="card"><div class="lbl">Peak Risk Score</div><div class="val">{round(max_risk, 2)}%</div></div>
        <div class="card"><div class="lbl">Payload Indicator</div><div class="val">{_safe(dominant_finding)}</div></div>
        <div class="card full alert-card"><div class="lbl">Primary Detection Pattern</div><div class="val" style="color:{_severity_color(top_attack_log.severity if top_attack_log else 'info')}; font-size:16px">{_safe(top_attack_log.detection_type if top_attack_log else "No dominant hostile pattern")}</div><p>{_safe(top_attack_log.summary if top_attack_log else "The monitor has not yet accumulated enough hostile evidence to identify a dominant attack narrative.")}</p></div>
      </div>

      <h2>Source and Destination Info</h2>
      <div class="info-grid">
        <div class="card"><div class="lbl">Top Source IP</div><div class="val">{_safe(top_source[0][0] if top_source else "-")}</div></div>
        <div class="card"><div class="lbl">Top Destination IP</div><div class="val">{_safe(top_destination[0][0] if top_destination else "-")}</div></div>
        <div class="card"><div class="lbl">Dominant Protocol</div><div class="val">{_safe(top_protocol[0][0] if top_protocol else "-")}</div></div>
        <div class="card"><div class="lbl">Distinct Targeted Ports</div><div class="val">{distinct_ports}</div></div>
      </div>

      <h2>Alert Information</h2>
      <div class="tbl">
        <table>
          <thead><tr><th>Created At</th><th>Title</th><th>Source IP</th><th>Type</th><th>Severity</th><th>Status</th></tr></thead>
          <tbody>{_build_alert_rows(alerts)}</tbody>
        </table>
      </div>

      <h2>Timeline of Events</h2>
      <div class="timeline">
        <div class="tl-item"><div class="tl-dot"></div><div><div class="lbl">Session Start</div><div class="val">{_safe(time_window_start.isoformat() if time_window_start else "-")}</div></div></div>
        <div class="tl-item"><div class="tl-dot" style="background:#ffb84d; box-shadow:0 0 16px rgba(255,184,77,0.55)"></div><div><div class="lbl">Peak Detection</div><div class="val">{_safe(top_attack_log.title if hasattr(top_attack_log, 'title') else (top_attack_log.detection_type if top_attack_log else 'N/A'))}</div></div></div>
        <div class="tl-item"><div class="tl-dot" style="background:#34e7a0; box-shadow:0 0 16px rgba(52,231,160,0.55)"></div><div><div class="lbl">Latest Event</div><div class="val">{_safe(latest_log.timestamp.isoformat() if latest_log else "-")}</div></div></div>
        <div class="tl-item"><div class="tl-dot" style="background:#4d8cff; box-shadow:0 0 16px rgba(77,140,255,0.55)"></div><div><div class="lbl">Report Generated</div><div class="val">{report_generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")}</div></div></div>
      </div>

      <h2>Evidence and Logs</h2>
      <p>The table below contains the most recent evidence rows from the selected session window and is intended for analyst review, triage, and export-ready incident notes.</p>
      <div class="tbl">
        <table>
          <thead><tr><th>Timestamp</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>Src Port</th><th>Dst Port</th><th>Size</th><th>Verdict</th><th>Risk</th><th>Detection Type</th><th>Payload Findings</th></tr></thead>
          <tbody>{_build_rows(logs)}</tbody>
        </table>
      </div>

      <h2>Impact Analysis</h2>
      <p>Overall impact is assessed as <strong style="color:{impact_color}">{impact_label}</strong> based on the proportion and severity of suspicious and attack-labelled traffic in this session. The current session indicates elevated focus on {_safe(top_destination[0][0] if top_destination else "internal services")} and should be reviewed for service exposure, repeated scanning, and payload abuse patterns.</p>
      <ul>
        <li>Operational availability risk increases when attack traffic repeatedly targets many ports or critical services.</li>
        <li>Confidentiality risk increases if payload inspection indicates SQL injection, command execution, or script injection patterns.</li>
        <li>Integrity risk increases when repeated hostile traffic reaches privileged or management interfaces.</li>
      </ul>

      <h2>Root Cause Analysis</h2>
      <p>{root_cause}</p>

      <h2>Mitigation and Response Taken</h2>
      <ul>
        <li>Sentinel recorded telemetry, alert, firewall, and payload evidence into the local platform database.</li>
        <li>Session window: <strong>{_safe(time_window_start.isoformat() if time_window_start else "-")}</strong> to <strong>{_safe(time_window_end.isoformat() if time_window_end else "-")}</strong>.</li>
        <li>Automatic recommendations were derived from the highest-risk recent activity and active monitor settings.</li>
        <li>Current firewall simulation setting: <strong>{'Enabled' if settings and settings.firewall_simulation_enabled else 'Disabled'}</strong>.</li>
      </ul>

      <h2>Recommendations</h2>
      <ol>
        {"".join(f"<li>{_safe(item)}</li>" for item in recommendations)}
      </ol>

      <h2>Conclusion</h2>
      <p>Sentinel generated this report for operator <strong>{_safe(current_user.username)}</strong> using the platform's latest session telemetry. {_safe(top_attack_log.detection_type if top_attack_log else 'No dominant hostile pattern')} was the most significant observed pattern, and the session should be treated as {impact_label.lower()} priority until the highlighted sources, payload indicators, and targeted services are reviewed.</p>
    </div>
    <div class="footer">Sentinel IDS/IPS Report • {report_generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
  </div>
</body>
</html>"""
