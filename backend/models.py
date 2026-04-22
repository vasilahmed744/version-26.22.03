from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from backend.database import Base


class TimestampMixin:
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="viewer", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login_at = Column(DateTime, nullable=True)

    sessions = relationship("SessionToken", back_populates="user")
    alerts_acknowledged = relationship("Alert", back_populates="acknowledged_by")
    blocks_created = relationship("BlockedIP", back_populates="created_by")


class SessionToken(Base):
    __tablename__ = "session_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(ForeignKey("users.id"), nullable=False)
    jti = Column(String(64), unique=True, index=True, nullable=False)
    token_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="sessions")


class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=False)
    destination_ip = Column(String(64), index=True, nullable=False)
    protocol = Column(String(20), nullable=False)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False)
    packet_size = Column(Integer, nullable=False)
    verdict = Column(String(20), index=True, nullable=False)
    severity = Column(String(20), index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    detection_type = Column(String(80), nullable=False)
    summary = Column(String(255), nullable=False)
    payload_sample = Column(Text, nullable=True)
    geo_country = Column(String(80), nullable=True)
    geo_region = Column(String(80), nullable=True)
    geo_city = Column(String(80), nullable=True)
    geo_isp = Column(String(120), nullable=True)
    recommended_action = Column(String(120), nullable=True)
    raw_event = Column(JSON, nullable=True)
    is_blocked = Column(Boolean, default=False, nullable=False)

    alert = relationship("Alert", back_populates="attack_log", uselist=False)
    payload_findings = relationship(
        "PayloadFinding",
        back_populates="attack_log",
        cascade="all, delete-orphan",
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    attack_log_id = Column(ForeignKey("attack_logs.id"), nullable=False, unique=True)
    severity = Column(String(20), index=True, nullable=False)
    alert_type = Column(String(80), nullable=False)
    title = Column(String(150), nullable=False)
    description = Column(Text, nullable=False)
    source_ip = Column(String(64), index=True, nullable=False)
    destination_ip = Column(String(64), nullable=False)
    recommended_action = Column(String(120), nullable=False)
    status = Column(String(20), default="open", nullable=False)
    acknowledged_by_id = Column(ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    attack_log = relationship("AttackLog", back_populates="alert")
    acknowledged_by = relationship("User", back_populates="alerts_acknowledged")


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(64), index=True, nullable=False)
    reason = Column(String(255), nullable=False)
    status = Column(String(20), default="active", nullable=False)
    mode = Column(String(20), default="simulation", nullable=False)
    blocked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by_id = Column(ForeignKey("users.id"), nullable=True)

    created_by = relationship("User", back_populates="blocks_created")


class GeoIPCache(Base):
    __tablename__ = "geoip_cache"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(64), unique=True, index=True, nullable=False)
    country = Column(String(80), nullable=True)
    region = Column(String(80), nullable=True)
    city = Column(String(80), nullable=True)
    isp = Column(String(120), nullable=True)
    source = Column(String(40), default="demo", nullable=False)
    fetched_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ttl_seconds = Column(Integer, default=86400, nullable=False)


class PayloadFinding(Base):
    __tablename__ = "payload_findings"

    id = Column(Integer, primary_key=True, index=True)
    attack_log_id = Column(ForeignKey("attack_logs.id"), nullable=False)
    rule_name = Column(String(120), nullable=False)
    category = Column(String(80), nullable=False)
    matched_fragment = Column(String(255), nullable=False)
    risk_score = Column(Float, nullable=False)
    details = Column(String(255), nullable=True)

    attack_log = relationship("AttackLog", back_populates="payload_findings")


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, default=1)
    demo_mode = Column(Boolean, default=True, nullable=False)
    live_mode = Column(Boolean, default=False, nullable=False)
    payload_inspection_enabled = Column(Boolean, default=True, nullable=False)
    firewall_simulation_enabled = Column(Boolean, default=True, nullable=False)
    geoip_enabled = Column(Boolean, default=True, nullable=False)
    auto_block_high_risk = Column(Boolean, default=False, nullable=False)
    alert_on_medium = Column(Boolean, default=True, nullable=False)
    alert_on_high = Column(Boolean, default=True, nullable=False)
    detection_threshold = Column(Integer, default=65, nullable=False)
    max_events_per_minute = Column(Integer, default=90, nullable=False)
    live_capture_interface = Column(String(120), nullable=True)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
