from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserPublic"


class LoginRequest(BaseModel):
    username: str
    password: str


class UserBase(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: str
    is_active: bool = True


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)


class UserUpdate(BaseModel):
    email: str | None = Field(default=None, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserPublic(UserBase):
    id: int
    last_login_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SettingsResponse(BaseModel):
    demo_mode: bool
    live_mode: bool
    payload_inspection_enabled: bool
    firewall_simulation_enabled: bool
    geoip_enabled: bool
    auto_block_high_risk: bool
    alert_on_medium: bool
    alert_on_high: bool
    detection_threshold: int
    max_events_per_minute: int
    live_capture_interface: str | None = ""
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class SettingsUpdate(BaseModel):
    demo_mode: bool
    live_mode: bool
    payload_inspection_enabled: bool
    firewall_simulation_enabled: bool
    geoip_enabled: bool
    auto_block_high_risk: bool
    alert_on_medium: bool
    alert_on_high: bool
    detection_threshold: int = Field(ge=1, le=100)
    max_events_per_minute: int = Field(ge=10, le=10000)
    live_capture_interface: str | None = ""


class PayloadFindingResponse(BaseModel):
    id: int
    rule_name: str
    category: str
    matched_fragment: str
    risk_score: float
    details: str | None = None

    model_config = ConfigDict(from_attributes=True)


class AttackLogResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packet_size: int
    verdict: str
    severity: str
    risk_score: float
    detection_type: str
    summary: str
    payload_sample: str | None = None
    geo_country: str | None = None
    geo_region: str | None = None
    geo_city: str | None = None
    geo_isp: str | None = None
    recommended_action: str | None = None
    is_blocked: bool
    payload_findings: list[PayloadFindingResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class AlertResponse(BaseModel):
    id: int
    attack_log_id: int
    severity: str
    alert_type: str
    title: str
    description: str
    source_ip: str
    destination_ip: str
    recommended_action: str
    status: str
    acknowledged_at: datetime | None = None
    created_at: datetime
    attack_log: AttackLogResponse | None = None

    model_config = ConfigDict(from_attributes=True)


class FirewallBlockCreate(BaseModel):
    ip_address: str
    reason: str = Field(min_length=3, max_length=255)
    duration_minutes: int | None = Field(default=None, ge=1, le=10080)
    permanent: bool = False


class FirewallBlockResponse(BaseModel):
    id: int
    ip_address: str
    reason: str
    status: str
    mode: str
    blocked_at: datetime
    expires_at: datetime | None = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class DashboardSummary(BaseModel):
    total_packets: int
    normal_traffic: int
    suspicious_traffic: int
    attack_count: int
    risk_percentage: float
    active_alerts: int
    blocked_ips: int
    monitoring_mode: str
    top_suspicious_ips: list[dict[str, Any]]
    geo_summary: list[dict[str, Any]]
    protocol_distribution: list[dict[str, Any]]
    traffic_trend: list[dict[str, Any]]


TokenResponse.model_rebuild()
