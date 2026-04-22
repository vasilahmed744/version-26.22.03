import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
ASSETS_DIR = FRONTEND_DIR / "assets"
ENV_FILE = BASE_DIR / ".env"

load_dotenv(ENV_FILE)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    stripped = value.strip()
    return stripped if stripped else default


APP_NAME = "Sentinel IDS/IPS Platform"
API_PREFIX = "/api"
WS_PATH = "/ws/stream"
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DEBUG = _env_bool("DEBUG", APP_ENV != "production")

DATABASE_PATH = Path(_env_str("DATABASE_PATH", str(BASE_DIR / "sentinel_ids.db"))).resolve()
DATABASE_URL = _env_str("DATABASE_URL", f"sqlite:///{DATABASE_PATH.as_posix()}")

JWT_SECRET = _env_str("JWT_SECRET", "change-this-demo-secret-before-production")
JWT_ALGORITHM = _env_str("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(_env_str("ACCESS_TOKEN_EXPIRE_MINUTES", str(60 * 12)))

HOST = _env_str("HOST", "127.0.0.1")
PORT = int(_env_str("PORT", "8000"))
RELOAD = _env_bool("RELOAD", APP_ENV != "production")

CORS_ALLOW_CREDENTIALS = _env_bool("CORS_ALLOW_CREDENTIALS", True)
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]

DEFAULT_SETTINGS = {
    "demo_mode": True,
    "live_mode": False,
    "payload_inspection_enabled": True,
    "firewall_simulation_enabled": True,
    "geoip_enabled": True,
    "auto_block_high_risk": False,
    "detection_threshold": 65,
    "alert_on_medium": True,
    "alert_on_high": True,
    "max_events_per_minute": 90,
    "live_capture_interface": "",
}

SUPPORTED_ROLES = ("admin", "analyst", "viewer")
