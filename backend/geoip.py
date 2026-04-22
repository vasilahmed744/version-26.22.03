from __future__ import annotations

from datetime import datetime, timedelta
import hashlib

import httpx
from sqlalchemy.orm import Session

from backend.models import GeoIPCache
from backend.utils.network import is_public_ip


class GeoIPService:
    def __init__(self) -> None:
        self.demo_countries = [
            ("United States", "Virginia", "Ashburn", "Amazon AWS"),
            ("Germany", "Hesse", "Frankfurt", "Hetzner"),
            ("India", "Maharashtra", "Mumbai", "Reliance Jio"),
            ("Singapore", "Central Singapore", "Singapore", "DigitalOcean"),
            ("Netherlands", "North Holland", "Amsterdam", "Leaseweb"),
            ("United Kingdom", "England", "London", "OVHcloud"),
        ]

    def lookup_ip(self, db: Session, ip_address: str, allow_external: bool = True) -> dict:
        if not is_public_ip(ip_address):
            return {
                "country": "Internal Network",
                "region": "Local Segment",
                "city": "Private Address Space",
                "isp": "Local Infrastructure",
                "source": "private",
            }

        cached = db.query(GeoIPCache).filter(GeoIPCache.ip_address == ip_address).first()
        if cached:
            expires_at = cached.fetched_at + timedelta(seconds=cached.ttl_seconds)
            if expires_at > datetime.utcnow():
                return {
                    "country": cached.country,
                    "region": cached.region,
                    "city": cached.city,
                    "isp": cached.isp,
                    "source": cached.source,
                }

        data = None
        if allow_external:
            data = self._lookup_external(ip_address)
        if not data:
            data = self._demo_lookup(ip_address)

        if cached:
            cached.country = data["country"]
            cached.region = data["region"]
            cached.city = data["city"]
            cached.isp = data["isp"]
            cached.source = data["source"]
            cached.fetched_at = datetime.utcnow()
        else:
            db.add(
                GeoIPCache(
                    ip_address=ip_address,
                    country=data["country"],
                    region=data["region"],
                    city=data["city"],
                    isp=data["isp"],
                    source=data["source"],
                )
            )
        db.flush()
        return data

    def _lookup_external(self, ip_address: str) -> dict | None:
        try:
            response = httpx.get(f"http://ip-api.com/json/{ip_address}", timeout=2.5)
            if response.status_code != 200:
                return None
            payload = response.json()
            if payload.get("status") != "success":
                return None
            return {
                "country": payload.get("country") or "Unknown",
                "region": payload.get("regionName") or "Unknown",
                "city": payload.get("city") or "Unknown",
                "isp": payload.get("isp") or "Unknown",
                "source": "ip-api",
            }
        except Exception:
            return None

    def _demo_lookup(self, ip_address: str) -> dict:
        digest = hashlib.sha256(ip_address.encode("utf-8")).hexdigest()
        index = int(digest[:8], 16) % len(self.demo_countries)
        country, region, city, isp = self.demo_countries[index]
        return {
            "country": country,
            "region": region,
            "city": city,
            "isp": isp,
            "source": "demo",
        }
