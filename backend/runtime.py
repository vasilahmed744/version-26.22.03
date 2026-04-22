from __future__ import annotations

from sqlalchemy.orm import sessionmaker

from backend.blocker import FirewallBlocker
from backend.detection_engine import DetectionEngine
from backend.geoip import GeoIPService
from backend.payload_inspector import PayloadInspector
from backend.traffic_simulator import TrafficMonitorService
from backend.websocket_manager import WebSocketManager


class AppServices:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.websocket_manager = WebSocketManager()
        self.blocker = FirewallBlocker()
        self.geoip = GeoIPService()
        self.payload_inspector = PayloadInspector()
        self.detector = DetectionEngine(self.payload_inspector, self.geoip, self.blocker)
        self.traffic_monitor = TrafficMonitorService(session_factory, self.detector, self.websocket_manager)
