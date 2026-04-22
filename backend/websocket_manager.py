from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class WebSocketManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast_json(self, payload: dict[str, Any]) -> None:
        dead_connections: list[WebSocket] = []
        async with self._lock:
            recipients = list(self._connections)

        for connection in recipients:
            try:
                await connection.send_json(payload)
            except Exception:
                dead_connections.append(connection)

        if dead_connections:
            async with self._lock:
                for connection in dead_connections:
                    self._connections.discard(connection)
