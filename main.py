from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.auth import get_user_from_token
from backend.config import (
    ALLOWED_ORIGINS,
    API_PREFIX,
    APP_NAME,
    APP_ENV,
    ASSETS_DIR,
    CORS_ALLOW_CREDENTIALS,
    DEBUG,
    FRONTEND_DIR,
    JWT_SECRET,
    WS_PATH,
)
from backend.database import SessionLocal
from backend.routes.alerts_routes import router as alerts_router
from backend.routes.auth_routes import router as auth_router
from backend.routes.dashboard_routes import router as dashboard_router
from backend.routes.firewall_routes import router as firewall_router
from backend.routes.logs_routes import router as logs_router
from backend.routes.settings_routes import router as settings_router
from backend.routes.traffic_routes import router as traffic_router
from backend.routes.users_routes import router as users_router
from backend.runtime import AppServices
from backend.seed import initialize_database, seed_defaults


@asynccontextmanager
async def lifespan(app: FastAPI):
    if APP_ENV == "production" and JWT_SECRET == "change-this-demo-secret-before-production":
        raise RuntimeError("JWT_SECRET must be set in production")

    initialize_database()
    with SessionLocal() as db:
        seed_defaults(db)

    app.state.services = AppServices(SessionLocal)
    await app.state.services.traffic_monitor.start()
    yield
    await app.state.services.traffic_monitor.stop()


app = FastAPI(title=APP_NAME, version="1.0.0", lifespan=lifespan, debug=DEBUG)

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=CORS_ALLOW_CREDENTIALS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(dashboard_router, prefix=API_PREFIX)
app.include_router(traffic_router, prefix=API_PREFIX)
app.include_router(alerts_router, prefix=API_PREFIX)
app.include_router(logs_router, prefix=API_PREFIX)
app.include_router(firewall_router, prefix=API_PREFIX)
app.include_router(users_router, prefix=API_PREFIX)
app.include_router(settings_router, prefix=API_PREFIX)


def _serve_page(filename: str) -> FileResponse:
    page_path = FRONTEND_DIR / filename
    return FileResponse(page_path)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/login")


@app.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok", "service": APP_NAME}


@app.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    return _serve_page("login.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page() -> FileResponse:
    return _serve_page("dashboard.html")


@app.get("/traffic", include_in_schema=False)
def traffic_page() -> FileResponse:
    return _serve_page("traffic.html")


@app.get("/alerts", include_in_schema=False)
def alerts_page() -> FileResponse:
    return _serve_page("alerts.html")


@app.get("/logs", include_in_schema=False)
def logs_page() -> FileResponse:
    return _serve_page("logs.html")


@app.get("/firewall", include_in_schema=False)
def firewall_page() -> FileResponse:
    return _serve_page("firewall.html")


@app.get("/users", include_in_schema=False)
def users_page() -> FileResponse:
    return _serve_page("users.html")


@app.get("/settings", include_in_schema=False)
def settings_page() -> FileResponse:
    return _serve_page("settings.html")


@app.websocket(WS_PATH, name="websocket_stream")
async def websocket_stream(websocket: WebSocket) -> None:
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    with SessionLocal() as db:
        try:
            user = get_user_from_token(db, token)
        except Exception:
            await websocket.close(code=1008)
            return

    services = websocket.app.state.services
    await services.websocket_manager.connect(websocket)
    await websocket.send_json(
        {
            "type": "welcome",
            "payload": {
                "message": f"Connected to Sentinel stream as {user.username}",
                "mode": services.traffic_monitor.runtime_mode,
                "note": services.traffic_monitor.runtime_note,
            },
        }
    )
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await services.websocket_manager.disconnect(websocket)
