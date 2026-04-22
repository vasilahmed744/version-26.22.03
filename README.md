# Sentinel IDS/IPS Platform

Sentinel is a final-year-project-quality Intrusion Detection System / lightweight Intrusion Prevention System built with FastAPI, SQLite, WebSockets, and a cybersecurity-themed HTML/CSS/JavaScript dashboard.

## Architecture Overview

The platform is split into two layers:

1. Backend
   - FastAPI REST APIs for authentication, users, alerts, logs, firewall controls, settings, and dashboard data.
   - WebSocket streaming for real-time packet, alert, and metrics updates.
   - A modular detection pipeline that simulates or ingests traffic, enriches public IPs, inspects payloads, scores risk, writes logs, and emits alerts.
   - A safe-by-default firewall blocker that persists block records and can optionally call Windows or Linux firewall commands.

2. Frontend
   - Multi-page SOC dashboard built with HTML5, CSS3, vanilla JavaScript, and Chart.js.
   - Real-time cards, charts, tables, alert workflow, firewall controls, log filtering, and user/role management.
   - Shared assets with a consistent dark cyber-defense visual language.

## Project Structure

```text
soc_ids_platform/
├── backend/
│   ├── routes/
│   ├── utils/
│   ├── auth.py
│   ├── blocker.py
│   ├── config.py
│   ├── database.py
│   ├── detection_engine.py
│   ├── geoip.py
│   ├── models.py
│   ├── payload_inspector.py
│   ├── schemas.py
│   ├── seed.py
│   ├── traffic_simulator.py
│   └── websocket_manager.py
├── frontend/
│   ├── assets/
│   │   ├── css/
│   │   ├── img/
│   │   └── js/
│   ├── alerts.html
│   ├── dashboard.html
│   ├── firewall.html
│   ├── login.html
│   ├── logs.html
│   ├── settings.html
│   ├── traffic.html
│   └── users.html
├── main.py
├── README.md
└── requirements.txt
```

## Default Demo Accounts

- Admin: `admin` / `Admin@123`
- Analyst: `analyst` / `Analyst@123`
- Viewer: `viewer` / `Viewer@123`

The app seeds those accounts automatically on first startup.

## Setup Instructions

1. Open the `soc_ids_platform` folder in VS Code.
2. Create and activate a virtual environment:
   - Windows PowerShell:
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
4. Copy the deployment template for local configuration:
   ```powershell
   Copy-Item .env.example .env
   ```

## Run Instructions

Start the application from the `soc_ids_platform` directory:

```powershell
python start_server.py
```

Open the platform at [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login).

## Deployment-Ready Configuration

The project now supports environment-based deployment without changing code:

- `.env.example`
  Contains the runtime variables you can copy into `.env`.
- `start_server.py`
  Starts Uvicorn using env-driven `HOST`, `PORT`, and `RELOAD`.
- `Dockerfile`
  Builds a production container image.
- `Procfile`
  Lets platforms like Render or similar process managers start the app with `python start_server.py`.

Important production variables:

- `APP_ENV=production`
- `JWT_SECRET=<strong-random-secret>`
- `DATABASE_URL=<production-database-url>` or keep SQLite with `DATABASE_PATH`
- `ALLOWED_ORIGINS=https://your-domain.example`
- `RELOAD=false`

If `APP_ENV=production` and `JWT_SECRET` is left at the demo default, the app now refuses to start.

## Docker Deployment

Build and run locally:

```powershell
docker build -t sentinel-ids .
docker run --rm -p 8000:8000 --env-file .env sentinel-ids
```

Then open [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login).

## Simple Production Run

For a non-Docker deployment:

```powershell
set APP_ENV=production
set JWT_SECRET=replace-with-a-strong-secret
set HOST=0.0.0.0
set PORT=8000
set RELOAD=false
python start_server.py
```

## Testing / Demo Workflow

1. Log in with the seeded admin account.
2. Open the dashboard and watch demo traffic stream in automatically.
3. Visit Alerts to acknowledge detections and block suspicious IPs.
4. Visit Traffic to watch the live packet table update without refresh.
5. Visit Logs to filter by IP, severity, protocol, or detection type and export CSV.
6. Visit Firewall to add temporary or permanent blocks.
7. Visit Users as admin to create operators or change their roles.
8. Visit Settings to toggle demo/live mode, payload inspection, and thresholds.

## Optional Live Mode Notes

- Live mode is isolated from demo mode and safely falls back when packet capture is unavailable.
- To experiment with live capture, install `scapy` manually:
  ```powershell
  pip install scapy
  ```
- Live capture may require elevated privileges depending on the operating system and adapter.

## Future Enhancements

- Integrate Suricata/Snort-style signature imports.
- Add machine-learning-assisted anomaly scoring.
- Add MITRE ATT&CK mapping and campaign correlation.
- Add alert assignment workflows and case notes.
- Add first-class PostgreSQL driver packaging and migrations for larger deployments.
- Add real firewall rule auditing and rollback history.
