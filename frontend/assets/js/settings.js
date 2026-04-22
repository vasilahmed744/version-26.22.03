document.addEventListener("DOMContentLoaded", async () => {
  const user = await SentinelApp.requireAuth(["admin", "analyst"]);
  SentinelApp.renderShell("settings", "Detector controls and policy");
  SentinelApp.attachLogout();

  const saveButton = document.getElementById("save-settings");
  if (user.role !== "admin") {
    saveButton.disabled = true;
    saveButton.textContent = "Admin Access Required";
  }

  const fieldIds = [
    "demo_mode",
    "live_mode",
    "payload_inspection_enabled",
    "firewall_simulation_enabled",
    "geoip_enabled",
    "auto_block_high_risk",
    "alert_on_medium",
    "alert_on_high",
    "detection_threshold",
    "max_events_per_minute",
    "live_capture_interface",
  ];

  function fillSettings(settings) {
    fieldIds.forEach((id) => {
      const element = document.getElementById(id);
      if (!element) return;
      if (element.type === "checkbox") {
        element.checked = Boolean(settings[id]);
      } else {
        element.value = settings[id] ?? "";
      }
      if (user.role !== "admin") {
        element.disabled = true;
      }
    });
  }

  async function loadSettings() {
    const response = await SentinelApp.authFetch("/api/settings");
    const data = await response.json();
    fillSettings(data.settings);
  }

  saveButton.addEventListener("click", async () => {
    if (user.role !== "admin") return;
    const payload = {};
    fieldIds.forEach((id) => {
      const element = document.getElementById(id);
      payload[id] = element.type === "checkbox" ? element.checked : element.value;
    });
    payload.detection_threshold = Number(payload.detection_threshold);
    payload.max_events_per_minute = Number(payload.max_events_per_minute);

    await SentinelApp.authFetch("/api/settings", {
      method: "PUT",
      body: JSON.stringify(payload),
    });
  });

  const statusResponse = await SentinelApp.authFetch("/api/dashboard/status");
  const statusData = await statusResponse.json();
  SentinelApp.updateStatusPill(statusData.mode, statusData.note);
  document.getElementById("monitor-note").textContent = statusData.note;

  await loadSettings();

  SentinelApp.connectSocket((message) => {
    if (message.type === "settings_updated") {
      fillSettings(message.payload);
    }
    if (message.type === "traffic_event") {
      SentinelApp.updateStatusPill(message.mode, message.note);
      document.getElementById("monitor-note").textContent = message.note;
    }
  });
});
