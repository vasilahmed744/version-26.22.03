document.addEventListener("DOMContentLoaded", async () => {
  const user = await SentinelApp.requireAuth(["admin", "analyst", "viewer"]);
  SentinelApp.renderShell("alerts", "Alert triage workflow");
  SentinelApp.attachLogout();

  const container = document.getElementById("alerts-container");

  function canRespond() {
    return ["admin", "analyst"].includes(user.role);
  }

  function alertCard(alert) {
    const actions = canRespond()
      ? `
        <div class="inline-actions">
          ${alert.status === "open" ? `<button class="btn" data-ack="${alert.id}">Acknowledge</button>` : ""}
          <button class="danger-btn" data-block="${SentinelApp.escapeHtml(alert.source_ip)}">Block IP</button>
        </div>
      `
      : "";

    return `
      <article class="alert-card">
        <div class="split">
          <div>
            <span class="${SentinelApp.badgeClass(alert.severity)}">${alert.severity}</span>
            <h3>${SentinelApp.escapeHtml(alert.title)}</h3>
          </div>
          <div class="role-badge">${SentinelApp.escapeHtml(alert.status)}</div>
        </div>
        <p>${SentinelApp.escapeHtml(alert.description)}</p>
        <div class="split">
          <span>Source: ${SentinelApp.escapeHtml(alert.source_ip)}</span>
          <span>Destination: ${SentinelApp.escapeHtml(alert.destination_ip)}</span>
        </div>
        <div class="split" style="margin-top: 10px;">
          <span>Action: ${SentinelApp.escapeHtml(alert.recommended_action)}</span>
          <span>${SentinelApp.formatDateTime(alert.created_at)}</span>
        </div>
        ${actions}
      </article>
    `;
  }

  async function loadAlerts() {
    const response = await SentinelApp.authFetch("/api/alerts");
    const data = await response.json();
    container.innerHTML = data.items.length
      ? data.items.map(alertCard).join("")
      : `<div class="panel"><div class="panel-body">No alerts are active right now.</div></div>`;
  }

  async function acknowledgeAlert(alertId) {
    await SentinelApp.authFetch(`/api/alerts/${alertId}/acknowledge`, { method: "POST" });
    await loadAlerts();
  }

  async function blockIp(ipAddress) {
    await SentinelApp.authFetch("/api/firewall/blocks", {
      method: "POST",
      body: JSON.stringify({
        ip_address: ipAddress,
        reason: "Blocked directly from alert queue",
        duration_minutes: 120,
        permanent: false,
      }),
    });
  }

  container.addEventListener("click", async (event) => {
    const ackId = event.target.getAttribute("data-ack");
    const blockIpAddress = event.target.getAttribute("data-block");
    if (ackId) {
      await acknowledgeAlert(ackId);
    }
    if (blockIpAddress) {
      await blockIp(blockIpAddress);
    }
  });

  const statusResponse = await SentinelApp.authFetch("/api/dashboard/status");
  const statusData = await statusResponse.json();
  SentinelApp.updateStatusPill(statusData.mode, statusData.note);
  document.getElementById("monitor-note").textContent = statusData.note;

  await loadAlerts();

  SentinelApp.connectSocket((message) => {
    if (["alert_event", "alert_acknowledged"].includes(message.type)) {
      loadAlerts();
    }
    if (message.type === "traffic_event") {
      SentinelApp.updateStatusPill(message.mode, message.note);
      document.getElementById("monitor-note").textContent = message.note;
    }
  });
});
