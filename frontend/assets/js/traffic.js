document.addEventListener("DOMContentLoaded", async () => {
  await SentinelApp.requireAuth(["admin", "analyst", "viewer"]);
  SentinelApp.renderShell("traffic", "Deep packet telemetry");
  SentinelApp.attachLogout();

  const body = document.getElementById("traffic-table-body");

  function renderRow(item) {
    return `
      <tr>
        <td>${SentinelApp.formatDateTime(item.timestamp)}</td>
        <td>${SentinelApp.escapeHtml(item.source_ip)}</td>
        <td>${SentinelApp.escapeHtml(item.destination_ip)}</td>
        <td>${SentinelApp.escapeHtml(item.protocol)}</td>
        <td>${item.source_port}</td>
        <td>${item.destination_port}</td>
        <td>${item.packet_size}</td>
        <td>${SentinelApp.verdictTag(item.verdict)}</td>
        <td>${item.risk_score}%</td>
      </tr>
    `;
  }

  async function loadTraffic() {
    const response = await SentinelApp.authFetch("/api/traffic?limit=120");
    const data = await response.json();
    body.innerHTML = data.items.map(renderRow).join("");
  }

  const statusResponse = await SentinelApp.authFetch("/api/dashboard/status");
  const statusData = await statusResponse.json();
  SentinelApp.updateStatusPill(statusData.mode, statusData.note);
  document.getElementById("monitor-note").textContent = statusData.note;

  await loadTraffic();

  SentinelApp.connectSocket((message) => {
    if (message.type === "traffic_event") {
      body.insertAdjacentHTML("afterbegin", renderRow(message.payload));
      while (body.children.length > 120) {
        body.removeChild(body.lastElementChild);
      }
      SentinelApp.updateStatusPill(message.mode, message.note);
      document.getElementById("monitor-note").textContent = message.note;
    }
  });
});
