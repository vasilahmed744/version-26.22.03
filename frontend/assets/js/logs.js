document.addEventListener("DOMContentLoaded", async () => {
  await SentinelApp.requireAuth(["admin", "analyst", "viewer"]);
  SentinelApp.renderShell("logs", "Searchable event history");
  SentinelApp.attachLogout();

  const form = document.getElementById("logs-filter-form");
  const tbody = document.getElementById("logs-table-body");

  function buildQuery() {
    const params = new URLSearchParams();
    new FormData(form).forEach((value, key) => {
      if (value) params.append(key, value);
    });
    return params.toString();
  }

  function renderRow(item) {
    const findings = item.payload_findings.length
      ? item.payload_findings.map((finding) => `${finding.category}: ${finding.matched_fragment}`).join("<br>")
      : "-";
    const geo = [item.geo_country, item.geo_region, item.geo_city].filter(Boolean).join(", ") || "Unknown";
    return `
      <tr>
        <td>${SentinelApp.formatDateTime(item.timestamp)}</td>
        <td>${SentinelApp.escapeHtml(item.source_ip)}</td>
        <td><span class="${SentinelApp.badgeClass(item.severity)}">${item.severity}</span></td>
        <td>${SentinelApp.escapeHtml(item.detection_type)}</td>
        <td>${SentinelApp.escapeHtml(item.protocol)}</td>
        <td>${item.risk_score}%</td>
        <td>${SentinelApp.escapeHtml(geo)}</td>
        <td>${findings}</td>
      </tr>
    `;
  }

  async function loadLogs() {
    const response = await SentinelApp.authFetch(`/api/logs?${buildQuery()}`);
    const data = await response.json();
    tbody.innerHTML = data.items.map(renderRow).join("");
  }

  async function exportLogs() {
    const response = await SentinelApp.authFetch(`/api/logs/export?${buildQuery()}`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "sentinel_logs.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  document.getElementById("apply-log-filters").addEventListener("click", loadLogs);
  document.getElementById("export-logs").addEventListener("click", exportLogs);

  const statusResponse = await SentinelApp.authFetch("/api/dashboard/status");
  const statusData = await statusResponse.json();
  SentinelApp.updateStatusPill(statusData.mode, statusData.note);
  document.getElementById("monitor-note").textContent = statusData.note;

  await loadLogs();

  SentinelApp.connectSocket((message) => {
    if (message.type === "traffic_event") {
      SentinelApp.updateStatusPill(message.mode, message.note);
      document.getElementById("monitor-note").textContent = message.note;
    }
  });
});
