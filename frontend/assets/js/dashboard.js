document.addEventListener("DOMContentLoaded", async () => {
  const currentUser = await SentinelApp.requireAuth(["admin", "analyst", "viewer"]);
  SentinelApp.renderShell("dashboard", "Real-time detection overview");
  SentinelApp.attachLogout();

  let trendChart;
  let protocolChart;
  let latestStatus = null;

  function initCharts() {
    trendChart = new Chart(document.getElementById("trafficTrendChart"), {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Packets",
            data: [],
            borderColor: "#39d5ff",
            backgroundColor: "rgba(57, 213, 255, 0.18)",
            tension: 0.35,
            fill: true,
          },
        ],
      },
      options: {
        plugins: { legend: { labels: { color: "#e6f7ff" } } },
        scales: { x: { ticks: { color: "#92a8c4" } }, y: { ticks: { color: "#92a8c4" } } },
      },
    });
    protocolChart = new Chart(document.getElementById("protocolChart"), {
      type: "doughnut",
      data: {
        labels: [],
        datasets: [
          {
            data: [],
            backgroundColor: ["#39d5ff", "#34e7a0", "#ff9f43", "#ff5978", "#4d8cff"],
          },
        ],
      },
      options: { plugins: { legend: { labels: { color: "#e6f7ff" } } } },
    });
  }

  function renderSummary(summary) {
    document.getElementById("metric-total").textContent = summary.total_packets;
    document.getElementById("metric-normal").textContent = summary.normal_traffic;
    document.getElementById("metric-suspicious").textContent = summary.suspicious_traffic;
    document.getElementById("metric-attack").textContent = summary.attack_count;
    document.getElementById("metric-risk").textContent = `${summary.risk_percentage}%`;
    document.getElementById("metric-alerts").textContent = summary.active_alerts;

    trendChart.data.labels = summary.traffic_trend.map((item) => item.minute);
    trendChart.data.datasets[0].data = summary.traffic_trend.map((item) => item.count);
    trendChart.update();

    protocolChart.data.labels = summary.protocol_distribution.map((item) => item.protocol);
    protocolChart.data.datasets[0].data = summary.protocol_distribution.map((item) => item.count);
    protocolChart.update();

    const suspiciousList = document.getElementById("top-suspicious");
    suspiciousList.innerHTML = summary.top_suspicious_ips.length
      ? summary.top_suspicious_ips
          .map((item) => `<li><div class="split"><span>${item.ip}</span><strong>${item.count}</strong></div></li>`)
          .join("")
      : `<li class="empty-state">No suspicious sources yet.</li>`;

    const geoList = document.getElementById("geo-summary");
    geoList.innerHTML = summary.geo_summary.length
      ? summary.geo_summary
          .map((item) => `<li><div class="split"><span>${item.country}</span><strong>${item.count}</strong></div></li>`)
          .join("")
      : `<li class="empty-state">No geo-enriched suspicious traffic yet.</li>`;

    if (latestStatus) {
      SentinelApp.updateStatusPill(latestStatus.mode, latestStatus.note, latestStatus.state);
    } else {
      SentinelApp.updateStatusPill(summary.monitoring_mode, `Monitoring mode: ${summary.monitoring_mode}`);
    }
  }

  function pushLiveEvent(event) {
    const container = document.getElementById("live-events");
    const markup = `
      <article class="event-item">
        <strong>${SentinelApp.escapeHtml(event.detection_type)}</strong>
        <div class="split">
          <span>${SentinelApp.escapeHtml(event.source_ip)} -> ${SentinelApp.escapeHtml(event.destination_ip)}</span>
          ${SentinelApp.verdictTag(event.verdict)}
        </div>
        <p class="muted">${SentinelApp.escapeHtml(event.summary)}</p>
        <div class="split">
          <span>${SentinelApp.formatDateTime(event.timestamp)}</span>
          <span>${event.risk_score}% risk</span>
        </div>
      </article>
    `;
    container.insertAdjacentHTML("afterbegin", markup);
    while (container.children.length > 8) {
      container.removeChild(container.lastElementChild);
    }
  }

  function applyStatus(statusData) {
    latestStatus = statusData;
    SentinelApp.updateStatusPill(statusData.mode, statusData.note, statusData.state);
    document.getElementById("monitor-note").textContent = statusData.note;

    const canOperate = ["admin", "analyst"].includes(currentUser.role);
    const controls = document.getElementById("dashboard-controls");
    if (controls) {
      controls.hidden = !canOperate;
    }

    const startButton = document.getElementById("start-monitoring");
    const stopButton = document.getElementById("stop-monitoring");
    const reportButton = document.getElementById("generate-report");
    if (startButton) startButton.disabled = !canOperate || statusData.state === "running";
    if (stopButton) stopButton.disabled = !canOperate || statusData.state === "paused";
    if (reportButton) reportButton.disabled = !canOperate;
  }

  async function controlMonitoring(action) {
    const response = await SentinelApp.authFetch(`/api/dashboard/${action}`, { method: "POST" });
    const data = await response.json();
    applyStatus(data.status);
    renderSummary(data.summary);
  }

  initCharts();

  const statusResponse = await SentinelApp.authFetch("/api/dashboard/status");
  const statusData = await statusResponse.json();
  applyStatus(statusData);

  const summaryResponse = await SentinelApp.authFetch("/api/dashboard/summary");
  const summary = await summaryResponse.json();
  renderSummary(summary);

  const trafficResponse = await SentinelApp.authFetch("/api/traffic?limit=8");
  const trafficData = await trafficResponse.json();
  trafficData.items.reverse().forEach(pushLiveEvent);

  document.getElementById("start-monitoring")?.addEventListener("click", async () => {
    await controlMonitoring("start");
  });

  document.getElementById("stop-monitoring")?.addEventListener("click", async () => {
    await controlMonitoring("stop");
  });

  document.getElementById("generate-report")?.addEventListener("click", () => {
    const token = SentinelApp.getToken();
    window.open(`/api/dashboard/report?token=${encodeURIComponent(token)}`, "_blank", "noopener");
  });

  SentinelApp.connectSocket((message) => {
    if (message.type === "traffic_event") {
      pushLiveEvent(message.payload);
      if (message.summary) {
        renderSummary(message.summary);
      }
      if (message.note && latestStatus?.state !== "paused") {
        latestStatus = {
          ...(latestStatus || {}),
          state: latestStatus?.state || "running",
          mode: message.mode,
          note: message.note,
        };
        applyStatus(latestStatus);
      }
    }

    if (message.type === "monitor_status") {
      if (message.payload.summary) {
        renderSummary(message.payload.summary);
      }
      applyStatus({
        ...latestStatus,
        ...message.payload,
      });
    }
  });
});
