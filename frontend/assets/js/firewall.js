document.addEventListener("DOMContentLoaded", async () => {
  const user = await SentinelApp.requireAuth(["admin", "analyst", "viewer"]);
  SentinelApp.renderShell("firewall", "Blocklist and containment");
  SentinelApp.attachLogout();

  const tbody = document.getElementById("firewall-table-body");
  const formCard = document.getElementById("firewall-form-card");
  if (!["admin", "analyst"].includes(user.role)) {
    formCard.style.display = "none";
  }

  function renderRow(item) {
    const actionButton = ["admin", "analyst"].includes(user.role) && item.is_active
      ? `<button class="danger-btn" data-unblock="${item.id}">Unblock</button>`
      : "-";
    return `
      <tr>
        <td>${SentinelApp.escapeHtml(item.ip_address)}</td>
        <td>${SentinelApp.escapeHtml(item.reason)}</td>
        <td>${SentinelApp.escapeHtml(item.status)}</td>
        <td>${SentinelApp.escapeHtml(item.mode)}</td>
        <td>${SentinelApp.formatDateTime(item.blocked_at)}</td>
        <td>${item.expires_at ? SentinelApp.formatDateTime(item.expires_at) : "Permanent"}</td>
        <td>${actionButton}</td>
      </tr>
    `;
  }

  async function loadBlocks() {
    const response = await SentinelApp.authFetch("/api/firewall/blocks");
    const data = await response.json();
    tbody.innerHTML = data.items.map(renderRow).join("");
  }

  document.getElementById("submit-block").addEventListener("click", async () => {
    const payload = {
      ip_address: document.getElementById("block-ip").value.trim(),
      reason: document.getElementById("block-reason").value.trim(),
      duration_minutes: Number(document.getElementById("block-duration").value || 60),
      permanent: document.getElementById("block-permanent").value === "true",
    };
    await SentinelApp.authFetch("/api/firewall/blocks", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    document.getElementById("firewall-form").reset();
    await loadBlocks();
  });

  tbody.addEventListener("click", async (event) => {
    const blockId = event.target.getAttribute("data-unblock");
    if (!blockId) return;
    await SentinelApp.authFetch(`/api/firewall/blocks/${blockId}`, { method: "DELETE" });
    await loadBlocks();
  });

  const statusResponse = await SentinelApp.authFetch("/api/dashboard/status");
  const statusData = await statusResponse.json();
  SentinelApp.updateStatusPill(statusData.mode, statusData.note);
  document.getElementById("monitor-note").textContent = statusData.note;

  await loadBlocks();

  SentinelApp.connectSocket((message) => {
    if (message.type === "blocklist_update") {
      loadBlocks();
    }
    if (message.type === "traffic_event") {
      SentinelApp.updateStatusPill(message.mode, message.note);
      document.getElementById("monitor-note").textContent = message.note;
    }
  });
});
