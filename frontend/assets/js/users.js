document.addEventListener("DOMContentLoaded", async () => {
  await SentinelApp.requireAuth(["admin"]);
  SentinelApp.renderShell("users", "Identity and access control");
  SentinelApp.attachLogout();

  const tbody = document.getElementById("users-table-body");

  function renderRow(user) {
    return `
      <tr>
        <td>${SentinelApp.escapeHtml(user.username)}</td>
        <td>${SentinelApp.escapeHtml(user.email)}</td>
        <td>
          <select data-role-id="${user.id}">
            ${["admin", "analyst", "viewer"].map((role) => `<option value="${role}" ${role === user.role ? "selected" : ""}>${role}</option>`).join("")}
          </select>
        </td>
        <td>${user.is_active ? "Active" : "Disabled"}</td>
        <td>${SentinelApp.formatDateTime(user.created_at)}</td>
        <td>${user.last_login_at ? SentinelApp.formatDateTime(user.last_login_at) : "-"}</td>
        <td>
          <button class="ghost-btn" data-toggle-id="${user.id}" data-next-state="${!user.is_active}">
            ${user.is_active ? "Disable" : "Enable"}
          </button>
        </td>
      </tr>
    `;
  }

  async function loadUsers() {
    const response = await SentinelApp.authFetch("/api/users");
    const data = await response.json();
    tbody.innerHTML = data.items.map(renderRow).join("");
  }

  document.getElementById("create-user").addEventListener("click", async () => {
    const payload = {
      username: document.getElementById("new-username").value.trim(),
      email: document.getElementById("new-email").value.trim(),
      password: document.getElementById("new-password").value,
      role: document.getElementById("new-role").value,
      is_active: true,
    };
    await SentinelApp.authFetch("/api/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    document.getElementById("user-form").reset();
    await loadUsers();
  });

  tbody.addEventListener("change", async (event) => {
    const userId = event.target.getAttribute("data-role-id");
    if (!userId) return;
    await SentinelApp.authFetch(`/api/users/${userId}`, {
      method: "PATCH",
      body: JSON.stringify({ role: event.target.value }),
    });
    await loadUsers();
  });

  tbody.addEventListener("click", async (event) => {
    const userId = event.target.getAttribute("data-toggle-id");
    if (!userId) return;
    await SentinelApp.authFetch(`/api/users/${userId}`, {
      method: "PATCH",
      body: JSON.stringify({ is_active: event.target.getAttribute("data-next-state") === "true" }),
    });
    await loadUsers();
  });

  const statusResponse = await SentinelApp.authFetch("/api/dashboard/status");
  const statusData = await statusResponse.json();
  SentinelApp.updateStatusPill(statusData.mode, statusData.note);
  document.getElementById("monitor-note").textContent = statusData.note;

  await loadUsers();
});
