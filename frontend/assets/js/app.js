const SentinelApp = (() => {
  const routes = {
    dashboard: { href: "/dashboard", label: "Overview", roles: ["admin", "analyst", "viewer"] },
    traffic: { href: "/traffic", label: "Traffic", roles: ["admin", "analyst", "viewer"] },
    alerts: { href: "/alerts", label: "Alerts", roles: ["admin", "analyst", "viewer"] },
    logs: { href: "/logs", label: "Logs", roles: ["admin", "analyst", "viewer"] },
    firewall: { href: "/firewall", label: "Firewall", roles: ["admin", "analyst", "viewer"] },
    users: { href: "/users", label: "Users", roles: ["admin"] },
    settings: { href: "/settings", label: "Settings", roles: ["admin", "analyst"] },
  };

  let currentUser = null;

  function getToken() {
    return localStorage.getItem("sentinel_token");
  }

  function setToken(token) {
    localStorage.setItem("sentinel_token", token);
  }

  function clearToken() {
    localStorage.removeItem("sentinel_token");
    localStorage.removeItem("sentinel_user");
  }

  function setUser(user) {
    currentUser = user;
    localStorage.setItem("sentinel_user", JSON.stringify(user));
  }

  function getCachedUser() {
    if (currentUser) return currentUser;
    const cached = localStorage.getItem("sentinel_user");
    if (!cached) return null;
    try {
      currentUser = JSON.parse(cached);
      return currentUser;
    } catch {
      return null;
    }
  }

  async function authFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    const token = getToken();
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
    if (!headers.has("Content-Type") && options.body && !(options.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(url, { ...options, headers });
    if (response.status === 401) {
      clearToken();
      if (location.pathname !== "/login") {
        location.href = "/login";
      }
      throw new Error("Authentication required");
    }
    return response;
  }

  async function requireAuth(allowedRoles = ["admin", "analyst", "viewer"]) {
    const token = getToken();
    if (!token) {
      location.href = "/login";
      throw new Error("Missing token");
    }

    const response = await authFetch("/api/auth/me");
    if (!response.ok) {
      clearToken();
      location.href = "/login";
      throw new Error("Session expired");
    }

    const data = await response.json();
    setUser(data.user);
    if (!allowedRoles.includes(data.user.role)) {
      location.href = "/dashboard";
      throw new Error("Role not allowed");
    }
    return data.user;
  }

  function renderShell(pageKey, subtitle) {
    const sidebarRoot = document.getElementById("sidebar-root");
    const user = getCachedUser();
    if (!sidebarRoot || !user) return;

    const navItems = Object.entries(routes)
      .filter(([, route]) => route.roles.includes(user.role))
      .map(([key, route]) => `
        <li>
          <a class="nav-link ${pageKey === key ? "active" : ""}" href="${route.href}">
            <span>+</span>
            <span>${route.label}</span>
          </a>
        </li>
      `)
      .join("");

    sidebarRoot.innerHTML = `
      <aside class="sidebar">
        <div class="brand">
          <span class="brand-kicker">Sentinel SOC Console</span>
          <h1>Cyber Defense Grid</h1>
          <p>Real-time packet telemetry, threat scoring, geo-enrichment, and response controls.</p>
        </div>
        <ul class="nav-list">${navItems}</ul>
        <div class="nav-footer">
          <div class="role-badge">Role: ${user.role}</div>
          <p>${subtitle || "Security telemetry and response operations"}</p>
        </div>
      </aside>
    `;

    const userRoot = document.getElementById("topbar-user");
    if (userRoot) {
      userRoot.textContent = `${user.username} (${user.role})`;
    }
  }

  function attachLogout() {
    const logoutButtons = document.querySelectorAll("[data-action='logout']");
    logoutButtons.forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await authFetch("/api/auth/logout", { method: "POST" });
        } catch {
          // Best-effort logout.
        } finally {
          clearToken();
          location.href = "/login";
        }
      });
    });
  }

  function connectSocket(handler) {
    const token = getToken();
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${protocol}://${location.host}/ws/stream?token=${encodeURIComponent(token)}`);
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      handler?.(message);
    });
    return socket;
  }

  function updateStatusPill(mode, note = "", state = "running") {
    const pill = document.getElementById("monitor-status");
    if (!pill) return;
    pill.className = "status-pill";
    if (state === "paused") {
      pill.classList.add("paused");
    } else if (mode === "live-fallback") {
      pill.classList.add("warning");
    } else if (mode === "idle") {
      pill.classList.add("critical");
    }
    const label = state === "paused" ? "Monitoring Paused" : `${capitalize(mode)} Mode`;
    pill.innerHTML = `<span class="status-dot"></span><span>${label}</span>`;
    const noteEl = document.getElementById("monitor-note");
    if (noteEl) noteEl.textContent = note;
  }

  function formatDateTime(value) {
    if (!value) return "-";
    return new Date(value).toLocaleString();
  }

  function badgeClass(value) {
    return `severity-badge severity-${String(value || "info").toLowerCase()}`;
  }

  function verdictTag(value) {
    return `<span class="tag ${String(value).toLowerCase()}">${value}</span>`;
  }

  function capitalize(value) {
    return String(value || "").replace(/(^\w|-\w)/g, (char) => char.replace("-", " ").toUpperCase());
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  return {
    authFetch,
    requireAuth,
    setToken,
    setUser,
    getToken,
    getCachedUser,
    clearToken,
    renderShell,
    attachLogout,
    connectSocket,
    updateStatusPill,
    formatDateTime,
    badgeClass,
    verdictTag,
    capitalize,
    escapeHtml,
    routes,
  };
})();
