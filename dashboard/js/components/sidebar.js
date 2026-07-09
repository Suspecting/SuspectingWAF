// dashboard/js/components/sidebar.js
// renders the sidebar navigation

const Sidebar = {
  render() {
    const el = document.getElementById('sidebar');
    if (!el) return;

    const user = Auth.getUser() || { username: 'Admin' };
    const currentPath = window.location.hash || '#/';

    const navItems = [
      { path: '#/', icon: '📊', label: 'Overview' },
      { path: '#/sites', icon: '🌐', label: 'Sites' },
      { path: '#/logs', icon: '🛡️', label: 'Attack Logs' },
      
      { section: 'Rules & Policies' },
      { path: '#/rules', icon: '📜', label: 'Custom Rules' },
      { path: '#/iplist', icon: '🚫', label: 'IP Lists' },
      { path: '#/ratelimit', icon: '⏱️', label: 'Rate Limiting' },
      
      { section: 'System' },
      { path: '#/certs', icon: '🔒', label: 'Certificates' },
      { path: '#/settings', icon: '⚙️', label: 'Settings' },
    ];

    let html = `
      <div class="sidebar-header">
        <div class="sidebar-logo">🛡️</div>
        <div>
          <div class="sidebar-title">SuspectingWAF</div>
          <div class="sidebar-version">v1.0.0</div>
        </div>
      </div>
      <div class="sidebar-nav">
    `;

    for (const item of navItems) {
      if (item.section) {
        html += `<div class="nav-section-label">${item.section}</div>`;
      } else {
        const active = currentPath === item.path || (item.path !== '#/' && currentPath.startsWith(item.path));
        html += `
          <div class="nav-section" style="margin-bottom: 2px;">
            <a href="${item.path}" class="nav-item ${active ? 'active' : ''}">
              <span class="nav-icon">${item.icon}</span>
              ${item.label}
            </a>
          </div>
        `;
      }
    }

    html += `
      </div>
      <div class="sidebar-footer">
        <div class="sidebar-user">
          <div class="sidebar-user-avatar">${user.username.charAt(0).toUpperCase()}</div>
          <div style="flex:1" class="truncate">${DOM.escapeHTML(user.username)}</div>
          <button class="btn-icon" title="Logout" onclick="Auth.logout()">🚪</button>
        </div>
      </div>
    `;

    el.innerHTML = html;
  },

  updateActive() {
    this.render(); // cheap enough to just re-render
  }
};

window.Sidebar = Sidebar;
