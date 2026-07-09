// dashboard/js/app.js
// Main Application Router & Initializer

const App = {
  routes: {
    '#/': 'dashboard',
    '#/sites': 'sites',
    '#/logs': 'logs',
    '#/rules': 'rules',
    '#/iplist': 'iplist',
    '#/certs': 'certs',
    '#/ratelimit': 'ratelimit',
    '#/settings': 'settings'
  },

  async init() {
    // Check auth first
    const loggedIn = await Auth.check();
    if (!loggedIn) return; // auth.check redirects to login

    // Render sidebar
    Sidebar.render();

    // Setup router
    window.addEventListener('hashchange', () => this.handleRoute());
    
    // Trigger initial route
    this.handleRoute();
  },

  async handleRoute() {
    const hash = window.location.hash || '#/';
    
    // simple matching (strip query params if any)
    const path = hash.split('?')[0];
    const pageKey = this.routes[path] || 'dashboard';
    
    const page = window.Pages[pageKey];
    if (!page) {
      console.error(`Page ${pageKey} not found`);
      return;
    }

    // Set title
    const titles = {
      dashboard: 'Dashboard',
      sites: 'Sites',
      logs: 'Attack Logs',
      rules: 'Custom Rules',
      iplist: 'IP Lists',
      certs: 'SSL Certificates',
      ratelimit: 'Rate Limiting',
      settings: 'Settings'
    };
    
    document.getElementById('pageTitle').textContent = titles[pageKey] || 'SuspectingWAF';
    document.title = `${titles[pageKey]} — SuspectingWAF`;

    // update sidebar active state
    Sidebar.updateActive();

    // render page
    try {
      if (page.destroy) page.destroy(); // cleanup previous
      await page.render();
    } catch (err) {
      console.error(`Failed to render page ${pageKey}:`, err);
      document.getElementById('pageBody').innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">⚠️</div>
          <h3>Error loading page</h3>
          <p>${err.message}</p>
        </div>
      `;
    }
  }
};

// Start the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
