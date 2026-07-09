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
    const loggedIn = await Auth.check();
    if (!loggedIn) return; // auth.check redirects to login
    Sidebar.render();
    window.addEventListener('hashchange', () => this.handleRoute());
    this.handleRoute();
  },

  async handleRoute() {
    const hash = window.location.hash || '#/';
    const path = hash.split('?')[0];
    const pageKey = this.routes[path] || 'dashboard';
    
    const page = window.Pages[pageKey];
    if (!page) {
      console.error(`Page ${pageKey} not found`);
      return;
    }
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
    Sidebar.updateActive();
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
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
