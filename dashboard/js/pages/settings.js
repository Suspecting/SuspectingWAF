// dashboard/js/pages/settings.js
// Global WAF settings

const SettingsPage = {
  async render() {
    DOM.empty(document.getElementById('pageActions'));

    const bodyEl = document.getElementById('pageBody');
    bodyEl.innerHTML = `
      <div class="grid grid-2">
        <div class="card">
          <div class="card-header"><div class="card-title">Engine Mode</div></div>
          <div class="card-body">
            <form id="modeForm">
              <div class="form-group">
                <label class="form-label">WAF Operation Mode</label>
                <select id="wafMode" class="form-select mb-sm">
                  <option value="block">🛡️ Block (Active Protection)</option>
                  <option value="monitor">👁️ Monitor (Log only, do not block)</option>
                  <option value="off">⭕ Off (Bypass entirely)</option>
                </select>
                <div class="form-help">Block: blocks attacks and returns 403. Monitor: logs attacks but lets traffic through.</div>
              </div>
              <button type="button" class="btn btn-primary" onclick="window.Pages.settings.saveMode()">Save Mode</button>
            </form>
          </div>
        </div>

        <div class="card">
          <div class="card-header"><div class="card-title">Admin Account</div></div>
          <div class="card-body">
            <form id="passwordForm">
              <div class="form-group">
                <label class="form-label">Current Password</label>
                <input type="password" id="currPass" class="form-input" required>
              </div>
              <div class="form-group">
                <label class="form-label">New Password</label>
                <input type="password" id="newPass" class="form-input" required>
              </div>
              <button type="button" class="btn btn-secondary" onclick="window.Pages.settings.changePassword()">Change Password</button>
            </form>
          </div>
        </div>
      </div>
    `;

    await this.loadData();
  },

  async loadData() {
    try {
      const res = await API.get('/settings');
      if (res.settings && res.settings.waf_mode) {
        document.getElementById('wafMode').value = res.settings.waf_mode;
      }
    } catch (err) {
      Toast.error('Failed to load settings');
    }
  },

  async saveMode() {
    try {
      const mode = document.getElementById('wafMode').value;
      await API.put('/settings', { waf_mode: mode });
      Toast.success('WAF mode updated');
    } catch (err) {
      Toast.error(err.message);
    }
  },

  async changePassword() {
    const curr = document.getElementById('currPass').value;
    const next = document.getElementById('newPass').value;
    if (!curr || !next) return Toast.error('Both fields required');
    if (next.length < 6) return Toast.error('Password too short');

    try {
      await API.put('/auth/password', { currentPassword: curr, newPassword: next });
      Toast.success('Password changed successfully');
      document.getElementById('currPass').value = '';
      document.getElementById('newPass').value = '';
    } catch (err) {
      Toast.error(err.message);
    }
  }
};

window.Pages = window.Pages || {};
window.Pages.settings = SettingsPage;
