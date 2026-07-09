// dashboard/js/pages/ratelimit.js
// Rate limit config page

const RateLimitPage = {
  sites: [],
  limits: [],

  async render() {
    DOM.empty(document.getElementById('pageActions'));

    const bodyEl = document.getElementById('pageBody');
    bodyEl.innerHTML = `
      <div class="card mb-lg">
        <div class="card-header">
          <div class="card-title">Global Default Settings</div>
        </div>
        <div class="card-body">
          <p class="text-muted mb-md text-sm">These settings apply to sites without specific overrides, or new sites created.</p>
          <div class="grid grid-3">
            <div class="form-group">
              <label class="form-label">Requests per second (RPS)</label>
              <input type="number" class="form-input" value="100" disabled>
            </div>
            <div class="form-group">
              <label class="form-label">Burst tolerance</label>
              <input type="number" class="form-input" value="200" disabled>
            </div>
            <div class="form-group">
              <label class="form-label">Ban duration (seconds)</label>
              <input type="number" class="form-input" value="300" disabled>
            </div>
          </div>
          <div class="form-help">Edit defaults in the <code>.env</code> file.</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Site-Specific Limits</div>
        </div>
        <div id="tableContainer" class="card-body no-pad">
          <div class="loading-overlay"><div class="spinner"></div></div>
        </div>
      </div>
    `;

    await this.loadData();
  },

  async loadData() {
    try {
      const [sitesRes, limitsRes] = await Promise.all([
        API.get('/sites'),
        API.get('/settings/ratelimit')
      ]);

      this.sites = sitesRes.sites || [];
      this.limits = limitsRes.limits || [];

      this.renderTable();
    } catch (err) {
      Toast.error('Failed to load rate limits');
    }
  },

  renderTable() {
    const container = document.getElementById('tableContainer');
    DOM.empty(container);

    // map limits by site_id for easy lookup
    const limitsMap = {};
    this.limits.forEach(l => limitsMap[l.site_id] = l);

    // build data based on all sites (even if they don't have a specific limit entry yet)
    const data = this.sites.map(site => {
      const l = limitsMap[site.id];
      return {
        id: l ? l.id : null,
        site_id: site.id,
        site_name: site.name,
        enabled: l ? !!l.enabled : true,
        rps: l ? l.requests_per_second : 100,
        burst: l ? l.burst : 200,
        ban_duration: l ? l.ban_duration : 300,
        isDefault: !l
      };
    });

    const table = new DataTable({
      data,
      emptyText: 'No sites available.',
      columns: [
        { 
          key: 'site_name', label: 'Site',
          render: (v) => `<div class="font-bold">${DOM.escapeHTML(v)}</div>`
        },
        {
          key: 'enabled', label: 'Status',
          render: (v) => v ? `<span class="badge badge-success">ON</span>` : `<span class="badge badge-danger">OFF</span>`
        },
        { 
          key: 'rps', label: 'Req / sec',
          render: (v, r) => r.isDefault ? `<span class="text-muted">${v} (default)</span>` : v
        },
        { 
          key: 'burst', label: 'Burst limit',
          render: (v, r) => r.isDefault ? `<span class="text-muted">${v} (default)</span>` : v
        },
        { 
          key: 'ban_duration', label: 'Ban time',
          render: (v, r) => r.isDefault ? `<span class="text-muted">${v}s (default)</span>` : `${v}s`
        },
        {
          key: 'actions', label: '',
          render: (v, row) => {
            const btn = document.createElement('button');
            btn.className = 'btn btn-sm btn-secondary';
            btn.textContent = 'Configure';
            btn.onclick = () => this.showEditModal(row);
            return btn;
          }
        }
      ]
    });

    container.appendChild(table.render());
  },

  showEditModal(row) {
    const html = `
      <form id="rlForm">
        <div class="form-group" style="padding: 16px; background: var(--bg-tertiary); border-radius: 8px; border: 1px solid var(--border-default);">
          <label class="form-label" style="display:flex; justify-content:space-between; align-items:center; margin:0;">
            <span>Enable Rate Limiting for ${DOM.escapeHTML(row.site_name)}</span>
            <label class="toggle">
              <input type="checkbox" id="rlEnabled" ${row.enabled ? 'checked' : ''}>
              <div class="toggle-slider"></div>
            </label>
          </label>
        </div>
        
        <div class="form-group mt-md">
          <label class="form-label">Requests per second (RPS)</label>
          <input type="number" id="rlRps" class="form-input" value="${row.rps}" required min="1">
          <div class="form-help">Average allowed requests per second per IP</div>
        </div>
        
        <div class="form-group">
          <label class="form-label">Burst limit</label>
          <input type="number" id="rlBurst" class="form-input" value="${row.burst}" required min="1">
          <div class="form-help">Maximum spike before triggering a ban</div>
        </div>

        <div class="form-group">
          <label class="form-label">Ban duration (seconds)</label>
          <input type="number" id="rlBan" class="form-input" value="${row.ban_duration}" required min="1">
          <div class="form-help">How long to block the IP (e.g. 300 = 5 minutes)</div>
        </div>
      </form>
    `;

    const saveBtn = DOM.h('button', {
      className: 'btn btn-primary',
      onclick: async () => {
        try {
          const data = {
            site_id: row.site_id,
            enabled: document.getElementById('rlEnabled').checked,
            requests_per_second: parseInt(document.getElementById('rlRps').value, 10),
            burst: parseInt(document.getElementById('rlBurst').value, 10),
            ban_duration: parseInt(document.getElementById('rlBan').value, 10)
          };

          await API.put('/settings/ratelimit', data);
          Toast.success('Rate limit updated');
          Modal.close();
          this.loadData();
        } catch (err) {
          Toast.error(err.message);
        }
      }
    }, 'Save Config');

    Modal.show(`Rate Limit: ${DOM.escapeHTML(row.site_name)}`, html, saveBtn);
  }
};

window.Pages = window.Pages || {};
window.Pages.ratelimit = RateLimitPage;
