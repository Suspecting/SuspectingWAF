// dashboard/js/pages/sites.js
// Site management page

const SitesPage = {
  async render() {
    const { h } = DOM;
    
    // setup actions (add button)
    const actionsEl = document.getElementById('pageActions');
    DOM.empty(actionsEl);
    
    const addBtn = h('button', { 
      className: 'btn btn-primary',
      onclick: () => this.showAddModal()
    }, '➕ Add Site');
    actionsEl.appendChild(addBtn);

    // main container
    const bodyEl = document.getElementById('pageBody');
    bodyEl.innerHTML = `
      <div class="card">
        <div id="tableContainer" class="card-body no-pad">
          <div class="loading-overlay"><div class="spinner"></div></div>
        </div>
      </div>
    `;

    await this.loadData();
  },

  async loadData() {
    try {
      const res = await API.get('/sites');
      const container = document.getElementById('tableContainer');
      DOM.empty(container);

      const table = new DataTable({
        data: res.sites,
        emptyText: 'No protected sites configured yet.',
        columns: [
          { 
            key: 'name', label: 'Name',
            render: (v, r) => `<div class="font-bold text-primary">${DOM.escapeHTML(v)}</div>`
          },
          { 
            key: 'status', label: 'Status',
            render: (v) => v === 'active' 
              ? `<span class="badge badge-success"><span class="status-dot active"></span>Active</span>`
              : `<span class="badge badge-info"><span class="status-dot inactive"></span>Inactive</span>`
          },
          { 
            key: 'listen_port', label: 'Port',
            render: (v, r) => {
              const p = r.ssl_enabled ? `${v} (SSL)` : v;
              return `<span class="mono">${p}</span>`;
            }
          },
          { 
            key: 'server_names', label: 'Domains',
            render: (v) => v ? DOM.escapeHTML(v) : '<span class="text-faint">Any</span>'
          },
          { 
            key: 'upstream_url', label: 'Upstream',
            render: (v) => `<span class="text-muted">${DOM.escapeHTML(v)}</span>`
          },
          {
            key: 'waf_enabled', label: 'WAF',
            render: (v) => v 
              ? `<span class="badge badge-success">ON</span>`
              : `<span class="badge badge-danger">OFF</span>`
          },
          {
            key: 'actions', label: '',
            render: (v, row) => {
              const div = document.createElement('div');
              div.className = 'flex gap-sm justify-end';
              
              const editBtn = document.createElement('button');
              editBtn.className = 'btn btn-sm btn-secondary';
              editBtn.textContent = 'Edit';
              editBtn.onclick = (e) => { e.stopPropagation(); this.showEditModal(row); };
              
              const delBtn = document.createElement('button');
              delBtn.className = 'btn btn-sm btn-ghost';
              delBtn.innerHTML = '<span class="text-danger">Delete</span>';
              delBtn.onclick = (e) => { e.stopPropagation(); this.deleteSite(row); };
              
              div.appendChild(editBtn);
              div.appendChild(delBtn);
              return div;
            }
          }
        ]
      });

      container.appendChild(table.render());
    } catch (err) {
      Toast.error('Failed to load sites');
      console.error(err);
    }
  },

  async fetchCerts() {
    try {
      const res = await API.get('/certs');
      return res.certs || [];
    } catch {
      return [];
    }
  },

  async getFormHtml(site = null) {
    const certs = await this.fetchCerts();
    const certOptions = certs.map(c => `<option value="${c.id}" ${site && site.cert_id === c.id ? 'selected' : ''}>${DOM.escapeHTML(c.name)} (${DOM.escapeHTML(c.domain)})</option>`).join('');
    
    return `
      <form id="siteForm">
        <div class="form-group">
          <label class="form-label">Site Name</label>
          <input type="text" id="siteName" class="form-input" required placeholder="e.g., Main Website" value="${site ? DOM.escapeHTML(site.name) : ''}">
        </div>
        
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Listen Port</label>
            <input type="number" id="sitePort" class="form-input" required placeholder="80" value="${site ? site.listen_port : '80'}">
          </div>
          <div class="form-group">
            <label class="form-label">Domains (Server Names)</label>
            <input type="text" id="siteDomains" class="form-input" placeholder="example.com, www.example.com" value="${site ? DOM.escapeHTML(site.server_names) : ''}">
            <div class="form-help">Comma-separated. Leave blank to match any.</div>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Upstream Target URL</label>
          <input type="url" id="siteUpstream" class="form-input" required placeholder="http://10.0.0.5:8080" value="${site ? DOM.escapeHTML(site.upstream_url) : ''}">
        </div>

        <div class="form-group">
          <label class="form-label">Status</label>
          <select id="siteStatus" class="form-select">
            <option value="active" ${site && site.status === 'active' ? 'selected' : ''}>Active</option>
            <option value="inactive" ${site && site.status === 'inactive' ? 'selected' : ''}>Inactive</option>
          </select>
        </div>

        <div class="form-row mt-md" style="padding: 16px; background: var(--bg-tertiary); border-radius: 8px; border: 1px solid var(--border-default);">
          <div class="form-group" style="margin-bottom:0">
            <label class="form-label" style="display:flex; justify-content:space-between; align-items:center;">
              <span>Enable WAF Protection</span>
              <label class="toggle">
                <input type="checkbox" id="siteWaf" ${!site || site.waf_enabled ? 'checked' : ''}>
                <div class="toggle-slider"></div>
              </label>
            </label>
            <div class="form-help">If disabled, traffic passes through without inspection.</div>
          </div>
        </div>

        <div class="form-row mt-md" style="padding: 16px; background: var(--bg-tertiary); border-radius: 8px; border: 1px solid var(--border-default);">
          <div style="flex:1">
            <div class="form-group">
              <label class="form-label" style="display:flex; justify-content:space-between; align-items:center;">
                <span>Enable SSL/TLS</span>
                <label class="toggle">
                  <input type="checkbox" id="siteSsl" ${site && site.ssl_enabled ? 'checked' : ''}>
                  <div class="toggle-slider"></div>
                </label>
              </label>
            </div>
            <div class="form-group" id="certGroup" style="${site && site.ssl_enabled ? '' : 'display:none;'} margin-bottom:0;">
              <label class="form-label">SSL Certificate</label>
              <select id="siteCert" class="form-select">
                <option value="">-- Select a Certificate --</option>
                ${certOptions}
              </select>
            </div>
          </div>
        </div>
      </form>
    `;
  },

  setupFormListeners() {
    const sslToggle = document.getElementById('siteSsl');
    const certGroup = document.getElementById('certGroup');
    if (sslToggle && certGroup) {
      sslToggle.addEventListener('change', (e) => {
        certGroup.style.display = e.target.checked ? 'block' : 'none';
      });
    }
  },

  getFormData() {
    return {
      name: document.getElementById('siteName').value,
      listen_port: parseInt(document.getElementById('sitePort').value, 10),
      server_names: document.getElementById('siteDomains').value,
      upstream_url: document.getElementById('siteUpstream').value,
      status: document.getElementById('siteStatus').value,
      waf_enabled: document.getElementById('siteWaf').checked,
      ssl_enabled: document.getElementById('siteSsl').checked,
      cert_id: document.getElementById('siteSsl').checked ? (parseInt(document.getElementById('siteCert').value, 10) || null) : null
    };
  },

  async showAddModal() {
    const html = await this.getFormHtml();
    
    const saveBtn = DOM.h('button', {
      className: 'btn btn-primary',
      onclick: async () => {
        try {
          const data = this.getFormData();
          if (!data.name || !data.upstream_url || !data.listen_port) {
            return Toast.error('Please fill required fields');
          }
          await API.post('/sites', data);
          Toast.success('Site added successfully');
          Modal.close();
          this.loadData();
        } catch (err) {
          Toast.error(err.message);
        }
      }
    }, 'Save Site');

    Modal.show('Add New Site', html, saveBtn);
    this.setupFormListeners();
  },

  async showEditModal(site) {
    const html = await this.getFormHtml(site);
    
    const saveBtn = DOM.h('button', {
      className: 'btn btn-primary',
      onclick: async () => {
        try {
          const data = this.getFormData();
          if (!data.name || !data.upstream_url || !data.listen_port) {
            return Toast.error('Please fill required fields');
          }
          await API.put(`/sites/${site.id}`, data);
          Toast.success('Site updated');
          Modal.close();
          this.loadData();
        } catch (err) {
          Toast.error(err.message);
        }
      }
    }, 'Update Site');

    Modal.show('Edit Site', html, saveBtn);
    this.setupFormListeners();
  },

  deleteSite(site) {
    Modal.confirm(
      'Delete Site', 
      `Are you sure you want to delete "${DOM.escapeHTML(site.name)}"? This action cannot be undone and will stop proxying traffic for this site.`,
      'Delete',
      async () => {
        try {
          await API.delete(`/sites/${site.id}`);
          Toast.success('Site deleted');
          this.loadData();
        } catch (err) {
          Toast.error(err.message);
        }
      },
      true // isDanger
    );
  }
};

window.Pages = window.Pages || {};
window.Pages.sites = SitesPage;
