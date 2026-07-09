const IpListPage = {
  currentTab: 'block', // 'block' or 'allow'

  async render() {
    const { h } = DOM;
    
    const actionsEl = document.getElementById('pageActions');
    DOM.empty(actionsEl);
    
    const addBtn = h('button', { 
      className: `btn ${this.currentTab === 'block' ? 'btn-danger' : 'btn-success'}`,
      onclick: () => this.showAddModal()
    }, `➕ Add IP to ${this.currentTab === 'block' ? 'Blocklist' : 'Allowlist'}`);
    const tabs = h('div', { className: 'flex gap-md mb-md' }, [
      h('button', { 
        className: `btn ${this.currentTab === 'block' ? 'btn-secondary' : 'btn-ghost'}`,
        onclick: () => { this.currentTab = 'block'; this.render(); }
      }, '🚫 Blocklist'),
      h('button', { 
        className: `btn ${this.currentTab === 'allow' ? 'btn-secondary' : 'btn-ghost'}`,
        onclick: () => { this.currentTab = 'allow'; this.render(); }
      }, '✅ Allowlist')
    ]);

    actionsEl.appendChild(tabs);
    actionsEl.appendChild(addBtn);

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
      const res = await API.get('/iplist', { type: this.currentTab });
      const container = document.getElementById('tableContainer');
      DOM.empty(container);

      const table = new DataTable({
        data: res.list,
        emptyText: `No IPs in the ${this.currentTab}list.`,
        columns: [
          { 
            key: 'ip', label: 'IP Address / CIDR',
            render: (v) => `<div class="mono font-bold text-primary">${DOM.escapeHTML(v)}</div>`
          },
          { 
            key: 'reason', label: 'Reason',
            render: (v) => `<span class="text-muted">${DOM.escapeHTML(v) || '-'}</span>`
          },
          { 
            key: 'created_at', label: 'Added On',
            render: (v) => `<span class="text-faint">${Format.formatDate(v)}</span>`
          },
          { 
            key: 'expires_at', label: 'Expires',
            render: (v) => v ? `<span class="text-warning">${Format.formatRelativeTime(v)}</span>` : '<span class="text-faint">Never</span>'
          },
          {
            key: 'actions', label: '',
            render: (v, row) => {
              const delBtn = document.createElement('button');
              delBtn.className = 'btn btn-sm btn-ghost';
              delBtn.innerHTML = '<span class="text-danger">Remove</span>';
              delBtn.onclick = (e) => { e.stopPropagation(); this.deleteIp(row); };
              return delBtn;
            }
          }
        ]
      });

      container.appendChild(table.render());
    } catch (err) {
      Toast.error('Failed to load IP list');
    }
  },

  showAddModal() {
    const isBlock = this.currentTab === 'block';
    
    const html = `
      <form id="ipForm">
        <div class="form-group">
          <label class="form-label">IP Address or CIDR Range</label>
          <input type="text" id="ipAddress" class="form-input" required placeholder="e.g., 192.168.1.100 or 10.0.0.0/24">
        </div>
        
        <div class="form-group">
          <label class="form-label">Reason (Optional)</label>
          <input type="text" id="ipReason" class="form-input" placeholder="e.g., Repeated SQLi attempts">
        </div>

        <div class="form-group">
          <label class="form-label">Expiration</label>
          <select id="ipExpiry" class="form-select">
            <option value="">Never expire</option>
            <option value="1">1 hour</option>
            <option value="24">24 hours</option>
            <option value="168">7 days</option>
            <option value="720">30 days</option>
          </select>
        </div>
      </form>
    `;

    const saveBtn = DOM.h('button', {
      className: `btn ${isBlock ? 'btn-danger' : 'btn-success'}`,
      onclick: async () => {
        try {
          const ip = document.getElementById('ipAddress').value.trim();
          const reason = document.getElementById('ipReason').value.trim();
          const expiryHours = document.getElementById('ipExpiry').value;
          
          if (!ip) return Toast.error('IP address required');
          
          if (!Validate.isIP(ip) && !Validate.isCIDR(ip)) {
            return Toast.error('Invalid IP address or CIDR format');
          }

          let expires_at = null;
          if (expiryHours) {
            const date = new Date();
            date.setHours(date.getHours() + parseInt(expiryHours, 10));
            expires_at = date.toISOString();
          }

          await API.post('/iplist', {
            ip, type: this.currentTab, reason, expires_at
          });
          
          Toast.success(`IP added to ${this.currentTab}list`);
          Modal.close();
          this.loadData();
        } catch (err) {
          Toast.error(err.message);
        }
      }
    }, `Add to ${isBlock ? 'Blocklist' : 'Allowlist'}`);

    Modal.show(`Add IP to ${isBlock ? 'Blocklist' : 'Allowlist'}`, html, saveBtn);
  },

  deleteIp(row) {
    Modal.confirm(
      'Remove IP', 
      `Remove ${DOM.escapeHTML(row.ip)} from the list?`,
      'Remove',
      async () => {
        try {
          await API.delete(`/iplist/${row.id}`);
          Toast.success('IP removed');
          this.loadData();
        } catch (err) { Toast.error(err.message); }
      },
      true
    );
  }
};

window.Pages = window.Pages || {};
window.Pages.iplist = IpListPage;
