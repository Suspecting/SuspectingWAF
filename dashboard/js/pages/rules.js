// dashboard/js/pages/rules.js
// Custom Rules page

const RulesPage = {
  async render() {
    const { h } = DOM;
    
    const actionsEl = document.getElementById('pageActions');
    DOM.empty(actionsEl);
    
    const addBtn = h('button', { 
      className: 'btn btn-primary',
      onclick: () => this.showRuleModal()
    }, '➕ Create Rule');
    actionsEl.appendChild(addBtn);

    const bodyEl = document.getElementById('pageBody');
    bodyEl.innerHTML = `
      <div class="card">
        <div class="card-header">
          <div class="card-title">Custom Traffic Rules</div>
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
      const res = await API.get('/rules');
      const container = document.getElementById('tableContainer');
      DOM.empty(container);

      const table = new DataTable({
        data: res.rules,
        emptyText: 'No custom rules created.',
        columns: [
          {
            key: 'enabled', label: 'Status',
            render: (v, r) => `
              <label class="toggle" onclick="event.stopPropagation()">
                <input type="checkbox" onchange="window.Pages.rules.toggleRule(${r.id}, this.checked)" ${v ? 'checked' : ''}>
                <div class="toggle-slider"></div>
              </label>
            `
          },
          { 
            key: 'name', label: 'Rule Name',
            render: (v) => `<div class="font-bold">${DOM.escapeHTML(v)}</div>`
          },
          { 
            key: 'type', label: 'Action',
            render: (v) => v === 'block' 
              ? `<span class="badge badge-danger">BLOCK</span>`
              : `<span class="badge badge-success">ALLOW</span>`
          },
          { 
            key: 'condition', label: 'Condition',
            render: (_, r) => `<span class="mono text-muted">${DOM.escapeHTML(r.field)} <span class="text-faint">${DOM.escapeHTML(r.operator)}</span> ${DOM.escapeHTML(r.value)}</span>`
          },
          {
            key: 'actions', label: '',
            render: (v, row) => {
              const div = document.createElement('div');
              div.className = 'flex gap-sm justify-end';
              
              const delBtn = document.createElement('button');
              delBtn.className = 'btn btn-sm btn-ghost';
              delBtn.innerHTML = '<span class="text-danger">Delete</span>';
              delBtn.onclick = (e) => { e.stopPropagation(); this.deleteRule(row); };
              
              div.appendChild(delBtn);
              return div;
            }
          }
        ]
      });

      container.appendChild(table.render());
    } catch (err) {
      Toast.error('Failed to load rules');
    }
  },

  async toggleRule(id, enabled) {
    try {
      await API.put(`/rules/${id}`, { enabled });
      Toast.success(`Rule ${enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      Toast.error(err.message);
      this.loadData(); // revert UI on failure
    }
  },

  showRuleModal() {
    const html = `
      <form id="ruleForm">
        <div class="form-group">
          <label class="form-label">Rule Name</label>
          <input type="text" id="ruleName" class="form-input" required placeholder="e.g., Block bad crawler">
        </div>
        
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Action</label>
            <select id="ruleType" class="form-select">
              <option value="block">Block request</option>
              <option value="allow">Allow request (bypass WAF)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Field to inspect</label>
            <select id="ruleField" class="form-select">
              <option value="ip">Client IP</option>
              <option value="url">Request URL</option>
              <option value="user_agent">User-Agent</option>
              <option value="header">HTTP Header</option>
            </select>
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Operator</label>
            <select id="ruleOp" class="form-select">
              <option value="equals">Equals</option>
              <option value="contains">Contains</option>
              <option value="regex">Matches Regex</option>
              <option value="cidr">CIDR Match (IP only)</option>
            </select>
          </div>
          <div class="form-group" style="flex:2">
            <label class="form-label">Value</label>
            <input type="text" id="ruleValue" class="form-input" required placeholder="e.g., /admin/login">
            <div class="form-help" id="ruleHelp">The value to match against</div>
          </div>
        </div>
      </form>
    `;

    const saveBtn = DOM.h('button', {
      className: 'btn btn-primary',
      onclick: async () => {
        try {
          const data = {
            name: document.getElementById('ruleName').value,
            type: document.getElementById('ruleType').value,
            field: document.getElementById('ruleField').value,
            operator: document.getElementById('ruleOp').value,
            value: document.getElementById('ruleValue').value,
          };
          
          if (!data.name || !data.value) return Toast.error('Please fill required fields');
          
          // minor validation
          if (data.field === 'header' && !data.value.includes(':')) {
            return Toast.error('Header value must be format "Header-Name: value"');
          }

          await API.post('/rules', data);
          Toast.success('Rule created');
          Modal.close();
          this.loadData();
        } catch (err) {
          Toast.error(err.message);
        }
      }
    }, 'Create Rule');

    Modal.show('Create Custom Rule', html, saveBtn);

    // Dynamic help text
    document.getElementById('ruleField').addEventListener('change', (e) => {
      const v = e.target.value;
      const h = document.getElementById('ruleHelp');
      if (v === 'header') h.textContent = 'Format: "Header-Name: value" (e.g. "X-Custom: blockme")';
      else if (v === 'ip') h.textContent = 'Use CIDR operator for ranges like 192.168.0.0/24';
      else h.textContent = 'The value to match against';
    });
  },

  deleteRule(rule) {
    Modal.confirm(
      'Delete Rule', 
      `Delete rule "${DOM.escapeHTML(rule.name)}"?`,
      'Delete',
      async () => {
        try {
          await API.delete(`/rules/${rule.id}`);
          Toast.success('Rule deleted');
          this.loadData();
        } catch (err) { Toast.error(err.message); }
      },
      true
    );
  }
};

window.Pages = window.Pages || {};
window.Pages.rules = RulesPage;
