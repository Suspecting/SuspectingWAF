// dashboard/js/pages/certs.js
// SSL Certificates page

const CertsPage = {
  async render() {
    const { h } = DOM;
    
    const actionsEl = document.getElementById('pageActions');
    DOM.empty(actionsEl);
    
    const addBtn = h('button', { 
      className: 'btn btn-primary',
      onclick: () => this.showAddModal()
    }, '➕ Upload Certificate');
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
      const res = await API.get('/certs');
      const container = document.getElementById('tableContainer');
      DOM.empty(container);

      const table = new DataTable({
        data: res.certs,
        emptyText: 'No certificates uploaded.',
        columns: [
          { 
            key: 'name', label: 'Name',
            render: (v) => `<div class="font-bold">${DOM.escapeHTML(v)}</div>`
          },
          { 
            key: 'domain', label: 'Domain(s)',
            render: (v) => `<span class="mono text-primary">${DOM.escapeHTML(v)}</span>`
          },
          { 
            key: 'created_at', label: 'Uploaded On',
            render: (v) => `<span class="text-faint">${Format.formatDate(v)}</span>`
          },
          {
            key: 'actions', label: '',
            render: (v, row) => {
              const delBtn = document.createElement('button');
              delBtn.className = 'btn btn-sm btn-ghost';
              delBtn.innerHTML = '<span class="text-danger">Delete</span>';
              delBtn.onclick = (e) => { e.stopPropagation(); this.deleteCert(row); };
              return delBtn;
            }
          }
        ]
      });

      container.appendChild(table.render());
    } catch (err) {
      Toast.error('Failed to load certificates');
    }
  },

  showAddModal() {
    const html = `
      <form id="certForm">
        <div class="form-group">
          <label class="form-label">Friendly Name</label>
          <input type="text" id="certName" class="form-input" required placeholder="e.g., example.com wildcard">
        </div>
        <div class="form-group">
          <label class="form-label">Primary Domain</label>
          <input type="text" id="certDomain" class="form-input" required placeholder="e.g., example.com">
        </div>
        <div class="form-group">
          <label class="form-label">Certificate (PEM)</label>
          <textarea id="certContent" class="form-input mono" style="font-size:11px" rows="5" required placeholder="-----BEGIN CERTIFICATE-----\n..."></textarea>
        </div>
        <div class="form-group">
          <label class="form-label">Private Key (PEM)</label>
          <textarea id="keyContent" class="form-input mono" style="font-size:11px" rows="5" required placeholder="-----BEGIN PRIVATE KEY-----\n..."></textarea>
        </div>
      </form>
    `;

    const saveBtn = DOM.h('button', {
      className: 'btn btn-primary',
      onclick: async () => {
        try {
          const data = {
            name: document.getElementById('certName').value.trim(),
            domain: document.getElementById('certDomain').value.trim(),
            cert_content: document.getElementById('certContent').value.trim(),
            key_content: document.getElementById('keyContent').value.trim(),
          };
          
          if (!data.name || !data.domain || !data.cert_content || !data.key_content) {
            return Toast.error('All fields are required');
          }

          if (!data.cert_content.includes('BEGIN CERTIFICATE')) {
            return Toast.error('Certificate appears invalid');
          }

          saveBtn.disabled = true;
          saveBtn.textContent = 'Uploading...';

          await API.post('/certs', data);
          Toast.success('Certificate uploaded successfully');
          Modal.close();
          this.loadData();
        } catch (err) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Upload';
          Toast.error(err.message);
        }
      }
    }, 'Upload');

    Modal.show('Upload SSL Certificate', html, saveBtn);
  },

  deleteCert(cert) {
    Modal.confirm(
      'Delete Certificate', 
      `Are you sure you want to delete the certificate for "${DOM.escapeHTML(cert.domain)}"? Sites using this cert will fail SSL termination.`,
      'Delete',
      async () => {
        try {
          await API.delete(`/certs/${cert.id}`);
          Toast.success('Certificate deleted');
          this.loadData();
        } catch (err) { Toast.error(err.message); }
      },
      true
    );
  }
};

window.Pages = window.Pages || {};
window.Pages.certs = CertsPage;
