// dashboard/js/pages/logs.js
// Attack logs page

const LogsPage = {
  currentPage: 1,
  limit: 50,
  filters: { rule_id: '', severity: '' },

  async render() {
    const { h } = DOM;
    
    const actionsEl = document.getElementById('pageActions');
    DOM.empty(actionsEl);

    // render filter bar
    actionsEl.innerHTML = `
      <div class="filter-bar">
        <select id="filterSeverity" class="form-select">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <button class="btn btn-secondary" id="btnRefresh">🔄 Refresh</button>
      </div>
    `;

    document.getElementById('filterSeverity').addEventListener('change', (e) => {
      this.filters.severity = e.target.value;
      this.currentPage = 1;
      this.loadData();
    });

    document.getElementById('btnRefresh').addEventListener('click', () => {
      this.loadData();
    });

    // main container
    const bodyEl = document.getElementById('pageBody');
    bodyEl.innerHTML = `
      <div class="card mb-md">
        <div id="tableContainer" class="card-body no-pad">
          <div class="loading-overlay"><div class="spinner"></div></div>
        </div>
      </div>
      <div id="paginationContainer"></div>
    `;

    await this.loadData();
  },

  async loadData() {
    try {
      const params = { page: this.currentPage, limit: this.limit, ...this.filters };
      const res = await API.get('/logs', params);
      
      this.renderTable(res.rows || []);
      this.renderPagination(res.total || 0);
    } catch (err) {
      Toast.error('Failed to load logs');
      console.error(err);
    }
  },

  renderTable(rows) {
    const container = document.getElementById('tableContainer');
    DOM.empty(container);

    const table = new DataTable({
      data: rows,
      emptyText: 'No attack logs found.',
      onRowClick: (row) => this.showDetailModal(row),
      columns: [
        { 
          key: 'timestamp', label: 'Time',
          render: (v) => `<span class="text-muted" style="white-space:nowrap">${Format.formatDate(v)}</span>`
        },
        { 
          key: 'src_ip', label: 'Source IP',
          render: (v) => `<span class="mono text-primary">${DOM.escapeHTML(v)}</span>`
        },
        { 
          key: 'rule_name', label: 'Rule triggered',
          render: (v) => `<div class="font-bold">${DOM.escapeHTML(v)}</div>`
        },
        { 
          key: 'severity', label: 'Severity',
          render: (v) => `<span class="badge badge-${v.toLowerCase()}">${v.toUpperCase()}</span>`
        },
        { 
          key: 'action', label: 'Action',
          render: (v) => {
            const cls = v === 'blocked' ? 'danger' : (v === 'monitored' ? 'warning' : 'info');
            return `<span class="text-${cls}">${v.toUpperCase()}</span>`;
          }
        },
        { 
          key: 'url', label: 'Path',
          render: (v) => `<span class="mono text-muted truncate" style="max-width:200px;display:inline-block;" title="${DOM.escapeHTML(v)}">${DOM.escapeHTML(v)}</span>`
        }
      ]
    });

    container.appendChild(table.render());
  },

  renderPagination(total) {
    const totalPages = Math.ceil(total / this.limit) || 1;
    const container = document.getElementById('paginationContainer');
    
    let html = `
      <div class="pagination">
        <div>Showing ${total === 0 ? 0 : (this.currentPage - 1) * this.limit + 1} - ${Math.min(this.currentPage * this.limit, total)} of ${total} logs</div>
        <div class="pagination-buttons">
          <button class="page-btn" ${this.currentPage <= 1 ? 'disabled' : ''} id="btnPrev">Previous</button>
          <div style="padding:6px 12px">Page ${this.currentPage} of ${totalPages}</div>
          <button class="page-btn" ${this.currentPage >= totalPages ? 'disabled' : ''} id="btnNext">Next</button>
        </div>
      </div>
    `;
    
    container.innerHTML = html;

    const btnPrev = document.getElementById('btnPrev');
    const btnNext = document.getElementById('btnNext');

    if (btnPrev) btnPrev.onclick = () => { this.currentPage--; this.loadData(); };
    if (btnNext) btnNext.onclick = () => { this.currentPage++; this.loadData(); };
  },

  async showDetailModal(row) {
    try {
      // fetch full details to get headers which might be large
      const res = await API.get(`/logs/${row.id}`);
      const log = res.log;

      let headersHtml = '';
      if (log.request_headers && typeof log.request_headers === 'object') {
        headersHtml = Object.entries(log.request_headers)
          .map(([k, v]) => `<div><strong style="color:#8b949e">${DOM.escapeHTML(k)}:</strong> <span style="color:#c9d1d9">${DOM.escapeHTML(v)}</span></div>`)
          .join('');
      }

      const html = `
        <div class="grid grid-2 mb-md">
          <div>
            <div class="text-faint" style="font-size:11px;text-transform:uppercase">Time</div>
            <div>${Format.formatDate(log.timestamp)}</div>
          </div>
          <div>
            <div class="text-faint" style="font-size:11px;text-transform:uppercase">Action</div>
            <div><span class="badge badge-${log.action === 'blocked' ? 'danger' : 'warning'}">${log.action.toUpperCase()}</span></div>
          </div>
          <div>
            <div class="text-faint" style="font-size:11px;text-transform:uppercase">Source IP</div>
            <div class="mono">${DOM.escapeHTML(log.src_ip)}</div>
          </div>
          <div>
            <div class="text-faint" style="font-size:11px;text-transform:uppercase">Rule</div>
            <div>${DOM.escapeHTML(log.rule_name)} <span class="badge badge-${log.severity}">${log.severity}</span></div>
          </div>
        </div>

        <div class="mb-md">
          <div class="text-faint mb-sm" style="font-size:11px;text-transform:uppercase">Request</div>
          <div class="mono" style="background:var(--bg-tertiary);padding:12px;border-radius:6px;border:1px solid var(--border-default);font-size:12px;word-break:break-all;">
            <strong>${DOM.escapeHTML(log.method)}</strong> ${DOM.escapeHTML(log.url)}
          </div>
        </div>

        <div class="mb-md">
          <div class="text-faint mb-sm" style="font-size:11px;text-transform:uppercase">Trigger Payload</div>
          <div class="mono" style="background:rgba(218,54,51,0.1);color:var(--red);padding:12px;border-radius:6px;border:1px solid rgba(218,54,51,0.3);font-size:12px;word-break:break-all;">
            ${DOM.escapeHTML(log.payload || '(None)')}
          </div>
        </div>

        <div>
          <div class="text-faint mb-sm" style="font-size:11px;text-transform:uppercase">Headers</div>
          <div class="mono" style="background:var(--bg-primary);padding:12px;border-radius:6px;border:1px solid var(--border-default);font-size:11px;max-height:200px;overflow-y:auto;">
            ${headersHtml || 'No headers recorded'}
          </div>
        </div>
      `;

      Modal.show('Attack Log Details', html);
    } catch (err) {
      Toast.error('Failed to load log details');
    }
  }
};

window.Pages = window.Pages || {};
window.Pages.logs = LogsPage;
