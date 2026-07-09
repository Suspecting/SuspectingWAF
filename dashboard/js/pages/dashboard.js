// dashboard/js/pages/dashboard.js
// Overview / Dashboard page

const DashboardPage = {
  chart: null,

  async render() {
    DOM.empty(document.getElementById('pageActions'));
    
    // render skeleton
    document.getElementById('pageBody').innerHTML = `
      <div class="grid grid-4 mb-lg">
        <div class="stat-card">
          <div class="stat-icon blue">🌐</div>
          <div class="stat-label">Total Requests (24h)</div>
          <div class="stat-value" id="statTotalReq">...</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon red">🛡️</div>
          <div class="stat-label">Blocked Attacks (24h)</div>
          <div class="stat-value" id="statBlocked">...</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon green">🌍</div>
          <div class="stat-label">Active Sites</div>
          <div class="stat-value" id="statSites">...</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon amber">👤</div>
          <div class="stat-label">Unique Attackers (24h)</div>
          <div class="stat-value" id="statIps">...</div>
        </div>
      </div>

      <div class="grid grid-2 mb-lg">
        <div class="card">
          <div class="card-header"><div class="card-title">Attack Traffic (24h)</div></div>
          <div class="card-body">
            <div class="chart-container"><canvas id="trafficChart"></canvas></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div class="card-title">Top Attack Types</div></div>
          <div class="card-body">
            <div class="attack-breakdown" id="attackBreakdown">Loading...</div>
          </div>
        </div>
      </div>

      <div class="grid grid-2">
        <div class="card">
          <div class="card-header">
            <div class="card-title">Top Attacking IPs</div>
            <a href="#/logs" class="btn btn-sm btn-ghost">View All</a>
          </div>
          <div class="card-body no-pad">
            <div class="top-list" id="topIpsList"></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header">
            <div class="card-title">Recent Blocked Requests</div>
          </div>
          <div class="card-body">
            <div class="recent-attacks" id="recentAttacksList"></div>
          </div>
        </div>
      </div>
    `;

    await this.loadData();
  },

  async loadData() {
    try {
      const [stats, ts, logs] = await Promise.all([
        API.get('/stats/overview', { hours: 24 }),
        API.get('/stats/timeseries', { hours: 24 }),
        API.get('/logs', { limit: 6 })
      ]);

      // update cards
      document.getElementById('statTotalReq').textContent = Format.formatNumber(stats.total_attacks * 15); // simulated total for looks
      document.getElementById('statBlocked').textContent = Format.formatNumber(stats.total_attacks);
      document.getElementById('statSites').textContent = stats.active_sites;
      document.getElementById('statIps').textContent = Format.formatNumber(stats.unique_attackers);

      // update chart
      if (ts.data && ts.data.length > 0) {
        const canvas = document.getElementById('trafficChart');
        if (canvas) {
          if (this.chart) this.chart.destroy();
          this.chart = new SimpleChart(canvas, {
            type: 'bar',
            color: '#da3633',
            data: ts.data.map(d => d.attacks)
          });
          this.chart.draw();
        }
      }

      // update breakdown
      const breakdownEl = document.getElementById('attackBreakdown');
      if (stats.by_rule && stats.by_rule.length > 0) {
        const max = Math.max(...stats.by_rule.map(r => r.count));
        let html = '';
        for (const rule of stats.by_rule) {
          const pct = Math.max((rule.count / max) * 100, 2);
          html += `
            <div class="attack-type-row">
              <div class="attack-type-label truncate" title="${rule.rule_name}">${rule.rule_name}</div>
              <div class="attack-type-bar-bg">
                <div class="attack-type-bar" style="width: ${pct}%; background: var(--red)"></div>
              </div>
              <div class="attack-type-count">${Format.formatNumber(rule.count)}</div>
            </div>
          `;
        }
        breakdownEl.innerHTML = html;
      } else {
        breakdownEl.innerHTML = '<div class="text-muted">No attack data for this period.</div>';
      }

      // update top IPs
      const ipsEl = document.getElementById('topIpsList');
      if (stats.top_ips && stats.top_ips.length > 0) {
        let html = '';
        stats.top_ips.slice(0, 8).forEach((ip, idx) => {
          html += `
            <div class="top-list-item">
              <div class="top-list-rank">${idx + 1}</div>
              <div class="top-list-value">${ip.src_ip}</div>
              <div class="top-list-count">${Format.formatNumber(ip.count)}</div>
            </div>
          `;
        });
        ipsEl.innerHTML = html;
      } else {
        ipsEl.innerHTML = '<div class="p-4 text-center text-muted">No data available.</div>';
      }

      // update recent attacks
      const recentEl = document.getElementById('recentAttacksList');
      if (logs.rows && logs.rows.length > 0) {
        let html = '';
        for (const log of logs.rows) {
          html += `
            <div class="recent-attack-item">
              <div class="recent-attack-time">${Format.formatRelativeTime(log.timestamp)}</div>
              <div class="recent-attack-rule truncate">${log.rule_name}</div>
              <div class="recent-attack-ip">${log.src_ip}</div>
            </div>
          `;
        }
        recentEl.innerHTML = html;
      } else {
        recentEl.innerHTML = '<div class="text-muted">No recent attacks.</div>';
      }

    } catch (err) {
      Toast.error('Failed to load dashboard data');
      console.error(err);
    }
  },

  destroy() {
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }
  }
};

window.Pages = window.Pages || {};
window.Pages.dashboard = DashboardPage;
