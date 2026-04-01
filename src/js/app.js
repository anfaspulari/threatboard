/* =========================================================
   ThreatBoard — Application Logic
   ========================================================= */
(function () {
  'use strict';

  /* ── Utilities ── */
  function sev(s) {
    return s.toLowerCase().replace(' ', '-');
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function badge(severity) {
    return `<span class="badge ${sev(severity)}">${escHtml(severity)}</span>`;
  }

  function updateTimestamp() {
    const el = document.getElementById('lastUpdated');
    if (el) {
      const now = new Date();
      el.textContent = 'Updated ' + now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
  }

  /* ── View routing ── */
  function initNav() {
    document.querySelectorAll('.nav-btn, .btn-link[data-view]').forEach(btn => {
      btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        if (!view) return;
        switchView(view);
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === view));
      });
    });
  }

  function switchView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + viewId));
  }

  /* ── KPIs ── */
  function renderKpis() {
    const { kpis } = TB_DATA;
    animateCount('kpiThreats',  kpis.activeThreats);
    animateCount('kpiIocs',     kpis.iocsTracked);
    animateCount('kpiCritical', kpis.criticalAlerts);
    animateCount('kpiActors',   kpis.threatActors);
  }

  function animateCount(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let start = 0;
    const step = Math.ceil(target / 40);
    const timer = setInterval(() => {
      start = Math.min(start + step, target);
      el.textContent = start.toLocaleString();
      if (start >= target) clearInterval(timer);
    }, 20);
  }

  /* ── Severity bars ── */
  function renderSeverityBars() {
    const container = document.getElementById('severityBars');
    if (!container) return;
    container.innerHTML = TB_DATA.severityBreakdown.map(({ level, count, pct }) => `
      <div class="sev-row">
        <div class="sev-top">
          <span class="sev-name">${escHtml(level)}</span>
          <span class="sev-count">${count}</span>
        </div>
        <div class="sev-track">
          <div class="sev-fill ${sev(level)}" style="width:0%" data-target="${pct}"></div>
        </div>
      </div>
    `).join('');

    /* Animate after paint */
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        container.querySelectorAll('.sev-fill').forEach(el => {
          el.style.width = el.dataset.target + '%';
        });
      });
    });
  }

  /* ── Activity chart ── */
  function renderChart() {
    const canvas = document.getElementById('activityChart');
    if (!canvas) return;
    TB_Chart.renderActivityChart(canvas, TB_DATA.activitySeries);
  }

  /* ── Alert table ── */
  function renderAlerts() {
    const el = document.getElementById('alertTable');
    if (!el) return;
    el.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Category</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          ${TB_DATA.alerts.map(a => `
            <tr>
              <td><code style="font-size:0.78rem;color:var(--text-muted)">${escHtml(a.id)}</code></td>
              <td class="title-cell">${escHtml(a.title)}</td>
              <td><span style="color:var(--text-secondary)">${escHtml(a.category)}</span></td>
              <td>${badge(a.severity)}</td>
              <td>${escHtml(a.source)}</td>
              <td style="color:var(--text-muted);white-space:nowrap">${escHtml(a.time)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  /* ── IOC table ── */
  let iocFilter = { search: '', type: '' };

  function renderIocs() {
    const el = document.getElementById('iocTable');
    if (!el) return;

    const filtered = TB_DATA.iocs.filter(ioc => {
      const matchSearch = !iocFilter.search ||
        ioc.value.toLowerCase().includes(iocFilter.search.toLowerCase()) ||
        ioc.tags.some(t => t.toLowerCase().includes(iocFilter.search.toLowerCase()));
      const matchType = !iocFilter.type || ioc.type === iocFilter.type;
      return matchSearch && matchType;
    });

    el.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Indicator</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>First Seen</th>
            <th>Tags</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.length ? filtered.map(ioc => `
            <tr>
              <td class="ioc-value ${ioc.type === 'Hash' ? 'ioc-hash' : ''}">${escHtml(ioc.value)}</td>
              <td><span style="color:var(--info);font-size:0.78rem;font-weight:600">${escHtml(ioc.type)}</span></td>
              <td>${badge(ioc.severity)}</td>
              <td>
                <span style="color:${ioc.confidence >= 85 ? 'var(--low)' : ioc.confidence >= 60 ? 'var(--medium)' : 'var(--text-muted)'}">
                  ${ioc.confidence}%
                </span>
              </td>
              <td style="color:var(--text-muted);white-space:nowrap">${escHtml(ioc.firstSeen)}</td>
              <td>${ioc.tags.map(t => `<span class="actor-tag">${escHtml(t)}</span>`).join(' ')}</td>
            </tr>
          `).join('') : '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted)">No indicators match your filter.</td></tr>'}
        </tbody>
      </table>
    `;
  }

  function initIocFilters() {
    const search = document.getElementById('iocSearch');
    const typeFilter = document.getElementById('iocTypeFilter');
    if (search) {
      search.addEventListener('input', () => {
        iocFilter.search = search.value;
        renderIocs();
      });
    }
    if (typeFilter) {
      typeFilter.addEventListener('change', () => {
        iocFilter.type = typeFilter.value;
        renderIocs();
      });
    }
  }

  /* ── Threat actors ── */
  function renderActors() {
    const el = document.getElementById('actorsGrid');
    if (!el) return;
    el.innerHTML = TB_DATA.actors.map(a => `
      <div class="actor-card">
        <div class="actor-header">
          <span class="actor-name">${escHtml(a.name)}</span>
          ${badge(a.severity)}
        </div>
        <p class="actor-origin">${escHtml(a.origin)}</p>
        <p class="actor-desc">${escHtml(a.description)}</p>
        <div class="actor-tags">
          ${a.tags.map(t => `<span class="actor-tag">${escHtml(t)}</span>`).join('')}
        </div>
      </div>
    `).join('');
  }

  /* ── Intel feed ── */
  let feedFilter = '';

  function renderFeed() {
    const el = document.getElementById('feedList');
    if (!el) return;

    const filtered = TB_DATA.feed.filter(item =>
      !feedFilter || item.severity === feedFilter
    );

    el.innerHTML = filtered.map(item => `
      <div class="feed-item">
        <span class="feed-time">${escHtml(item.time)}</span>
        <div>
          <p class="feed-title">${escHtml(item.title)}</p>
          <p class="feed-body">${escHtml(item.body)}</p>
        </div>
        ${badge(item.severity)}
      </div>
    `).join('') || '<p style="padding:24px 20px;color:var(--text-muted)">No items match the selected filter.</p>';
  }

  function initFeedFilter() {
    const filter = document.getElementById('feedSeverityFilter');
    if (filter) {
      filter.addEventListener('change', () => {
        feedFilter = filter.value;
        renderFeed();
      });
    }
  }

  /* ── Refresh ── */
  function initRefresh() {
    const btn = document.getElementById('refreshBtn');
    if (!btn) return;
    btn.addEventListener('click', () => {
      btn.classList.add('spinning');
      setTimeout(() => {
        btn.classList.remove('spinning');
        updateTimestamp();
      }, 800);
    });
  }

  /* ── Resize handler ── */
  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(renderChart, 200);
  });

  /* ── Bootstrap ── */
  document.addEventListener('DOMContentLoaded', () => {
    initNav();
    renderKpis();
    renderSeverityBars();
    renderChart();
    renderAlerts();
    renderIocs();
    renderActors();
    renderFeed();
    initIocFilters();
    initFeedFilter();
    initRefresh();
    updateTimestamp();

    /* Auto-refresh every 60 s */
    setInterval(updateTimestamp, 60000);
  });

})();
