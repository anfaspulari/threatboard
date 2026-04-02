/* =========================================================
   ThreatBoard — Application Logic
   ========================================================= */
(function () {
  'use strict';

  /* ── Utilities ── */
  function sev(s) {
    return s.toLowerCase().replace(/\s+/g, '-');
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

  function statusBadge(status) {
    return `<span class="status-badge status-${escHtml(status)}">${escHtml(status)}</span>`;
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
        document.querySelectorAll('.nav-btn').forEach(b =>
          b.classList.toggle('active', b.dataset.view === view)
        );
      });
    });
  }

  function switchView(viewId) {
    document.querySelectorAll('.view').forEach(v =>
      v.classList.toggle('active', v.id === 'view-' + viewId)
    );
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

  /* ── Analyst Insight ── */
  function renderInsight() {
    const el = document.getElementById('analystInsight');
    if (!el) return;

    const active    = TB_DATA.iocs.filter(i => i.status !== 'closed');
    const critical  = active.filter(i => i.severity === 'Critical');
    const escalated = active.filter(i => i.status === 'escalated');

    /* Find top active campaign by IOC count */
    const campaignCounts = {};
    active.forEach(i => {
      if (i.campaign) campaignCounts[i.campaign] = (campaignCounts[i.campaign] || 0) + 1;
    });
    const sorted      = Object.entries(campaignCounts).sort((a, b) => b[1] - a[1]);
    const topCampaign = sorted[0];
    const activeCamps = sorted.length;

    /* Build dynamic sentences */
    const sentences = [];

    if (critical.length > 0) {
      sentences.push(
        `<strong>${critical.length} critical indicator${critical.length > 1 ? 's' : ''}</strong> ` +
        `remain unresolved — immediate triage required.`
      );
    } else {
      sentences.push('No unresolved critical indicators. Threat posture is currently stable.');
    }

    if (topCampaign) {
      const others = activeCamps > 1
        ? ` alongside ${activeCamps - 1} other active campaign${activeCamps > 2 ? 's' : ''}`
        : '';
      sentences.push(
        `Campaign <strong class="insight-campaign">${escHtml(topCampaign[0])}</strong> ` +
        `is the highest-priority cluster (${topCampaign[1]} active IOC${topCampaign[1] > 1 ? 's' : ''})${others}.`
      );
    }

    if (escalated.length > 0) {
      sentences.push(
        `${escalated.length} indicator${escalated.length > 1 ? 's have' : ' has'} been escalated — ` +
        `ensure IR tickets are open and containment actions are in progress.`
      );
    } else if (critical.length > 0) {
      sentences.push('No indicators have been escalated yet — consider escalating critical IOCs to the IR team.');
    }

    el.innerHTML = `
      <div class="insight-inner">
        <div class="insight-icon">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M10 2a8 8 0 1 0 0 16A8 8 0 0 0 10 2z" stroke-linecap="round"/>
            <path d="M10 7v4" stroke-linecap="round"/>
            <circle cx="10" cy="14" r="0.5" fill="currentColor" stroke="none"/>
          </svg>
        </div>
        <div class="insight-body">
          <p class="insight-label">Analyst Insight</p>
          <p class="insight-text">${sentences.join(' ')}</p>
        </div>
      </div>
    `;
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
              <td><code class="mono-muted">${escHtml(a.id)}</code></td>
              <td class="title-cell">${escHtml(a.title)}</td>
              <td><span style="color:var(--text-secondary)">${escHtml(a.category)}</span></td>
              <td>${badge(a.severity)}</td>
              <td>${escHtml(a.source)}</td>
              <td class="time-cell">${escHtml(a.time)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  /* ── IOC table ── */
  let iocFilter     = { search: '', type: '', status: '' };
  let selectedIocId = null;

  function iocActionButtons(ioc) {
    switch (ioc.status) {
      case 'open':
        return `
          <button class="action-btn action-investigate" data-action="investigating" data-ioc-id="${escHtml(ioc.id)}" title="Begin investigation">Investigate</button>
          <button class="action-btn action-escalate"   data-action="escalated"     data-ioc-id="${escHtml(ioc.id)}" title="Escalate to IR">Escalate</button>
          <button class="action-btn action-close"      data-action="closed"        data-ioc-id="${escHtml(ioc.id)}" title="Mark as closed">Close</button>
        `;
      case 'investigating':
        return `
          <button class="action-btn action-escalate" data-action="escalated" data-ioc-id="${escHtml(ioc.id)}" title="Escalate to IR">Escalate</button>
          <button class="action-btn action-close"    data-action="closed"    data-ioc-id="${escHtml(ioc.id)}" title="Mark as closed">Close</button>
        `;
      case 'escalated':
        return `
          <button class="action-btn action-close" data-action="closed" data-ioc-id="${escHtml(ioc.id)}" title="Mark as closed">Close</button>
        `;
      case 'closed':
        return `
          <button class="action-btn action-reopen" data-action="open" data-ioc-id="${escHtml(ioc.id)}" title="Reopen indicator">Reopen</button>
        `;
      default:
        return '';
    }
  }

  function renderIocRow(ioc) {
    const selected = ioc.id === selectedIocId ? ' ioc-row--selected' : '';
    return `
      <tr class="ioc-row${selected}" data-ioc-id="${escHtml(ioc.id)}">
        <td class="ioc-value${ioc.type === 'Hash' ? ' ioc-hash' : ''}">${escHtml(ioc.value)}</td>
        <td><span class="type-label">${escHtml(ioc.type)}</span></td>
        <td>${badge(ioc.severity)}</td>
        <td data-cell="status">${statusBadge(ioc.status)}</td>
        <td>
          <span class="conf-value" style="color:${ioc.confidence >= 85 ? 'var(--low)' : ioc.confidence >= 60 ? 'var(--medium)' : 'var(--text-muted)'}">
            ${ioc.confidence}%
          </span>
        </td>
        <td class="campaign-cell">${ioc.campaign ? `<span class="campaign-tag">${escHtml(ioc.campaign)}</span>` : '<span class="text-muted-sm">—</span>'}</td>
        <td class="time-cell">${escHtml(ioc.lastSeen)}</td>
        <td data-cell="actions"><div class="action-group">${iocActionButtons(ioc)}</div></td>
      </tr>
    `;
  }

  function renderIocs() {
    const el = document.getElementById('iocTable');
    if (!el) return;

    const filtered = TB_DATA.iocs.filter(ioc => {
      const matchSearch = !iocFilter.search ||
        ioc.value.toLowerCase().includes(iocFilter.search.toLowerCase()) ||
        (ioc.campaign || '').toLowerCase().includes(iocFilter.search.toLowerCase()) ||
        ioc.tags.some(t => t.toLowerCase().includes(iocFilter.search.toLowerCase()));
      const matchType   = !iocFilter.type   || ioc.type === iocFilter.type;
      const matchStatus = !iocFilter.status || ioc.status === iocFilter.status;
      return matchSearch && matchType && matchStatus;
    });

    el.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Indicator</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Confidence</th>
            <th>Campaign</th>
            <th>Last Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.length
            ? filtered.map(renderIocRow).join('')
            : '<tr><td colspan="8" class="empty-state">No indicators match your filter.</td></tr>'
          }
        </tbody>
      </table>
    `;
  }

  /* Update a single row in-place after a status change */
  function updateIocRow(ioc) {
    const row = document.querySelector(`.ioc-row[data-ioc-id="${ioc.id}"]`);
    if (!row) return;
    row.querySelector('[data-cell="status"]').innerHTML  = statusBadge(ioc.status);
    row.querySelector('[data-cell="actions"]').innerHTML = `<div class="action-group">${iocActionButtons(ioc)}</div>`;
  }

  function initIocActions() {
    const container = document.getElementById('iocTable');
    if (!container) return;

    /* Row selection */
    container.addEventListener('click', e => {
      const row = e.target.closest('.ioc-row');
      if (!row) return;

      /* Don't fire selection when clicking action buttons */
      if (e.target.closest('.action-btn')) return;

      const id = row.dataset.iocId;
      if (selectedIocId === id) {
        selectedIocId = null;
        row.classList.remove('ioc-row--selected');
      } else {
        document.querySelectorAll('.ioc-row--selected').forEach(r => r.classList.remove('ioc-row--selected'));
        selectedIocId = id;
        row.classList.add('ioc-row--selected');
      }
    });

    /* Action buttons */
    container.addEventListener('click', e => {
      const btn = e.target.closest('.action-btn[data-action]');
      if (!btn) return;

      const iocId    = btn.dataset.iocId;
      const newStatus = btn.dataset.action;
      const ioc      = TB_DATA.iocs.find(i => i.id === iocId);
      if (!ioc) return;

      ioc.status = newStatus;
      updateIocRow(ioc);
      renderInsight();   /* Insight text updates to reflect the change */
    });
  }

  function initIocFilters() {
    const search      = document.getElementById('iocSearch');
    const typeFilter  = document.getElementById('iocTypeFilter');
    const statusFilter = document.getElementById('iocStatusFilter');

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
    if (statusFilter) {
      statusFilter.addEventListener('change', () => {
        iocFilter.status = statusFilter.value;
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
        <div class="actor-techniques">
          ${a.techniques.map(t => `<span class="attack-tag" title="MITRE ATT&amp;CK">${escHtml(t)}</span>`).join('')}
        </div>
        <p class="actor-activity">${escHtml(a.lastActivity)}</p>
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
        <div class="feed-meta">
          <span class="feed-time">${escHtml(item.time)}</span>
          <span class="feed-source">${escHtml(item.source)}</span>
        </div>
        <div>
          <p class="feed-title">${escHtml(item.title)}</p>
          <p class="feed-body">${escHtml(item.body)}</p>
        </div>
        ${badge(item.severity)}
      </div>
    `).join('') || '<p class="empty-state" style="padding:24px 20px">No items match the selected filter.</p>';
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
    renderInsight();
    renderAlerts();
    renderIocs();
    initIocActions();
    initIocFilters();
    renderActors();
    renderFeed();
    initFeedFilter();
    initRefresh();
    updateTimestamp();

    setInterval(updateTimestamp, 60000);
  });

})();
