/* =========================================================
   ThreatBoard — Lightweight Canvas Bar Chart
   No third-party dependencies — pure Canvas 2D API
   ========================================================= */

(function () {
  'use strict';

  /**
   * Render a grouped bar chart onto a <canvas> element.
   * @param {HTMLCanvasElement} canvas
   * @param {{ labels, critical, high, medium }} series
   */
  function renderActivityChart(canvas, series) {
    const dpr   = window.devicePixelRatio || 1;
    const rect  = canvas.parentElement.getBoundingClientRect();
    const W     = rect.width;
    const H     = rect.height;

    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';

    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    const PAD_L = 36, PAD_R = 16, PAD_T = 16, PAD_B = 32;
    const chartW = W - PAD_L - PAD_R;
    const chartH = H - PAD_T - PAD_B;

    const n     = series.labels.length;
    const maxV  = Math.max(
      ...series.critical, ...series.high, ...series.medium
    );
    const yMax  = Math.ceil(maxV / 5) * 5 || 10;

    const COLORS = {
      critical: 'rgba(255,68,68,0.85)',
      high:     'rgba(255,140,0,0.85)',
      medium:   'rgba(240,180,41,0.70)'
    };

    /* ── Grid lines ── */
    const gridLines = 4;
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.lineWidth = 1;
    ctx.fillStyle = 'rgba(139,148,158,0.6)';
    ctx.font = '10px -apple-system, sans-serif';
    ctx.textAlign = 'right';

    for (let i = 0; i <= gridLines; i++) {
      const y = PAD_T + chartH - (i / gridLines) * chartH;
      ctx.beginPath();
      ctx.moveTo(PAD_L, y);
      ctx.lineTo(PAD_L + chartW, y);
      ctx.stroke();
      ctx.fillText(Math.round((yMax * i) / gridLines), PAD_L - 4, y + 3.5);
    }

    /* ── Bars ── */
    const groupW  = chartW / n;
    const barKeys = ['critical', 'high', 'medium'];
    const barW    = (groupW * 0.65) / barKeys.length;
    const gapW    = (groupW - barW * barKeys.length) / 2;
    const radius  = 3;

    barKeys.forEach((key, ki) => {
      series[key].forEach((val, i) => {
        const barH = (val / yMax) * chartH;
        const x    = PAD_L + i * groupW + gapW + ki * barW;
        const y    = PAD_T + chartH - barH;

        ctx.fillStyle = COLORS[key];
        roundedBar(ctx, x, y, barW - 2, barH, radius);
      });
    });

    /* ── X-axis labels ── */
    ctx.fillStyle  = 'rgba(139,148,158,0.7)';
    ctx.textAlign  = 'center';
    ctx.font = '11px -apple-system, sans-serif';
    series.labels.forEach((label, i) => {
      const x = PAD_L + i * groupW + groupW / 2;
      ctx.fillText(label, x, PAD_T + chartH + 18);
    });
  }

  function roundedBar(ctx, x, y, w, h, r) {
    if (h < r) r = h;
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.arcTo(x + w, y, x + w, y + r, r);
    ctx.lineTo(x + w, y + h);
    ctx.lineTo(x, y + h);
    ctx.lineTo(x, y + r);
    ctx.arcTo(x, y, x + r, y, r);
    ctx.closePath();
    ctx.fill();
  }

  /* Expose */
  window.TB_Chart = { renderActivityChart };
})();
