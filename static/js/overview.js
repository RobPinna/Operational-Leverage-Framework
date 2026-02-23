function clamp01(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(100, v));
}

function initExecutiveRiskRadar() {
  const cfg = window.__executiveRadar;
  const el = document.getElementById('globalRiskRadar');
  if (!cfg || !el || !window.Chart) return;

  const labels = Array.isArray(cfg.labels) ? cfg.labels : [];
  const values = Array.isArray(cfg.values) ? cfg.values : [];
  const explanations = cfg.explanations || {};

  // eslint-disable-next-line no-new
  new Chart(el, {
    type: 'radar',
    data: {
      labels,
      datasets: [
        {
          label: 'Derived estimate',
          data: values.map(clamp01),
          fill: true,
          backgroundColor: 'rgba(37, 99, 235, 0.12)',
          borderColor: 'rgba(29, 78, 216, 0.85)',
          pointBackgroundColor: 'rgba(29, 78, 216, 0.85)',
          pointBorderColor: '#ffffff',
          pointHoverRadius: 4,
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: (items) => (items && items[0] ? items[0].label : ''),
            label: (item) => `Score: ${Math.round(item.raw || 0)}/100`,
            afterLabel: (item) => {
              const axis = item.label || '';
              return explanations[axis] ? `Note: ${explanations[axis]}` : '';
            },
          },
        },
      },
      scales: {
        r: {
          min: 0,
          max: 100,
          ticks: { display: false },
          grid: { color: 'rgba(148, 163, 184, 0.35)' },
          angleLines: { color: 'rgba(148, 163, 184, 0.35)' },
          pointLabels: { color: '#334155', font: { size: 12, weight: '600' } },
        },
      },
    },
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initExecutiveRiskRadar();
});
