function levelClass(value) {
  if (value >= 4) return 'text-red-300';
  if (value === 3) return 'text-amber-300';
  return 'text-emerald-300';
}

window.ExposureMapperUI = {
  levelClass,
};

function initTooltips() {
  const tip = document.createElement('div');
  tip.className = 'ui-tooltip hidden';
  tip.setAttribute('role', 'tooltip');
  document.body.appendChild(tip);

  let activeEl = null;

  function hide() {
    tip.classList.add('hidden');
    activeEl = null;
  }

  function show(el) {
    const text = String(el.getAttribute('data-tooltip') || '').trim();
    if (!text) return;
    activeEl = el;
    tip.textContent = text;
    tip.classList.remove('hidden');

    const rect = el.getBoundingClientRect();
    const pad = 10;
    const maxW = Math.min(360, window.innerWidth - (pad * 2));
    tip.style.maxWidth = `${maxW}px`;

    // Position above, fallback below
    const tipRect = tip.getBoundingClientRect();
    let top = rect.top - tipRect.height - 10;
    let left = rect.left + (rect.width / 2) - (tipRect.width / 2);
    if (top < pad) top = rect.bottom + 10;
    if (left < pad) left = pad;
    if (left + tipRect.width > window.innerWidth - pad) left = window.innerWidth - pad - tipRect.width;

    tip.style.top = `${Math.round(top + window.scrollY)}px`;
    tip.style.left = `${Math.round(left + window.scrollX)}px`;
  }

  document.addEventListener('mouseover', (e) => {
    const el = e.target && e.target.closest ? e.target.closest('[data-tooltip]') : null;
    if (!el) return;
    show(el);
  });
  document.addEventListener('mouseout', (e) => {
    if (!activeEl) return;
    const related = e.relatedTarget;
    if (related && activeEl.contains && activeEl.contains(related)) return;
    hide();
  });
  document.addEventListener('focusin', (e) => {
    const el = e.target && e.target.closest ? e.target.closest('[data-tooltip]') : null;
    if (!el) return;
    show(el);
  });
  document.addEventListener('focusout', () => hide());
  document.addEventListener('scroll', () => hide(), { passive: true });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); });

  // Tap to toggle (mobile friendly)
  document.addEventListener('click', (e) => {
    const el = e.target && e.target.closest ? e.target.closest('[data-tooltip]') : null;
    if (!el) return;
    if (activeEl === el && !tip.classList.contains('hidden')) {
      hide();
      return;
    }
    show(el);
  });
}

function initOpenDetailsButtons() {
  document.querySelectorAll('[data-open-details]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = String(btn.getAttribute('data-open-details') || '').trim();
      if (!id) return;
      const el = document.getElementById(id);
      if (!el || el.tagName.toLowerCase() !== 'details') return;
      el.open = true;
      const body = el.querySelector('.accordion-body');
      if (body) body.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
  });
}

function initLoadingOverlay() {
  const overlay = document.getElementById('loadingOverlay');
  const status = document.getElementById('loadingStatus');
  if (!overlay || !status) return;

  const msgSets = {
    collect: [
      'Discovering relevant pages…',
      'Crawling key pages…',
      'Rendering dynamic pages (fallback)…',
      'Downloading PDFs…',
      'Scanning PDF contents…',
      'Crawling job postings…',
      'Enumerating subdomains…',
      'Resolving DNS footprint…',
      'Detecting website vendors…',
      'Correlating signals…',
    ],
    model: [
      'Normalizing evidence…',
      'Building findings model…',
      'Extracting public exposure signals…',
      'Prioritizing findings…',
    ],
    assess: [
      'Building local retrieval index…',
      'Retrieving top evidence passages…',
      'Generating risk scenarios…',
      'Scoring confidence and impact…',
    ],
    report: [
      'Rendering PDF report…',
      'Packaging JSON export…',
      'Finalizing assessment artifacts…',
    ],
    default: [
      'Working…',
      'Please wait…',
    ],
  };

  let timer = null;
  let idx = 0;
  let current = msgSets.default;

  function setMsg(text) {
    status.textContent = text;
    status.classList.remove('animate');
    // Force reflow so the animation reliably restarts.
    // eslint-disable-next-line no-unused-expressions
    status.offsetHeight;
    status.classList.add('animate');
  }

  function show(mode) {
    current = msgSets[String(mode || '').trim()] || msgSets.default;
    idx = 0;
    overlay.classList.remove('hidden');
    overlay.setAttribute('aria-hidden', 'false');
    setMsg(current[0] || 'Working…');
    if (timer) window.clearInterval(timer);
    timer = window.setInterval(() => {
      idx = (idx + 1) % current.length;
      setMsg(current[idx] || 'Working…');
    }, 2200);
  }

  function hide() {
    if (timer) window.clearInterval(timer);
    timer = null;
    overlay.classList.add('hidden');
    overlay.setAttribute('aria-hidden', 'true');
  }

  window.ExposureMapperUI = window.ExposureMapperUI || {};
  window.ExposureMapperUI.showLoading = show;
  window.ExposureMapperUI.hideLoading = hide;

  document.querySelectorAll('form[data-loading]').forEach((form) => {
    form.addEventListener('submit', () => {
      const mode = form.getAttribute('data-loading') || 'default';
      show(mode);
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide && typeof window.lucide.createIcons === 'function') {
    window.lucide.createIcons();
  }
  initTooltips();
  initOpenDetailsButtons();
  initLoadingOverlay();
});
