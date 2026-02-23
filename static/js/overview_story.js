(function () {
  function safeString(v) {
    return typeof v === 'string' ? v : String(v || '');
  }

  function RiskStoryPage(vm) {
    const data = vm || {};
    return {
      mode: 'top',
      vm: data,
      drawer: {
        open: false,
        title: '',
        subtitle: '',
        items: [],
      },
      setMode(next) {
        const v = safeString(next);
        this.mode = v === 'all' ? 'all' : 'top';
      },
      openEvidence(setId, title) {
        const id = safeString(setId);
        const sets = (this.vm && this.vm.evidenceSets) ? this.vm.evidenceSets : {};
        const items = Array.isArray(sets[id]) ? sets[id] : [];
        this.drawer.open = true;
        this.drawer.title = safeString(title || 'Evidence');
        this.drawer.subtitle = items.length ? `${items.length} evidence item(s) (deduped)` : 'No evidence items available.';
        this.drawer.items = items;
      },
      closeEvidence() {
        this.drawer.open = false;
        this.drawer.title = '';
        this.drawer.subtitle = '';
        this.drawer.items = [];
      },
    };
  }

  window.RiskStoryPage = RiskStoryPage;
})();

