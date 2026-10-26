/**
 * Domain Recon Tool — Cyber Intelligence Operations Platform
 * Client Application Logic & Interactive Domain Infrastructure Map Engine
 */

(function () {
  'use strict';

  // Application State
  const state = {
    modules: [],
    currentScan: null,
    isScanning: false,
    eventSource: null,
    activeTab: 'tab-overview',
    reports: [],
    infrastructureMap: null,
  };

  // Defensive HTTP Headers explanation dictionary
  const HEADER_DESCRIPTIONS = {
    'Strict-Transport-Security': 'Enforces secure HTTPS connections and prevents SSL stripping attacks.',
    'Content-Security-Policy': 'Mitigates Cross-Site Scripting (XSS) and data injection by whitelisting trusted sources.',
    'X-Frame-Options': 'Prevents Clickjacking by restricting embedding in iframes.',
    'X-Content-Type-Options': 'Prevents MIME-type sniffing (nosniff) by modern browsers.',
    'Referrer-Policy': 'Controls sensitive referral information leaked in the Referer header.',
    'Permissions-Policy': 'Restricts browser capabilities (camera, microphone, geolocation) to authorized contexts.',
    'X-XSS-Protection': 'Legacy cross-site scripting filter protection for older browser agents.',
  };

  // DOM Elements Cache
  const el = {
    form: document.getElementById('recon-form'),
    targetInput: document.getElementById('target-input'),
    submitBtn: document.getElementById('btn-submit-scan'),
    modulesContainer: document.getElementById('modules-container'),
    moduleSettingsContainer: document.getElementById('module-settings-container'),
    btnToggleSettings: document.getElementById('btn-toggle-settings'),
    timeoutSlider: document.getElementById('timeout-slider'),
    timeoutDisplay: document.getElementById('timeout-display'),
    saveReportToggle: document.getElementById('save-report-toggle'),
    
    // Controls & Actions
    selectAllBtn: document.getElementById('btn-select-all'),
    selectNoneBtn: document.getElementById('btn-select-none'),
    selectPassiveBtn: document.getElementById('btn-select-passive'),
    openArchiveBtn: document.getElementById('btn-open-archive'),
    loadSampleBtn: document.getElementById('btn-load-sample'),
    emptyLoadSampleBtn: document.getElementById('btn-empty-load-sample'),
    headerReportsBadge: document.getElementById('header-reports-badge'),

    // Live Tracker
    liveTracker: document.getElementById('live-tracker'),
    trackerStatusText: document.getElementById('tracker-status-text'),
    trackerTargetMeta: document.getElementById('tracker-target-meta'),
    trackerCounter: document.getElementById('tracker-counter'),
    progressBar: document.getElementById('progress-bar'),
    stepsGrid: document.getElementById('steps-grid'),

    // Target Strip & KPIs
    emptyState: document.getElementById('empty-state'),
    targetSummaryStrip: document.getElementById('target-summary-strip'),
    activeDomainName: document.getElementById('active-domain-name'),
    activeScanTimestamp: document.getElementById('active-scan-timestamp'),
    activeModulesCount: document.getElementById('active-active-modules-count'),
    btnCopyTarget: document.getElementById('btn-copy-target'),
    btnDownloadJson: document.getElementById('btn-download-json'),
    btnDownloadHtml: document.getElementById('btn-download-html'),

    kpiSection: document.getElementById('kpi-section'),
    kpiHeadersScore: document.getElementById('kpi-headers-score'),
    kpiHeadersBadge: document.getElementById('kpi-headers-badge'),
    kpiSubsCount: document.getElementById('kpi-subs-count'),
    kpiPortsCount: document.getElementById('kpi-ports-count'),
    kpiPortsBadge: document.getElementById('kpi-ports-badge'),
    kpiTlsDays: document.getElementById('kpi-tls-days'),
    kpiTlsBadge: document.getElementById('kpi-tls-badge'),
    kpiEmailScore: document.getElementById('kpi-email-score'),
    kpiEmailBadge: document.getElementById('kpi-email-badge'),

    // Infrastructure Map Workspace
    mapWorkspaceSection: document.getElementById('map-workspace-section'),
    mapWorkbenchBody: document.getElementById('map-workbench-body'),
    mapCanvas: document.getElementById('infrastructure-canvas'),
    mapTooltip: document.getElementById('canvas-tooltip'),
    tooltipType: document.getElementById('tooltip-type'),
    tooltipVal: document.getElementById('tooltip-val'),
    tooltipSub: document.getElementById('tooltip-sub'),
    mapNodeCount: document.getElementById('map-node-count'),
    mapNodeSearch: document.getElementById('map-node-search'),
    btnMapZoomIn: document.getElementById('btn-map-zoom-in'),
    btnMapZoomOut: document.getElementById('btn-map-zoom-out'),
    btnMapFit: document.getElementById('btn-map-fit'),
    btnMapPhysics: document.getElementById('btn-map-physics'),
    btnMapReset: document.getElementById('btn-map-reset'),
    btnMapFullscreen: document.getElementById('btn-map-fullscreen'),
    btnMapToggleInspector: document.getElementById('btn-map-toggle-inspector'),

    // Map Inspector Panel
    mapInspectorPanel: document.getElementById('map-inspector-panel'),
    btnCloseInspector: document.getElementById('btn-close-inspector'),
    inspectorEmptyState: document.getElementById('inspector-empty-state'),
    inspectorDetails: document.getElementById('inspector-details'),
    inspectorAssetType: document.getElementById('inspector-asset-type'),
    inspectorAssetTitle: document.getElementById('inspector-asset-title'),
    inspectorAssetMeta: document.getElementById('inspector-asset-meta'),
    inspectorKvTable: document.getElementById('inspector-kv-table'),
    inspectorNeighborsList: document.getElementById('inspector-neighbors-list'),
    inspectorNeighborCount: document.getElementById('inspector-neighbor-count'),

    // Deep-dive & Tabs
    deepDiveSection: document.getElementById('deep-dive-section'),
    tabNav: document.getElementById('tab-nav'),

    // Archive Modal
    archiveModal: document.getElementById('archive-modal'),
    btnCloseArchive: document.getElementById('btn-close-archive'),
    tableArchiveReports: document.getElementById('table-archive-reports'),

    toastContainer: document.getElementById('toast-container'),
  };

  // =========================================================================
  // Initialize Application
  // =========================================================================
  async function init() {
    setupEventListeners();
    await loadModulesConfig();
    await loadReportsList();

    // Check if URL has ?target= param
    const urlParams = new URLSearchParams(window.location.search);
    const urlTarget = urlParams.get('target');
    if (urlTarget) {
      el.targetInput.value = urlTarget;
      startScan();
    }
  }

  // Fetch Available Modules from FastAPI
  async function loadModulesConfig() {
    try {
      const res = await fetch('/api/modules');
      if (!res.ok) throw new Error('Failed to load modules list');
      state.modules = await res.json();
      renderModulesGrid();
    } catch (err) {
      console.error(err);
      showToast('Could not load module configurations', 'danger');
    }
  }

  function renderModulesGrid() {
    el.modulesContainer.innerHTML = '';
    state.modules.forEach(mod => {
      const label = document.createElement('label');
      label.className = 'module-checkbox-label checked';
      label.id = `mod-card-${mod.id}`;
      label.innerHTML = `
        <input type="checkbox" name="module" value="${mod.id}" class="custom-checkbox" checked>
        <div class="module-info">
          <div class="module-name-row">
            <span class="module-title">${mod.name}</span>
            <span class="module-category">${mod.category}</span>
          </div>
          <span class="module-desc">${mod.description}</span>
        </div>
      `;

      const input = label.querySelector('input');
      input.addEventListener('change', () => {
        if (input.checked) {
          label.classList.add('checked');
        } else {
          label.classList.remove('checked');
        }
      });

      el.modulesContainer.appendChild(label);
    });
  }

  // =========================================================================
  // Event Listeners
  // =========================================================================
  function setupEventListeners() {
    // Settings toggle
    el.btnToggleSettings.addEventListener('click', () => {
      const isOpen = el.moduleSettingsContainer.classList.toggle('open');
      document.getElementById('settings-toggle-text').textContent = isOpen 
        ? 'Hide Settings' 
        : 'Configure Modules (9)';
    });

    // Timeout Slider
    el.timeoutSlider.addEventListener('input', (e) => {
      el.timeoutDisplay.textContent = `${e.target.value}s`;
    });

    // Form Submit
    el.form.addEventListener('submit', (e) => {
      e.preventDefault();
      startScan();
    });

    // Quick Target Pills
    document.querySelectorAll('.hint-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        el.targetInput.value = pill.dataset.domain;
        el.targetInput.focus();
      });
    });

    // Module Selection Helpers
    el.selectAllBtn.addEventListener('click', () => setAllModulesChecked(true));
    el.selectNoneBtn.addEventListener('click', () => setAllModulesChecked(false));
    el.selectPassiveBtn.addEventListener('click', () => {
      const passiveModules = ['dns', 'whois', 'crtsh', 'headers', 'tls', 'email', 'tech', 'wayback'];
      document.querySelectorAll('#modules-container input[name="module"]').forEach(input => {
        const check = passiveModules.includes(input.value);
        input.checked = check;
        const parent = input.closest('.module-checkbox-label');
        if (check) parent.classList.add('checked');
        else parent.classList.remove('checked');
      });
    });

    // Tab Navigation
    el.tabNav.addEventListener('click', (e) => {
      const btn = e.target.closest('.tab-btn');
      if (!btn) return;
      switchTab(btn.dataset.tab);
    });

    // Search filters in tabs
    setupFilter('filter-dns', 'table-dns');
    setupFilter('filter-subdomains', 'subdomains-container', '.subdomain-chip');
    setupFilter('filter-wayback', 'table-wayback');

    // Copy Domain
    el.btnCopyTarget.addEventListener('click', () => {
      if (state.currentScan?.target) {
        navigator.clipboard.writeText(state.currentScan.target);
        showToast(`Copied ${state.currentScan.target} to clipboard`, 'safe');
      }
    });

    // Export buttons
    el.btnDownloadJson.addEventListener('click', () => {
      if (!state.currentScan) return;
      const jsonStr = JSON.stringify(state.currentScan, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      downloadBlob(blob, `${state.currentScan.target.replace(/\./g, '_')}_recon.json`);
    });

    el.btnDownloadHtml.addEventListener('click', () => {
      if (!state.currentScan) return;
      const savedHtml = state.currentScan.saved_reports?.html;
      if (savedHtml) {
        window.open(`/api/reports/${savedHtml}`, '_blank');
      } else {
        window.print();
      }
    });

    // Subdomains Export & Copy
    const copySubsBtn = document.getElementById('btn-copy-all-subs');
    if (copySubsBtn) {
      copySubsBtn.addEventListener('click', () => {
        const subs = state.currentScan?.modules?.crtsh?.subdomains || [];
        if (subs.length === 0) {
          showToast('No subdomains to copy', 'warn');
          return;
        }
        navigator.clipboard.writeText(subs.join('\n'));
        showToast(`Copied ${subs.length} subdomains to clipboard`, 'safe');
      });
    }

    const exportSubsBtn = document.getElementById('btn-export-subs-txt');
    if (exportSubsBtn) {
      exportSubsBtn.addEventListener('click', () => {
        const subs = state.currentScan?.modules?.crtsh?.subdomains || [];
        if (subs.length === 0) {
          showToast('No subdomains to export', 'warn');
          return;
        }
        const blob = new Blob([subs.join('\n')], { type: 'text/plain' });
        downloadBlob(blob, `${state.currentScan.target}_subdomains.txt`);
      });
    }

    // Modal controls
    el.openArchiveBtn.addEventListener('click', () => openArchiveModal());
    el.btnCloseArchive.addEventListener('click', () => closeArchiveModal());
    el.archiveModal.addEventListener('click', (e) => {
      if (e.target === el.archiveModal) closeArchiveModal();
    });

    // Sample Loaders
    el.loadSampleBtn.addEventListener('click', () => loadSampleReport());
    el.emptyLoadSampleBtn.addEventListener('click', () => loadSampleReport());

    // Map Inspector controls
    el.btnCloseInspector.addEventListener('click', () => {
      if (state.infrastructureMap) {
        state.infrastructureMap.selectNode(null);
      }
    });

    el.btnMapToggleInspector.addEventListener('click', () => {
      el.mapWorkbenchBody.classList.toggle('inspector-collapsed');
      el.btnMapToggleInspector.classList.toggle('active');
    });

    // Map Fullscreen Toggle
    el.btnMapFullscreen.addEventListener('click', () => {
      const isFull = el.mapWorkspaceSection.classList.toggle('fullscreen-active');
      el.btnMapFullscreen.classList.toggle('active', isFull);
      if (state.infrastructureMap) {
        state.infrastructureMap.handleResize();
      }
    });
  }

  function setAllModulesChecked(checked) {
    document.querySelectorAll('#modules-container input[name="module"]').forEach(input => {
      input.checked = checked;
      const parent = input.closest('.module-checkbox-label');
      if (checked) parent.classList.add('checked');
      else parent.classList.remove('checked');
    });
  }

  function switchTab(tabId) {
    state.activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(btn => {
      if (btn.dataset.tab === tabId) btn.classList.add('active');
      else btn.classList.remove('active');
    });
    document.querySelectorAll('.tab-content-panel').forEach(panel => {
      if (panel.id === tabId) panel.classList.add('active');
      else panel.classList.remove('active');
    });
  }

  function setupFilter(inputId, targetId, itemSelector) {
    const input = document.getElementById(inputId);
    if (!input) return;
    input.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      if (itemSelector) {
        document.querySelectorAll(`#${targetId} ${itemSelector}`).forEach(elem => {
          const text = elem.textContent.toLowerCase();
          elem.style.display = text.includes(q) ? '' : 'none';
        });
      } else {
        const rows = document.querySelectorAll(`#${targetId} tbody tr`);
        rows.forEach(row => {
          const text = row.textContent.toLowerCase();
          row.style.display = text.includes(q) ? '' : 'none';
        });
      }
    });
  }

  function sanitizeDomain(raw) {
    let d = raw.trim().toLowerCase();
    d = d.replace(/^https?:\/\//, '');
    d = d.split('/')[0].split('?')[0].split(':')[0];
    return d;
  }

  // =========================================================================
  // Scan Execution (SSE Stream)
  // =========================================================================
  function startScan() {
    const rawTarget = el.targetInput.value;
    const target = sanitizeDomain(rawTarget);
    if (!target || !target.includes('.')) {
      showToast('Please enter a valid domain name (e.g. example.com)', 'warn');
      return;
    }

    const selectedModules = Array.from(
      document.querySelectorAll('#modules-container input[name="module"]:checked')
    ).map(i => i.value);

    if (selectedModules.length === 0) {
      showToast('Select at least one reconnaissance module to execute', 'warn');
      return;
    }

    const timeout = parseInt(el.timeoutSlider.value, 10) || 15;
    const saveReport = el.saveReportToggle.checked;

    // Reset UI for Live Scan
    state.isScanning = true;
    el.submitBtn.disabled = true;
    el.liveTracker.classList.add('active');
    el.progressBar.style.width = '0%';
    el.trackerTargetMeta.textContent = `Target: ${target}`;
    el.trackerStatusText.textContent = 'Initializing multi-threaded reconnaissance engines...';
    el.trackerCounter.textContent = `0 / ${selectedModules.length} Modules`;

    renderStepsGrid(selectedModules);

    if (state.eventSource) {
      state.eventSource.close();
    }

    const streamUrl = `/api/scan/stream?target=${encodeURIComponent(target)}&modules=${encodeURIComponent(selectedModules.join(','))}&timeout=${timeout}&save_report=${saveReport}`;
    const es = new EventSource(streamUrl);
    state.eventSource = es;

    const accumulatedResults = {
      target: target,
      timestamp: new Date().toISOString(),
      modules: {}
    };

    es.addEventListener('start', (e) => {
      const data = JSON.parse(e.data);
      el.trackerStatusText.textContent = `Running 9-vector reconnaissance against ${data.target}...`;
    });

    es.addEventListener('module_done', (e) => {
      const item = JSON.parse(e.data);
      accumulatedResults.modules[item.module] = item.data;
      updateStepCard(item.module, item.status, item.summary);
      
      el.progressBar.style.width = `${item.progress}%`;
      el.trackerCounter.textContent = `${item.completed_count} / ${item.total} Modules`;
      el.trackerStatusText.textContent = `Completed ${item.module.toUpperCase()}: ${item.summary}`;
    });

    es.addEventListener('complete', (e) => {
      const finalData = JSON.parse(e.data);
      es.close();
      state.eventSource = null;
      state.isScanning = false;
      el.submitBtn.disabled = false;

      el.progressBar.style.width = '100%';
      el.trackerStatusText.textContent = `Reconnaissance complete. Intelligence synthesized for ${target}.`;
      showToast(`Intelligence report generated for ${target}`, 'safe');

      state.currentScan = {
        target: finalData.target,
        timestamp: finalData.timestamp,
        modules: finalData.results.modules,
        saved_reports: finalData.saved_reports
      };

      renderScanResults(state.currentScan);
      loadReportsList();
    });

    es.addEventListener('error', () => {
      if (state.isScanning) {
        es.close();
        state.eventSource = null;
        state.isScanning = false;
        el.submitBtn.disabled = false;
        el.trackerStatusText.textContent = 'Reconnaissance connection closed or interrupted.';
        showToast('Stream finished or interrupted. Displaying collected intelligence.', 'warn');
        
        if (Object.keys(accumulatedResults.modules).length > 0) {
          state.currentScan = accumulatedResults;
          renderScanResults(accumulatedResults);
        }
      }
    });
  }

  function renderStepsGrid(moduleKeys) {
    el.stepsGrid.innerHTML = '';
    moduleKeys.forEach(key => {
      const modObj = state.modules.find(m => m.id === key) || { name: key };
      const card = document.createElement('div');
      card.className = 'step-card running';
      card.id = `step-card-${key}`;
      card.innerHTML = `
        <span class="step-name">${modObj.name}</span>
        <span class="step-indicator" id="step-indicator-${key}">Running…</span>
      `;
      el.stepsGrid.appendChild(card);
    });
  }

  function updateStepCard(moduleKey, status, summary) {
    const card = document.getElementById(`step-card-${moduleKey}`);
    const indicator = document.getElementById(`step-indicator-${moduleKey}`);
    if (!card || !indicator) return;

    card.classList.remove('running');
    if (status === 'ok') {
      card.classList.add('ok');
      indicator.innerHTML = `<span style="color: var(--status-safe);">✓ ${escapeHtml(summary)}</span>`;
    } else {
      card.classList.add('error');
      indicator.innerHTML = `<span style="color: var(--status-danger);">✗ Error</span>`;
    }
  }

  // =========================================================================
  // Render Scan Results & Build Infrastructure Graph
  // =========================================================================
  function renderScanResults(scan) {
    if (!scan || !scan.target) return;

    el.emptyState.style.display = 'none';
    el.targetSummaryStrip.style.display = 'flex';
    el.kpiSection.style.display = 'grid';
    el.mapWorkspaceSection.style.display = 'block';
    el.deepDiveSection.style.display = 'block';

    // Target Strip
    el.activeDomainName.textContent = scan.target;
    const formattedDate = scan.timestamp ? new Date(scan.timestamp).toUTCString() : 'N/A';
    el.activeScanTimestamp.textContent = formattedDate;
    
    const mods = scan.modules || {};
    const modCount = Object.keys(mods).length;
    el.activeModulesCount.textContent = `${modCount} modules evaluated`;

    // 5 Executive KPIs
    renderExecutiveKPIs(mods);

    // Render Deep-Dive Tabs
    renderOverviewTab(scan);
    renderDnsTab(mods.dns);
    renderWhoisTab(mods.whois);
    renderSubdomainsTab(mods.crtsh);
    renderHeadersTab(mods.headers);
    renderPortsTab(mods.ports);
    renderTlsTab(mods.tls);
    renderEmailTab(mods.email);
    renderTechTab(mods.tech);
    renderWaybackTab(mods.wayback);

    // Build and Launch Interactive Infrastructure Map
    initOrUpdateInfrastructureMap(scan);

    // Scroll smoothly to target dashboard strip
    el.targetSummaryStrip.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Executive KPI Calculation
  function renderExecutiveKPIs(mods) {
    // 1. Headers Score
    const headersData = mods.headers?.https || mods.headers?.http || {};
    const hScore = typeof headersData.security_score === 'number' ? headersData.security_score : null;
    if (hScore !== null) {
      el.kpiHeadersScore.textContent = `${hScore}%`;
      el.kpiHeadersBadge.textContent = hScore >= 70 ? 'Defensive' : hScore >= 40 ? 'Moderate' : 'Low Posture';
      el.kpiHeadersBadge.className = `badge ${hScore >= 70 ? 'badge-safe' : hScore >= 40 ? 'badge-warn' : 'badge-danger'}`;
    } else {
      el.kpiHeadersScore.textContent = '—';
      el.kpiHeadersBadge.textContent = 'N/A';
      el.kpiHeadersBadge.className = 'badge badge-muted';
    }

    // 2. Subdomains Count
    const subs = mods.crtsh?.subdomains || [];
    el.kpiSubsCount.textContent = subs.length;
    document.getElementById('count-subs').textContent = subs.length;

    // 3. Open Ports & Risky
    const ports = mods.ports?.open_ports || [];
    const risky = mods.ports?.risky || [];
    el.kpiPortsCount.textContent = ports.length;
    document.getElementById('count-ports').textContent = ports.length;
    if (risky.length > 0) {
      el.kpiPortsBadge.textContent = `${risky.length} Risky Exposed`;
      el.kpiPortsBadge.className = 'badge badge-danger';
    } else {
      el.kpiPortsBadge.textContent = ports.length > 0 ? 'Standard Services' : 'No Open Ports';
      el.kpiPortsBadge.className = ports.length > 0 ? 'badge badge-safe' : 'badge badge-muted';
    }

    // 4. TLS Certificate Days
    const tlsCert = mods.tls?.cert || {};
    const daysLeft = tlsCert.days_left;
    if (typeof daysLeft === 'number') {
      el.kpiTlsDays.textContent = `${daysLeft}d`;
      el.kpiTlsBadge.textContent = daysLeft > 30 ? 'Valid' : daysLeft >= 0 ? 'Expiring Soon' : 'Expired';
      el.kpiTlsBadge.className = `badge ${daysLeft > 30 ? 'badge-safe' : daysLeft >= 0 ? 'badge-warn' : 'badge-danger'}`;
    } else {
      el.kpiTlsDays.textContent = '—';
      el.kpiTlsBadge.textContent = mods.tls?.negotiated_version || 'N/A';
      el.kpiTlsBadge.className = 'badge badge-muted';
    }

    // 5. Email Posture
    const emailData = mods.email || {};
    const emailScore = typeof emailData.score === 'number' ? emailData.score : null;
    if (emailScore !== null) {
      el.kpiEmailScore.textContent = `${emailScore}%`;
      el.kpiEmailBadge.textContent = emailScore >= 70 ? 'Protected' : emailScore >= 40 ? 'Partial' : 'Vulnerable';
      el.kpiEmailBadge.className = `badge ${emailScore >= 70 ? 'badge-safe' : emailScore >= 40 ? 'badge-warn' : 'badge-danger'}`;
    } else {
      el.kpiEmailScore.textContent = '—';
      el.kpiEmailBadge.textContent = 'N/A';
      el.kpiEmailBadge.className = 'badge badge-muted';
    }
  }

  // =========================================================================
  // THE KEY FEATURE: Interactive Domain Infrastructure Map Engine
  // =========================================================================

  function buildGraphDataFromScan(scan) {
    const target = scan.target;
    const mods = scan.modules || {};
    
    const nodes = [];
    const edges = [];
    const nodeMap = new Map();

    function addNode(id, label, type, meta = {}) {
      if (nodeMap.has(id)) return nodeMap.get(id);
      const node = {
        id,
        label,
        type, // 'domain', 'subdomain', 'ip', 'mx', 'ns', 'port', 'tech'
        meta,
        x: (Math.random() - 0.5) * 400,
        y: (Math.random() - 0.5) * 400,
        vx: 0,
        vy: 0,
        radius: type === 'domain' ? 24 : type === 'ip' ? 16 : type === 'subdomain' ? 12 : 10,
      };
      nodes.push(node);
      nodeMap.set(id, node);
      return node;
    }

    function addEdge(sourceId, targetId, rel, label = '') {
      if (!nodeMap.has(sourceId) || !nodeMap.has(targetId)) return;
      if (sourceId === targetId) return;
      const edgeKey = `${sourceId}->${targetId}:${rel}`;
      edges.push({
        source: nodeMap.get(sourceId),
        target: nodeMap.get(targetId),
        rel,
        label: label || rel
      });
    }

    // 1. Root Target Node
    const rootNode = addNode(target, target, 'domain', {
      title: 'Target Apex Domain',
      timestamp: scan.timestamp,
    });
    rootNode.x = 0;
    rootNode.y = 0;

    // 2. IP Addresses (from dns.A, dns.AAAA, ports.ip, crtsh.subdomain_ips)
    const ipList = new Set();
    if (mods.dns?.A) mods.dns.A.forEach(ip => ipList.add(ip));
    if (mods.dns?.AAAA) mods.dns.AAAA.forEach(ip => ipList.add(ip));
    if (mods.ports?.ip) ipList.add(mods.ports.ip);
    if (mods.crtsh?.subdomain_ips) {
      Object.values(mods.crtsh.subdomain_ips).forEach(ip => ipList.add(ip));
    }

    // Lookup table for IP intelligence
    const ipIntelMap = new Map();
    (mods.dns?.ip_intelligence || []).forEach(intel => ipIntelMap.set(intel.ip, intel));
    if (mods.ports?.ip && mods.ports?.ip_info) {
      const existing = ipIntelMap.get(mods.ports.ip) || {};
      ipIntelMap.set(mods.ports.ip, { ...existing, ...mods.ports.ip_info, ip: mods.ports.ip });
    }

    ipList.forEach(ip => {
      const intel = ipIntelMap.get(ip) || {};
      const ipNode = addNode(`ip:${ip}`, ip, 'ip', {
        title: 'Resolved IP Address',
        ip: ip,
        asn: intel.asn || 'ASN Lookup Available',
        isp: intel.isp || intel.org || 'Hosting Provider',
        location: [intel.city, intel.country].filter(Boolean).join(', ') || 'Global',
        ptr: intel.ptr || null,
        ports: (mods.ports?.open_ports || []).map(p => `${p.port}/${p.service}`).join(', ') || 'No open ports detected'
      });
      addEdge(target, `ip:${ip}`, 'RESOLVES_TO');
    });

    // 3. Open Ports & Services (linked to primary IP node)
    const primaryIpId = mods.ports?.ip ? `ip:${mods.ports.ip}` : (ipList.size > 0 ? `ip:${Array.from(ipList)[0]}` : target);
    if (mods.ports?.open_ports && Array.isArray(mods.ports.open_ports)) {
      mods.ports.open_ports.forEach(p => {
        const portId = `port:${p.port}`;
        addNode(portId, `${p.port}/${p.service}`, 'port', {
          title: `Port ${p.port} (${p.service})`,
          state: p.state || 'open',
          service: p.service,
          risk: !!p.risk,
          hostIp: mods.ports.ip || target
        });
        addEdge(primaryIpId, portId, 'EXPOSES_PORT');
      });
    }

    // 4. Subdomains (from crtsh, wayback, TLS SANs)
    const subdomains = new Set();
    if (mods.crtsh?.subdomains) {
      mods.crtsh.subdomains.forEach(s => {
        if (s && s !== target && !s.startsWith('*.')) subdomains.add(s);
      });
    }
    if (mods.tls?.cert?.sans) {
      mods.tls.cert.sans.forEach(s => {
        if (s && s !== target && !s.startsWith('*.')) subdomains.add(s);
      });
    }
    if (mods.wayback?.subdomains) {
      mods.wayback.subdomains.forEach(s => {
        if (s && s !== target) subdomains.add(s);
      });
    }

    // Limit to reasonable count to avoid graph explosion while preserving diversity
    const subList = Array.from(subdomains).slice(0, 48);
    const subIpMap = mods.crtsh?.subdomain_ips || {};

    subList.forEach(sub => {
      const mappedIp = subIpMap[sub];
      addNode(`sub:${sub}`, sub, 'subdomain', {
        title: 'Discovered Subdomain',
        parent: target,
        mappedIp: mappedIp || null,
        source: 'Certificate Transparency / SANs'
      });
      addEdge(target, `sub:${sub}`, 'SUBDOMAIN');

      // If this subdomain resolved to an IP, link them on the graph!
      if (mappedIp) {
        addEdge(`sub:${sub}`, `ip:${mappedIp}`, 'HOSTED_ON');
      }
    });

    // 5. Mail Infrastructure (MX records)
    if (mods.dns?.MX && Array.isArray(mods.dns.MX)) {
      mods.dns.MX.forEach(mx => {
        const mxName = mx.replace(/^\d+\s+/, '').replace(/\.$/, '');
        addNode(`mx:${mxName}`, mxName, 'mx', {
          title: 'Mail Exchanger (MX)',
          rawRecord: mx,
          spfEnforced: mods.email?.spf?.present ? 'Enforced' : 'Missing',
          dmarcEnforced: mods.email?.dmarc?.present ? 'Enforced' : 'Missing'
        });
        addEdge(target, `mx:${mxName}`, 'MAIL_SERVER');
      });
    }

    // 6. Nameservers (NS records + WHOIS)
    const nsList = new Set();
    if (mods.dns?.NS && Array.isArray(mods.dns.NS)) {
      mods.dns.NS.forEach(ns => nsList.add(ns.replace(/\.$/, '')));
    }
    if (mods.whois?.name_servers && Array.isArray(mods.whois.name_servers)) {
      mods.whois.name_servers.forEach(ns => nsList.add(ns.toLowerCase().replace(/\.$/, '')));
    }

    nsList.forEach(ns => {
      addNode(`ns:${ns}`, ns, 'ns', {
        title: 'Authoritative Nameserver',
        zone: target
      });
      addEdge(target, `ns:${ns}`, 'NAMESERVER');
    });

    // 7. Technology Stack (from tech.technologies)
    if (mods.tech?.technologies) {
      Object.entries(mods.tech.technologies).forEach(([techName, techInfo]) => {
        addNode(`tech:${techName}`, techName, 'tech', {
          title: 'Technology Fingerprint',
          category: techInfo.category || 'Platform',
          evidence: techInfo.evidence || 'Header / HTML signature'
        });
        addEdge(target, `tech:${techName}`, 'USES_TECH');
      });
    }

    return { nodes, edges, target };
  }

  class InfrastructureMapRenderer {
    constructor(canvas, container) {
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.container = container;

      this.nodes = [];
      this.edges = [];
      this.nodeMap = new Map();
      this.targetDomain = '';

      // Camera Viewport Matrix
      this.camera = { x: 0, y: 0, zoom: 1 };
      this.isDragging = false;
      this.dragNode = null;
      this.dragStart = { x: 0, y: 0 };
      this.hoverNode = null;
      this.selectedNode = null;

      // Physics State
      this.physicsEnabled = true;
      this.activeFilter = 'all';
      this.animFrameId = null;

      // Ambient Particle Backdrop (Cyber Spatial Depth)
      this.particles = [];
      this.initParticles();

      this.setupControls();
      this.handleResize();
      window.addEventListener('resize', () => this.handleResize());
    }

    initParticles() {
      this.particles = [];
      for (let i = 0; i < 65; i++) {
        this.particles.push({
          x: (Math.random() - 0.5) * 1600,
          y: (Math.random() - 0.5) * 1200,
          size: Math.random() * 1.5 + 0.5,
          alpha: Math.random() * 0.35 + 0.1,
          vx: (Math.random() - 0.5) * 0.15,
          vy: (Math.random() - 0.5) * 0.15,
        });
      }
    }

    setData(graphData) {
      this.nodes = graphData.nodes;
      this.edges = graphData.edges;
      this.targetDomain = graphData.target;
      this.nodeMap = new Map(this.nodes.map(n => [n.id, n]));

      // Arrange nodes initially around center
      this.nodes.forEach((n, idx) => {
        if (n.type === 'domain') {
          n.x = 0;
          n.y = 0;
        } else {
          const angle = (idx / (this.nodes.length || 1)) * Math.PI * 2;
          const dist = n.type === 'subdomain' ? 220 + (idx % 3) * 40 :
                       n.type === 'ip' ? 140 :
                       n.type === 'port' ? 240 : 180;
          n.x = Math.cos(angle) * dist + (Math.random() - 0.5) * 40;
          n.y = Math.sin(angle) * dist + (Math.random() - 0.5) * 40;
        }
        n.vx = 0;
        n.vy = 0;
      });

      this.updateNodeCounter();
      this.fitView();
      this.startLoop();
    }

    handleResize() {
      const rect = this.canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.width = rect.width;
      this.height = rect.height;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = rect.height * dpr;
      this.ctx.resetTransform();
      this.ctx.scale(dpr, dpr);
    }

    setupControls() {
      // Mouse & Touch events
      this.canvas.addEventListener('mousedown', (e) => this.onMouseDown(e));
      this.canvas.addEventListener('mousemove', (e) => this.onMouseMove(e));
      window.addEventListener('mouseup', () => this.onMouseUp());
      this.canvas.addEventListener('wheel', (e) => this.onWheel(e), { passive: false });

      // HUD Button Listeners
      el.btnMapZoomIn.addEventListener('click', () => this.zoom(1.25));
      el.btnMapZoomOut.addEventListener('click', () => this.zoom(0.8));
      el.btnMapFit.addEventListener('click', () => this.fitView());
      el.btnMapPhysics.addEventListener('click', () => {
        this.physicsEnabled = !this.physicsEnabled;
        el.btnMapPhysics.classList.toggle('active', this.physicsEnabled);
      });
      el.btnMapReset.addEventListener('click', () => {
        this.nodes.forEach((n, i) => {
          if (n.type !== 'domain') {
            const angle = (i / this.nodes.length) * Math.PI * 2;
            n.x = Math.cos(angle) * 180;
            n.y = Math.sin(angle) * 180;
            n.vx = 0;
            n.vy = 0;
          }
        });
        this.fitView();
      });

      // Filter Buttons
      document.querySelectorAll('.map-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('.map-filter-btn').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          this.activeFilter = btn.dataset.filter;
          this.updateNodeCounter();
        });
      });

      // Search Box
      el.mapNodeSearch.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        if (!query) return;
        const match = this.nodes.find(n => n.label.toLowerCase().includes(query));
        if (match) {
          this.selectNode(match);
          this.centerOn(match.x, match.y);
        }
      });
    }

    updateNodeCounter() {
      const visibleCount = this.getVisibleNodes().length;
      el.mapNodeCount.textContent = `${visibleCount} / ${this.nodes.length} nodes`;
    }

    getVisibleNodes() {
      if (this.activeFilter === 'all') return this.nodes;
      return this.nodes.filter(n => n.type === 'domain' || n.type === this.activeFilter);
    }

    screenToWorld(sx, sy) {
      const cx = this.width / 2;
      const cy = this.height / 2;
      return {
        x: (sx - cx - this.camera.x) / this.camera.zoom,
        y: (sy - cy - this.camera.y) / this.camera.zoom,
      };
    }

    onMouseDown(e) {
      const rect = this.canvas.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      const world = this.screenToWorld(sx, sy);

      // Check if clicking a node
      const hit = this.findNodeAt(world.x, world.y);
      if (hit) {
        this.dragNode = hit;
        this.selectNode(hit);
      } else {
        this.isDragging = true;
        this.dragStart = { x: sx - this.camera.x, y: sy - this.camera.y };
      }
    }

    onMouseMove(e) {
      const rect = this.canvas.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      const world = this.screenToWorld(sx, sy);

      if (this.dragNode) {
        this.dragNode.x = world.x;
        this.dragNode.y = world.y;
        this.dragNode.vx = 0;
        this.dragNode.vy = 0;
        return;
      }

      if (this.isDragging) {
        this.camera.x = sx - this.dragStart.x;
        this.camera.y = sy - this.dragStart.y;
        return;
      }

      // Hover check
      const hit = this.findNodeAt(world.x, world.y);
      if (hit !== this.hoverNode) {
        this.hoverNode = hit;
        this.canvas.style.cursor = hit ? 'pointer' : 'grab';
        this.updateTooltip(hit, sx, sy);
      } else if (hit) {
        this.updateTooltip(hit, sx, sy);
      }
    }

    onMouseUp() {
      this.dragNode = null;
      this.isDragging = false;
    }

    onWheel(e) {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.12 : 0.89;
      this.zoom(factor);
    }

    zoom(factor) {
      const newZoom = Math.min(Math.max(this.camera.zoom * factor, 0.25), 3.5);
      this.camera.zoom = newZoom;
    }

    centerOn(wx, wy) {
      this.camera.x = -wx * this.camera.zoom;
      this.camera.y = -wy * this.camera.zoom;
    }

    fitView() {
      const visible = this.getVisibleNodes();
      if (visible.length === 0) return;

      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
      visible.forEach(n => {
        if (n.x < minX) minX = n.x;
        if (n.x > maxX) maxX = n.x;
        if (n.y < minY) minY = n.y;
        if (n.y > maxY) maxY = n.y;
      });

      const spanX = Math.max(maxX - minX + 160, 300);
      const spanY = Math.max(maxY - minY + 160, 300);

      const zoomX = (this.width - 60) / spanX;
      const zoomY = (this.height - 60) / spanY;
      this.camera.zoom = Math.min(Math.max(Math.min(zoomX, zoomY), 0.4), 1.6);

      const midX = (minX + maxX) / 2;
      const midY = (minY + maxY) / 2;
      this.centerOn(midX, midY);
    }

    findNodeAt(wx, wy) {
      const visible = this.getVisibleNodes();
      for (let i = visible.length - 1; i >= 0; i--) {
        const n = visible[i];
        const dx = n.x - wx;
        const dy = n.y - wy;
        const hitRadius = Math.max(n.radius, 14);
        if (dx * dx + dy * dy <= hitRadius * hitRadius) {
          return n;
        }
      }
      return null;
    }

    updateTooltip(node, sx, sy) {
      if (!node) {
        el.mapTooltip.style.display = 'none';
        return;
      }
      el.tooltipType.textContent = node.type.toUpperCase();
      el.tooltipType.style.color = this.getNodeColor(node);
      el.tooltipVal.textContent = node.label;
      el.tooltipSub.textContent = node.meta.title || 'Click to inspect infrastructure connections';

      const left = Math.min(sx + 14, this.width - 240);
      const top = Math.min(sy + 14, this.height - 90);
      el.mapTooltip.style.left = `${left}px`;
      el.mapTooltip.style.top = `${top}px`;
      el.mapTooltip.style.display = 'block';
    }

    selectNode(node) {
      this.selectedNode = node;
      renderNodeInspector(node, this.edges);
    }

    getNodeColor(node) {
      switch (node.type) {
        case 'domain': return '#69B8AD';
        case 'subdomain': return '#82A0B8';
        case 'ip': return '#68B684';
        case 'mx': return '#D99B43';
        case 'ns': return '#9B8EC4';
        case 'port': return node.meta?.risk ? '#D9534F' : '#6B8EC4';
        case 'tech': return '#85B59B';
        default: return '#98A6B5';
      }
    }

    // Force simulation step
    stepPhysics() {
      if (!this.physicsEnabled) return;

      const visible = this.getVisibleNodes();
      const kRepel = 2400;
      const kSpring = 0.035;
      const damp = 0.84;
      const centerGravity = 0.008;

      // 1. Node Repulsion
      for (let i = 0; i < visible.length; i++) {
        const n1 = visible[i];
        for (let j = i + 1; j < visible.length; j++) {
          const n2 = visible[j];
          const dx = n2.x - n1.x;
          const dy = n2.y - n1.y;
          const distSq = dx * dx + dy * dy + 100;
          const dist = Math.sqrt(distSq);
          const force = kRepel / distSq;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          if (n1 !== this.dragNode && n1.type !== 'domain') {
            n1.vx -= fx;
            n1.vy -= fy;
          }
          if (n2 !== this.dragNode && n2.type !== 'domain') {
            n2.vx += fx;
            n2.vy += fy;
          }
        }
      }

      // 2. Spring Attraction along visible edges
      const visibleSet = new Set(visible);
      this.edges.forEach(e => {
        if (!visibleSet.has(e.source) || !visibleSet.has(e.target)) return;
        const dx = e.target.x - e.source.x;
        const dy = e.target.y - e.source.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const idealDist = e.target.type === 'port' ? 80 : 150;
        const springForce = (dist - idealDist) * kSpring;
        const fx = (dx / dist) * springForce;
        const fy = (dy / dist) * springForce;

        if (e.source !== this.dragNode && e.source.type !== 'domain') {
          e.source.vx += fx;
          e.source.vy += fy;
        }
        if (e.target !== this.dragNode && e.target.type !== 'domain') {
          e.target.vx -= fx;
          e.target.vy -= fy;
        }
      });

      // 3. Central Gravity & Integration
      visible.forEach(n => {
        if (n === this.dragNode || n.type === 'domain') return;

        n.vx -= n.x * centerGravity;
        n.vy -= n.y * centerGravity;

        n.vx *= damp;
        n.vy *= damp;

        n.x += n.vx;
        n.y += n.vy;
      });

      // Ambient drift for background particles
      this.particles.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < -800) p.x = 800;
        if (p.x > 800) p.x = -800;
        if (p.y < -600) p.y = 600;
        if (p.y > 600) p.y = -600;
      });
    }

    startLoop() {
      if (this.animFrameId) cancelAnimationFrame(this.animFrameId);
      const loop = () => {
        this.stepPhysics();
        this.render();
        this.animFrameId = requestAnimationFrame(loop);
      };
      loop();
    }

    render() {
      const ctx = this.ctx;
      const w = this.width;
      const h = this.height;

      // Clear Canvas
      ctx.fillStyle = '#0D1218';
      ctx.fillRect(0, 0, w, h);

      // Coordinate Matrix Transform
      ctx.save();
      ctx.translate(w / 2 + this.camera.x, h / 2 + this.camera.y);
      ctx.scale(this.camera.zoom, this.camera.zoom);

      // 1. Draw Cyber Ambient Grid & Stars
      this.drawSpatialGrid(ctx);

      // 2. Identify Selected Neighbors
      const incidentEdges = new Set();
      const neighborNodes = new Set();
      if (this.selectedNode) {
        neighborNodes.add(this.selectedNode);
        this.edges.forEach(e => {
          if (e.source === this.selectedNode || e.target === this.selectedNode) {
            incidentEdges.add(e);
            neighborNodes.add(e.source);
            neighborNodes.add(e.target);
          }
        });
      }

      const visible = this.getVisibleNodes();
      const visibleSet = new Set(visible);

      // 3. Draw Edges
      this.edges.forEach(e => {
        if (!visibleSet.has(e.source) || !visibleSet.has(e.target)) return;

        const isHighlight = incidentEdges.has(e);
        const isDim = this.selectedNode && !isHighlight;

        ctx.beginPath();
        ctx.moveTo(e.source.x, e.source.y);
        ctx.lineTo(e.target.x, e.target.y);

        if (isHighlight) {
          ctx.strokeStyle = '#69B8AD';
          ctx.lineWidth = 2;
        } else if (isDim) {
          ctx.strokeStyle = 'rgba(42, 53, 65, 0.25)';
          ctx.lineWidth = 1;
        } else {
          ctx.strokeStyle = '#222D39';
          ctx.lineWidth = 1.2;
        }
        ctx.stroke();

        // Edge Direction Arrow
        this.drawEdgeArrow(ctx, e.source, e.target, isHighlight ? '#69B8AD' : '#2A3541');
      });

      // 4. Draw Nodes
      visible.forEach(n => {
        const isSelected = n === this.selectedNode;
        const isHovered = n === this.hoverNode;
        const isNeighbor = this.selectedNode && neighborNodes.has(n);
        const isDim = this.selectedNode && !isNeighbor;

        ctx.save();
        ctx.translate(n.x, n.y);

        if (isDim) {
          ctx.globalAlpha = 0.22;
        }

        this.drawNodeGeometry(ctx, n, isSelected, isHovered);

        ctx.restore();
      });

      ctx.restore();
    }

    drawSpatialGrid(ctx) {
      // Background Particle Dust
      ctx.fillStyle = '#69B8AD';
      this.particles.forEach(p => {
        ctx.globalAlpha = p.alpha;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
      });
      ctx.globalAlpha = 1;

      // Fine coordinate grid lines
      ctx.strokeStyle = 'rgba(42, 53, 65, 0.22)';
      ctx.lineWidth = 0.75;
      const gridSize = 120;
      const range = 1200;

      ctx.beginPath();
      for (let x = -range; x <= range; x += gridSize) {
        ctx.moveTo(x, -range);
        ctx.lineTo(x, range);
      }
      for (let y = -range; y <= range; y += gridSize) {
        ctx.moveTo(-range, y);
        ctx.lineTo(range, y);
      }
      ctx.stroke();

      // Subtle center axis
      ctx.strokeStyle = 'rgba(105, 184, 173, 0.12)';
      ctx.beginPath();
      ctx.moveTo(-range, 0); ctx.lineTo(range, 0);
      ctx.moveTo(0, -range); ctx.lineTo(0, range);
      ctx.stroke();
    }

    drawEdgeArrow(ctx, src, dst, color) {
      const dx = dst.x - src.x;
      const dy = dst.y - src.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 40) return;

      const angle = Math.atan2(dy, dx);
      const arrowDist = dist - dst.radius - 4;
      const ax = src.x + Math.cos(angle) * arrowDist;
      const ay = src.y + Math.sin(angle) * arrowDist;

      ctx.save();
      ctx.translate(ax, ay);
      ctx.rotate(angle);
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(-6, -3);
      ctx.lineTo(-6, 3);
      ctx.closePath();
      ctx.fill();
      ctx.restore();
    }

    drawNodeGeometry(ctx, node, isSelected, isHovered) {
      const color = this.getNodeColor(node);

      // Glow halo for root domain or selected node
      if (node.type === 'domain' || isSelected) {
        ctx.beginPath();
        ctx.arc(0, 0, node.radius + 8, 0, Math.PI * 2);
        ctx.fillStyle = node.type === 'domain' ? 'rgba(105, 184, 173, 0.16)' : 'rgba(255, 255, 255, 0.12)';
        ctx.fill();
      }

      // Risky port pulsing ring
      if (node.meta?.risk) {
        ctx.beginPath();
        ctx.arc(0, 0, node.radius + 5, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(217, 83, 79, 0.5)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // Node Body
      ctx.beginPath();
      if (node.type === 'domain') {
        // Root Target Diamond/Ring
        ctx.arc(0, 0, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = '#16222A';
        ctx.fill();
        ctx.strokeStyle = color;
        ctx.lineWidth = 2.5;
        ctx.stroke();

        // Inner core
        ctx.beginPath();
        ctx.arc(0, 0, 7, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
      } else if (node.type === 'ip') {
        // IP rounded pill
        const w = 18; const h = 14;
        ctx.roundRect(-w / 2, -h / 2, w, h, 4);
        ctx.fillStyle = '#141F1A';
        ctx.fill();
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.8;
        ctx.stroke();
      } else {
        // Circular nodes
        ctx.arc(0, 0, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = '#141C25';
        ctx.fill();
        ctx.strokeStyle = isSelected ? '#FFFFFF' : color;
        ctx.lineWidth = isSelected ? 2 : 1.5;
        ctx.stroke();
      }

      // Node Label
      ctx.font = node.type === 'domain' ? '600 12px Inter, sans-serif' : '500 10px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      const labelText = node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label;
      const textMetrics = ctx.measureText(labelText);
      const textWidth = textMetrics.width;

      // Label Pill Background
      ctx.fillStyle = 'rgba(11, 15, 20, 0.88)';
      ctx.roundRect(-textWidth / 2 - 4, node.radius + 4, textWidth + 8, 16, 3);
      ctx.fill();
      ctx.strokeStyle = isSelected ? color : 'rgba(42, 53, 65, 0.6)';
      ctx.lineWidth = 0.75;
      ctx.stroke();

      // Label Text
      ctx.fillStyle = isSelected ? '#FFFFFF' : '#E7EDF2';
      ctx.fillText(labelText, 0, node.radius + 12);
    }
  }

  function initOrUpdateInfrastructureMap(scan) {
    const graphData = buildGraphDataFromScan(scan);
    if (!state.infrastructureMap) {
      state.infrastructureMap = new InfrastructureMapRenderer(el.mapCanvas, el.canvasViewport);
    }
    state.infrastructureMap.setData(graphData);
  }

  // =========================================================================
  // Secondary Panel: Asset Inspector Logic
  // =========================================================================
  function renderNodeInspector(node, allEdges) {
    if (!node) {
      el.inspectorEmptyState.style.display = 'block';
      el.inspectorDetails.style.display = 'none';
      return;
    }

    el.inspectorEmptyState.style.display = 'none';
    el.inspectorDetails.style.display = 'block';

    // Type Badge & Title
    el.inspectorAssetType.textContent = node.type.toUpperCase();
    el.inspectorAssetType.className = `inspector-asset-type-badge badge ${
      node.type === 'domain' ? 'badge-safe' :
      node.meta?.risk ? 'badge-danger' :
      node.type === 'ip' ? 'badge-safe' : 'badge-muted'
    }`;

    el.inspectorAssetTitle.textContent = node.label;
    el.inspectorAssetMeta.textContent = node.meta.title || 'Passive Intelligence Node';

    // Attributes Table
    const tbody = el.inspectorKvTable.querySelector('tbody');
    tbody.innerHTML = '';

    const props = [];
    const scanMods = state.currentScan?.modules || {};
    if (node.type === 'domain') {
      props.push({ k: 'Entity Class', v: 'Apex Domain Target' });
      if (scanMods.whois?.org) props.push({ k: 'Organization', v: scanMods.whois.org });
      if (scanMods.whois?.registrar) props.push({ k: 'Registrar', v: scanMods.whois.registrar });
      if (scanMods.whois?.country) props.push({ k: 'Country', v: scanMods.whois.country });
      if (scanMods.whois?.expiration_date) props.push({ k: 'Expires', v: scanMods.whois.expiration_date.split('T')[0] });
    } else if (node.type === 'subdomain') {
      props.push({ k: 'Entity Class', v: 'Subdomain' });
      props.push({ k: 'Apex Domain', v: node.meta.parent || '—' });
      if (node.meta.mappedIp) props.push({ k: 'Resolved IP', v: node.meta.mappedIp });
      props.push({ k: 'Discovery Feed', v: node.meta.source || 'crt.sh' });
    } else if (node.type === 'ip') {
      props.push({ k: 'Entity Class', v: 'Network Endpoint (IPv4/v6)' });
      props.push({ k: 'IP Address', v: node.meta.ip });
      if (node.meta.asn) props.push({ k: 'Autonomous System', v: node.meta.asn });
      if (node.meta.isp) props.push({ k: 'Hosting / ISP', v: node.meta.isp });
      if (node.meta.location) props.push({ k: 'Geographic Location', v: node.meta.location });
      if (node.meta.ptr) props.push({ k: 'Reverse DNS (PTR)', v: node.meta.ptr });
      props.push({ k: 'Exposed Ports', v: node.meta.ports || 'None detected' });
    } else if (node.type === 'port') {
      props.push({ k: 'Port / Protocol', v: node.label });
      props.push({ k: 'Service', v: node.meta.service });
      props.push({ k: 'State', v: node.meta.state });
      props.push({ k: 'Risk Classification', v: node.meta.risk ? 'CRITICAL RISKY' : 'Standard' });
    } else if (node.type === 'mx') {
      props.push({ k: 'Entity Class', v: 'Mail Server (MX)' });
      if (scanMods.email?.mx_provider) props.push({ k: 'Mail Provider', v: scanMods.email.mx_provider });
      props.push({ k: 'SPF Posture', v: node.meta.spfEnforced });
      props.push({ k: 'DMARC Posture', v: node.meta.dmarcEnforced });
    } else if (node.type === 'ns') {
      props.push({ k: 'Entity Class', v: 'DNS Nameserver' });
      props.push({ k: 'Zone Authority', v: node.meta.zone });
    } else if (node.type === 'tech') {
      props.push({ k: 'Category', v: node.meta.category });
      props.push({ k: 'Detection Clue', v: node.meta.evidence });
    }

    props.forEach(p => {
      tbody.innerHTML += `
        <tr>
          <td>${escapeHtml(p.k)}</td>
          <td>${escapeHtml(p.v)}</td>
        </tr>
      `;
    });

    // Connected Neighbors
    const neighborsList = el.inspectorNeighborsList;
    neighborsList.innerHTML = '';

    const neighbors = [];
    allEdges.forEach(e => {
      if (e.source === node) {
        neighbors.push({ node: e.target, rel: e.rel, dir: '➔' });
      } else if (e.target === node) {
        neighbors.push({ node: e.source, rel: e.rel, dir: '←' });
      }
    });

    el.inspectorNeighborCount.textContent = neighbors.length;

    if (neighbors.length === 0) {
      neighborsList.innerHTML = `<div style="color: var(--text-muted); font-size: 0.75rem;">No directly linked infrastructure nodes in scope.</div>`;
      return;
    }

    neighbors.forEach(item => {
      const row = document.createElement('div');
      row.className = 'inspector-neighbor-item';
      row.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.4rem;">
          <span style="color: var(--accent-teal); font-size: 0.7rem;">${item.dir}</span>
          <span class="neighbor-name" title="${escapeHtml(item.node.label)}">${escapeHtml(item.node.label)}</span>
        </div>
        <span class="neighbor-rel">${escapeHtml(item.rel)}</span>
      `;
      row.addEventListener('click', () => {
        if (state.infrastructureMap) {
          state.infrastructureMap.selectNode(item.node);
          state.infrastructureMap.centerOn(item.node.x, item.node.y);
        }
      });
      neighborsList.appendChild(row);
    });
  }

  // =========================================================================
  // Deep-Dive Tab Renderers (10 Analyzers)
  // =========================================================================

  // 1. Overview Tab
  function renderOverviewTab(scan) {
    const alertsContainer = document.getElementById('overview-risk-alerts');
    alertsContainer.innerHTML = '';

    const risks = [];
    const mods = scan.modules || {};

    // Check risky ports
    if (mods.ports?.risky && mods.ports.risky.length > 0) {
      risks.push({
        type: 'danger',
        title: 'High-Risk Services Exposed Publicly',
        desc: `Target exposes critical services: ${mods.ports.risky.map(p => `${p.port}/${p.service}`).join(', ')}. Services like SMB, RDP, or raw databases should not face the public internet.`
      });
    }

    // Check missing security headers
    const hData = mods.headers?.https || mods.headers?.http || {};
    if (hData.missing_security_headers && hData.missing_security_headers.length >= 4) {
      risks.push({
        type: 'warn',
        title: 'Multiple Defensive Security Headers Absent',
        desc: `Target is missing ${hData.missing_security_headers.length} security headers (${hData.missing_security_headers.slice(0, 3).join(', ')}...). Enable HSTS and CSP to mitigate injection attacks.`
      });
    }

    // Check Email Spoofing
    if (mods.email?.dmarc?.present === false) {
      risks.push({
        type: 'warn',
        title: 'Missing DMARC Email Authentication',
        desc: 'No valid DMARC record found. Attackers can forge and spoof emails originating from this domain.'
      });
    }

    // Check TLS expiry
    const daysLeft = mods.tls?.cert?.days_left;
    if (typeof daysLeft === 'number' && daysLeft <= 15) {
      risks.push({
        type: 'danger',
        title: 'TLS Certificate Expiration Imminent',
        desc: `The SSL/TLS certificate expires in ${daysLeft} days (${mods.tls?.cert?.not_after}). Immediate renewal required.`
      });
    }

    if (risks.length === 0) {
      alertsContainer.innerHTML = `
        <div style="background: var(--status-safe-bg); border: 1px solid var(--status-safe-border); border-radius: 8px; padding: 0.85rem 1.15rem; display: flex; align-items: center; gap: 0.75rem;">
          <span style="color: var(--status-safe); font-size: 1.1rem;">✓</span>
          <div>
            <div style="font-weight: 600; color: var(--text-primary); font-size: 0.85rem;">Defensive Perimeter Baseline Verified</div>
            <div style="color: var(--text-muted); font-size: 0.78rem;">No critical high-risk ports or immediate certificate expirations flagged. Inspect individual module tabs for granular intelligence.</div>
          </div>
        </div>
      `;
    } else {
      risks.forEach(r => {
        const borderClass = r.type === 'danger' ? 'var(--status-danger-border)' : 'var(--status-warn-border)';
        const bgClass = r.type === 'danger' ? 'var(--status-danger-bg)' : 'var(--status-warn-bg)';
        const textClass = r.type === 'danger' ? 'var(--status-danger)' : 'var(--status-warn)';
        alertsContainer.innerHTML += `
          <div style="background: ${bgClass}; border: 1px solid ${borderClass}; border-radius: 8px; padding: 0.8rem 1.1rem; margin-bottom: 0.55rem; display: flex; align-items: flex-start; gap: 0.7rem;">
            <span style="color: ${textClass}; font-weight: 700; margin-top: 0.1rem;">⚠</span>
            <div>
              <div style="font-weight: 600; color: var(--text-primary); font-size: 0.85rem;">${r.title}</div>
              <div style="color: var(--text-secondary); font-size: 0.78rem; margin-top: 0.15rem;">${r.desc}</div>
            </div>
          </div>
        `;
      });
    }

    // Overview Table
    const tbody = document.querySelector('#table-overview-modules tbody');
    tbody.innerHTML = '';
    state.modules.forEach(m => {
      const modResult = mods[m.id];
      if (!modResult) return;

      const hasError = !!modResult.error;
      const statusBadge = hasError 
        ? `<span class="badge badge-danger">Error</span>`
        : `<span class="badge badge-safe">Evaluated</span>`;

      let summaryText = 'Completed successfully';
      if (hasError) {
        summaryText = modResult.error;
      } else if (m.id === 'dns') {
        const total = Object.values(modResult).filter(Array.isArray).reduce((acc, v) => acc + v.length, 0);
        summaryText = `${total} DNS records cataloged across ${Object.keys(modResult).length} types`;
      } else if (m.id === 'whois') {
        summaryText = `Registrar: ${modResult.registrar || 'N/A'}, Expires: ${modResult.expiration_date || 'N/A'}`;
      } else if (m.id === 'crtsh') {
        summaryText = `${(modResult.subdomains || []).length} passive subdomains discovered`;
      } else if (m.id === 'headers') {
        const sc = modResult.https?.security_score ?? modResult.http?.security_score ?? 'N/A';
        summaryText = `Compliance score: ${sc}%, Server: ${modResult.https?.server || 'N/A'}`;
      } else if (m.id === 'ports') {
        summaryText = `${(modResult.open_ports || []).length} open ports detected`;
      } else if (m.id === 'tls') {
        summaryText = `${modResult.negotiated_version || 'TLS'} · Issuer: ${modResult.cert?.issuer_org || 'N/A'}`;
      } else if (m.id === 'email') {
        summaryText = `Email Security Score: ${modResult.score || 0}%`;
      } else if (m.id === 'tech') {
        summaryText = `${modResult.total || 0} technologies detected`;
      } else if (m.id === 'wayback') {
        summaryText = `${modResult.total_snapshots || 0} historical snapshots archived`;
      }

      tbody.innerHTML += `
        <tr>
          <td style="font-weight: 600; color: var(--text-primary);">${m.name}</td>
          <td><span class="module-category">${m.category}</span></td>
          <td>${statusBadge}</td>
          <td style="font-size: 0.8rem; color: var(--text-secondary);">${summaryText}</td>
        </tr>
      `;
    });
  }

  // 2. DNS Tab
  function renderDnsTab(dnsData) {
    const tbody = document.querySelector('#table-dns tbody');
    const intelContainer = document.getElementById('dns-ip-intel-container');
    tbody.innerHTML = '';
    if (intelContainer) intelContainer.innerHTML = '';
    const dnsCounter = document.getElementById('count-dns');

    if (!dnsData || dnsData.error) {
      tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">${dnsData?.error || 'No DNS records obtained'}</td></tr>`;
      dnsCounter.textContent = '0';
      return;
    }

    // Render IP Geolocation & ASN Intelligence Cards
    const intelList = dnsData.ip_intelligence || [];
    if (intelContainer && intelList.length > 0) {
      let intelHtml = `<div class="kv-grid" style="margin-bottom: 0.5rem;">`;
      intelList.forEach(item => {
        intelHtml += `
          <div class="kv-item" style="border-left: 3px solid var(--accent-teal);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
              <span class="kv-key">PRIMARY HOST ENDPOINT</span>
              <span class="badge badge-safe">${item.ip}</span>
            </div>
            <div style="font-size: 0.88rem; font-weight: 600; color: var(--text-primary); margin-bottom: 3px;">
              ${escapeHtml(item.isp || item.org || 'Hosting Provider')}
            </div>
            <div style="font-size: 0.76rem; color: var(--text-secondary); margin-bottom: 2px;">
              <span style="color: var(--accent-teal); font-family: var(--font-mono);">${escapeHtml(item.asn || '')}</span> · ${escapeHtml(item.city ? `${item.city}, ` : '')}${escapeHtml(item.country || 'Global')}
            </div>
            ${item.ptr ? `<div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">PTR: ${escapeHtml(item.ptr)}</div>` : ''}
          </div>
        `;
      });
      intelHtml += `</div>`;
      intelContainer.innerHTML = intelHtml;
    }

    let totalRecords = 0;
    const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'];
    types.forEach(type => {
      const records = dnsData[type];
      if (Array.isArray(records) && records.length > 0) {
        totalRecords += records.length;
        const valsHtml = records.map(r => `
          <div style="font-family: var(--font-mono); font-size: 0.8rem; padding: 0.2rem 0; word-break: break-all;">
            ${escapeHtml(r)}
          </div>
        `).join('');

        tbody.innerHTML += `
          <tr>
            <td style="font-weight: 700; color: var(--accent-teal); font-family: var(--font-mono);">${type}</td>
            <td>${valsHtml}</td>
            <td style="text-align: right;">
              <button class="copy-btn" onclick="navigator.clipboard.writeText('${escapeQuotes(records.join('\n'))}'); this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy', 1500);">Copy</button>
            </td>
          </tr>
        `;
      }
    });

    dnsCounter.textContent = totalRecords;
    if (totalRecords === 0) {
      tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">No standard DNS records found</td></tr>`;
    }
  }

  // 3. WHOIS Tab
  function renderWhoisTab(whois) {
    const grid = document.getElementById('whois-grid');
    grid.innerHTML = '';

    if (!whois || whois.error) {
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${whois?.error || 'WHOIS registry data unavailable'}</div>`;
      return;
    }

    const fields = [
      { key: 'Registrant Organization', val: whois.org || 'Not Publicly Disclosed' },
      { key: 'Registrar', val: whois.registrar || '—' },
      { key: 'Registry Source', val: whois.source || 'RDAP + WHOIS Hybrid' },
      { key: 'Country', val: whois.country || '—' },
      { key: 'Domain Status', val: Array.isArray(whois.status) ? whois.status.join(', ') : whois.status },
      { key: 'Creation Date', val: whois.creation_date ? whois.creation_date.split('T')[0] : '—' },
      { key: 'Expiration Date', val: whois.expiration_date ? whois.expiration_date.split('T')[0] : '—' },
      { key: 'Updated Date', val: whois.updated_date ? whois.updated_date.split('T')[0] : '—' },
      { key: 'Name Servers', val: Array.isArray(whois.name_servers) ? whois.name_servers.join(', ') : whois.name_servers },
      { key: 'Contact Emails', val: Array.isArray(whois.emails) ? whois.emails.join(', ') : whois.emails },
    ];

    fields.forEach(f => {
      let displayVal = f.val;
      if (Array.isArray(displayVal)) displayVal = displayVal.join('\n');
      if (!displayVal) displayVal = '—';

      grid.innerHTML += `
        <div class="kv-item">
          <span class="kv-key">${f.key}</span>
          <span class="kv-val">${escapeHtml(String(displayVal))}</span>
        </div>
      `;
    });
  }

  // 4. Subdomains Tab
  function renderSubdomainsTab(crtsh) {
    const container = document.getElementById('subdomains-container');
    const badge = document.getElementById('subdomains-total-badge');
    container.innerHTML = '';

    const subs = crtsh?.subdomains || [];
    const ipMap = crtsh?.subdomain_ips || {};
    badge.textContent = `${subs.length} discovered`;

    if (subs.length === 0) {
      container.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${crtsh?.error || crtsh?.note || 'No subdomains found in Certificate Transparency logs'}</div>`;
      return;
    }

    subs.forEach(s => {
      const chip = document.createElement('div');
      chip.className = 'subdomain-chip';
      const mappedIp = ipMap[s];
      chip.innerHTML = `
        <span>${escapeHtml(s)}</span>
        ${mappedIp ? `<span style="color: var(--accent-teal); font-size: 0.68rem; background: var(--bg-surface-sunken); padding: 0.1rem 0.35rem; border-radius: 3px; border: 1px solid var(--border-subtle); font-family: var(--font-mono);">${escapeHtml(mappedIp)}</span>` : ''}
        <button class="copy-btn" title="Copy subdomain" onclick="navigator.clipboard.writeText('${escapeQuotes(s)}'); this.textContent='✓'; setTimeout(()=>this.textContent='📋', 1200);">📋</button>
      `;
      container.appendChild(chip);
    });
  }

  // 5. Security Headers Tab
  function renderHeadersTab(headers) {
    const tbody = document.querySelector('#table-headers tbody');
    const circle = document.getElementById('headers-score-circle');
    const explanation = document.getElementById('headers-score-explanation');
    tbody.innerHTML = '';

    const h = headers?.https || headers?.http || {};
    const score = typeof h.security_score === 'number' ? h.security_score : 0;
    
    circle.textContent = `${score}%`;
    circle.className = `score-circle ${score >= 70 ? 'good' : score >= 40 ? 'warning' : 'bad'}`;

    if (score >= 70) {
      explanation.textContent = 'Excellent defensive header configuration. Strong transport and content restrictions.';
    } else if (score >= 40) {
      explanation.textContent = 'Moderate security posture. Several critical defensive headers are missing.';
    } else {
      explanation.textContent = 'Weak defensive posture. Heightened exposure to clickjacking, injection, and MIME-type risks.';
    }

    const secHeaders = h.security_headers || {};
    const headerList = [
      'Strict-Transport-Security',
      'Content-Security-Policy',
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Referrer-Policy',
      'Permissions-Policy',
      'X-XSS-Protection'
    ];

    headerList.forEach(name => {
      const info = secHeaders[name] || { present: false, value: null };
      const desc = HEADER_DESCRIPTIONS[name] || 'Defensive HTTP header directive.';
      const statusBadge = info.present 
        ? `<span class="badge badge-safe">✓ Configured</span>`
        : `<span class="badge badge-danger">✗ Missing</span>`;

      tbody.innerHTML += `
        <tr>
          <td style="font-weight: 600; color: var(--text-primary); font-family: var(--font-mono);">${name}</td>
          <td>${statusBadge}</td>
          <td class="mono-cell" style="color: ${info.present ? 'var(--text-secondary)' : 'var(--text-dim)'};">
            ${info.value ? escapeHtml(info.value) : '—'}
          </td>
          <td style="font-size: 0.78rem; color: var(--text-dim);">${desc}</td>
        </tr>
      `;
    });
  }

  // 6. Ports Tab
  function renderPortsTab(portsData) {
    const grid = document.getElementById('ports-grid');
    const label = document.getElementById('ports-detected-label');
    grid.innerHTML = '';

    if (!portsData || portsData.error) {
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${portsData?.error || 'Port scan data unavailable'}</div>`;
      label.textContent = '0 open ports detected';
      return;
    }

    const ipInfo = portsData.ip_info || {};
    const ipStr = portsData.ip || 'Unknown';
    const assessment = portsData.assessment || 'Perimeter audit complete.';

    const openPorts = portsData.open_ports || [];
    const openSet = new Map();
    openPorts.forEach(p => openSet.set(p.port, p));

    label.textContent = `${openPorts.length} open ports detected`;

    // Render ASN & Host Provider Banner
    let hostBanner = document.getElementById('ports-host-banner');
    if (!hostBanner) {
      hostBanner = document.createElement('div');
      hostBanner.id = 'ports-host-banner';
      grid.parentNode.insertBefore(hostBanner, grid);
    }
    hostBanner.innerHTML = `
      <div style="background: var(--bg-surface-sunken); border: 1px solid var(--border-default); border-radius: 8px; padding: 0.85rem 1.15rem; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem;">
        <div>
          <div style="font-size: 0.88rem; font-weight: 600; color: var(--text-primary); font-family: var(--font-mono);">${escapeHtml(ipStr)} <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-sans);">· ${escapeHtml(ipInfo.isp || ipInfo.org || 'Perimeter Host')}</span></div>
          <div style="font-size: 0.76rem; color: var(--text-secondary); margin-top: 2px;">
            <span style="color: var(--accent-teal); font-family: var(--font-mono);">${escapeHtml(ipInfo.asn || '')}</span> · ${escapeHtml(ipInfo.city ? `${ipInfo.city}, ` : '')}${escapeHtml(ipInfo.country || 'Global')}
          </div>
        </div>
        <div style="font-size: 0.78rem; color: ${portsData.risky && portsData.risky.length > 0 ? 'var(--status-danger)' : 'var(--text-muted)'}; max-width: 380px; text-align: right;">
          ${escapeHtml(assessment)}
        </div>
      </div>
    `;

    const standardPorts = [
      { port: 21, svc: 'FTP' },
      { port: 22, svc: 'SSH' },
      { port: 23, svc: 'Telnet', risky: true },
      { port: 25, svc: 'SMTP' },
      { port: 53, svc: 'DNS' },
      { port: 80, svc: 'HTTP' },
      { port: 110, svc: 'POP3' },
      { port: 143, svc: 'IMAP' },
      { port: 443, svc: 'HTTPS' },
      { port: 445, svc: 'SMB', risky: true },
      { port: 587, svc: 'SMTP/TLS' },
      { port: 3306, svc: 'MySQL' },
      { port: 3389, svc: 'RDP', risky: true },
      { port: 5432, svc: 'PostgreSQL' },
      { port: 6379, svc: 'Redis', risky: true },
      { port: 8080, svc: 'HTTP-alt' },
      { port: 8443, svc: 'HTTPS-alt' },
      { port: 27017, svc: 'MongoDB', risky: true },
    ];

    standardPorts.forEach(item => {
      const isOpen = openSet.has(item.port);
      const isRisky = item.risky && isOpen;
      
      let statusTag = isOpen ? `<span class="badge badge-safe port-tag">OPEN</span>` : `<span class="badge badge-muted port-tag">CLOSED</span>`;
      if (isRisky) {
        statusTag = `<span class="badge badge-danger port-tag">⚠ HIGH RISK</span>`;
      }

      grid.innerHTML += `
        <div class="port-box ${isOpen ? 'open' : ''} ${isRisky ? 'risky' : ''}">
          <div class="port-num">${item.port}</div>
          <div class="port-service">${item.svc}</div>
          ${statusTag}
        </div>
      `;
    });
  }

  // 7. TLS Tab
  function renderTlsTab(tls) {
    const grid = document.getElementById('tls-grid');
    const sansContainer = document.getElementById('tls-sans-container');
    grid.innerHTML = '';
    sansContainer.innerHTML = '';

    if (!tls || tls.error) {
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${tls?.error || 'TLS certificate analysis unavailable'}</div>`;
      return;
    }

    const cert = tls.cert || {};
    const cipher = tls.cipher || {};

    const fields = [
      { key: 'Negotiated Protocol', val: tls.negotiated_version || 'TLS' },
      { key: 'Cipher Suite', val: cipher.name || 'N/A' },
      { key: 'Cipher Strength', val: cipher.bits ? `${cipher.bits} bits` : 'N/A' },
      { key: 'Certificate Issuer', val: cert.issuer_org || cert.issuer_cn || 'N/A' },
      { key: 'Subject Common Name', val: cert.subject_cn || 'N/A' },
      { key: 'Valid From', val: cert.not_before || 'N/A' },
      { key: 'Valid Until (Expiry)', val: cert.not_after || 'N/A' },
      { key: 'Days Remaining', val: cert.days_left !== undefined ? `${cert.days_left} days` : 'N/A' },
      { key: 'Trust Chain Verification', val: cert.trust_verified === false ? 'Failed / Self-Signed' : 'Verified Valid' },
    ];

    fields.forEach(f => {
      grid.innerHTML += `
        <div class="kv-item">
          <span class="kv-key">${f.key}</span>
          <span class="kv-val">${escapeHtml(String(f.val))}</span>
        </div>
      `;
    });

    const sans = cert.sans || [];
    if (sans.length > 0) {
      sans.forEach(s => {
        sansContainer.innerHTML += `<span class="subdomain-chip">${escapeHtml(s)}</span>`;
      });
    } else {
      sansContainer.innerHTML = `<span style="color: var(--text-dim); font-size: 0.82rem;">No alternative names configured</span>`;
    }
  }

  // 8. Email Tab
  function renderEmailTab(email) {
    const grid = document.getElementById('email-grid');
    const issuesContainer = document.getElementById('email-issues-list');
    const pill = document.getElementById('email-score-pill');
    grid.innerHTML = '';
    issuesContainer.innerHTML = '';

    if (!email || email.error) {
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${email?.error || 'Email security posture data unavailable'}</div>`;
      return;
    }

    const score = email.score || 0;
    pill.textContent = `Score: ${score}%`;
    pill.className = `badge ${score >= 70 ? 'badge-safe' : score >= 40 ? 'badge-warn' : 'badge-danger'}`;

    const spf = email.spf || {};
    const dmarc = email.dmarc || {};
    const dkim = email.dkim || {};
    const isSpoofable = email.spoofing_vulnerable;

    const fields = [
      { key: 'Mail Security Provider', val: email.mx_provider || 'Independent / None' },
      { key: 'Executive Spoofing Risk', val: isSpoofable ? 'HIGH VULNERABILITY (Spoofable)' : 'PROTECTED (DMARC Enforced)' },
      { key: 'SPF Record Configured', val: spf.present ? 'Yes' : 'No' },
      { key: 'SPF Policy Enforced', val: spf.policy || 'None' },
      { key: 'Raw SPF Record', val: spf.record || '—' },
      { key: 'DMARC Record Configured', val: dmarc.present ? 'Yes' : 'No' },
      { key: 'DMARC Policy Enforcement', val: dmarc.policy || 'None' },
      { key: 'DMARC Aggregate Reporting (rua)', val: dmarc.rua || '—' },
      { key: 'DKIM Selector Discovery', val: dkim.found ? `Discovered (${(dkim.selectors || []).map(s => s.selector).join(', ')})` : 'No standard selectors found' },
      { key: 'Resolved MX Mail Servers', val: (email.mx_records || []).join('\n') || 'None Configured' },
    ];

    fields.forEach(f => {
      grid.innerHTML += `
        <div class="kv-item">
          <span class="kv-key">${f.key}</span>
          <span class="kv-val">${escapeHtml(String(f.val))}</span>
        </div>
      `;
    });

    const issues = email.all_issues || [];
    if (issues.length > 0) {
      issues.forEach(iss => {
        issuesContainer.innerHTML += `
          <div style="background: var(--status-warn-bg); border: 1px solid var(--status-warn-border); border-radius: 6px; padding: 0.6rem 0.85rem; margin-bottom: 0.45rem; color: var(--text-secondary); font-size: 0.8rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="color: var(--status-warn);">⚠</span>
            <span>${escapeHtml(iss)}</span>
          </div>
        `;
      });
    } else {
      issuesContainer.innerHTML = `<div style="color: var(--status-safe); font-size: 0.82rem;">✓ No anti-spoofing weaknesses detected.</div>`;
    }
  }

  // 9. Tech Tab
  function renderTechTab(tech) {
    const grid = document.getElementById('tech-grid');
    const badge = document.getElementById('tech-total-badge');
    grid.innerHTML = '';

    if (!tech || tech.error) {
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${tech?.error || 'Technology stack fingerprinting unavailable'}</div>`;
      badge.textContent = '0 detected';
      return;
    }

    const byCat = tech.by_category || {};
    const total = tech.total || 0;
    badge.textContent = `${total} detected`;
    document.getElementById('count-tech').textContent = total;

    if (total === 0) {
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">Stack signatures unidentified or masked by target CDN.</div>`;
      return;
    }

    for (const [cat, items] of Object.entries(byCat)) {
      grid.innerHTML += `
        <div class="kv-item">
          <span class="kv-key">${escapeHtml(cat)}</span>
          <div style="display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.3rem;">
            ${items.map(it => `<span class="badge badge-safe" style="font-family: var(--font-mono);">${escapeHtml(it)}</span>`).join('')}
          </div>
        </div>
      `;
    }
  }

  // 10. Wayback Tab
  function renderWaybackTab(wb) {
    const summaryGrid = document.getElementById('wayback-summary-grid');
    const tbody = document.querySelector('#table-wayback tbody');
    summaryGrid.innerHTML = '';
    tbody.innerHTML = '';

    if (!wb || wb.error) {
      summaryGrid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${wb?.error || 'Wayback Machine archive data unavailable'}</div>`;
      document.getElementById('count-wb').textContent = '0';
      return;
    }

    const totalSnaps = wb.total_snapshots || 0;
    document.getElementById('count-wb').textContent = totalSnaps;

    const fields = [
      { key: 'Total Archived Snapshots', val: totalSnaps },
      { key: 'Latest Archived Snapshot', val: wb.latest_snapshot ? `<a href="${escapeHtml(wb.latest_snapshot)}" target="_blank" style="color: var(--accent-teal); text-decoration: underline;">${escapeHtml(wb.latest_timestamp || 'Open Snapshot')}</a>` : 'N/A' },
      { key: 'Archived Subdomains', val: (wb.subdomains || []).slice(0, 5).join(', ') || '—' },
      { key: 'Sensitive / High-Value Endpoints', val: (wb.interesting || []).length },
    ];

    fields.forEach(f => {
      summaryGrid.innerHTML += `
        <div class="kv-item">
          <span class="kv-key">${f.key}</span>
          <span class="kv-val">${f.val}</span>
        </div>
      `;
    });

    const interesting = wb.interesting || [];
    if (interesting.length > 0) {
      interesting.forEach(url => {
        let tag = '<span class="badge badge-muted">Historical URL</span>';
        if (url.includes('.env') || url.includes('/backup') || url.includes('/.git')) {
          tag = '<span class="badge badge-danger">Sensitive File</span>';
        } else if (url.includes('/admin') || url.includes('/login') || url.includes('/console')) {
          tag = '<span class="badge badge-warn">Auth / Admin</span>';
        } else if (url.includes('/api/') || url.includes('/graphql') || url.includes('/swagger')) {
          tag = '<span class="badge badge-safe">API Surface</span>';
        }

        tbody.innerHTML += `
          <tr>
            <td class="mono-cell" style="word-break: break-all;">${escapeHtml(url)}</td>
            <td>${tag}</td>
            <td style="text-align: right;">
              <button class="copy-btn" onclick="navigator.clipboard.writeText('${escapeQuotes(url)}'); this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy', 1500);">Copy</button>
            </td>
          </tr>
        `;
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">No sensitive or interesting historical endpoints found</td></tr>`;
    }
  }

  // =========================================================================
  // Reports Archive Modal
  // =========================================================================
  async function loadReportsList() {
    try {
      const res = await fetch('/api/reports');
      if (!res.ok) return;
      state.reports = await res.json();
      el.headerReportsBadge.textContent = state.reports.length;
    } catch (err) {
      console.error('Failed to fetch reports list', err);
    }
  }

  function openArchiveModal() {
    el.archiveModal.classList.add('open');
    renderArchiveReportsTable();
  }

  function closeArchiveModal() {
    el.archiveModal.classList.remove('open');
  }

  function renderArchiveReportsTable() {
    const tbody = document.querySelector('#table-archive-reports tbody');
    tbody.innerHTML = '';

    if (state.reports.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 2rem;">No saved reports in the archives directory yet.</td></tr>`;
      return;
    }

    state.reports.forEach(r => {
      const sizeKb = Math.round(r.size_bytes / 1024);
      const dateStr = new Date(r.timestamp).toLocaleString();

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-weight: 600; color: var(--text-primary); font-family: var(--font-mono);">${escapeHtml(r.target)}</td>
        <td style="font-size: 0.78rem; color: var(--text-muted);">${dateStr}</td>
        <td><span class="badge badge-muted">${r.modules.length} mods</span></td>
        <td style="font-family: var(--font-mono); font-size: 0.78rem;">${sizeKb} KB</td>
        <td style="text-align: right; white-space: nowrap;">
          <button class="btn-action primary" style="padding: 0.25rem 0.55rem; font-size: 0.75rem;" data-action="load" data-file="${r.json_file}">Load</button>
          ${r.html_file ? `<a href="/api/reports/${r.html_file}" target="_blank" class="btn-action" style="padding: 0.25rem 0.55rem; font-size: 0.75rem;">HTML</a>` : ''}
          <button class="btn-action" style="padding: 0.25rem 0.45rem; font-size: 0.75rem; color: var(--status-danger);" data-action="delete" data-id="${r.id}">🗑</button>
        </td>
      `;

      tr.querySelector('[data-action="load"]')?.addEventListener('click', () => {
        loadReportFile(r.json_file);
        closeArchiveModal();
      });

      tr.querySelector('[data-action="delete"]')?.addEventListener('click', async () => {
        if (confirm(`Delete report for ${r.target}?`)) {
          await deleteReport(r.id);
        }
      });

      tbody.appendChild(tr);
    });
  }

  async function loadReportFile(filename) {
    try {
      showToast(`Loading report: ${filename}...`);
      const res = await fetch(`/api/reports/${filename}`);
      if (!res.ok) throw new Error('Report could not be retrieved');
      const data = await res.json();
      state.currentScan = data;
      renderScanResults(data);
      showToast(`Loaded ${data.target} intelligence report`, 'safe');
    } catch (err) {
      showToast(`Error loading report: ${err.message}`, 'danger');
    }
  }

  async function deleteReport(reportId) {
    try {
      const res = await fetch(`/api/reports/${reportId}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to delete report');
      showToast('Report deleted', 'safe');
      await loadReportsList();
      renderArchiveReportsTable();
    } catch (err) {
      showToast(err.message, 'danger');
    }
  }

  async function loadSampleReport() {
    // Prefer siesgst.edu.in or google.com pre-saved reports
    const sample = state.reports.find(r => r.target.includes('siesgst') || r.target.includes('google')) || state.reports[0];
    if (sample) {
      loadReportFile(sample.json_file);
    } else {
      showToast('No pre-saved sample scan found in reports folder.', 'warn');
    }
  }

  // =========================================================================
  // Utilities
  // =========================================================================
  function showToast(msg, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    let icon = 'ℹ';
    let border = 'var(--border-default)';
    if (type === 'safe') { icon = '✓'; border = 'var(--status-safe-border)'; }
    if (type === 'warn') { icon = '⚠'; border = 'var(--status-warn-border)'; }
    if (type === 'danger') { icon = '✗'; border = 'var(--status-danger-border)'; }

    toast.style.borderColor = border;
    toast.innerHTML = `<span style="font-weight: 700;">${icon}</span> <span>${escapeHtml(msg)}</span>`;
    el.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function escapeQuotes(str) {
    if (!str) return '';
    return String(str).replace(/'/g, "\\'").replace(/"/g, '\\"');
  }

  // Initialize
  document.addEventListener('DOMContentLoaded', init);
})();
