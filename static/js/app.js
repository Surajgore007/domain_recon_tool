/**
 * OSINT Recon Platform - Client Application Logic
 * Premium GUI Dashboard for Passive Domain Intelligence
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
  };

  // Header explanation dictionary for security headers tab
  const HEADER_DESCRIPTIONS = {
    'Strict-Transport-Security': 'Enforces secure HTTPS connections and prevents SSL stripping attacks.',
    'Content-Security-Policy': 'Mitigates Cross-Site Scripting (XSS) and data injection by whitelisting trusted sources.',
    'X-Frame-Options': 'Prevents Clickjacking by restricting embedding in iframes.',
    'X-Content-Type-Options': 'Prevents MIME-type sniffing (nosniff) by modern browsers.',
    'Referrer-Policy': 'Controls sensitive referral information leaked in the Referer header.',
    'Permissions-Policy': 'Restricts browser capabilities (camera, microphone, geolocation) to authorized contexts.',
    'X-XSS-Protection': 'Legacy cross-site scripting filter protection for older browser agents.',
  };

  // DOM Elements
  const el = {
    form: document.getElementById('recon-form'),
    targetInput: document.getElementById('target-input'),
    submitBtn: document.getElementById('btn-submit-scan'),
    modulesContainer: document.getElementById('modules-container'),
    timeoutSlider: document.getElementById('timeout-slider'),
    timeoutDisplay: document.getElementById('timeout-display'),
    saveReportToggle: document.getElementById('save-report-toggle'),
    
    // Controls
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

    // Target Strip & KPI
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

    // Deep-dive & Tabs
    deepDiveSection: document.getElementById('deep-dive-section'),
    tabNav: document.getElementById('tab-nav'),

    // Archive Modal
    archiveModal: document.getElementById('archive-modal'),
    btnCloseArchive: document.getElementById('btn-close-archive'),
    tableArchiveReports: document.getElementById('table-archive-reports'),

    toastContainer: document.getElementById('toast-container'),
  };

  // Initialize
  async function init() {
    setupEventListeners();
    await loadModulesConfig();
    await loadReportsList();
  }

  // Fetch Available Modules
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

  // Render Module Checkboxes
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

  // Setup Event Listeners
  function setupEventListeners() {
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
      const tabId = btn.dataset.tab;
      switchTab(tabId);
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
      // If server saved HTML file, open or download it
      const savedHtml = state.currentScan.saved_reports?.html;
      if (savedHtml) {
        window.open(`/api/reports/${savedHtml}`, '_blank');
      } else {
        // Fallback: trigger browser print
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

    // Sample Loader
    el.loadSampleBtn.addEventListener('click', () => loadSampleReport());
    el.emptyLoadSampleBtn.addEventListener('click', () => loadSampleReport());
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

  // Quick Table and List Filtering
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

  // Clean and sanitize domain
  function sanitizeDomain(raw) {
    let d = raw.trim().toLowerCase();
    d = d.replace(/^https?:\/\//, '');
    d = d.split('/')[0].split('?')[0].split(':')[0];
    return d;
  }

  // Launch Scan with SSE Stream
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
    el.trackerStatusText.textContent = 'Initializing reconnaissance engines...';
    el.trackerCounter.textContent = `0 / ${selectedModules.length} Modules`;

    // Render Steps in Grid
    renderStepsGrid(selectedModules);

    // Close any previous event source
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
      el.trackerStatusText.textContent = `Scan complete. Generated reports for ${target}.`;
      showToast(`Reconnaissance complete for ${target}`, 'safe');

      // Update state & render
      state.currentScan = {
        target: finalData.target,
        timestamp: finalData.timestamp,
        modules: finalData.results.modules,
        saved_reports: finalData.saved_reports
      };

      renderScanResults(state.currentScan);
      loadReportsList(); // Refresh archive list
    });

    es.addEventListener('error', (e) => {
      // If server closed or errored
      if (state.isScanning) {
        es.close();
        state.eventSource = null;
        state.isScanning = false;
        el.submitBtn.disabled = false;
        el.trackerStatusText.textContent = 'Scan encountered a network error or interruption.';
        showToast('Stream interrupted or failed. Loading available results.', 'danger');
        
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
      indicator.innerHTML = `<span style="color: var(--status-safe);">✓ ${summary}</span>`;
    } else {
      card.classList.add('error');
      indicator.innerHTML = `<span style="color: var(--status-danger);">✗ Error</span>`;
    }
  }

  // Render Full Scan Results into Dashboard
  function renderScanResults(scan) {
    if (!scan || !scan.target) return;

    el.emptyState.style.display = 'none';
    el.targetSummaryStrip.style.display = 'flex';
    el.kpiSection.style.display = 'grid';
    el.deepDiveSection.style.display = 'block';

    // Populate Target Strip
    el.activeDomainName.textContent = scan.target;
    const formattedDate = scan.timestamp ? new Date(scan.timestamp).toUTCString() : 'N/A';
    el.activeScanTimestamp.textContent = formattedDate;
    
    const mods = scan.modules || {};
    const modCount = Object.keys(mods).length;
    el.activeModulesCount.textContent = `${modCount} modules evaluated`;

    // Render 5 Executive KPI Cards
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

    // Scroll to dashboard
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
        desc: `Target is exposing risky ports: ${mods.ports.risky.map(p => `${p.port}/${p.service}`).join(', ')}. Services like SMB (445), RDP (3389), or unauthenticated databases must never be open to the public internet.`
      });
    }

    // Check missing security headers
    const hData = mods.headers?.https || mods.headers?.http || {};
    if (hData.missing_security_headers && hData.missing_security_headers.length >= 4) {
      risks.push({
        type: 'warn',
        title: 'Multiple Defensive Security Headers Absent',
        desc: `Target is missing ${hData.missing_security_headers.length} security headers (${hData.missing_security_headers.slice(0, 3).join(', ')}...). Implement HSTS and Content-Security-Policy to prevent injection and downgrade attacks.`
      });
    }

    // Check Email Spoofing
    if (mods.email?.dmarc?.present === false) {
      risks.push({
        type: 'warn',
        title: 'Missing DMARC Email Authentication',
        desc: 'No valid DMARC record found. Attackers can forge and spoof emails originating from this domain to target users or employees.'
      });
    }

    // Check TLS expiry
    const daysLeft = mods.tls?.cert?.days_left;
    if (typeof daysLeft === 'number' && daysLeft <= 15) {
      risks.push({
        type: 'danger',
        title: 'TLS Certificate Expiration Imminent',
        desc: `The SSL/TLS certificate will expire in ${daysLeft} days (${mods.tls?.cert?.not_after}). Immediate renewal required to prevent service disruption.`
      });
    }

    if (risks.length === 0) {
      alertsContainer.innerHTML = `
        <div style="background: var(--status-safe-bg); border: 1px solid var(--status-safe-border); border-radius: 10px; padding: 1rem 1.25rem; display: flex; align-items: center; gap: 0.75rem;">
          <span style="color: var(--status-safe); font-size: 1.2rem;">✓</span>
          <div>
            <div style="font-weight: 600; color: var(--text-primary); font-size: 0.9rem;">Strong Base Perimeter Posture</div>
            <div style="color: var(--text-muted); font-size: 0.8rem;">No critical high-risk ports or immediate certificate expirations identified. Review module tabs for detailed intelligence.</div>
          </div>
        </div>
      `;
    } else {
      risks.forEach(r => {
        const borderClass = r.type === 'danger' ? 'var(--status-danger-border)' : 'var(--status-warn-border)';
        const bgClass = r.type === 'danger' ? 'var(--status-danger-bg)' : 'var(--status-warn-bg)';
        const textClass = r.type === 'danger' ? 'var(--status-danger)' : 'var(--status-warn)';
        alertsContainer.innerHTML += `
          <div style="background: ${bgClass}; border: 1px solid ${borderClass}; border-radius: 10px; padding: 0.9rem 1.2rem; margin-bottom: 0.6rem; display: flex; align-items: flex-start; gap: 0.75rem;">
            <span style="color: ${textClass}; font-weight: 700; margin-top: 0.1rem;">⚠</span>
            <div>
              <div style="font-weight: 600; color: var(--text-primary); font-size: 0.88rem;">${r.title}</div>
              <div style="color: var(--text-secondary); font-size: 0.8rem; margin-top: 0.15rem;">${r.desc}</div>
            </div>
          </div>
        `;
      });
    }

    // Populate Overview Table
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
          <td style="font-size: 0.82rem; color: var(--text-secondary);">${summaryText}</td>
        </tr>
      `;
    });
  }

  // 2. DNS Tab
  function renderDnsTab(dnsData) {
    const tbody = document.querySelector('#table-dns tbody');
    tbody.innerHTML = '';
    const dnsCounter = document.getElementById('count-dns');

    if (!dnsData || dnsData.error) {
      tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">${dnsData?.error || 'No DNS records obtained'}</td></tr>`;
      dnsCounter.textContent = '0';
      return;
    }

    let totalRecords = 0;
    const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
    types.forEach(type => {
      const records = dnsData[type];
      if (Array.isArray(records) && records.length > 0) {
        totalRecords += records.length;
        const valsHtml = records.map(r => `
          <div style="font-family: var(--font-mono); font-size: 0.82rem; padding: 0.2rem 0; word-break: break-all;">
            ${escapeHtml(r)}
          </div>
        `).join('');

        tbody.innerHTML += `
          <tr>
            <td style="font-weight: 700; color: var(--accent-cyan); font-family: var(--font-mono);">${type}</td>
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
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${whois?.error || 'WHOIS data not available'}</div>`;
      return;
    }

    const fields = [
      { key: 'Registrar', val: whois.registrar },
      { key: 'Creation Date', val: whois.creation_date },
      { key: 'Expiration Date', val: whois.expiration_date },
      { key: 'Updated Date', val: whois.updated_date },
      { key: 'Registrant Organization', val: whois.org },
      { key: 'Country', val: whois.country },
      { key: 'Domain Status', val: Array.isArray(whois.status) ? whois.status.join(', ') : whois.status },
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
    badge.textContent = `${subs.length} discovered`;

    if (subs.length === 0) {
      container.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${crtsh?.error || 'No subdomains found in Certificate Transparency logs'}</div>`;
      return;
    }

    subs.forEach(s => {
      const chip = document.createElement('div');
      chip.className = 'subdomain-chip';
      chip.innerHTML = `
        <span>${escapeHtml(s)}</span>
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
      explanation.textContent = 'Excellent defensive header configuration. Strong transport and content controls.';
    } else if (score >= 40) {
      explanation.textContent = 'Moderate security posture. Several critical security headers are missing.';
    } else {
      explanation.textContent = 'Weak defensive headers. High risk of clickjacking, XSS, and MIME-type vulnerabilities.';
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
          <td style="font-size: 0.8rem; color: var(--text-dim);">${desc}</td>
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

    const openPorts = portsData.open_ports || [];
    const openSet = new Map();
    openPorts.forEach(p => openSet.set(p.port, p));

    label.textContent = `${openPorts.length} open ports detected`;

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
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${tls?.error || 'TLS certificate analysis not available'}</div>`;
      return;
    }

    const cert = tls.cert || {};
    const cipher = tls.cipher || {};

    const fields = [
      { key: 'Negotiated Protocol', val: tls.negotiated_version || 'TLS' },
      { key: 'Cipher Suite', val: cipher.name || 'N/A' },
      { key: 'Cipher Bits', val: cipher.bits ? `${cipher.bits} bits` : 'N/A' },
      { key: 'Certificate Issuer', val: cert.issuer_org || cert.issuer_cn || 'N/A' },
      { key: 'Subject Common Name', val: cert.subject_cn || 'N/A' },
      { key: 'Valid From', val: cert.not_before || 'N/A' },
      { key: 'Valid Until (Expiration)', val: cert.not_after || 'N/A' },
      { key: 'Days Remaining', val: cert.days_left !== undefined ? `${cert.days_left} days` : 'N/A' },
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
      sansContainer.innerHTML = `<span style="color: var(--text-dim); font-size: 0.85rem;">No alternative names listed</span>`;
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
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${email?.error || 'Email security data not available'}</div>`;
      return;
    }

    const score = email.score || 0;
    pill.textContent = `Score: ${score}%`;
    pill.className = `badge ${score >= 70 ? 'badge-safe' : score >= 40 ? 'badge-warn' : 'badge-danger'}`;

    const spf = email.spf || {};
    const dmarc = email.dmarc || {};
    const dkim = email.dkim || {};

    const fields = [
      { key: 'SPF Record Present', val: spf.present ? 'Yes' : 'No' },
      { key: 'SPF Policy Enforced', val: spf.policy || 'None' },
      { key: 'Raw SPF Record', val: spf.record || '—' },
      { key: 'DMARC Record Present', val: dmarc.present ? 'Yes' : 'No' },
      { key: 'DMARC Policy Enforcement', val: dmarc.policy || 'None' },
      { key: 'DMARC Percentage (pct)', val: dmarc.pct ? `${dmarc.pct}%` : '—' },
      { key: 'DMARC Reporting (rua)', val: dmarc.rua || '—' },
      { key: 'DKIM Selector Discovery', val: dkim.found ? `Found (${(dkim.selectors || []).map(s => s.selector).join(', ')})` : 'No standard selectors' },
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
          <div style="background: var(--status-warn-bg); border: 1px solid var(--status-warn-border); border-radius: 8px; padding: 0.65rem 0.9rem; margin-bottom: 0.5rem; color: var(--text-secondary); font-size: 0.82rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="color: var(--status-warn);">⚠</span>
            <span>${escapeHtml(iss)}</span>
          </div>
        `;
      });
    } else {
      issuesContainer.innerHTML = `<div style="color: var(--status-safe); font-size: 0.85rem;">✓ No critical email anti-spoofing issues detected.</div>`;
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
      grid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">Stack unidentified or intentionally obfuscated by target.</div>`;
      return;
    }

    for (const [cat, items] of Object.entries(byCat)) {
      grid.innerHTML += `
        <div class="kv-item">
          <span class="kv-key">${escapeHtml(cat)}</span>
          <div style="display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.3rem;">
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
      summaryGrid.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">${wb?.error || 'Wayback machine archive data unavailable'}</div>`;
      document.getElementById('count-wb').textContent = '0';
      return;
    }

    const totalSnaps = wb.total_snapshots || 0;
    document.getElementById('count-wb').textContent = totalSnaps;

    const fields = [
      { key: 'Total Historical Snapshots', val: totalSnaps },
      { key: 'Latest Archived Snapshot', val: wb.latest_snapshot ? `<a href="${escapeHtml(wb.latest_snapshot)}" target="_blank" style="color: var(--accent-cyan); text-decoration: underline;">${escapeHtml(wb.latest_timestamp || 'Open Snapshot')}</a>` : 'N/A' },
      { key: 'Archived Subdomains', val: (wb.subdomains || []).slice(0, 5).join(', ') || '—' },
      { key: 'High-Value Endpoints Flagged', val: (wb.interesting || []).length },
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
      tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">No specifically interesting or sensitive historical endpoints isolated</td></tr>`;
    }
  }

  // Reports Archive Modal
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
        <td style="font-size: 0.8rem; color: var(--text-muted);">${dateStr}</td>
        <td><span class="badge badge-muted">${r.modules.length} mods</span></td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem;">${sizeKb} KB</td>
        <td style="text-align: right; white-space: nowrap;">
          <button class="btn-action primary" style="padding: 0.3rem 0.6rem; font-size: 0.78rem;" data-action="load" data-file="${r.json_file}">Load</button>
          ${r.html_file ? `<a href="/api/reports/${r.html_file}" target="_blank" class="btn-action" style="padding: 0.3rem 0.6rem; font-size: 0.78rem;">HTML</a>` : ''}
          <button class="btn-action" style="padding: 0.3rem 0.5rem; font-size: 0.78rem; color: var(--status-danger);" data-action="delete" data-id="${r.id}">🗑</button>
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
      showToast(`Loaded ${data.target} intelligence data`, 'safe');
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
    const sample = state.reports.find(r => r.target.includes('google.com')) || state.reports[0];
    if (sample) {
      loadReportFile(sample.json_file);
    } else {
      showToast('No pre-saved sample scan found in reports folder.', 'warn');
    }
  }

  // Utility Toast Notifications
  function showToast(msg, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    let icon = 'ℹ';
    let border = 'var(--border-medium)';
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

  // Initialize on DOM ready
  document.addEventListener('DOMContentLoaded', init);
})();
