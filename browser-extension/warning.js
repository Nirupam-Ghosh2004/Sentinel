// Warning.js v4.2 — Forensics Terminal Theme
// Reads enriched data from chrome.storage.local
// Matches Stitch "Security Gateway" design

console.log('Warning.js v4.2 — Forensics Terminal loaded');

document.addEventListener('DOMContentLoaded', function () {
  // Basic data from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = urlParams.get('url');
  const blockReason = urlParams.get('reason');
  const source = urlParams.get('source') || 'UNKNOWN';
  const type = urlParams.get('type') || 'block';
  const riskScore = parseInt(urlParams.get('risk_score') || '0');

  let reasons = [];
  try {
    const raw = urlParams.get('reasons');
    if (raw) reasons = JSON.parse(decodeURIComponent(raw));
  } catch (e) {
    console.error('Failed to parse reasons:', e);
  }

  const isAnomaly = type === 'anomaly';

  // Set basic UI from URL params
  setBasicUI(blockedUrl, blockReason, source, isAnomaly, riskScore, reasons);

  // Load enriched data
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get('lastBlockData', function (result) {
      const data = result.lastBlockData;
      if (data) {
        console.log('Enriched block data:', data);
        populateEnrichedData(data, isAnomaly);
      }
    });
  }

  // Button handlers
  setupButtons(blockedUrl, isAnomaly);

  // Sidebar toggle
  setupSidebarToggle();

  // Log toggle
  setupLogToggle();
});

// ===== BASIC UI =====
function setBasicUI(blockedUrl, blockReason, source, isAnomaly, riskScore, reasons) {
  // Blocked URL
  const urlEl = document.getElementById('blockedUrl');
  urlEl.textContent = blockedUrl ? decodeURIComponent(blockedUrl) : 'Unknown URL';

  // Alert title
  const title = document.getElementById('alertTitle');
  title.textContent = isAnomaly
    ? '[ ALERT ] Access Blocked: Structural Anomaly Detected'
    : '[ ALERT ] Access Blocked: Threat Detected';

  // Category
  const cat = document.getElementById('alertCategory');
  cat.textContent = isAnomaly ? 'Structural Anomaly' : 'Phishing / Malware';

  // Alert tag
  const tag = document.getElementById('alertTag');
  tag.textContent = isAnomaly ? 'Anomaly Detected' : 'Critical Threat Detected';

  // Explanation
  const explainText = document.getElementById('explainText');
  if (isAnomaly) {
    explainText.innerHTML =
      'Subsystem analysis identified multiple <span class="neon-text">high-confidence</span> ' +
      'structural deviations. The URL pattern exhibits statistical anomalies across multiple feature ' +
      'dimensions, suggesting potential deceptive intent.';
  } else if (blockReason) {
    explainText.textContent = decodeURIComponent(blockReason);
  }

  // Risk triggers from URL params
  if (reasons && reasons.length > 0) {
    populateTriggers(reasons);
  } else if (blockReason) {
    populateTriggers([decodeURIComponent(blockReason)]);
  }

  // Threat gauge
  const score = isAnomaly ? riskScore : 0;
  buildGauge(score);

  // Proceed button for anomaly
  if (isAnomaly) {
    const wrap = document.getElementById('proceedWrap');
    wrap.style.display = 'block';
    setupProceedDelay();
  }

  // Scan ID
  const scanId = document.getElementById('gaugeScanId');
  scanId.textContent = 'SCAN_COMPLETE_' + Math.random().toString(36).substring(2, 8).toUpperCase();

  // Node ID
  const nodeId = document.getElementById('nodeId');
  nodeId.textContent = 'SG-WAF-' + String(Math.floor(Math.random() * 999)).padStart(3, '0') + '-A';
}

// ===== RISK TRIGGERS =====
function populateTriggers(reasons) {
  const list = document.getElementById('triggersList');
  list.innerHTML = '';

  reasons.forEach((reason, i) => {
    const card = document.createElement('div');
    card.className = 'trigger-card' + (i >= 2 ? ' mild' : '');

    const iconName = i >= 2 ? 'info' : 'warning';
    const iconOpacity = i >= 2 ? 'style="opacity:0.6"' : '';

    // Extract short label and detail
    const parts = reason.split(':');
    const label = parts.length > 1 ? parts[0].trim() : reason.substring(0, 40);
    const detail = parts.length > 1 ? parts.slice(1).join(':').trim() : reason;

    card.innerHTML = `
      <div class="trigger-header">
        <span class="material-symbols-outlined trigger-icon" ${iconOpacity}>${iconName}</span>
        <span class="trigger-label">${label}</span>
      </div>
      <p class="trigger-detail">${detail}</p>
    `;
    list.appendChild(card);
  });
}

// ===== THREAT GAUGE (20 segments) =====
function buildGauge(score) {
  const container = document.getElementById('gaugeBlocks');
  const scoreEl = document.getElementById('gaugeScore');
  container.innerHTML = '';

  const filledCount = Math.round(score / 5);

  for (let i = 0; i < 20; i++) {
    const block = document.createElement('div');
    block.className = 'gauge-block';

    if (i < filledCount - 2) {
      block.classList.add('filled');
    } else if (i < filledCount - 1) {
      block.classList.add('dim');
    } else if (i < filledCount) {
      block.classList.add('faint');
    } else {
      block.classList.add('empty');
    }

    container.appendChild(block);
  }

  // Animate score counter
  animateCounter(scoreEl, score);
}

function animateCounter(el, target) {
  let current = 0;
  const step = Math.max(1, Math.floor(target / 30));
  const interval = setInterval(() => {
    current += step;
    if (current >= target) {
      current = target;
      clearInterval(interval);
    }
    el.textContent = current;
  }, 30);
}

// ===== ENRICHED DATA =====
function populateEnrichedData(data, isAnomaly) {
  // Model scores
  populateModelScores(data, isAnomaly);

  // Feature deviations
  if (data.feature_deviations && Object.keys(data.feature_deviations).length > 0) {
    populateDeviations(data.feature_deviations);
  }

  // Domain intelligence
  if (data.reputation_data || data.reputation_score !== null) {
    populateDomainIntel(data);
  }

  // Recent blocks
  if (data.recentBlocks && data.recentBlocks.length > 0) {
    populateRecentBlocks(data.recentBlocks);
  }

  // Update triggers with richer reasons
  if (data.reasons && data.reasons.length > 0) {
    populateTriggers(data.reasons);
  }

  // Update gauge with better score
  if (isAnomaly && data.risk_score) {
    buildGauge(data.risk_score);
  } else if (!isAnomaly && data.confidence) {
    buildGauge(Math.round(data.confidence * 100));
  }
}

// ===== MODEL SCORES =====
function populateModelScores(data, isAnomaly) {
  // Anomaly / Isolation Forest score
  const anomalyVal = document.getElementById('anomalyScoreVal');
  const anomalyFill = document.getElementById('anomalyScoreFill');

  if (isAnomaly && data.risk_score) {
    anomalyVal.textContent = data.risk_score + '%';
    setTimeout(() => { anomalyFill.style.width = data.risk_score + '%'; }, 200);
  } else if (data.confidence) {
    anomalyVal.textContent = Math.round(data.confidence * 100) + '%';
    setTimeout(() => { anomalyFill.style.width = Math.round(data.confidence * 100) + '%'; }, 200);
  }

  // ML / XGBoost score
  const mlVal = document.getElementById('mlScoreVal');
  const mlFill = document.getElementById('mlScoreFill');
  const mlScore = data.ml_raw_score || data.prediction_score || 0;
  const mlPct = Math.round(mlScore * 100);

  if (mlPct > 0) {
    mlVal.textContent = mlPct + '%';
    setTimeout(() => { mlFill.style.width = mlPct + '%'; }, 400);
  }
}

// ===== FEATURE DEVIATIONS =====
function populateDeviations(deviations) {
  const list = document.getElementById('deviationsList');
  const entries = Object.entries(deviations);
  if (entries.length === 0) return;

  list.innerHTML = '';

  entries.forEach(([feature, info]) => {
    const item = document.createElement('div');
    item.className = 'deviation-item';

    let sigma = '--';
    let barWidth = 0;

    if (typeof info === 'object' && info !== null) {
      const dev = Math.abs(info.z_score || info.deviation || 0);
      sigma = dev.toFixed(1) + 'σ';
      barWidth = Math.min(100, (dev / 5) * 100);
    } else if (typeof info === 'number') {
      sigma = Math.abs(info).toFixed(1) + 'σ';
      barWidth = Math.min(100, (Math.abs(info) / 5) * 100);
    } else if (typeof info === 'string') {
      sigma = info;
      barWidth = 50;
    }

    item.innerHTML = `
      <div class="deviation-header">
        <span class="deviation-name">${feature}</span>
        <span class="deviation-sigma">${sigma}</span>
      </div>
      <div class="deviation-bar-bg">
        <div class="deviation-bar-fill" style="width: ${barWidth}%;"></div>
      </div>
    `;
    list.appendChild(item);
  });
}

// ===== DOMAIN INTELLIGENCE =====
function populateDomainIntel(data) {
  const rep = data.reputation_data || {};
  const breakdown = rep.score_breakdown || {};

  // Trust score
  const trustEl = document.getElementById('intelTrust');
  const score = data.reputation_score ?? rep.total_score;
  if (score !== null && score !== undefined) {
    trustEl.textContent = score + '/100';
    trustEl.className = 'intel-value ' + (score >= 60 ? 'neon-text' : '');
  }

  // Domain age (from breakdown.domain_age.age_days)
  const ageEl = document.getElementById('intelAge');
  const ageDays = breakdown.domain_age?.age_days;
  if (ageDays != null && ageDays >= 0) {
    if (ageDays >= 365) ageEl.textContent = Math.floor(ageDays / 365) + ' Years';
    else if (ageDays >= 30) ageEl.textContent = Math.floor(ageDays / 30) + ' Months';
    else ageEl.textContent = ageDays + ' Days';
  } else {
    ageEl.textContent = 'Unknown';
  }

  // SSL (from breakdown.ssl_certificate.info)
  const sslEl = document.getElementById('intelSSL');
  const sslInfo = breakdown.ssl_certificate?.info;
  if (typeof sslInfo === 'object' && sslInfo !== null) {
    sslEl.textContent = sslInfo.issuer || (sslInfo.valid ? 'Valid' : 'Invalid');
  } else if (typeof sslInfo === 'string') {
    sslEl.textContent = sslInfo;
  } else {
    // Check for simple ssl string in breakdown
    const sslScore = breakdown.ssl_certificate?.score;
    sslEl.textContent = sslScore > 0 ? 'Valid' : 'Not found';
  }

  // Trust level (from reputation_data.trust_level)
  const regEl = document.getElementById('intelRegistrar');
  if (rep.trust_level) {
    regEl.textContent = rep.trust_level.charAt(0).toUpperCase() + rep.trust_level.slice(1);
  }
}

// ===== RECENT BLOCKS =====
function populateRecentBlocks(blocks) {
  const container = document.getElementById('blocksLogContainer');
  if (!blocks || blocks.length === 0) return;

  container.innerHTML = '';

  blocks.forEach(entry => {
    const div = document.createElement('div');
    div.className = 'log-entry';

    let displayUrl = entry.url || 'Unknown';
    try {
      const u = new URL(displayUrl);
      displayUrl = u.hostname;
    } catch (e) { /* keep full */ }

    const tag = entry.status === 'ANOMALY' ? 'ANOMALY' : 'BLOCKED';

    div.innerHTML = `
      <div class="log-meta">
        <span>${entry.time || '--:--'}</span>
        <span class="log-score">SCORE: ${entry.score || '--'}</span>
      </div>
      <div class="log-url">${displayUrl}</div>
      <div class="log-tag">${tag}</div>
    `;
    container.appendChild(div);
  });

  // End marker
  const end = document.createElement('div');
  end.style.cssText = 'opacity:0.3; padding:8px; border:1px dashed rgba(255,255,255,0.1); text-align:center; text-transform:uppercase; letter-spacing:-0.02em; font-size:9px;';
  end.textContent = 'End of recent stack';
  container.appendChild(end);
}

// ===== BUTTONS =====
function setupButtons(blockedUrl, isAnomaly) {
  // Back to Safety
  document.getElementById('homeBtn').addEventListener('click', function () {
    window.location.href = 'https://www.google.com';
  });

  // Close Tab
  document.getElementById('closeBtn').addEventListener('click', function () {
    window.close();
    setTimeout(() => { window.location.href = 'about:blank'; }, 100);
  });

  // Proceed
  const proceedBtn = document.getElementById('proceedBtn');
  if (proceedBtn) {
    proceedBtn.addEventListener('click', function (e) {
      e.preventDefault();
      if (blockedUrl && !this.dataset.locked) {
        window.location.href = decodeURIComponent(blockedUrl);
      }
    });
  }
}

// ===== PROCEED DELAY =====
function setupProceedDelay() {
  const btn = document.getElementById('proceedBtn');
  const delayText = document.getElementById('proceedDelay');
  let seconds = 3;

  btn.dataset.locked = 'true';
  btn.style.pointerEvents = 'none';
  btn.style.opacity = '0.3';

  const timer = setInterval(() => {
    seconds--;
    if (seconds <= 0) {
      clearInterval(timer);
      delayText.textContent = 'Override available';
      btn.style.pointerEvents = 'auto';
      btn.style.opacity = '1';
      delete btn.dataset.locked;
    } else {
      delayText.textContent = seconds + 's safety delay required';
    }
  }, 1000);
}

// ===== SIDEBAR TOGGLE =====
function setupSidebarToggle() {
  const btn = document.getElementById('systemMinimizeToggle');
  const sidebar = document.getElementById('rightSidebar');
  const grid = document.getElementById('forensicsGrid');
  const text = btn.querySelector('.toggle-text');

  btn.addEventListener('click', () => {
    const isMin = sidebar.classList.toggle('sidebar-minimized');
    grid.classList.toggle('minimized');
    text.textContent = isMin ? 'EXPAND SYSTEM DATA' : 'MINIMIZE SYSTEM DATA';
  });
}

// ===== LOG TOGGLE =====
function setupLogToggle() {
  const btn = document.getElementById('toggleLogsBtn');
  const container = document.getElementById('blocksLogContainer');

  btn.addEventListener('click', () => {
    const isExpanded = container.classList.toggle('expanded');
    const text = btn.querySelector('span:first-child');
    const icon = btn.querySelector('.log-toggle-icon');

    text.textContent = isExpanded ? 'Hide Full Logs' : 'View Full Logs';
    icon.textContent = isExpanded ? 'keyboard_double_arrow_up' : 'keyboard_double_arrow_down';
  });
}