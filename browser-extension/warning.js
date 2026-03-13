// Warning.js v4.2 — Forensics Terminal Theme
// Reads enriched data from chrome.storage.local
// Matches Stitch "Security Gateway" design

console.log('Warning.js v4.2 — Forensics Terminal loaded');

// Shared API cache — prevents redundant calls to the same endpoint
const _apiCache = {};
function getAnomaly(url) {
  if (!_apiCache['anomaly_' + url]) {
    _apiCache['anomaly_' + url] = fetch('http://localhost:8000/api/anomaly', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    }).then(r => r.json()).catch(() => null);
  }
  return _apiCache['anomaly_' + url];
}
function getML(url) {
  if (!_apiCache['ml_' + url]) {
    _apiCache['ml_' + url] = fetch('http://localhost:8000/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    }).then(r => r.json()).catch(() => null);
  }
  return _apiCache['ml_' + url];
}

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

  // Explain section toggle + populate
  setupExplainToggle();
  if (blockedUrl) populateExplainSection(blockedUrl, isAnomaly, riskScore, blockReason);
});

// ===== BASIC UI =====
function setBasicUI(blockedUrl, blockReason, source, isAnomaly, riskScore, reasons) {
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

  // Explanation — set a brief placeholder; populateExplainSection() fills real data
  const explainText = document.getElementById('explainText');
  if (explainText) {
    explainText.textContent = 'Analyzing threat data…';
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

    // Split by colon if present
    const colonIndex = reason.indexOf(':');
    let label, detail;
    
    if (colonIndex !== -1) {
      label = reason.substring(0, colonIndex).trim();
      detail = reason.substring(colonIndex + 1).trim();
    } else {
      // No colon: use full text for both
      label = reason;
      detail = reason;
    }
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
    // Anomaly block — use the stored risk_score directly
    anomalyVal.textContent = data.risk_score + '%';
    setTimeout(() => { anomalyFill.style.width = data.risk_score + '%'; }, 200);
  } else {
    // ML block — fetch the REAL anomaly score from the cache
    const urlParams = new URLSearchParams(window.location.search);
    const blockedUrl = urlParams.get('url');
    if (blockedUrl) {
      anomalyVal.textContent = '...';
      getAnomaly(blockedUrl)
      .then(result => {
        if (!result) { anomalyVal.textContent = '--'; return; }
        const realScore = result.risk_score || 0;
        anomalyVal.textContent = realScore + '%';
        setTimeout(() => { anomalyFill.style.width = realScore + '%'; }, 200);
      });
    }
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

// ===== EXPLAIN TOGGLE =====
function setupExplainToggle() {
  const header = document.getElementById('explainToggle');
  const section = document.getElementById('explainSection');
  if (!header || !section) return;

  header.addEventListener('click', () => {
    section.classList.toggle('expanded');
  });
}

// ===== POPULATE EXPLAIN SECTION =====
function populateExplainSection(blockedUrl, isAnomaly, riskScore, blockReason) {
  const url = decodeURIComponent(blockedUrl);

  // Target URL — set immediately
  const urlEl = document.getElementById('explainTargetUrl');
  if (urlEl) urlEl.textContent = url;

  // Fetch both models' results via shared cache
  const anomalyReq = getAnomaly(url);
  const mlReq = getML(url);

  Promise.all([anomalyReq, mlReq]).then(([anomaly, ml]) => {
    // --- Explanation (summary text) ---
    const summaryEl = document.getElementById('explainText');
    if (summaryEl) {
      if (isAnomaly && anomaly) {
        const mlOverride = ml && ml.status === 'LEGITIMATE';
        if (mlOverride) {
          summaryEl.innerHTML =
            `Sentinel's Isolation Forest flagged <span class="neon-text">${anomaly.reasons?.length || 0} structural anomalies</span> ` +
            `(risk score: <span class="neon-text">${anomaly.risk_score}/100</span>), but the XGBoost classifier ` +
            `identifies this URL as <span class="neon-text">LEGITIMATE</span> with ${Math.round((ml.confidence || 0) * 100)}% confidence. ` +
            `The anomaly may be a false positive due to unusual URL structure.`;
        } else {
          summaryEl.innerHTML =
            `Sentinel's Isolation Forest detected <span class="neon-text">${anomaly.reasons?.length || 0} structural anomalies</span> ` +
            `in this URL. The risk score of <span class="neon-text">${anomaly.risk_score}/100</span> exceeds the blocking threshold. ` +
            `This URL deviates significantly from known legitimate URL patterns.`;
        }
      } else if (ml) {
        const conf = Math.round((ml.confidence || 0) * 100);
        summaryEl.innerHTML =
          `Sentinel's XGBoost classifier identified this URL as <span class="neon-text">${ml.status}</span> ` +
          `with <span class="neon-text">${conf}% confidence</span>. ` +
          (ml.reason || 'Multiple threat indicators were detected.');
      }
    }

    // --- Detection Signals (deduplicated) ---
    const signalsEl = document.getElementById('explainSignals');
    if (signalsEl) {
      const seen = new Set();
      const signals = [];

      // Helper to normalize text for deduplication
      const normalize = (s) => s.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();

      if (anomaly && anomaly.reasons) {
        anomaly.reasons.forEach(r => {
          const key = normalize(r);
          if (!seen.has(key)) {
            seen.add(key);
            signals.push(`⚡ ${r}`);
          }
        });
      }
      if (anomaly && anomaly.homograph_flags && anomaly.homograph_flags.length > 0) {
        anomaly.homograph_flags.forEach(h => {
          const key = normalize(h);
          if (!seen.has(key)) {
            seen.add(key);
            signals.push(`⚡ Homograph: ${h}`);
          }
        });
      }
      if (ml && ml.reason) {
        ml.reason.split(';').forEach(r => {
          const trimmed = r.trim();
          const key = normalize(trimmed);
          if (trimmed && !seen.has(key)) {
            seen.add(key);
            signals.push(`${trimmed}`);
          }
        });
      }

      // Show ML verdict as a signal too
      if (ml && ml.status === 'LEGITIMATE') {
        signals.push(`✅ ML model classified as legitimate (${Math.round((ml.confidence || 0) * 100)}% confidence)`);
      }

      signalsEl.innerHTML = signals.length > 0
        ? signals.map(s => `<div style="margin-bottom:4px">${s}</div>`).join('')
        : 'No specific signals identified';
    }

    // --- Model Decision ---
    const decisionEl = document.getElementById('explainModelDecision');
    if (decisionEl) {
      let parts = [];
      if (anomaly) {
        parts.push(
          `<div style="margin-bottom:6px"><strong style="color:var(--neon)">Isolation Forest:</strong> ` +
          `${anomaly.risk_level || 'UNKNOWN'} — risk score ${anomaly.risk_score || 0}/100</div>`
        );
      }
      if (ml) {
        const mlConf = Math.round((ml.confidence || 0) * 100);
        parts.push(
          `<div><strong style="color:var(--neon)">XGBoost Classifier:</strong> ` +
          `${ml.status || 'UNKNOWN'} — ${mlConf}% confidence (raw score: ${(ml.prediction_score || 0).toFixed(4)})</div>`
        );
      }
      decisionEl.innerHTML = parts.join('') || 'Models unavailable';
    }

    // --- Risk Interpretation ---
    const interpEl = document.getElementById('explainRiskInterp');
    if (interpEl) {
      const aScore = anomaly?.risk_score || 0;
      const mlConf = ml ? Math.round((ml.confidence || 0) * 100) : 0;
      const mlStatus = ml?.status || '';

      let interp = '';
      if (aScore >= 70 && mlStatus === 'MALICIOUS') {
        interp = 'Both engines agree: this URL is highly dangerous. The structural pattern is abnormal AND matches known malicious signatures. Extremely high confidence in this classification.';
      } else if (mlStatus === 'MALICIOUS' && aScore < 50) {
        interp = `The ML classifier flagged this URL (${mlConf}% confidence) based on learned phishing patterns, but the anomaly engine found it structurally normal (risk: ${aScore}/100). This suggests pattern-based phishing using a clean-looking domain.`;
      } else if (aScore >= 50 && mlStatus === 'LEGITIMATE') {
        interp = `The anomaly engine flagged unusual URL structure (risk: ${aScore}/100), but the ML classifier — trained on 280K+ URLs — identifies this as LEGITIMATE with ${mlConf}% confidence. The structural deviation is likely due to long product paths, query parameters, or regional domain patterns. This is most likely a false positive.`;
      } else if (aScore >= 70 && mlStatus !== 'MALICIOUS') {
        interp = `The anomaly engine detected significant structural deviations (risk: ${aScore}/100), but the ML classifier did not match known malicious patterns. This may be a zero-day threat or an unusual but legitimate URL.`;
      } else if (mlStatus === 'SUSPICIOUS') {
        interp = `The URL shows some concerning patterns but does not fully match known malicious signatures. Exercise caution.`;
      } else {
        interp = blockReason ? decodeURIComponent(blockReason) : 'URL was flagged based on combined analysis from multiple detection engines.';
      }
      interpEl.textContent = interp;
    }

    // --- Recommended Action ---
    const actionEl = document.getElementById('explainAction');
    if (actionEl) {
      const mlStatus = ml?.status || '';
      const mlConf = ml ? Math.round((ml.confidence || 0) * 100) : 0;
      const aScore = anomaly?.risk_score || 0;

      if (mlStatus === 'MALICIOUS' && aScore >= 70) {
        actionEl.textContent = 'Do NOT proceed. Navigate away immediately. If you received this link via email or message, report it as phishing.';
      } else if (mlStatus === 'MALICIOUS') {
        actionEl.textContent = 'Do NOT proceed. The ML model has identified this URL as malicious with high confidence.';
      } else if (aScore >= 50 && mlStatus === 'LEGITIMATE' && mlConf >= 70) {
        actionEl.textContent = `This URL is likely safe. The ML model classifies it as legitimate with ${mlConf}% confidence. The anomaly flag is likely a false positive caused by unusual URL structure (long paths, product IDs, etc.). You may proceed.`;
      } else if (aScore >= 70) {
        actionEl.textContent = 'Proceed with caution. The URL has unusual structural patterns. Verify the domain independently before entering credentials.';
      } else if (mlStatus === 'SUSPICIOUS' || aScore >= 50) {
        actionEl.textContent = 'Proceed with caution. Verify the URL independently before entering any credentials or personal information.';
      } else {
        actionEl.textContent = 'This URL was flagged by automated heuristics. If you trust the source, you may proceed.';
      }
    }
  });
}

// ===== FEATURE IMPORTANCE RADAR CHART =====
(function initFeatureImportance() {
  const openBtn = document.getElementById('featureImportanceBtn');
  const overlay = document.getElementById('fiModalOverlay');
  const closeBtn = document.getElementById('fiCloseBtn');
  const toggleNorm = document.getElementById('fiToggleNorm');
  const exportBtn = document.getElementById('fiExportBtn');

  if (!openBtn || !overlay) return;

  let isNormalized = false;
  let radarData = null;
  let animProgress = 0;
  let animFrame = null;

  // Readable names for ML features
  const FEATURE_LABELS = {
    subdomain_count: 'Subdomain Count',
    domain_length: 'Domain Length',
    entropy: 'Entropy',
    brand_without_official_tld: 'Brand Impersonation',
    num_hyphens: 'Hyphen Count',
    has_path: 'Has Path',
    path_length: 'Path Length',
    url_length: 'URL Length',
    digit_ratio: 'Digit Ratio',
    num_dots: 'Dot Count',
    is_ip_address: 'IP Address',
    is_suspicious_tld: 'Suspicious TLD',
    has_at_symbol: '@ Symbol',
    num_at: '@ Count',
    long_path: 'Long Path',
    high_entropy: 'High Entropy',
    is_https: 'HTTPS',
    special_char_ratio: 'Special Chars',
    num_params: 'URL Params',
    path_depth: 'Path Depth'
  };

  // Features we care about for the radar (most meaningful for risk)
  const IMPORTANT_FEATURES = [
    'subdomain_count', 'domain_length', 'entropy',
    'brand_without_official_tld', 'num_hyphens', 'path_length',
    'digit_ratio', 'num_dots', 'is_ip_address', 'is_suspicious_tld',
    'has_at_symbol', 'long_path', 'high_entropy', 'special_char_ratio'
  ];

  function getFeatureData() {
    // Get the blocked URL from the page's URL params
    const urlParams = new URLSearchParams(window.location.search);
    const blockedUrl = urlParams.get('url');

    if (!blockedUrl) return Promise.resolve(buildFallbackData());

    // Use the shared cache for the anomaly API call
    return getAnomaly(blockedUrl)
    .then(result => {
      if (!result) return buildFallbackFromStorage();
      const items = [];

      // Extract feature_deviations from the anomaly response
      if (result.feature_deviations && typeof result.feature_deviations === 'object') {
        for (const [key, info] of Object.entries(result.feature_deviations)) {
          const zScore = typeof info === 'object' ? Math.abs(info.z_score || 0) : Math.abs(info || 0);
          if (zScore > 0) {
            items.push({
              name: FEATURE_LABELS[key] || formatFeatureName(key),
              raw: parseFloat(zScore.toFixed(2))
            });
          }
        }
      }

      if (items.length < 3) return buildFallbackFromStorage();

      // Sort by z-score descending, take top 8
      items.sort((a, b) => b.raw - a.raw);
      const top = items.slice(0, 8);
      const maxVal = Math.max(...top.map(i => i.raw), 1);
      return top.map(i => ({
        name: i.name,
        value: i.raw / maxVal,
        raw: i.raw
      }));
    })
    .catch(() => buildFallbackFromStorage());
  }

  // Fallback: try chrome.storage transparency features
  function buildFallbackFromStorage() {
    return new Promise((resolve) => {
      if (typeof chrome === 'undefined' || !chrome.storage) {
        resolve(buildFallbackData());
        return;
      }
      chrome.storage.local.get('lastBlockData', (result) => {
        const data = result.lastBlockData;
        if (!data || !data.transparency) { resolve(buildFallbackData()); return; }

        const items = [];
        for (const key of IMPORTANT_FEATURES) {
          const val = data.transparency[key];
          if (val !== undefined && val !== null && val > 0) {
            items.push({
              name: FEATURE_LABELS[key] || formatFeatureName(key),
              raw: val
            });
          }
        }

        if (items.length < 3) { resolve(buildFallbackData()); return; }

        items.sort((a, b) => b.raw - a.raw);
        const top = items.slice(0, 8);
        const maxVal = Math.max(...top.map(i => i.raw), 1);
        resolve(top.map(i => ({
          name: i.name,
          value: i.raw / maxVal,
          raw: i.raw
        })));
      });
    });
  }

  function formatFeatureName(key) {
    return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }

  function buildFallbackData() {
    const defaults = [
      { name: 'Subdomain Count', raw: 0.21 },
      { name: 'Domain Length', raw: 0.17 },
      { name: 'Entropy', raw: 0.15 },
      { name: 'Brand Impersonation', raw: 0.14 },
      { name: 'Hyphen Count', raw: 0.11 }
    ];
    const maxVal = Math.max(...defaults.map(f => f.raw));
    return defaults.map(f => ({ name: f.name, value: f.raw / maxVal, raw: f.raw }));
  }

  function drawRadar(canvas, data, progress) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const W = 400;
    const H = 400;
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width = W + 'px';
    canvas.style.height = H + 'px';
    ctx.scale(dpr, dpr);

    const cx = W / 2;
    const cy = H / 2;
    const maxR = 150;
    const n = data.length;
    const angleStep = (Math.PI * 2) / n;
    const startAngle = -Math.PI / 2;

    // Clear
    ctx.clearRect(0, 0, W, H);

    // Grid rings
    const rings = 5;
    for (let r = 1; r <= rings; r++) {
      const radius = (maxR / rings) * r;
      ctx.beginPath();
      for (let i = 0; i <= n; i++) {
        const angle = startAngle + angleStep * i;
        const x = cx + Math.cos(angle) * radius;
        const y = cy + Math.sin(angle) * radius;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.strokeStyle = `rgba(0, 255, 0, ${r === rings ? 0.15 : 0.06})`;
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Axis lines
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(angle) * maxR, cy + Math.sin(angle) * maxR);
      ctx.strokeStyle = 'rgba(0, 255, 0, 0.08)';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Data polygon (animated)
    ctx.beginPath();
    for (let i = 0; i <= n; i++) {
      const idx = i % n;
      const angle = startAngle + angleStep * idx;
      const val = data[idx].value * progress;
      const r = val * maxR;
      const x = cx + Math.cos(angle) * r;
      const y = cy + Math.sin(angle) * r;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.fillStyle = 'rgba(0, 255, 0, 0.12)';
    ctx.fill();
    ctx.strokeStyle = '#00FF00';
    ctx.lineWidth = 2;
    ctx.shadowColor = '#00FF00';
    ctx.shadowBlur = 8;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Data points
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      const val = data[i].value * progress;
      const r = val * maxR;
      const x = cx + Math.cos(angle) * r;
      const y = cy + Math.sin(angle) * r;

      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#00FF00';
      ctx.shadowColor = '#00FF00';
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // Labels
    ctx.font = '700 10px "Space Mono", monospace';
    ctx.textAlign = 'center';
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      const labelR = maxR + 24;
      let x = cx + Math.cos(angle) * labelR;
      let y = cy + Math.sin(angle) * labelR;

      // Adjust alignment based on position
      if (Math.cos(angle) > 0.3) ctx.textAlign = 'left';
      else if (Math.cos(angle) < -0.3) ctx.textAlign = 'right';
      else ctx.textAlign = 'center';

      ctx.fillStyle = '#777777';
      ctx.fillText(data[i].name, x, y);

      // Value below label
      const valText = isNormalized
        ? Math.round(data[i].value * 100) + '%'
        : '+' + data[i].raw.toFixed(2);
      ctx.fillStyle = '#00FF00';
      ctx.font = '700 9px "Space Mono", monospace';
      ctx.fillText(valText, x, y + 13);
      ctx.font = '700 10px "Space Mono", monospace';
    }

    ctx.textAlign = 'left';
  }

  function buildLegend(data) {
    const legend = document.getElementById('fiLegend');
    if (!legend) return;
    legend.innerHTML = '';
    data.forEach(d => {
      const item = document.createElement('div');
      item.className = 'fi-legend-item';
      const valText = isNormalized
        ? Math.round(d.value * 100) + '%'
        : '+' + d.raw.toFixed(2);
      item.innerHTML = `
        <span class="fi-legend-dot"></span>
        <span>${d.name}</span>
        <span class="fi-legend-val">${valText}</span>
      `;
      legend.appendChild(item);
    });
  }

  async function openModal() {
    radarData = await getFeatureData();
    overlay.classList.add('active');
    buildLegend(radarData);

    // Animate radar drawing
    animProgress = 0;
    if (animFrame) cancelAnimationFrame(animFrame);

    const canvas = document.getElementById('radarCanvas');
    const duration = 800;
    const start = performance.now();

    function animate(now) {
      const elapsed = now - start;
      animProgress = Math.min(1, elapsed / duration);
      // Ease out cubic
      const t = 1 - Math.pow(1 - animProgress, 3);
      drawRadar(canvas, radarData, t);
      if (animProgress < 1) {
        animFrame = requestAnimationFrame(animate);
      }
    }
    animFrame = requestAnimationFrame(animate);
  }

  function closeModal() {
    overlay.classList.remove('active');
    if (animFrame) cancelAnimationFrame(animFrame);
  }

  // Event listeners
  openBtn.addEventListener('click', openModal);
  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal();
  });

  // Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay.classList.contains('active')) closeModal();
  });

  // Percentage toggle
  toggleNorm.addEventListener('click', () => {
    isNormalized = !isNormalized;
    toggleNorm.classList.toggle('active', isNormalized);
    if (radarData) {
      const canvas = document.getElementById('radarCanvas');
      drawRadar(canvas, radarData, 1);
      buildLegend(radarData);
    }
  });

  // Export as PNG
  exportBtn.addEventListener('click', () => {
    const canvas = document.getElementById('radarCanvas');
    // Redraw on a temp canvas with black background for export
    const expCanvas = document.createElement('canvas');
    const dpr = window.devicePixelRatio || 1;
    expCanvas.width = canvas.width;
    expCanvas.height = canvas.height;
    const expCtx = expCanvas.getContext('2d');
    expCtx.fillStyle = '#050505';
    expCtx.fillRect(0, 0, expCanvas.width, expCanvas.height);
    expCtx.drawImage(canvas, 0, 0);

    const link = document.createElement('a');
    link.download = 'sentinel-feature-importance.png';
    link.href = expCanvas.toDataURL('image/png');
    link.click();
  });

  // Canvas hover tooltip
  const canvas = document.getElementById('radarCanvas');
  const tooltip = document.createElement('div');
  tooltip.style.cssText = `
    position: fixed; padding: 6px 10px; background: rgba(0,0,0,0.9);
    border: 1px solid rgba(0,255,0,0.3); color: #00FF00;
    font: 700 10px 'Space Mono', monospace; pointer-events: none;
    z-index: 200; display: none; white-space: nowrap;
  `;
  document.body.appendChild(tooltip);

  canvas.addEventListener('mousemove', (e) => {
    if (!radarData) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const cx = 200, cy = 200, maxR = 150;
    const n = radarData.length;
    const startAngle = -Math.PI / 2;
    const angleStep = (Math.PI * 2) / n;

    let hit = null;
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      const r = radarData[i].value * maxR;
      const px = cx + Math.cos(angle) * r;
      const py = cy + Math.sin(angle) * r;
      const dist = Math.hypot(mx - px, my - py);
      if (dist < 12) { hit = radarData[i]; break; }
    }

    if (hit) {
      tooltip.style.display = 'block';
      tooltip.style.left = (e.clientX + 12) + 'px';
      tooltip.style.top = (e.clientY - 8) + 'px';
      const val = isNormalized ? Math.round(hit.value * 100) + '%' : '+' + hit.raw.toFixed(2);
      tooltip.textContent = `${hit.name}: ${val}`;
    } else {
      tooltip.style.display = 'none';
    }
  });

  canvas.addEventListener('mouseleave', () => {
    tooltip.style.display = 'none';
  });
})();