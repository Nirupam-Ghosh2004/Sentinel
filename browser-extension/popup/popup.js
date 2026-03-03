// Sentinel Popup — handles stats, URL scanning, activity, and visual effects

let stats = {
  totalChecked: 0,
  blocked: 0,
  warnings: 0,
  legitimate: 0,
  anomaliesDetected: 0,
  anomalySuspicious: 0,
  homographsDetected: 0
};

let recentActivity = [];

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  await loadStats();
  updateUI();
  setupEventListeners();
});

// Setup event listeners
function setupEventListeners() {
  const scanBtn = document.getElementById('scanBtn');
  const urlInput = document.getElementById('urlInput');
  const clearCacheBtn = document.getElementById('clearCacheBtn');

  scanBtn.addEventListener('click', scanURL);
  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') scanURL();
  });
  clearCacheBtn.addEventListener('click', clearCache);
}

// Load stats from background
async function loadStats() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getStats' });
    if (response) {
      stats = response;
      if (response.recentActivity && response.recentActivity.length > 0) {
        renderActivity(response.recentActivity);
      }
    }
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
}

// Scan URL
async function scanURL() {
  const urlInput = document.getElementById('urlInput');
  const scanBtn = document.getElementById('scanBtn');
  const resultDiv = document.getElementById('scanResult');

  let url = urlInput.value.trim();

  if (!url) {
    showNotification('Please enter a URL', 'warning');
    return;
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  try {
    new URL(url);
  } catch {
    showNotification('Invalid URL format', 'warning');
    return;
  }

  // Loading state
  scanBtn.classList.add('loading');
  scanBtn.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" width="14" height="14">
      <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" opacity="0.25"/>
      <path d="M12 2a10 10 0 0110 10" stroke="currentColor" stroke-width="2" stroke-linecap="round">
        <animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite"/>
      </path>
    </svg>
  `;
  resultDiv.classList.add('hidden');

  const startTime = Date.now();

  try {
    const [mlResponse, anomalyResponse] = await Promise.allSettled([
      fetch('http://localhost:8000/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      }),
      fetch('http://localhost:8000/api/anomaly', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      })
    ]);

    let result = null;
    let anomalyResult = null;

    if (mlResponse.status === 'fulfilled' && mlResponse.value.ok) {
      result = await mlResponse.value.json();
    }
    if (anomalyResponse.status === 'fulfilled' && anomalyResponse.value.ok) {
      anomalyResult = await anomalyResponse.value.json();
    }
    if (!result && !anomalyResult) {
      throw new Error('Both APIs failed');
    }

    const processingTime = Date.now() - startTime;
    displayResult(result, anomalyResult, url, processingTime);

    const displayStatus = anomalyResult?.risk_level === 'HIGH_ANOMALY' ? 'ANOMALY'
      : (result?.status || 'LEGITIMATE');
    addToActivity(url, displayStatus);

  } catch (error) {
    console.error('Scan error:', error);
    showNotification('Backend unreachable — is the server running?', 'error');
  } finally {
    scanBtn.classList.remove('loading');
    scanBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" width="14" height="14">
        <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
      </svg>
    `;
  }
}

// Display scan result
function displayResult(result, anomalyResult, url, processingTime) {
  const resultDiv = document.getElementById('scanResult');
  const resultIcon = document.getElementById('resultIcon');
  const resultStatus = document.getElementById('resultStatus');
  const resultUrl = document.getElementById('resultUrl');
  const confidenceBar = document.getElementById('confidenceBar');
  const confidenceText = document.getElementById('confidenceText');
  const resultReason = document.getElementById('resultReason');
  const processingTimeEl = document.getElementById('processingTime');

  let status, icon, iconClass;
  let confidence = 0;
  let reason = '';

  if (anomalyResult && anomalyResult.risk_level === 'HIGH_ANOMALY') {
    status = 'Structural Anomaly';
    icon = '';
    iconClass = 'suspicious';
    confidence = anomalyResult.risk_score / 100;
    reason = anomalyResult.reasons?.join('; ') || 'Structurally abnormal URL';
  } else if (anomalyResult && anomalyResult.risk_level === 'SUSPICIOUS') {
    status = 'Unusual Pattern';
    icon = '';
    iconClass = 'suspicious';
    confidence = anomalyResult.risk_score / 100;
    reason = anomalyResult.reasons?.join('; ') || 'Some unusual patterns detected';
  } else if (result && result.status === 'MALICIOUS') {
    status = 'Malicious Website';
    icon = '';
    iconClass = 'malicious';
    confidence = result.confidence;
    reason = result.reason;
  } else if (result && result.status === 'SUSPICIOUS') {
    status = 'Suspicious Website';
    icon = '';
    iconClass = 'suspicious';
    confidence = result.confidence;
    reason = result.reason;
  } else {
    status = 'Safe Website';
    icon = '';
    iconClass = 'safe';
    confidence = result ? result.confidence : (anomalyResult ? (1 - anomalyResult.risk_score / 100) : 0.5);
    reason = result ? result.reason : 'No anomalies detected';
  }

  if (anomalyResult && anomalyResult.risk_level !== 'HIGH_ANOMALY') {
    reason += ` | Anomaly risk: ${anomalyResult.risk_score}/100`;
  }

  resultIcon.textContent = icon;
  resultIcon.className = `result-icon ${iconClass}`;
  resultStatus.textContent = status;
  resultUrl.textContent = url;

  const confPct = Math.round(confidence * 100);
  confidenceBar.style.width = confPct + '%';
  confidenceText.textContent = confPct + '%';

  if (iconClass === 'malicious') {
    confidenceBar.style.background = 'linear-gradient(90deg, #FF3B3B, #FF6B6B)';
  } else if (iconClass === 'suspicious') {
    confidenceBar.style.background = 'linear-gradient(90deg, #FFB020, #FFD060)';
  } else {
    confidenceBar.style.background = 'linear-gradient(90deg, #00E676, #69F0AE)';
  }

  resultReason.textContent = reason || 'No details available';
  processingTimeEl.textContent = `${processingTime}ms`;
  resultDiv.classList.remove('hidden');
}

// Render recent activity from background data
function renderActivity(activities) {
  const timeline = document.getElementById('activityTimeline');
  if (!timeline) return;
  timeline.innerHTML = '';

  if (!activities || activities.length === 0) {
    timeline.innerHTML = '<div class="timeline-empty"><p>No activity yet</p></div>';
    return;
  }

  const items = activities.slice(0, 5);

  for (const activity of items) {
    const item = document.createElement('div');
    const statusClass = activity.status === 'BLOCKED' ? 'malicious'
      : activity.status === 'ANOMALY' ? 'anomaly'
        : activity.status === 'SUSPICIOUS' ? 'suspicious'
          : 'legitimate';
    item.className = `timeline-item ${statusClass}`;

    let icon;
    if (activity.status === 'BLOCKED') icon = '';
    else if (activity.status === 'ANOMALY') icon = '';
    else if (activity.status === 'SUSPICIOUS') icon = '';
    else icon = '';

    let displayUrl = activity.url;
    try {
      const urlObj = new URL(activity.url);
      displayUrl = urlObj.hostname + (urlObj.pathname !== '/' ? urlObj.pathname : '');
      if (displayUrl.length > 35) displayUrl = displayUrl.substring(0, 32) + '...';
    } catch (e) {
      if (displayUrl.length > 35) displayUrl = displayUrl.substring(0, 32) + '...';
    }

    item.innerHTML = `
      <div class="timeline-icon">${icon}</div>
      <div class="timeline-content">
        <div class="timeline-url" title="${activity.url}">${displayUrl}</div>
        <div class="timeline-time">${activity.time}</div>
      </div>
    `;
    timeline.appendChild(item);
  }
}

// Add to recent activity (for popup scans)
function addToActivity(url, status) {
  const timeline = document.getElementById('activityTimeline');
  const empty = timeline.querySelector('.timeline-empty');
  if (empty) empty.remove();

  const item = document.createElement('div');
  const statusClass = status === 'MALICIOUS' ? 'malicious'
    : status === 'ANOMALY' ? 'anomaly'
      : status === 'SUSPICIOUS' ? 'suspicious'
        : 'legitimate';
  item.className = `timeline-item ${statusClass}`;

  let icon;
  if (status === 'MALICIOUS') icon = '';
  else if (status === 'ANOMALY') icon = '';
  else if (status === 'SUSPICIOUS') icon = '';
  else icon = '';

  const time = new Date().toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit'
  });

  let displayUrl = url;
  try {
    const urlObj = new URL(url);
    displayUrl = urlObj.hostname + (urlObj.pathname !== '/' ? urlObj.pathname : '');
    if (displayUrl.length > 35) displayUrl = displayUrl.substring(0, 32) + '...';
  } catch (e) {
    if (displayUrl.length > 35) displayUrl = displayUrl.substring(0, 32) + '...';
  }

  item.innerHTML = `
    <div class="timeline-icon">${icon}</div>
    <div class="timeline-content">
      <div class="timeline-url" title="${url}">${displayUrl}</div>
      <div class="timeline-time">${time}</div>
    </div>
  `;

  timeline.insertBefore(item, timeline.firstChild);

  const items = timeline.querySelectorAll('.timeline-item');
  if (items.length > 5) items[items.length - 1].remove();
}

// Update UI with stats
function updateUI() {
  document.getElementById('blockedCount').textContent = stats.blocked || 0;
  document.getElementById('safeCount').textContent = stats.legitimate || 0;
  document.getElementById('warningCount').textContent = stats.warnings || 0;
  document.getElementById('totalCount').textContent = stats.totalChecked || 0;
  document.getElementById('anomalyCount').textContent = stats.anomaliesDetected || 0;
  document.getElementById('homographCount').textContent = stats.homographsDetected || 0;

  document.getElementById('legendBlocked').textContent = `Blocked: ${stats.blocked || 0}`;
  document.getElementById('legendSafe').textContent = `Safe: ${stats.legitimate || 0}`;
  document.getElementById('legendWarning').textContent = `Warnings: ${stats.warnings || 0}`;

  updateThreatBars();
}

// Horizontal threat bar chart
function updateThreatBars() {
  const total = stats.totalChecked || 1;
  const blockedPct = ((stats.blocked || 0) / total) * 100;
  const warningPct = ((stats.warnings || 0) / total) * 100;
  const safePct = ((stats.legitimate || 0) / total) * 100;

  const barBlocked = document.getElementById('barBlocked');
  const barWarning = document.getElementById('barWarning');
  const barSafe = document.getElementById('barSafe');

  if (barBlocked) barBlocked.style.width = blockedPct + '%';
  if (barWarning) barWarning.style.width = warningPct + '%';
  if (barSafe) barSafe.style.width = safePct + '%';
}

// Clear cache
async function clearCache() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'clearCache' });
    const count = response?.cleared || 0;
    showNotification(`Cache cleared (${count} entries)`, 'success');
  } catch (error) {
    showNotification('Failed to clear cache', 'error');
  }
}

// Toast notification
function showNotification(message, type) {
  const toast = document.createElement('div');
  const bg = type === 'success' ? '#00E676' : type === 'error' ? '#FF3B3B' : '#FFB020';
  toast.style.cssText = `
    position: fixed;
    top: 12px;
    left: 50%;
    transform: translateX(-50%);
    padding: 8px 16px;
    background: ${bg};
    color: ${type === 'success' ? '#000' : '#fff'};
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    z-index: 100;
    animation: slideIn 0.3s ease-out;
    white-space: nowrap;
    font-family: 'Inter', sans-serif;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

// Auto-refresh stats every 5 seconds
setInterval(async () => {
  await loadStats();
  updateUI();
}, 5000);

// ===== CURSOR GLOW =====
(function initCursorGlow() {
  const glow = document.getElementById('cursorGlow');
  if (!glow) return;

  document.addEventListener('mousemove', (e) => {
    glow.style.left = e.clientX + 'px';
    glow.style.top = e.clientY + 'px';
    glow.style.opacity = '1';
  });

  document.addEventListener('mouseleave', () => {
    glow.style.opacity = '0';
  });
})();

// ===== BACKGROUND PARTICLES =====
(function initParticles() {
  const canvas = document.getElementById('particleCanvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let particles = [];
  const COUNT = 30;

  function resize() {
    canvas.width = document.body.clientWidth;
    canvas.height = document.body.scrollHeight || 560;
  }

  function create() {
    return {
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      r: Math.random() * 1.2 + 0.4,
      dx: (Math.random() - 0.5) * 0.25,
      dy: (Math.random() - 0.5) * 0.25,
      o: Math.random() * 0.25 + 0.05
    };
  }

  resize();
  for (let i = 0; i < COUNT; i++) particles.push(create());

  (function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of particles) {
      p.x += p.dx;
      p.y += p.dy;
      if (p.x < 0) p.x = canvas.width;
      if (p.x > canvas.width) p.x = 0;
      if (p.y < 0) p.y = canvas.height;
      if (p.y > canvas.height) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(139, 92, 246, ${p.o})`;
      ctx.fill();
    }
    requestAnimationFrame(draw);
  })();

  window.addEventListener('resize', resize);
})();