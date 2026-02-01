// Modern Popup JavaScript with Charts and URL Scanner

let stats = {
  totalChecked: 0,
  blocked: 0,
  warnings: 0,
  legitimate: 0
};

let recentActivity = [];

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  await loadStats();
  updateUI();
  setupEventListeners();
  drawChart();
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
  
  // Add protocol if missing
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  
  // Validate URL
  try {
    new URL(url);
  } catch {
    showNotification('Invalid URL format', 'warning');
    return;
  }
  
  // Show loading state
  scanBtn.classList.add('loading');
  scanBtn.innerHTML = `
    <svg class="btn-icon" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" opacity="0.25"/>
      <path d="M12 2a10 10 0 0110 10" stroke="currentColor" stroke-width="2" stroke-linecap="round">
        <animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite"/>
      </path>
    </svg>
    Scanning...
  `;
  
  resultDiv.classList.add('hidden');
  
  const startTime = Date.now();
  
  try {
    // Call backend API
    const response = await fetch('http://localhost:8000/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });
    
    if (!response.ok) {
      throw new Error('API request failed');
    }
    
    const result = await response.json();
    const processingTime = Date.now() - startTime;
    
    displayResult(result, url, processingTime);
    
    // Add to activity
    addToActivity(url, result.status);
    
  } catch (error) {
    console.error('Scan error:', error);
    showNotification('Failed to scan URL. Is the backend running?', 'error');
  } finally {
    // Reset button
    scanBtn.classList.remove('loading');
    scanBtn.innerHTML = `
      <svg class="btn-icon" viewBox="0 0 24 24" fill="none">
        <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" 
              stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
      </svg>
      Scan
    `;
  }
}

// Display scan result
function displayResult(result, url, processingTime) {
  const resultDiv = document.getElementById('scanResult');
  const resultIcon = document.getElementById('resultIcon');
  const resultStatus = document.getElementById('resultStatus');
  const resultUrl = document.getElementById('resultUrl');
  const confidenceBar = document.getElementById('confidenceBar');
  const confidenceText = document.getElementById('confidenceText');
  const resultReason = document.getElementById('resultReason');
  const processingTimeEl = document.getElementById('processingTime');
  
  // Determine status
  let status, icon, iconClass;
  
  if (result.status === 'MALICIOUS') {
    status = '🚫 Malicious Website';
    icon = '⚠️';
    iconClass = 'malicious';
  } else if (result.status === 'SUSPICIOUS') {
    status = '⚠️ Suspicious Website';
    icon = '⚠️';
    iconClass = 'suspicious';
  } else {
    status = '✅ Safe Website';
    icon = '✓';
    iconClass = 'safe';
  }
  
  // Update UI
  resultIcon.textContent = icon;
  resultIcon.className = `result-icon ${iconClass}`;
  resultStatus.textContent = status;
  resultUrl.textContent = url;
  
  const confidence = Math.round(result.confidence * 100);
  confidenceBar.style.width = confidence + '%';
  confidenceText.textContent = confidence + '%';
  
  // Color confidence bar based on status
  if (result.status === 'MALICIOUS') {
    confidenceBar.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
  } else if (result.status === 'SUSPICIOUS') {
    confidenceBar.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
  } else {
    confidenceBar.style.background = 'linear-gradient(90deg, #10b981, #059669)';
  }
  
  resultReason.textContent = result.reason || 'No details available';
  processingTimeEl.textContent = `${processingTime}ms`;
  
  resultDiv.classList.remove('hidden');
}

// Add to recent activity
function addToActivity(url, status) {
  const timeline = document.getElementById('activityTimeline');
  
  // Remove empty state
  const empty = timeline.querySelector('.timeline-empty');
  if (empty) {
    empty.remove();
  }
  
  // Create activity item
  const item = document.createElement('div');
  item.className = `timeline-item ${status.toLowerCase()}`;
  
  let icon;
  if (status === 'MALICIOUS') icon = '🚫';
  else if (status === 'SUSPICIOUS') icon = '⚠️';
  else icon = '✓';
  
  const time = new Date().toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit'
  });
  
  item.innerHTML = `
    <div class="timeline-icon">${icon}</div>
    <div class="timeline-content">
      <div class="timeline-url">${url}</div>
      <div class="timeline-time">${time}</div>
    </div>
  `;
  
  // Add to top
  timeline.insertBefore(item, timeline.firstChild);
  
  // Keep only last 5
  const items = timeline.querySelectorAll('.timeline-item');
  if (items.length > 5) {
    items[items.length - 1].remove();
  }
}

// Update UI with stats
function updateUI() {
  document.getElementById('blockedCount').textContent = stats.blocked;
  document.getElementById('safeCount').textContent = stats.legitimate;
  document.getElementById('warningCount').textContent = stats.warnings;
  document.getElementById('totalCount').textContent = stats.totalChecked;
  
  document.getElementById('legendBlocked').textContent = `Blocked: ${stats.blocked}`;
  document.getElementById('legendSafe').textContent = `Safe: ${stats.legitimate}`;
  document.getElementById('legendWarning').textContent = `Warnings: ${stats.warnings}`;
  
  drawChart();
}

// Draw donut chart
function drawChart() {
  const svg = document.getElementById('chartSvg');
  const chartTotal = document.getElementById('chartTotal');
  
  const total = stats.totalChecked || 1; // Avoid division by zero
  chartTotal.textContent = stats.totalChecked;
  
  const blocked = stats.blocked;
  const warnings = stats.warnings;
  const safe = stats.legitimate;
  
  // Calculate percentages
  const blockedPct = (blocked / total) * 100;
  const warningsPct = (warnings / total) * 100;
  const safePct = (safe / total) * 100;
  
  // Draw donut chart
  const radius = 90;
  const strokeWidth = 20;
  const circumference = 2 * Math.PI * radius;
  
  // Calculate stroke dasharray for each segment
  const blockedDash = (blockedPct / 100) * circumference;
  const warningsDash = (warningsPct / 100) * circumference;
  const safeDash = (safePct / 100) * circumference;
  
  // Clear existing paths
  svg.innerHTML = '';
  
  let currentOffset = 0;
  
  // Blocked segment
  if (blocked > 0) {
    const path = createCircleSegment(blockedDash, currentOffset, '#ef4444');
    svg.appendChild(path);
    currentOffset += blockedDash;
  }
  
  // Warnings segment
  if (warnings > 0) {
    const path = createCircleSegment(warningsDash, currentOffset, '#f59e0b');
    svg.appendChild(path);
    currentOffset += warningsDash;
  }
  
  // Safe segment
  if (safe > 0) {
    const path = createCircleSegment(safeDash, currentOffset, '#10b981');
    svg.appendChild(path);
  }
}

function createCircleSegment(dashLength, offset, color) {
  const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  const radius = 90;
  const strokeWidth = 20;
  const circumference = 2 * Math.PI * radius;
  
  circle.setAttribute('cx', '100');
  circle.setAttribute('cy', '100');
  circle.setAttribute('r', radius);
  circle.setAttribute('fill', 'none');
  circle.setAttribute('stroke', color);
  circle.setAttribute('stroke-width', strokeWidth);
  circle.setAttribute('stroke-dasharray', `${dashLength} ${circumference}`);
  circle.setAttribute('stroke-dashoffset', -offset);
  circle.setAttribute('transform', 'rotate(-90 100 100)');
  
  return circle;
}

// Clear cache
async function clearCache() {
  try {
    await chrome.runtime.sendMessage({ action: 'clearCache' });
    showNotification('Cache cleared successfully', 'success');
  } catch (error) {
    showNotification('Failed to clear cache', 'error');
  }
}

// Show notification
function showNotification(message, type) {
  // Create toast notification
  const toast = document.createElement('div');
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#f59e0b'};
    color: white;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    z-index: 1000;
    animation: slideIn 0.3s ease-out;
  `;
  toast.textContent = message;
  
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease-out';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Auto-refresh stats every 5 seconds
setInterval(async () => {
  await loadStats();
  updateUI();
}, 5000);