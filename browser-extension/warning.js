console.log('Warning.js v3.0.0 loaded');

document.addEventListener('DOMContentLoaded', function () {
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = urlParams.get('url');
  const blockReason = urlParams.get('reason');
  const source = urlParams.get('source') || 'UNKNOWN';
  const type = urlParams.get('type') || 'block';     // 'block' or 'anomaly'
  const riskScore = parseInt(urlParams.get('risk_score') || '0');
  let reasons = [];

  try {
    const rawReasons = urlParams.get('reasons');
    if (rawReasons) {
      reasons = JSON.parse(decodeURIComponent(rawReasons));
    }
  } catch (e) {
    console.error('Failed to parse reasons:', e);
  }

  // Set mode
  const isAnomaly = type === 'anomaly';
  document.body.classList.add(isAnomaly ? 'mode-anomaly' : 'mode-block');

  // Icon
  const iconEl = document.getElementById('warningIcon');
  if (isAnomaly) {
    iconEl.textContent = '!';
    iconEl.classList.add('icon-anomaly');
  } else {
    iconEl.textContent = '!';
    iconEl.classList.add('icon-block');
  }

  // Source badge
  const badgeEl = document.getElementById('sourceBadge');
  const sourceLabels = {
    'ANOMALY_DETECTION': 'Zero-Day Anomaly Detection',
    'ML_CLASSIFIER': 'ML Classifier',
    'HEURISTIC': 'Heuristic Filter',
    'CACHED': 'Cached Result'
  };
  badgeEl.textContent = sourceLabels[source] || source;

  if (isAnomaly) {
    badgeEl.classList.add('badge-anomaly');
  } else if (source === 'HEURISTIC') {
    badgeEl.classList.add('badge-heuristic');
  } else {
    badgeEl.classList.add('badge-ml');
  }

  // Title
  const titleEl = document.getElementById('warningTitle');
  if (isAnomaly) {
    titleEl.textContent = 'Structural Anomaly Detected';
    titleEl.classList.add('anomaly-title');
  } else {
    titleEl.textContent = 'Malicious Website Blocked';
    titleEl.classList.add('block-title');
  }

  // Message
  const msgEl = document.getElementById('warningMessage');
  if (isAnomaly) {
    msgEl.textContent =
      'This URL\'s structure is statistically different from normal browsing patterns. ' +
      'It may be safe, but it was flagged for your review.';
  } else {
    msgEl.textContent =
      'This website has been identified as potentially dangerous and was blocked for your safety.';
  }

  // URL
  const urlEl = document.getElementById('blockedUrl');
  urlEl.textContent = blockedUrl ? decodeURIComponent(blockedUrl) : 'Unknown URL';

  // Risk gauge (anomaly only)
  if (isAnomaly && riskScore > 0) {
    const scoreTextEl = document.getElementById('riskScoreText');
    const fillEl = document.getElementById('riskGaugeFill');

    scoreTextEl.textContent = riskScore;

    // Set color class
    let riskClass = 'risk-low';
    if (riskScore >= 70) riskClass = 'risk-high';
    else if (riskScore >= 50) riskClass = 'risk-medium';

    scoreTextEl.classList.add(riskClass);
    fillEl.classList.add(riskClass);

    // Animate fill after a short delay
    setTimeout(() => {
      fillEl.style.width = riskScore + '%';
    }, 100);
  }

  // Reasons list (anomaly only)
  if (isAnomaly && reasons.length > 0) {
    const ulEl = document.getElementById('reasonsUl');
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      ulEl.appendChild(li);
    });
  } else if (isAnomaly && blockReason) {
    const ulEl = document.getElementById('reasonsUl');
    const li = document.createElement('li');
    li.textContent = decodeURIComponent(blockReason);
    ulEl.appendChild(li);
  }

  // Single reason (block mode)
  if (!isAnomaly) {
    const reasonEl = document.getElementById('blockReason');
    reasonEl.textContent = blockReason
      ? decodeURIComponent(blockReason)
      : 'This URL was flagged as potentially malicious.';
  }

  // Button handlers

  // Close tab
  document.getElementById('closeBtn').addEventListener('click', function () {
    window.close();
    setTimeout(() => { window.location.href = 'about:blank'; }, 100);
  });

  // Go home
  document.getElementById('homeBtn').addEventListener('click', function () {
    window.location.href = 'https://www.google.com';
  });

  // Proceed anyway (anomaly override)
  const proceedBtn = document.getElementById('proceedBtn');
  if (proceedBtn) {
    proceedBtn.addEventListener('click', function () {
      if (blockedUrl) {
        // Navigate to the original URL
        window.location.href = decodeURIComponent(blockedUrl);
      }
    });
  }

  console.log(`Warning page initialized: type=${type}, source=${source}, riskScore=${riskScore}`);
});