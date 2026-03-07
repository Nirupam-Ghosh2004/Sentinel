// Sentinel v3.0.0 - Background Script
// Anomaly Detection + ML Classification
// All processing is local

// Load sub-modules (Manifest V3 service worker)
importScripts('anomaly_engine.js', 'homograph_checker.js');

// ==================== CACHE MANAGER ====================
class CacheManager {
  constructor() {
    this.cacheDuration = 3600000; // 1 hour
  }

  async get(url) {
    try {
      const result = await chrome.storage.local.get([url]);
      if (result[url]) {
        const cached = result[url];
        if (Date.now() - cached.timestamp < this.cacheDuration) {
          return cached.data;
        }
        await this.remove(url);
      }
      return null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set(url, data) {
    try {
      const cacheEntry = { data: data, timestamp: Date.now() };
      await chrome.storage.local.set({ [url]: cacheEntry });
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }

  async remove(url) {
    try {
      await chrome.storage.local.remove([url]);
    } catch (error) {
      console.error('Cache remove error:', error);
    }
  }

  async clear() {
    try {
      await chrome.storage.local.clear();
    } catch (error) {
      console.error('Cache clear error:', error);
    }
  }
}

// ==================== WHITELIST ====================
const SAFE_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
  'reddit.com', 'wikipedia.org', 'amazon.com', 'ebay.com',
  'microsoft.com', 'apple.com', 'netflix.com', 'yahoo.com',
  'leetcode.com', 'hackerrank.com',
  'twitch.tv', 'discord.com', 'slack.com', 'zoom.us',
  'pinterest.com', 'tumblr.com', 'dropbox.com', 'notion.so',
  // Office & productivity
  'office365.com', 'office.com', 'outlook.com', 'live.com',
  'microsoftonline.com', 'sharepoint.com', 'onedrive.com',
  // Streaming & media
  'primevideo.com', 'hotstar.com', 'spotify.com', 'soundcloud.com',
  'hulu.com', 'disneyplus.com',
  // Education & learning
  'pwskills.com', 'udemy.com', 'coursera.org', 'edx.org',
  'khanacademy.org', 'geeksforgeeks.org',
  // Shopping
  'flipkart.com', 'myntra.com', 'walmart.com', 'target.com',
  // Social & messaging
  'whatsapp.com', 'telegram.org', 'signal.org', 'snapchat.com',
  // Dev tools (NOT hosting platforms — those need scanning)
  'gitlab.com', 'bitbucket.org', 'npmjs.com', 'pypi.org',
  'docker.com',
  // NOTE: vercel.app, netlify.app, herokuapp.com, codepen.io, replit.com
  // are INTENTIONALLY excluded — anyone can deploy phishing on them
  // News & media
  'bbc.com', 'cnn.com', 'nytimes.com', 'medium.com', 'substack.com',
  // Cloud & infra
  'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
  // Other popular
  'quora.com', 'bing.com', 'duckduckgo.com', 'archive.org',
];

const LONG_URL_OK_DOMAINS = [
  'google.com', 'youtube.com', 'amazon.com', 'ebay.com',
  'github.com', 'stackoverflow.com', 'reddit.com',
  'leetcode.com', 'hackerrank.com', 'twitter.com',
  'facebook.com', 'linkedin.com', 'pinterest.com',
  'primevideo.com', 'flipkart.com', 'office365.com',
  'outlook.com', 'sharepoint.com',
];

// ==================== UTILITY FUNCTIONS ====================
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (error) {
    return '';
  }
}

function isWhitelistedDomain(url) {
  const hostname = extractDomain(url).toLowerCase();
  return SAFE_DOMAINS.some(domain =>
    hostname === domain || hostname.endsWith('.' + domain)
  );
}

function allowsLongURLs(url) {
  const hostname = extractDomain(url).toLowerCase();
  return LONG_URL_OK_DOMAINS.some(domain =>
    hostname === domain || hostname.endsWith('.' + domain)
  );
}

function calculateEntropy(str) {
  const len = str.length;
  const frequencies = {};
  for (let char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (let char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function extractFeatures(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const path = urlObj.pathname;

    return {
      urlLength: url.length,
      pathLength: path.length,
      domainLength: hostname.length,
      numDots: (url.match(/\./g) || []).length,
      numAt: (url.match(/@/g) || []).length,
      subdomainCount: hostname.split('.').length - 2,
      hasIPAddress: /^\d+\.\d+\.\d+\.\d+$/.test(hostname),
      tld: hostname.split('.').pop(),
      suspiciousTLD: ['tk', 'ml', 'ga', 'cf', 'gq'].includes(hostname.split('.').pop()),
      entropy: calculateEntropy(hostname)
    };
  } catch (error) {
    return null;
  }
}

// ==================== HEURISTICS ====================
// Only catch the ONE pattern the anomaly engine can't score well:
// @ symbol redirect attacks (http://google.com@evil.com sends you to evil.com)
function quickHeuristicCheck(url) {
  try {
    const features = extractFeatures(url);
    if (!features) return { shouldBlock: false };

    // @ symbol is an actual redirect attack, not just suspicious structure
    if (features.numAt > 0) {
      return { shouldBlock: true, reason: 'URL contains @ symbol — possible redirect attack', confidence: 0.95 };
    }
  } catch (e) { /* ignore */ }

  return { shouldBlock: false };
}

// ==================== BACKEND APIs ====================
const BACKEND_API = 'http://localhost:8000/api';
const cache = new CacheManager();

let stats = {
  totalChecked: 0,
  blocked: 0,
  warnings: 0,
  legitimate: 0,
  // Anomaly-specific stats
  anomaliesDetected: 0,
  anomalySuspicious: 0,
  homographsDetected: 0
};

// Recent activity log, shared with popup
let recentActivity = [];
const MAX_ACTIVITY = 20;

function addActivity(url, status, reason) {
  recentActivity.unshift({
    url: url,
    status: status,
    reason: reason || '',
    time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
    timestamp: Date.now()
  });
  if (recentActivity.length > MAX_ACTIVITY) {
    recentActivity = recentActivity.slice(0, MAX_ACTIVITY);
  }
}

const blockedTabs = new Set();

// ML backend client
async function checkWithBackendML(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(`${BACKEND_API}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`ML API returned status: ${response.status}`);
      return null;
    }

    const data = await response.json();
    console.log('ML API response:', data);
    return data;

  } catch (error) {
    if (error.name === 'AbortError') {
      console.error('ML API timeout');
    } else {
      console.error('ML API error:', error.message);
    }
    return null;
  }
}

// ==================== MAIN DETECTION PIPELINE ====================
async function checkAndBlockURL(details) {
  // Only check main page navigations
  if (details.type !== 'main_frame') return;

  // Skip internal pages
  if (details.url.startsWith('chrome://') ||
    details.url.startsWith('chrome-extension://') ||
    details.url.startsWith('about:') ||
    details.url.startsWith('edge://')) {
    return;
  }

  const url = details.url;
  const tabId = details.tabId;
  if (tabId === -1) return;

  // Skip if we just blocked this tab
  if (blockedTabs.has(tabId)) {
    blockedTabs.delete(tabId);
    return;
  }

  console.log('Checking URL:', url);

  try {
    // Step 1: Whitelist check
    if (isWhitelistedDomain(url)) {
      stats.totalChecked++;
      stats.legitimate++;
      console.log('[OK] Whitelisted:', url);
      addActivity(url, 'SAFE', 'Whitelisted domain');
      return;
    }

    // Step 2: Cache check
    const cachedResult = await cache.get(url);
    if (cachedResult) {
      stats.totalChecked++;
      handleCachedResult(tabId, url, cachedResult);
      return;
    }

    // Step 3: Client-side homograph check
    const homographResult = checkHomograph(url);
    if (homographResult.isSuspicious) {
      stats.homographsDetected++;
      console.log('Homograph detected:', homographResult.reasons);
    }

    // Step 4: @ symbol check
    const heuristicResult = quickHeuristicCheck(url);
    if (heuristicResult.shouldBlock) {
      const result = {
        status: 'MALICIOUS',
        confidence: heuristicResult.confidence,
        reason: heuristicResult.reason,
        source: 'local_heuristics'
      };

      await cache.set(url, result);
      stats.totalChecked++;
      stats.blocked++;
      console.log('[BLOCK] Heuristic block:', url);
      blockTab(tabId, url, heuristicResult.reason, 'HEURISTIC');
      addActivity(url, 'BLOCKED', heuristicResult.reason);
      return;
    }

    // Step 5: Anomaly detection (backend, local only)
    console.log('Calling anomaly detection engine...');
    const anomalyResult = await checkUrlAnomaly(url);

    if (anomalyResult) {
      // Combine anomaly result with client-side homograph
      const effectiveRiskScore = Math.min(
        anomalyResult.risk_score + homographResult.riskBoost,
        100
      );
      const effectiveLevel = effectiveRiskScore >= 70 ? 'HIGH_ANOMALY'
        : effectiveRiskScore >= 50 ? 'SUSPICIOUS'
          : 'NORMAL';

      if (effectiveLevel === 'HIGH_ANOMALY') {
        const allReasons = [
          ...anomalyResult.reasons,
          ...homographResult.reasons
        ];

        const result = {
          status: 'ANOMALY',
          risk_score: effectiveRiskScore,
          risk_level: effectiveLevel,
          confidence: effectiveRiskScore / 100,
          reason: allReasons.join('; ') || 'Structurally abnormal URL detected',
          reasons: allReasons,
          source: 'anomaly_detection',
          allow_override: true
        };

        await cache.set(url, result);
        stats.totalChecked++;
        stats.anomaliesDetected++;
        console.log('[ANOMALY]', url, `(risk: ${effectiveRiskScore})`);

        // Warning page with override, not hard block
        showAnomalyWarning(tabId, url, result);
        addActivity(url, 'ANOMALY', allReasons[0] || 'Structural anomaly');
        return;
      }

      if (effectiveLevel === 'SUSPICIOUS') {
        stats.anomalySuspicious++;
        console.log('[WARN] Anomaly suspicious:', url, `(risk: ${effectiveRiskScore})`);
        warnUser(url,
          anomalyResult.reasons[0] || 'URL shows unusual structural patterns',
          effectiveRiskScore / 100
        );
        // Don't block, just notify — continue to ML check for second opinion
      }
    }

    // Step 6: ML classification (complementary to anomaly)
    console.log('Calling ML classifier...');
    const mlResult = await checkWithBackendML(url);

    if (mlResult) {
      stats.totalChecked++;

      if (mlResult.status === 'MALICIOUS') {
        // ML detected malicious pattern, block regardless of anomaly score
        const result = {
          status: 'MALICIOUS',
          confidence: mlResult.confidence,
          reason: mlResult.reason,
          source: 'backend_ml'
        };
        await cache.set(url, result);
        stats.blocked++;
        console.log('[BLOCK] ML:', url);
        blockTab(tabId, url, mlResult.reason, 'ML_CLASSIFIER', mlResult);
        addActivity(url, 'BLOCKED', mlResult.reason);
      } else if (mlResult.status === 'SUSPICIOUS') {
        stats.warnings++;
        console.log('[WARN] ML:', url);
        warnUser(url, mlResult.reason, mlResult.confidence);
        addActivity(url, 'SUSPICIOUS', mlResult.reason);
      } else {
        stats.legitimate++;
        console.log('[OK] ML safe:', url);
        addActivity(url, 'SAFE', 'Passed all checks');
      }
    } else {
      // Both backends unavailable — use local checks only
      console.log('[WARN] Backends unavailable, using local checks only');
      const result = {
        status: 'LEGITIMATE',
        confidence: 0.5,
        reason: 'Backends unavailable, local checks passed',
        source: 'local_fallback'
      };

      await cache.set(url, result);
      stats.totalChecked++;
      stats.legitimate++;
    }

  } catch (error) {
    console.error('Error in checkAndBlockURL:', error);
    // On error, allow the page to load (fail-safe)
  }
}

// ==================== RESULT HANDLERS ====================

function handleCachedResult(tabId, url, cachedResult) {
  if (cachedResult.status === 'MALICIOUS') {
    stats.blocked++;
    console.log('[BLOCK] Cache hit:', url);
    blockTab(tabId, url, cachedResult.reason, cachedResult.source || 'CACHED');
  } else if (cachedResult.status === 'ANOMALY') {
    stats.anomaliesDetected++;
    console.log('[ANOMALY] Cache hit:', url);
    showAnomalyWarning(tabId, url, cachedResult);
  } else if (cachedResult.status === 'SUSPICIOUS') {
    stats.warnings++;
    console.log('[WARN] Cache hit:', url);
    warnUser(url, cachedResult.reason, cachedResult.confidence);
  } else {
    stats.legitimate++;
    console.log('[OK] Cache hit:', url);
  }
}

function blockTab(tabId, url, reason, source, mlData) {
  blockedTabs.add(tabId);

  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('assets/icons/icon48.png'),
    title: 'Malicious Website Blocked',
    message: reason || 'This site was flagged as dangerous',
    priority: 2
  });

  console.log('[BLOCK]', url, '| Source:', source, '| Reason:', reason);

  // Store enriched data for the warning page
  const feats = mlData?.features || {};
  const blockData = {
    type: 'block',
    url: url,
    reason: reason || 'Malicious site detected',
    source: source || 'UNKNOWN',
    confidence: mlData?.confidence || 0,
    prediction_score: mlData?.prediction_score || 0,
    ml_raw_score: feats.ml_raw_score || mlData?.prediction_score || 0,
    reputation_score: feats.reputation_score ?? null,
    reputation_data: feats.reputation_data || null,
    transparency: feats,
    recentBlocks: recentActivity.filter(a => a.status === 'BLOCKED' || a.status === 'ANOMALY').slice(0, 5),
    timestamp: Date.now()
  };
  chrome.storage.local.set({ lastBlockData: blockData });

  const warningUrl = chrome.runtime.getURL('warning.html') +
    '?url=' + encodeURIComponent(url) +
    '&reason=' + encodeURIComponent(reason || 'Malicious site detected') +
    '&source=' + encodeURIComponent(source || 'UNKNOWN') +
    '&type=block';

  chrome.tabs.update(tabId, { url: warningUrl });
}

function showAnomalyWarning(tabId, url, result) {
  blockedTabs.add(tabId);

  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('assets/icons/icon48.png'),
    title: 'Structural Anomaly Detected',
    message: `Risk score: ${result.risk_score}/100 — ${result.reasons?.[0] || 'Unusual URL pattern'}`,
    priority: 1
  });

  console.log('[ANOMALY]', url, '| Risk:', result.risk_score);

  // Store enriched data for the warning page
  const blockData = {
    type: 'anomaly',
    url: url,
    reason: result.reason || 'Structural anomaly detected',
    source: 'ANOMALY_DETECTION',
    risk_score: result.risk_score || 0,
    risk_level: result.risk_level || 'HIGH_ANOMALY',
    reasons: result.reasons || [],
    feature_deviations: result.feature_deviations || {},
    homograph_flags: result.homograph_flags || [],
    processing_time_ms: result.processing_time_ms || 0,
    confidence: result.confidence || (result.risk_score / 100),
    recentBlocks: recentActivity.filter(a => a.status === 'BLOCKED' || a.status === 'ANOMALY').slice(0, 5),
    timestamp: Date.now()
  };
  chrome.storage.local.set({ lastBlockData: blockData });

  const warningUrl = chrome.runtime.getURL('warning.html') +
    '?url=' + encodeURIComponent(url) +
    '&reason=' + encodeURIComponent(result.reason || 'Structural anomaly detected') +
    '&source=ANOMALY_DETECTION' +
    '&type=anomaly' +
    '&risk_score=' + encodeURIComponent(result.risk_score) +
    '&reasons=' + encodeURIComponent(JSON.stringify(result.reasons || []));

  chrome.tabs.update(tabId, { url: warningUrl });
}

function warnUser(url, reason, confidence) {
  const confidencePct = confidence ? (confidence * 100).toFixed(0) : '50';

  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('assets/icons/icon48.png'),
    title: 'Suspicious Website',
    message: `${reason} (${confidencePct}% confidence)`,
    priority: 1
  });

  console.log('[WARN]', url);
}

// ==================== EVENT LISTENERS ====================

// Listen to navigation requests
chrome.webRequest.onBeforeRequest.addListener(
  checkAndBlockURL,
  {
    urls: ["<all_urls>"],
    types: ["main_frame"]
  }
);

// Message handler for popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getStats') {
    sendResponse({ ...stats, recentActivity: recentActivity });
  } else if (request.action === 'getActivity') {
    sendResponse(recentActivity);
  } else if (request.action === 'clearCache') {
    // Only clear URL cache entries, not stats
    chrome.storage.local.get(null, (items) => {
      const urlKeys = Object.keys(items).filter(key =>
        key.startsWith('http://') || key.startsWith('https://')
      );
      if (urlKeys.length > 0) {
        chrome.storage.local.remove(urlKeys, () => {
          sendResponse({ success: true, cleared: urlKeys.length });
        });
      } else {
        sendResponse({ success: true, cleared: 0 });
      }
    });
    return true; // Async response
  }
  return true;
});

// Startup log
console.log('Sentinel v3.0.0 loaded');
console.log('  Anomaly Detection enabled');
console.log('  ML Classification enabled');
console.log('  Homograph Protection enabled');
console.log('  Backend API:', BACKEND_API);
console.log('  All processing local');