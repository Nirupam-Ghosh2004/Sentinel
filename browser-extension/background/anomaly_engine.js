// ==================== ANOMALY ENGINE ====================
// Client-side integration with the backend anomaly detection API
// Privacy-first: sends URL to LOCAL backend only, no external calls

const ANOMALY_API = 'http://localhost:8000/api';

/**
 * Check a URL against the local anomaly detection engine.
 * 
 * @param {string} url - The URL to analyze
 * @returns {Object|null} - Risk result or null if backend unavailable
 */
async function checkUrlAnomaly(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`${ANOMALY_API}/anomaly`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`Anomaly API returned status: ${response.status}`);
      return null;
    }

    const data = await response.json();
    console.log('Anomaly API response:', data);
    return data;

  } catch (error) {
    if (error.name === 'AbortError') {
      console.error('Anomaly API timeout');
    } else {
      console.error('Anomaly API error:', error.message);
    }
    return null;
  }
}

/**
 * Fetch anomaly detection statistics from the backend.
 * 
 * @returns {Object|null} - Stats object or null
 */
async function getAnomalyStats() {
  try {
    const response = await fetch(`${ANOMALY_API}/anomaly/stats`, {
      method: 'GET',
      signal: AbortSignal.timeout(3000)
    });

    if (response.ok) {
      return await response.json();
    }
    return null;
  } catch {
    return null;
  }
}
