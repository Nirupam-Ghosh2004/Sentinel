// Load statistics when popup opens
document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  
  document.getElementById('refreshBtn').addEventListener('click', loadStats);
  document.getElementById('clearCacheBtn').addEventListener('click', clearCache);
});

function loadStats() {
  chrome.runtime.sendMessage({ action: 'getStats' }, (response) => {
    if (response) {
      document.getElementById('totalChecked').textContent = response.totalChecked;
      document.getElementById('blocked').textContent = response.blocked;
      document.getElementById('warnings').textContent = response.warnings;
      document.getElementById('legitimate').textContent = response.legitimate;
    }
  });
}

function clearCache() {
  chrome.storage.local.clear(() => {
    alert('Cache cleared successfully!');
    loadStats();
  });
}
