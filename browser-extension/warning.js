console.log('Warning.js loaded!');

document.addEventListener('DOMContentLoaded', function() {
  console.log('DOM Content Loaded!');
  
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = urlParams.get('url');
  const blockReason = urlParams.get('reason');
  
  console.log('URL from params:', blockedUrl);
  console.log('Reason from params:', blockReason);
  
  const urlElement = document.getElementById('blockedUrl');
  const reasonElement = document.getElementById('blockReason');
  
  if (urlElement) {
    if (blockedUrl) {
      urlElement.textContent = decodeURIComponent(blockedUrl);
      console.log('Set URL to:', urlElement.textContent);
    } else {
      urlElement.textContent = 'Unknown URL';
      console.log('No URL parameter found');
    }
  } else {
    console.error('blockedUrl element not found!');
  }
  
  if (reasonElement) {
    if (blockReason) {
      reasonElement.textContent = decodeURIComponent(blockReason);
      console.log('Set reason to:', reasonElement.textContent);
    } else {
      reasonElement.textContent = 'This URL was flagged as potentially malicious.';
      console.log('No reason parameter found');
    }
  } else {
    console.error('blockReason element not found!');
  }
  
  const closeBtn = document.getElementById('closeBtn');
  if (closeBtn) {
    console.log('Close button found');
    closeBtn.addEventListener('click', function() {
      console.log('Close button clicked!');
      window.close();
      setTimeout(function() {
        console.log('Navigating to blank');
        window.location.href = 'about:blank';
      }, 100);
    });
  } else {
    console.error('Close button not found!');
  }
  
  const homeBtn = document.getElementById('homeBtn');
  if (homeBtn) {
    console.log('Home button found');
    homeBtn.addEventListener('click', function() {
      console.log('Home button clicked!');
      window.location.href = 'https://www.google.com';
    });
  } else {
    console.error('Home button not found!');
  }
  
  console.log('All event listeners attached!');
});