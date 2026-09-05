document.addEventListener('DOMContentLoaded', async () => {
    const noScanEl = document.getElementById('no-scan');
    const scanResultEl = document.getElementById('scan-result');
    const badgeEl = document.getElementById('prediction-badge');
    const confidenceEl = document.getElementById('confidence');
    const sourceEl = document.getElementById('url-source');
    const summaryEl = document.getElementById('summary-text');
    const allowBtn = document.getElementById('allow-btn');
    const blockBtn = document.getElementById('block-btn');
    const toggleSwitch = document.getElementById('extension-toggle');
    const toggleLabel = document.querySelector('.toggle-label');

    // Load extension state
    const { extensionEnabled } = await chrome.storage.local.get('extensionEnabled');
    const isEnabled = extensionEnabled !== false; // Default to enabled
    toggleSwitch.checked = isEnabled;
    updateToggleLabel(isEnabled);

    // Toggle switch handler
    toggleSwitch.addEventListener('change', async () => {
        const newState = toggleSwitch.checked;
        await chrome.storage.local.set({ extensionEnabled: newState });
        updateToggleLabel(newState);
        
        if (newState) {
            // Extension enabled
            console.log('PDF Protection enabled');
        } else {
            // Extension disabled
            console.log('PDF Protection disabled');
            chrome.storage.local.remove('lastScan');
        }
    });

    function updateToggleLabel(enabled) {
        toggleLabel.textContent = enabled ? 'Protection Active' : 'Protection Disabled';
        toggleLabel.style.color = enabled ? '#28a745' : '#dc3545';
    }

    // Load last scan from storage
    const data = await chrome.storage.local.get('lastScan');
    const lastScan = data.lastScan;

    if (lastScan && (Date.now() - lastScan.timestamp < 3600000)) { // Valid for 1 hour
        noScanEl.classList.add('hidden');
        scanResultEl.classList.remove('hidden');

        const isMalicious = lastScan.prediction === "malicious";
        badgeEl.textContent = lastScan.prediction.toUpperCase();
        badgeEl.className = `badge ${isMalicious ? 'malicious' : 'safe'}`;
        confidenceEl.textContent = `${(lastScan.confidence * 100).toFixed(1)}%`;
        sourceEl.textContent = lastScan.url;
        
        // Show full summary for malicious files
        const summaryBox = document.querySelector('.summary-box');
        if (isMalicious) {
            summaryBox.classList.remove('hidden');
            summaryEl.textContent = lastScan.summary;
            summaryEl.style.whiteSpace = 'pre-wrap';
        } else {
            summaryBox.classList.add('hidden');
        }

        allowBtn.onclick = () => {
            chrome.downloads.download({ url: lastScan.url });
            chrome.storage.local.remove('lastScan');
            window.close();
        };

        blockBtn.onclick = () => {
            chrome.storage.local.remove('lastScan');
            window.close();
        };
    } else {
        noScanEl.classList.remove('hidden');
        scanResultEl.classList.add('hidden');
    }
});
