// content.js - PDF Malware Detector
// This script runs on every page to assist with PDF detection and scanning.

console.log('PDF Malware Detector: Content script active');

// Function to find PDF links on the page
function findPDFLinks() {
    const links = document.getElementsByTagName('a');
    for (let link of links) {
        if (link.href && link.href.toLowerCase().includes('.pdf')) {
            // Found a PDF link! 
            // We could add a "Scan" badge here in the future.
        }
    }
}

// Help background script identify PDFs that might not have .pdf extension
// by checking the link text or other attributes
document.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (link && link.href) {
        const fn = link.href.toLowerCase();
        const isLikelyDoc = fn.includes('.pdf') ||
                           link.textContent.toLowerCase().includes('.pdf') ||
                           link.getAttribute('type') === 'application/pdf';
        
        if (isLikelyDoc) {
            console.log('PDF link clicked:', link.href);
            // We could pre-scan here if we wanted to
        }
    }
}, true);

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'ping') {
        sendResponse({status: 'ok'});
        return true;
    }
    
    if (request.action === 'showScanningOverlay') {
        createScanningOverlay(request.filename);
        sendResponse({status: 'overlay_shown'});
    }

    if (request.action === 'updateScanResult') {
        updateOverlayResult(request.result, request.pendingId, request.filename);
        sendResponse({status: 'result_updated'});
    }

    if (request.action === 'fetchBlob') {
        console.log('PDF Malware Detector: Fetching blob for', request.url);
        fetch(request.url)
            .then(response => response.blob())
            .then(blob => {
                const reader = new FileReader();
                reader.onloadend = () => {
                    sendResponse({ dataUrl: reader.result });
                };
                reader.readAsDataURL(blob);
            })
            .catch(error => {
                console.error('Fetch error:', error);
                sendResponse({ error: error.message });
            });
        return true; // Keep channel open for async response
    }
});

function createScanningOverlay(filename) {
    const existing = document.getElementById('pdf-scanner-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'pdf-scanner-overlay';
    overlay.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 380px;
        background: white;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        overflow: hidden;
        animation: slideInUp 0.4s ease-out;
        border: 1px solid #eee;
    `;

    overlay.innerHTML = `
        <div style="padding: 15px; display: flex; align-items: center; background: #f8f9fa; border-bottom: 1px solid #eee;">
            <div class="scanner-spinner" style="
                width: 20px;
                height: 20px;
                border: 3px solid #667eea;
                border-top: 3px solid transparent;
                border-radius: 50%;
                margin-right: 12px;
                animation: spin 1s linear infinite;
            "></div>
            <div style="font-weight: bold; color: #333;">Analyzing PDF Safety...</div>
        </div>
        <div style="padding: 15px;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px; padding: 8px 12px; background: #fff3cd; border-radius: 8px; border: 1px solid #ffc107;">
                <span style="font-size: 16px;">🔒</span>
                <span style="font-size: 12px; color: #856404; font-weight: 600;">File held in temporary sandbox — NOT saved to Downloads</span>
            </div>
            <div style="font-size: 14px; color: #666; margin-bottom: 5px;">File:</div>
            <div style="font-size: 14px; color: #333; font-weight: 500; word-break: break-all;">${filename}</div>
            <div style="margin-top: 15px; font-size: 12px; color: #888;">
                Using AI to check for malicious scripts, JavaScript, and structural anomalies in the PDF.
            </div>
        </div>
        <style>
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            @keyframes slideInUp { from { transform: translateY(100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        </style>
    `;

    document.body.appendChild(overlay);
}

function updateOverlayResult(res, pendingId, filename) {
    const overlay = document.getElementById('pdf-scanner-overlay');
    if (!overlay) return;

    const prediction = res.prediction;
    const isSafe = prediction === 'safe';
    const isError = prediction === 'error';
    
    let badgeText = isSafe ? '✓ SAFE' : (isError ? '❓ SCAN ERROR' : '⚠️ MALICIOUS');
    let headerBg = isSafe ? '#28a745' : (isError ? '#ffc107' : '#dc3545');

    overlay.innerHTML = `
        <div style="padding: 15px; display: flex; align-items: center; justify-content: space-between; background: ${headerBg}; color: white;">
            <div style="font-weight: bold;">Scan Result: ${badgeText}</div>
            <button id="close-overlay" style="background: none; border: none; color: white; cursor: pointer; font-size: 20px;">&times;</button>
        </div>
        <div style="padding: 15px;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px; padding: 8px 12px; background: #fff3cd; border-radius: 8px; border: 1px solid #ffc107;">
                <span style="font-size: 16px;">🔒</span>
                <span style="font-size: 12px; color: #856404; font-weight: 600;">File is in temporary sandbox — NOT saved to Downloads yet</span>
            </div>
            <div style="margin-bottom: 12px;">
                <div style="font-size: 14px; color: #666; margin-bottom: 4px;">File:</div>
                <div style="font-size: 14px; font-weight: bold; color: #333; word-break: break-all;">${filename || 'Unknown'}</div>
            </div>
            <div style="margin-bottom: 12px;">
                <div style="font-size: 16px; font-weight: bold; color: #333; margin-bottom: 8px;">
                    Confidence: ${(res.confidence * 100).toFixed(1)}%
                </div>
                <div style="font-size: 13px; line-height: 1.5; color: #444; background: #f8f9fa; padding: 10px; border-radius: 6px; margin-top: 10px; white-space: pre-wrap; max-height: 200px; overflow-y: auto;">
                    ${res.summary || 'No summary available.'}
                </div>
            </div>
            
            <div style="display: flex; gap: 10px;">
                ${isSafe ? 
                    `<button id="overlay-approve" style="flex: 1; padding: 10px; background: #28a745; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 14px;">✓ Save to Downloads</button>
                     <button id="overlay-cancel" style="flex: 1; padding: 10px; background: #f8f9fa; color: #333; border: 1px solid #ddd; border-radius: 6px; cursor: pointer; font-size: 14px;">Cancel</button>` :
                    `<button id="overlay-block" style="flex: 1; padding: 10px; background: #dc3545; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 14px;">🛑 Block File</button>
                     <button id="overlay-anyway" style="flex: 1; padding: 10px; background: #f8f9fa; color: #333; border: 1px solid #ddd; border-radius: 6px; cursor: pointer; font-size: 14px;">Download Anyway</button>`
                }
            </div>
        </div>
    `;

    // Close button — treat as block/cancel (discard from sandbox)
    document.getElementById('close-overlay').onclick = () => {
        chrome.runtime.sendMessage({ action: 'downloadBlocked', pendingId: pendingId });
        overlay.remove();
    };

    // --- SAFE FILE BUTTONS ---
    if (document.getElementById('overlay-approve')) {
        document.getElementById('overlay-approve').onclick = () => {
            chrome.runtime.sendMessage({
                action: 'downloadApproved',
                pendingId: pendingId,
                prediction: res.prediction,
                confidence: res.confidence
            });
            overlay.innerHTML = `
                <div style="padding: 20px; text-align: center;">
                    <div style="font-size: 32px; margin-bottom: 8px;">✅</div>
                    <div style="font-weight: bold; color: #28a745; font-size: 16px;">File saved to Downloads!</div>
                </div>
            `;
            setTimeout(() => overlay.remove(), 2500);
        };
    }
    if (document.getElementById('overlay-cancel')) {
        document.getElementById('overlay-cancel').onclick = () => {
            chrome.runtime.sendMessage({ action: 'downloadBlocked', pendingId: pendingId });
            overlay.innerHTML = `
                <div style="padding: 20px; text-align: center;">
                    <div style="font-size: 32px; margin-bottom: 8px;">❌</div>
                    <div style="font-weight: bold; color: #6c757d; font-size: 16px;">Download cancelled</div>
                </div>
            `;
            setTimeout(() => overlay.remove(), 1500);
        };
    }

    // --- MALICIOUS FILE BUTTONS ---
    if (document.getElementById('overlay-block')) {
        document.getElementById('overlay-block').onclick = () => {
            chrome.runtime.sendMessage({ 
                action: 'downloadBlocked', 
                pendingId: pendingId,
                prediction: res.prediction,
                confidence: res.confidence
            });
            overlay.innerHTML = `
                <div style="padding: 20px; text-align: center;">
                    <div style="font-size: 32px; margin-bottom: 8px;">🛑</div>
                    <div style="font-weight: bold; color: #dc3545; font-size: 16px;">Malicious file blocked!</div>
                    <div style="font-size: 13px; color: #666; margin-top: 4px;">File was discarded from sandbox.</div>
                </div>
            `;
            setTimeout(() => overlay.remove(), 2500);
        };
    }
    if (document.getElementById('overlay-anyway')) {
        document.getElementById('overlay-anyway').onclick = () => {
            chrome.runtime.sendMessage({
                action: 'downloadApproved',
                pendingId: pendingId,
                prediction: res.prediction,
                confidence: res.confidence,
                forcedByUser: true
            });
            overlay.innerHTML = `
                <div style="padding: 20px; text-align: center;">
                    <div style="font-size: 32px; margin-bottom: 8px;">⚠️</div>
                    <div style="font-weight: bold; color: #ffc107; font-size: 16px;">File saved (user override)</div>
                    <div style="font-size: 13px; color: #666; margin-top: 4px;">Proceed with caution.</div>
                </div>
            `;
            setTimeout(() => overlay.remove(), 2500);
        };
    }
}
