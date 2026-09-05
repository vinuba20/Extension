const API_URL = "http://localhost:8000/predict-file";
const FEEDBACK_URL = "http://localhost:8000/feedback";

let currentPopupTabId = null;
let popupTimeoutId = null;

// State management
const scannedUrls = new Map(); 
const activeScans = new Set(); 
const whitelistedDownloads = new Set(); // Track download URLs we triggered ourselves

// --- SANDBOX: Store pending downloads in memory until user approves ---
// Map<string, { blobDataUrl: string, filename: string, scanResult: object, originalUrl: string }>
const pendingDownloads = new Map();
let pendingIdCounter = 0;

function generatePendingId() {
    return `pending_${Date.now()}_${++pendingIdCounter}`;
}

// Function to create a small corner popup (fallback when content script unavailable)
async function showCornerPopup(result, pendingId, filename) {
    if (popupTimeoutId) clearTimeout(popupTimeoutId);
    await removeExistingPopup();

    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    if (!tab) return;

    const iconUrl = chrome.runtime.getURL('icon.png');
    try {
        await chrome.scripting.executeScript({
            target: {tabId: tab.id},
            func: (res, pId, fname, icon) => {
                const existing = document.getElementById('pdf-scanner-popup');
                if (existing) existing.remove();
                
                const prediction = res.prediction;
                const isSafe = prediction === 'safe';
                const isError = prediction === 'error';
                let badgeBg = isSafe ? '#28a745' : (isError ? '#ffc107' : '#dc3545');
                let statusIcon = isSafe ? '✓' : (isError ? '❓' : '⚠️');
                let statusText = isSafe ? 'PDF SAFE' : (isError ? 'SCAN ERROR' : 'MALICIOUS PDF');
                
                const card = document.createElement('div');
                card.id = 'pdf-scanner-popup';
                card.style.cssText = `position:fixed;top:20px;right:20px;width:400px;background:white;z-index:2147483647;border-radius:12px;box-shadow:0 15px 40px rgba(0,0,0,0.3);font-family:sans-serif;overflow:hidden;border:1px solid #eee;animation:popupSlideIn 0.4s ease-out;`;
                
                // Add animation keyframes
                const style = document.createElement('style');
                style.textContent = `
                    @keyframes popupSlideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
                    @keyframes sandboxPulse { 0%, 100% { opacity: 0.7; } 50% { opacity: 1; } }
                `;
                document.head.appendChild(style);

                card.innerHTML = `
                    <div style="background:${badgeBg};color:white;padding:15px;font-weight:bold;display:flex;justify-content:space-between;align-items:center;">
                        <span style="font-size:16px;">${statusIcon} ${statusText}</span>
                        <span id="pdf-scanner-close" style="cursor:pointer;font-size:24px;">×</span>
                    </div>
                    <div style="padding:20px;">
                        <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;padding:8px 12px;background:#fff3cd;border-radius:8px;border:1px solid #ffc107;">
                            <span style="font-size:16px;">🔒</span>
                            <span style="font-size:12px;color:#856404;font-weight:600;">File held in temporary sandbox — NOT saved to Downloads yet</span>
                        </div>
                        <div style="font-weight:bold;margin-bottom:12px;color:#333;font-size:15px;">${fname || 'Unknown File'}</div>
                        <div style="font-size:13px;color:#555;white-space:pre-wrap;max-height:180px;overflow-y:auto;background:#f8f9fa;padding:12px;border-radius:8px;line-height:1.5;">${res.summary}</div>
                        
                        <div style="display:flex;gap:12px;margin-top:20px;">
                            ${isSafe ? 
                                `<button id="pdf-approve-btn" style="flex:1.2;padding:12px;background:#28a745;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">✓ Save to Downloads</button>
                                 <button id="pdf-cancel-btn" style="flex:1;padding:12px;background:#6c757d;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">Cancel</button>` :
                                `<button id="pdf-block-btn" style="flex:1.2;padding:12px;background:#dc3545;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">🛑 Block & Delete</button>
                                 <button id="pdf-anyway-btn" style="flex:1;padding:12px;background:#6c757d;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">Download Anyway</button>`
                            }
                        </div>
                    </div>`;
                document.body.appendChild(card);

                // Close button
                document.getElementById('pdf-scanner-close').onclick = () => {
                    chrome.runtime.sendMessage({ action: 'downloadBlocked', pendingId: pId });
                    card.remove();
                };

                // Safe file: Save or Cancel
                if (document.getElementById('pdf-approve-btn')) {
                    document.getElementById('pdf-approve-btn').onclick = () => {
                        chrome.runtime.sendMessage({
                            action: 'downloadApproved',
                            pendingId: pId,
                            prediction: res.prediction,
                            confidence: res.confidence
                        });
                        card.innerHTML = `<div style="padding:20px;text-align:center;color:#28a745;font-weight:bold;">✓ File saved to Downloads!</div>`;
                        setTimeout(() => card.remove(), 2000);
                    };
                }
                if (document.getElementById('pdf-cancel-btn')) {
                    document.getElementById('pdf-cancel-btn').onclick = () => {
                        chrome.runtime.sendMessage({ action: 'downloadBlocked', pendingId: pId });
                        card.innerHTML = `<div style="padding:20px;text-align:center;color:#6c757d;font-weight:bold;">Download cancelled.</div>`;
                        setTimeout(() => card.remove(), 1500);
                    };
                }

                // Malicious file: Block or Download Anyway
                if (document.getElementById('pdf-block-btn')) {
                    document.getElementById('pdf-block-btn').onclick = () => {
                        chrome.runtime.sendMessage({
                            action: 'downloadBlocked',
                            pendingId: pId,
                            prediction: res.prediction,
                            confidence: res.confidence
                        });
                        card.innerHTML = `<div style="padding:20px;text-align:center;color:#dc3545;font-weight:bold;">🛑 Malicious file blocked!</div>`;
                        setTimeout(() => card.remove(), 2000);
                    };
                }
                if (document.getElementById('pdf-anyway-btn')) {
                    document.getElementById('pdf-anyway-btn').onclick = () => {
                        chrome.runtime.sendMessage({
                            action: 'downloadApproved',
                            pendingId: pId,
                            prediction: res.prediction,
                            confidence: res.confidence,
                            forcedByUser: true
                        });
                        card.innerHTML = `<div style="padding:20px;text-align:center;color:#ffc107;font-weight:bold;">⚠️ File saved (user override)</div>`;
                        setTimeout(() => card.remove(), 2000);
                    };
                }
            },
            args: [result, pendingId, filename, iconUrl]
        });
        currentPopupTabId = tab.id;
    } catch (e) {
        console.error('Failed to show corner popup:', e);
    }
}

async function removeExistingPopup() {
    if (currentPopupTabId) {
        try {
            await chrome.scripting.executeScript({
                target: {tabId: currentPopupTabId},
                func: () => { document.getElementById('pdf-scanner-popup')?.remove(); }
            });
        } catch (e) {}
        currentPopupTabId = null;
    }
}

async function downloadBlobContent(downloadItem) {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) throw new Error('No active tab');
        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: (url) => fetch(url).then(r => r.blob()).then(b => new Promise(res => {
                const f = new FileReader(); f.onloadend = () => res(f.result); f.readAsDataURL(b);
            })),
            args: [downloadItem.url]
        });
        if (results?.[0]?.result) {
            const res = await fetch(results[0].result);
            return await res.blob();
        }
    } catch (e) { console.error(e); }
    return null;
}

// Convert a blob to a data URL string for storage in the pending map
async function blobToDataUrl(blob) {
    const response = new Response(blob);
    const buffer = await response.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    const mimeType = blob.type || 'application/pdf';
    return `data:${mimeType};base64,${base64}`;
}

async function scanFile(downloadItem) {
    const url = downloadItem.url;
    if (activeScans.has(url)) return;
    activeScans.add(url);

    const filename = downloadItem.filename 
        ? downloadItem.filename.split(/[/\\]/).pop() 
        : 'file.pdf';

    try {
        // Show scanning overlay on active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) {
            chrome.tabs.sendMessage(tab.id, { 
                action: 'showScanningOverlay', 
                filename: filename 
            }).catch(() => {});
        }
        
        // Step 1: Fetch the PDF content into memory (our "sandbox")
        let fileBlob = null;
        if (url.startsWith('blob:')) {
            fileBlob = await downloadBlobContent(downloadItem);
        } else {
            try {
                const response = await fetch(url);
                fileBlob = await response.blob();
            } catch (e) {
                console.error('Failed to fetch PDF:', e);
            }
        }

        if (!fileBlob) {
            console.error('Could not fetch PDF content for sandbox analysis');
            activeScans.delete(url);
            return;
        }

        // Step 2: Send to backend for analysis
        let result = null;
        const formData = new FormData();
        formData.append('file', fileBlob, filename);
        
        try {
            const scanRes = await fetch("http://localhost:8000/predict-file", { 
                method: "POST", 
                body: formData 
            });
            if (scanRes?.ok) result = await scanRes.json();
        } catch (e) {
            console.error('Backend scan failed:', e);
        }

        // Fallback: try URL-based analysis
        if (!result && !url.startsWith('blob:')) {
            try {
                const urlRes = await fetch("http://localhost:8000/predict-url", { 
                    method: "POST", 
                    headers: {"Content-Type": "application/json"}, 
                    body: JSON.stringify({url}) 
                });
                if (urlRes?.ok) result = await urlRes.json();
            } catch (e) {
                console.error('URL scan fallback failed:', e);
            }
        }

        if (!result) {
            result = {
                prediction: 'error',
                confidence: 0,
                summary: 'Could not analyze this file. Backend may be offline.'
            };
        }

        // Step 3: Store the blob in our pending downloads map
        const pendingId = generatePendingId();
        const blobDataUrl = await blobToDataUrl(fileBlob);
        
        pendingDownloads.set(pendingId, {
            blobDataUrl: blobDataUrl,
            filename: filename,
            originalUrl: url,
            scanResult: result
        });

        scannedUrls.set(url, { prediction: result.prediction, timestamp: Date.now() });

        // Step 4: Show results to user with approval buttons
        if (tab?.id) {
            try {
                await chrome.tabs.sendMessage(tab.id, { 
                    action: 'updateScanResult', 
                    result: result, 
                    pendingId: pendingId,
                    filename: filename
                });
            } catch (e) {
                // Content script not available, use corner popup
                showCornerPopup(result, pendingId, filename);
            }
        } else {
            showCornerPopup(result, pendingId, filename);
        }

        // Auto-cleanup pending downloads after 10 minutes to prevent memory leaks
        setTimeout(() => {
            if (pendingDownloads.has(pendingId)) {
                console.log(`⏰ Auto-cleanup: Removing expired pending download ${pendingId}`);
                pendingDownloads.delete(pendingId);
            }
        }, 10 * 60 * 1000);

    } finally {
        activeScans.delete(url);
    }
}

// --- MESSAGE HANDLERS ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // User approved the download — save from sandbox to Downloads
    if (request.action === 'downloadApproved') {
        const pending = pendingDownloads.get(request.pendingId);
        if (pending) {
            console.log('✅ User approved download:', pending.filename);

            // Add the data URL to the whitelist so onCreated doesn't intercept it again
            // This prevents the infinite loop of popup -> download -> intercept -> popup
            whitelistedDownloads.add(pending.blobDataUrl);

            chrome.downloads.download({ 
                url: pending.blobDataUrl, 
                filename: pending.filename,
                saveAs: false
            }, (newDownloadId) => {
                if (chrome.runtime.lastError) {
                    console.error('Download failed:', chrome.runtime.lastError.message);
                } else {
                    console.log('✅ Download started, ID:', newDownloadId);
                }
            });

            // Send feedback if user overrode a malicious prediction
            if (request.forcedByUser && request.prediction === 'malicious') {
                sendFeedback(pending.originalUrl, 'safe', request.prediction, request.confidence);
            }

            pendingDownloads.delete(request.pendingId);
        } else {
            console.warn('Pending download not found:', request.pendingId);
        }
    }

    // User blocked the download — discard from sandbox
    if (request.action === 'downloadBlocked') {
        const pending = pendingDownloads.get(request.pendingId);
        if (pending) {
            console.log('🛑 User blocked download:', pending.filename);
            
            // Send feedback for malicious blocks
            if (request.prediction) {
                sendFeedback(pending.originalUrl, 'malicious', request.prediction, request.confidence || 0);
            }
            
            pendingDownloads.delete(request.pendingId);
        }
    }

    // Legacy support: blockFile for popup.js
    if (request.action === 'blockFile') {
        console.log("🛑 Forced deletion of file ID:", request.id);
        chrome.downloads.cancel(request.id).catch(() => {}); 
        chrome.downloads.removeFile(request.id).catch(() => {}); 
        chrome.downloads.erase({id: request.id}).catch(() => {});
        if (request.url) {
            sendFeedback(request.url, 'malicious', request.prediction, request.confidence);
        }
    }

    // Legacy support: downloadAnyway for popup.js  
    if (request.action === 'downloadAnyway') {
        const downloadUrl = request.url;
        whitelistedDownloads.add(downloadUrl);
        chrome.downloads.download({ url: downloadUrl, filename: request.filename });
        sendFeedback(downloadUrl, 'safe', request.prediction, request.confidence);
    }
});

// Send user feedback to backend for retraining
async function sendFeedback(url, actualLabel, prediction, confidence) {
    try {
        const response = await fetch(FEEDBACK_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url,
                actual_label: actualLabel,
                predicted_label: prediction,
                confidence: confidence,
                timestamp: Date.now()
            })
        });
        
        if (response.ok) {
            console.log('✅ Feedback sent to backend:', actualLabel);
            return true;
        } else {
            console.log('❌ Failed to send feedback');
            return false;
        }
    } catch (error) {
        console.error('❌ Feedback error:', error);
        return false;
    }
}

// --- DOWNLOAD INTERCEPTOR ---
// Cancel ALL PDF downloads immediately and route them through the sandbox
chrome.downloads.onCreated.addListener(async (item) => {
    // Skip downloads triggered by our own extension (approved files)
    if (item.byExtensionId === chrome.runtime.id) {
        return;
    }

    // Check if this download URL is whitelisted (we triggered it after approval)
    if (whitelistedDownloads.has(item.url)) {
        whitelistedDownloads.delete(item.url);
        return;
    }

    const fn = item.filename?.toLowerCase() || "";
    const isPDF = item.mime === 'application/pdf' || 
                  fn.endsWith('.pdf') || 
                  item.url?.toLowerCase().includes('.pdf') || 
                  item.url.startsWith('blob:');
                   
    if (!isPDF) return;

    // SANDBOX FLOW: Cancel the download immediately — file goes to sandbox, not Downloads
    console.log('🔒 Intercepted PDF download, routing to sandbox:', item.filename || item.url);
    
    try {
        await chrome.downloads.cancel(item.id);
        console.log('⏸️ Download cancelled, ID:', item.id);
    } catch (e) {
        console.warn('Could not cancel download:', e);
    }
    
    // Clean up the cancelled download entry from Chrome's download bar
    try {
        chrome.downloads.erase({id: item.id});
    } catch (e) {}

    // Now scan the file in our sandbox
    scanFile(item);
});
