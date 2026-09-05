// ======================================================
// PDF Malware Detector — background.js (corrected)
// Make sure manifest.json includes these permissions:
// "permissions": ["downloads", "scripting", "notifications", "activeTab", "tabs"]
// ======================================================

const API_URL = "http://localhost:8000/predict-file";
const URL_API = "http://localhost:8000/predict-url";
const FEEDBACK_URL = "http://localhost:8000/feedback";

let currentPopupTabId = null;
let popupTimeoutId = null;

// State management
const scannedUrls = new Map();
const activeScans = new Set();
const whitelistedDownloads = new Set();

// Store pending downloads in memory until user approves
const pendingDownloads = new Map();

let pendingIdCounter = 0;

function generatePendingId() {
    return `pending_${Date.now()}_${++pendingIdCounter}`;
}

// Check whether the current page can be accessed by the extension
function isScriptableUrl(url) {
    if (!url) return false;

    return !(
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:") ||
        url.startsWith("devtools://") ||
        url.startsWith("https://chrome.google.com/webstore")
    );
}

// Show browser notification
function showNotification(title, message) {
    try {
        chrome.notifications.create({
            type: "basic",
            iconUrl: chrome.runtime.getURL("icon.png"),
            title: title,
            message: message
        });
    } catch (e) {
        console.error("Notification error:", e);
    }
}

// Safely get the active tab (never throws)
async function getActiveTab() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        return tab || null;
    } catch (e) {
        console.error("Failed to query active tab:", e);
        return null;
    }
}

// Function to create a small corner popup
async function showCornerPopup(result, pendingId, filename) {
    if (popupTimeoutId) {
        clearTimeout(popupTimeoutId);
    }

    await removeExistingPopup();

    const tab = await findScriptableTab();

    if (!tab || !tab.id) {
        showNotification(
            "PDF Malware Detector",
            `${filename || "PDF"} has been scanned. Open the extension popup to view the result.`
        );
        return;
    }

    const iconUrl = chrome.runtime.getURL("icon.png");

    try {
        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: (res, pId, fname, icon) => {
                const existing = document.getElementById("pdf-scanner-popup");
                if (existing) existing.remove();

                const prediction = res.prediction;
                const isSafe = prediction === "safe";
                const isError = prediction === "error";

                const badgeBg = isSafe ? "#28a745" : isError ? "#ffc107" : "#dc3545";
                const statusIcon = isSafe ? "✓" : isError ? "❓" : "⚠️";
                const statusText = isSafe ? "PDF SAFE" : isError ? "SCAN ERROR" : "MALICIOUS PDF";

                const card = document.createElement("div");
                card.id = "pdf-scanner-popup";
                card.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    width: 400px;
                    background: white;
                    z-index: 2147483647;
                    border-radius: 12px;
                    box-shadow: 0 15px 40px rgba(0,0,0,0.3);
                    font-family: sans-serif;
                    overflow: hidden;
                    border: 1px solid #eee;
                    animation: popupSlideIn 0.4s ease-out;
                `;

                const style = document.createElement("style");
                style.textContent = `
                    @keyframes popupSlideIn {
                        from { transform: translateX(100%); opacity: 0; }
                        to { transform: translateX(0); opacity: 1; }
                    }
                    @keyframes sandboxPulse {
                        0%, 100% { opacity: 0.7; }
                        50% { opacity: 1; }
                    }
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
                            <span style="font-size:12px;color:#856404;font-weight:600;">
                                File held in temporary sandbox — NOT saved to Downloads yet
                            </span>
                        </div>
                        <div style="font-weight:bold;margin-bottom:12px;color:#333;font-size:15px;">
                            ${fname || "Unknown File"}
                        </div>
                        <div style="font-size:13px;color:#555;white-space:pre-wrap;max-height:180px;overflow-y:auto;background:#f8f9fa;padding:12px;border-radius:8px;line-height:1.5;">
                            ${res.summary || "No summary available."}
                        </div>
                        <div style="display:flex;gap:12px;margin-top:20px;">
                            ${
                                isSafe
                                    ? `<button id="pdf-approve-btn" style="flex:1.2;padding:12px;background:#28a745;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">✓ Save to Downloads</button>
                                       <button id="pdf-cancel-btn" style="flex:1;padding:12px;background:#6c757d;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">Cancel</button>`
                                    : `<button id="pdf-block-btn" style="flex:1.2;padding:12px;background:#dc3545;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">🛑 Block & Delete</button>
                                       <button id="pdf-anyway-btn" style="flex:1;padding:12px;background:#6c757d;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">Download Anyway</button>`
                            }
                        </div>
                    </div>
                `;

                document.body.appendChild(card);

                const closeButton = document.getElementById("pdf-scanner-close");
                if (closeButton) {
                    closeButton.onclick = () => {
                        chrome.runtime.sendMessage({ action: "downloadBlocked", pendingId: pId });
                        card.remove();
                    };
                }

                const approveButton = document.getElementById("pdf-approve-btn");
                if (approveButton) {
                    approveButton.onclick = () => {
                        chrome.runtime.sendMessage({
                            action: "downloadApproved",
                            pendingId: pId,
                            prediction: res.prediction,
                            confidence: res.confidence
                        });
                        card.innerHTML = `<div style="padding:20px;text-align:center;color:#28a745;font-weight:bold;">✓ File saved to Downloads!</div>`;
                        setTimeout(() => card.remove(), 2000);
                    };
                }

                const cancelButton = document.getElementById("pdf-cancel-btn");
                if (cancelButton) {
                    cancelButton.onclick = () => {
                        chrome.runtime.sendMessage({ action: "downloadBlocked", pendingId: pId });
                        card.innerHTML = `<div style="padding:20px;text-align:center;color:#6c757d;font-weight:bold;">Download cancelled.</div>`;
                        setTimeout(() => card.remove(), 1500);
                    };
                }

                const blockButton = document.getElementById("pdf-block-btn");
                if (blockButton) {
                    blockButton.onclick = () => {
                        chrome.runtime.sendMessage({
                            action: "downloadBlocked",
                            pendingId: pId,
                            prediction: res.prediction,
                            confidence: res.confidence
                        });
                        card.innerHTML = `<div style="padding:20px;text-align:center;color:#dc3545;font-weight:bold;">🛑 Malicious file blocked!</div>`;
                        setTimeout(() => card.remove(), 2000);
                    };
                }

                const anywayButton = document.getElementById("pdf-anyway-btn");
                if (anywayButton) {
                    anywayButton.onclick = () => {
                        chrome.runtime.sendMessage({
                            action: "downloadApproved",
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
        console.error("Failed to show corner popup:", e);
        showNotification("PDF Malware Detector", `${filename || "PDF"} has been scanned.`);
    }
}

// Remove existing popup
async function removeExistingPopup() {
    if (!currentPopupTabId) return;

    try {
        const tab = await getActiveTab();

        if (tab && tab.id && isScriptableUrl(tab.url)) {
            await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    const popup = document.getElementById("pdf-scanner-popup");
                    if (popup) popup.remove();
                }
            });
        }
    } catch (e) {
        // Ignore protected page errors
    }

    currentPopupTabId = null;
}

// Find the best tab to inject into: prefer the active tab, but fall back
// to any other scriptable tab if the active one is protected (e.g. the
// built-in PDF viewer, which is itself a chrome-extension:// page).
async function findScriptableTab() {
    const activeTab = await getActiveTab();
    if (activeTab && activeTab.id && isScriptableUrl(activeTab.url)) {
        return activeTab;
    }

    try {
        const tabs = await chrome.tabs.query({ currentWindow: true });
        const fallback = tabs.find(t => t.id && isScriptableUrl(t.url));
        if (fallback) {
            console.log("Active tab not scriptable, falling back to:", fallback.url);
            return fallback;
        }
    } catch (e) {
        console.error("Failed to query tabs for fallback:", e);
    }

    return null;
}

// Handle blob URLs
async function downloadBlobContent(downloadItem) {
    try {
        const tab = await findScriptableTab();

        if (!tab || !tab.id) {
            throw new Error("No scriptable tab available (active tab may be a protected page like the built-in PDF viewer)");
        }

        console.log("DEBUG: Attempting to script tab:", tab.id, tab.url);

        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: (url) => {
                return fetch(url)
                    .then(response => {
                        if (!response.ok) throw new Error(`HTTP ${response.status}`);
                        return response.blob();
                    })
                    .then(blob => {
                        return new Promise(resolve => {
                            const reader = new FileReader();
                            reader.onloadend = () => resolve(reader.result);
                            reader.readAsDataURL(blob);
                        });
                    });
            },
            args: [downloadItem.url]
        });

        if (results?.[0]?.result) {
            const response = await fetch(results[0].result);
            return await response.blob();
        }
    } catch (e) {
        console.error("Blob download error:", e);
    }

    return null;
}

// Convert blob to Data URL
async function blobToDataUrl(blob) {
    const response = new Response(blob);
    const buffer = await response.arrayBuffer();
    const bytes = new Uint8Array(buffer);

    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    const base64 = btoa(binary);
    const mimeType = blob.type || "application/pdf";

    return `data:${mimeType};base64,${base64}`;
}

// Scan file
async function scanFile(downloadItem) {
    const url = downloadItem.url;

    if (activeScans.has(url)) return;
    activeScans.add(url);

    const filename = downloadItem.filename
        ? downloadItem.filename.split(/[\/\\]/).pop()
        : "file.pdf";

    try {
        const tab = await getActiveTab();

        if (tab?.id && isScriptableUrl(tab.url)) {
            chrome.tabs.sendMessage(tab.id, {
                action: "showScanningOverlay",
                filename: filename
            }).catch(() => {});
        }

        // Step 1: Fetch PDF content into memory
        let fileBlob = null;

        if (url.startsWith("blob:")) {
            fileBlob = await downloadBlobContent(downloadItem);
        } else {
            try {
                const response = await fetch(url);
                if (response.ok) {
                    fileBlob = await response.blob();
                } else {
                    console.error("PDF fetch returned HTTP status:", response.status);
                }
            } catch (e) {
                console.error("Failed to fetch PDF:", e);
            }
        }

        if (!fileBlob) {
            console.error("Could not fetch PDF content");
            showNotification("PDF Malware Detector", `Could not read ${filename}.`);
            return;
        }

        // Step 2: Send PDF to backend
        let result = null;
        const formData = new FormData();
        formData.append("file", fileBlob, filename);

        try {
            const scanRes = await fetch(API_URL, { method: "POST", body: formData });
            if (scanRes.ok) {
                result = await scanRes.json();
            } else {
                console.error("Backend returned:", scanRes.status);
            }
        } catch (e) {
            console.error("Backend scan failed:", e);
        }

        // Fallback: URL-based analysis
        if (!result && !url.startsWith("blob:")) {
            try {
                const urlRes = await fetch(URL_API, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: url })
                });
                if (urlRes.ok) {
                    result = await urlRes.json();
                }
            } catch (e) {
                console.error("URL scan fallback failed:", e);
            }
        }

        if (!result) {
            result = {
                prediction: "error",
                confidence: 0,
                summary: "Could not analyze this file. Backend may be offline."
            };
        }

        // Step 3: Store PDF in pending sandbox
        const pendingId = generatePendingId();
        const blobDataUrl = await blobToDataUrl(fileBlob);

        pendingDownloads.set(pendingId, {
            blobDataUrl: blobDataUrl,
            filename: filename,
            originalUrl: url,
            scanResult: result
        });

        scannedUrls.set(url, { prediction: result.prediction, timestamp: Date.now() });

        // Step 4: Show result
        if (tab?.id) {
            try {
                if (isScriptableUrl(tab.url)) {
                    await chrome.tabs.sendMessage(tab.id, {
                        action: "updateScanResult",
                        result: result,
                        pendingId: pendingId,
                        filename: filename
                    });
                } else {
                    await showCornerPopup(result, pendingId, filename);
                }
            } catch (e) {
                await showCornerPopup(result, pendingId, filename);
            }
        } else {
            await showCornerPopup(result, pendingId, filename);
        }

        // Auto cleanup after 10 minutes
        setTimeout(() => {
            if (pendingDownloads.has(pendingId)) {
                console.log(`Auto-cleanup: Removing expired pending download ${pendingId}`);
                pendingDownloads.delete(pendingId);
            }
        }, 10 * 60 * 1000);

    } finally {
        activeScans.delete(url);
    }
}

// ======================================================
// MESSAGE HANDLERS
// ======================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // User approved download
    if (request.action === "downloadApproved") {
        const pending = pendingDownloads.get(request.pendingId);

        if (pending) {
            console.log("User approved download:", pending.filename);

            whitelistedDownloads.add(pending.blobDataUrl);

            chrome.downloads.download(
                { url: pending.blobDataUrl, filename: pending.filename, saveAs: false },
                newDownloadId => {
                    if (chrome.runtime.lastError) {
                        console.error("Download failed:", chrome.runtime.lastError.message);
                    } else {
                        console.log("Download started, ID:", newDownloadId);
                    }
                }
            );

            if (request.forcedByUser && request.prediction === "malicious") {
                sendFeedback(pending.originalUrl, "safe", request.prediction, request.confidence);
            }

            pendingDownloads.delete(request.pendingId);
        } else {
            console.warn("Pending download not found:", request.pendingId);
        }
    }

    // User blocked download
    if (request.action === "downloadBlocked") {
        const pending = pendingDownloads.get(request.pendingId);

        if (pending) {
            console.log("User blocked download:", pending.filename);

            if (request.prediction) {
                sendFeedback(pending.originalUrl, "malicious", request.prediction, request.confidence || 0);
            }

            pendingDownloads.delete(request.pendingId);
        }
    }

    // Legacy support: blockFile
    if (request.action === "blockFile") {
        console.log("Forced deletion of file ID:", request.id);

        chrome.downloads.cancel(request.id, () => {});
        chrome.downloads.erase({ id: request.id }, () => {});

        if (request.url) {
            sendFeedback(request.url, "malicious", request.prediction, request.confidence);
        }
    }

    // Legacy support: downloadAnyway
    if (request.action === "downloadAnyway") {
        const downloadUrl = request.url;

        whitelistedDownloads.add(downloadUrl);

        chrome.downloads.download({ url: downloadUrl, filename: request.filename });

        sendFeedback(downloadUrl, "safe", request.prediction, request.confidence);
    }
});

// ======================================================
// SEND USER FEEDBACK TO BACKEND
// ======================================================

async function sendFeedback(url, actualLabel, prediction, confidence) {
    try {
        const response = await fetch(FEEDBACK_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: url,
                actual_label: actualLabel,
                predicted_label: prediction,
                confidence: confidence,
                timestamp: Date.now()
            })
        });

        if (response.ok) {
            console.log("Feedback sent to backend:", actualLabel);
            return true;
        } else {
            console.log("Failed to send feedback");
            return false;
        }
    } catch (error) {
        console.error("Feedback error:", error);
        return false;
    }
}

// ======================================================
// DOWNLOAD INTERCEPTOR
// ======================================================

chrome.downloads.onCreated.addListener(async item => {
    // Skip downloads triggered by our extension
    if (item.byExtensionId === chrome.runtime.id) {
        return;
    }

    // Check whitelist
    if (whitelistedDownloads.has(item.url)) {
        whitelistedDownloads.delete(item.url);
        return;
    }

    const fn = item.filename?.toLowerCase() || "";
    const itemUrl = item.url?.toLowerCase() || "";

    const isPDF =
        item.mime === "application/pdf" ||
        fn.endsWith(".pdf") ||
        itemUrl.includes(".pdf") ||
        item.url?.startsWith("blob:");

    if (!isPDF) return;

    console.log("Intercepted PDF download, routing to sandbox:", item.filename || item.url);

    try {
        await chrome.downloads.cancel(item.id);
        console.log("Download cancelled, ID:", item.id);
    } catch (e) {
        console.warn("Could not cancel download:", e);
    }

    try {
        chrome.downloads.erase({ id: item.id });
    } catch (e) {
        // Ignore erase errors
    }

    scanFile(item);
});

console.log("PDF Malware Detector background service worker loaded.");