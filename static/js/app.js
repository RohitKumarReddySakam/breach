'use strict';

const socket = io();
let currentScanId = null;

// ── Scan form submission ─────────────────────────────────────────
const scanForm = document.getElementById('scan-form');
if (scanForm) {
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = document.getElementById('target').value.trim();
        const scanType = document.getElementById('scan_type').value;
        const portRange = document.getElementById('port_range').value;

        if (!target) return;

        showProgress('Queuing scan...');

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, scan_type: scanType, port_range: portRange }),
            });
            const data = await res.json();
            if (!res.ok) {
                showError(data.error || 'Scan failed to start');
                return;
            }
            currentScanId = data.scan_id;
            updateProgress('Scan queued. Connecting...', 10);
            pollScan(currentScanId);
        } catch (err) {
            showError('Network error: ' + err.message);
        }
    });
}

function pollScan(scanId) {
    const interval = setInterval(async () => {
        try {
            const res = await fetch(`/api/scan/${scanId}`);
            const scan = await res.json();
            const status = scan.status;

            if (status === 'SCANNING') {
                updateProgress(`Scanning ${scan.target}...`, 50);
            } else if (status === 'COMPLETED') {
                clearInterval(interval);
                updateProgress('Scan complete! Redirecting...', 100);
                setTimeout(() => {
                    window.location.href = `/scan/${scanId}`;
                }, 1200);
            } else if (status && status.startsWith('FAILED')) {
                clearInterval(interval);
                showError('Scan failed: ' + status);
            }
        } catch (err) {
            clearInterval(interval);
            showError('Connection lost');
        }
    }, 2000);
}

// ── Socket events ────────────────────────────────────────────────
socket.on('scan_progress', (data) => {
    if (data.scan_id === currentScanId) {
        updateProgress(`Scanning ${data.host}...`, 40);
    }
});

socket.on('scan_complete', (data) => {
    if (data.scan_id === currentScanId) {
        updateProgress('Complete!', 100);
    }
});

// ── Report generation ────────────────────────────────────────────
async function generateReport(scanId, format) {
    const btn = document.getElementById(`btn-report-${format}`);
    if (btn) btn.disabled = true;

    try {
        const res = await fetch('/api/report/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_id: scanId, format }),
        });
        const data = await res.json();
        if (res.ok) {
            window.open(`/api/report/${data.report_id}`, '_blank');
        } else {
            alert('Report generation failed');
        }
    } catch (err) {
        alert('Error: ' + err.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

// ── Helpers ──────────────────────────────────────────────────────
function showProgress(msg) {
    const section = document.getElementById('progress-section');
    const status = document.getElementById('progress-status');
    if (section) section.style.display = 'block';
    if (status) status.textContent = msg;
    updateProgress(msg, 5);
}

function updateProgress(msg, pct) {
    const bar = document.getElementById('progress-bar');
    const status = document.getElementById('progress-status');
    if (bar) bar.style.width = pct + '%';
    if (status) status.textContent = msg;
}

function showError(msg) {
    const section = document.getElementById('progress-section');
    const status = document.getElementById('progress-status');
    if (section) { section.style.display = 'block'; section.style.borderColor = 'var(--red)'; }
    if (status) { status.style.color = 'var(--red)'; status.textContent = msg; }
}

function severityClass(sev) {
    return { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }[sev] || 'info';
}
