// CyberShield Frontend Interactive Engine - Full Screen Clean Interface

let scoreGaugeChart = null;
let currentEmlFile = null;

document.addEventListener("DOMContentLoaded", () => {
    initScoreGauge(0, "SAFE");
    initDropZone();
    initRealTimeListeners();
    switchMainTool('home-view');
});

// Switch between Home, Tool 1 (Analyse Email), and Tool 2 (Scan URL)
function switchMainTool(toolId) {
    const homeView = document.getElementById('home-view');
    const emailTool = document.getElementById('email-tool');
    const urlTool = document.getElementById('url-tool');
    const resultsSec = document.getElementById('results-section');

    const navBtnHome = document.getElementById('nav-btn-home');
    const navBtnEmail = document.getElementById('nav-btn-email');
    const navBtnUrl = document.getElementById('nav-btn-url');

    // Reset all nav tabs
    if (navBtnHome) navBtnHome.classList.remove('active');
    if (navBtnEmail) navBtnEmail.classList.remove('active');
    if (navBtnUrl) navBtnUrl.classList.remove('active');

    // Hide all views
    if (homeView) homeView.classList.add('hidden');
    if (emailTool) emailTool.classList.add('hidden');
    if (urlTool) urlTool.classList.add('hidden');

    if (toolId === 'home-view') {
        if (homeView) homeView.classList.remove('hidden');
        if (navBtnHome) navBtnHome.classList.add('active');
        // Always hide results when going home
        if (resultsSec) resultsSec.classList.add('hidden');
    } else if (toolId === 'email-tool') {
        if (emailTool) emailTool.classList.remove('hidden');
        if (navBtnEmail) navBtnEmail.classList.add('active');
        // Results section stays as-is (hidden until manual scan is run)
    } else if (toolId === 'url-tool') {
        if (urlTool) urlTool.classList.remove('hidden');
        if (navBtnUrl) navBtnUrl.classList.add('active');
        // Results section stays as-is (hidden until manual scan is run)
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Switch between Manual Input and .eml File Upload inside Tool 1
function switchEmailMode(mode) {
    const manualSec = document.getElementById('email-manual-section');
    const emlSec = document.getElementById('email-eml-section');
    const btnManual = document.getElementById('mode-btn-manual');
    const btnEml = document.getElementById('mode-btn-eml');

    if (mode === 'manual') {
        manualSec.classList.remove('hidden');
        emlSec.classList.add('hidden');
        btnManual.classList.add('active');
        btnEml.classList.remove('active');
    } else {
        manualSec.classList.add('hidden');
        emlSec.classList.remove('hidden');
        btnManual.classList.remove('active');
        btnEml.classList.add('active');
    }
}

// Clear manual input fields
function clearManualFields() {
    document.getElementById('input-sender').value = '';
    document.getElementById('input-subject').value = '';
    document.getElementById('input-body').value = '';
    document.getElementById('attachments-container').innerHTML = '';
    // Reset the inline email ML card to idle state
    resetEmailMlCard();
}

// ============================================================
// .EML File Drag & Drop & Upload
// ============================================================
function initDropZone() {
    const dropZone = document.getElementById('eml-drop-zone');
    const fileInput = document.getElementById('eml-file-input');

    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleEmlFileSelect(e.dataTransfer.files);
        }
    });
}

function handleEmlFileSelect(files) {
    if (!files || files.length === 0) return;
    const file = files[0];

    if (!file.name.toLowerCase().endsWith('.eml')) {
        alert('Please select a valid RFC 822 .eml email file.');
        return;
    }

    currentEmlFile = file;
    document.getElementById('eml-filename').innerText = file.name;
    document.getElementById('eml-filesize').innerText = formatBytes(file.size);
    document.getElementById('eml-file-preview').classList.remove('hidden');
}

function clearEmlFile() {
    currentEmlFile = null;
    document.getElementById('eml-file-input').value = '';
    document.getElementById('eml-file-preview').classList.add('hidden');
}

async function uploadAndScanEml() {
    if (!currentEmlFile) {
        alert('Please select or drop a .eml file first.');
        return;
    }

    const btn = document.getElementById('btn-scan-eml');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Parsing and Inspecting .eml...`;

    const formData = new FormData();
    formData.append('file', currentEmlFile);

    try {
        const res = await fetch('/api/scan/eml', {
            method: 'POST',
            body: formData
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.summary || 'Failed to scan .eml file');
        }

        const data = await res.json();
        renderScanResults(data);

        // Show results section and scroll to it
        const resSec = document.getElementById('results-section');
        if (resSec) resSec.classList.remove('hidden');
        resSec.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        alert('EML Analysis Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-bolt text-lg"></i> Analyze Uploaded .eml File`;
    }
}

// ============================================================
// Tool 1: Manual Email Scan (Full 5-Layer Deep Forensic Scan)
// ============================================================
async function performManualEmailScan() {
    const sender = document.getElementById('input-sender').value.trim();
    const subject = document.getElementById('input-subject').value.trim();
    const body = document.getElementById('input-body').value.trim();

    if (!sender && !subject && !body) {
        alert('Please provide at least a sender address, subject, or email body to analyze.');
        return;
    }

    const btn = document.getElementById('btn-scan-manual');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Running 5-Layer Deep Scan…`;

    const payload = {
        sender: sender,
        subject: subject,
        body: body,
        attachments: getAttachmentsData(),
        triggerVirusTotal: true
    };

    try {
        const res = await fetch('/api/scan/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error('Scan failed with status ' + res.status);
        const data = await res.json();

        // Full render: gauge + layers + findings table + advisory
        renderScanResults(data);
        renderEmailMlCard(data);
        loadDatabaseHistory();

        // Show the results section and scroll smoothly to it
        const resSec = document.getElementById('results-section');
        if (resSec) resSec.classList.remove('hidden');
        resSec.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        alert('Scan Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-shield-virus text-lg"></i> Analyze Email (5-Layer Engine)`;
    }
}

// ============================================================
// Tool 2: URL Scan (Full 5-Layer Deep Forensic Scan)
// ============================================================
async function performUrlScan() {
    const urlInput = document.getElementById('input-target-url').value.trim();
    if (!urlInput) {
        alert('Please enter a target URL to scan.');
        return;
    }

    const btn = document.getElementById('btn-scan-url');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Running 5-Layer Deep Scan…`;

    try {
        const res = await fetch('/api/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput, forceVirusTotal: true })
        });

        if (!res.ok) throw new Error('URL scan failed with status ' + res.status);
        const data = await res.json();

        // Full render: gauge + layers + findings table + advisory
        renderScanResults(data);
        renderUrlMlCard(data);
        loadDatabaseHistory();

        // Show the results section and scroll smoothly to it
        const resSec = document.getElementById('results-section');
        if (resSec) resSec.classList.remove('hidden');
        resSec.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        alert('URL Scan Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-magnifying-glass text-lg"></i> Scan URL (5-Layer Engine)`;
    }
}

// ============================================================
// Real-Time Live Scan — ONLY updates the inline AI/ML card
// Does NOT touch the gauge, layer scores, findings, or advisory
// ============================================================
let realtimeEmailTimer = null;
let realtimeUrlTimer = null;

function initRealTimeListeners() {
    const senderInp = document.getElementById('input-sender');
    const subjectInp = document.getElementById('input-subject');
    const bodyInp = document.getElementById('input-body');
    const urlInp = document.getElementById('input-target-url');

    const handleEmailInput = () => {
        const toggle = document.getElementById('toggle-realtime-email');
        if (!toggle || !toggle.checked) return;

        clearTimeout(realtimeEmailTimer);
        realtimeEmailTimer = setTimeout(() => {
            triggerRealtimeEmailScan();
        }, 350);
    };

    if (senderInp) senderInp.addEventListener('input', handleEmailInput);
    if (subjectInp) subjectInp.addEventListener('input', handleEmailInput);
    if (bodyInp) bodyInp.addEventListener('input', handleEmailInput);

    if (urlInp) {
        urlInp.addEventListener('input', () => {
            const toggle = document.getElementById('toggle-realtime-url');
            if (!toggle || !toggle.checked) return;

            clearTimeout(realtimeUrlTimer);
            realtimeUrlTimer = setTimeout(() => {
                triggerRealtimeUrlScan();
            }, 350);
        });
    }
}

async function triggerRealtimeEmailScan() {
    const sender = document.getElementById('input-sender')?.value.trim() || '';
    const subject = document.getElementById('input-subject')?.value.trim() || '';
    const body = document.getElementById('input-body')?.value.trim() || '';

    // If all fields are empty, reset the inline card to idle
    if (!sender && !subject && !body) {
        resetEmailMlCard();
        return;
    }

    // Show scanning pulse in status
    setEmailMlStatus('scanning');

    const payload = {
        sender: sender,
        subject: subject,
        body: body,
        attachments: typeof getAttachmentsData === 'function' ? getAttachmentsData() : [],
        triggerVirusTotal: false  // Fast real-time — no external API wait
    };

    try {
        const res = await fetch('/api/scan/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            const data = await res.json();
            // ONLY update the inline email ML card — nothing else
            renderEmailMlCard(data);
        }
    } catch (e) {
        console.warn('Real-time email scan error:', e);
        setEmailMlStatus('error');
    }
}

async function triggerRealtimeUrlScan() {
    const urlInput = document.getElementById('input-target-url')?.value.trim() || '';
    if (!urlInput || urlInput.length < 5) {
        resetUrlMlCard();
        return;
    }

    // Show scanning pulse in status
    setUrlMlStatus('scanning');

    try {
        const res = await fetch('/api/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput, forceVirusTotal: false })
        });
        if (res.ok) {
            const data = await res.json();
            // ONLY update the inline URL ML card — nothing else
            renderUrlMlCard(data);
        }
    } catch (e) {
        console.warn('Real-time URL scan error:', e);
        setUrlMlStatus('error');
    }
}

// ============================================================
// Inline Email AI/ML Card — Real-Time Only Renderer
// Updates: email-ml-* element IDs only (no gauge, no findings)
// ============================================================
function renderEmailMlCard(result) {
    const mlPred = result.mlPrediction || 'LEGITIMATE';
    const mlConf = result.mlConfidence || '0.0%';
    const mlProb = (result.mlProbability !== undefined && result.mlProbability !== null) ? result.mlProbability : 0.0;
    const mlFeatures = result.mlTopFeatures || [];

    const badge = document.getElementById('email-ml-prediction-badge');
    const confVal = document.getElementById('email-ml-confidence-val');
    const probVal = document.getElementById('email-ml-prob-val');
    const confBar = document.getElementById('email-ml-confidence-bar');
    const chips = document.getElementById('email-ml-feature-chips');

    if (badge) {
        badge.innerText = mlPred;
        if (mlPred === 'PHISHING') {
            badge.className = 'text-lg font-extrabold tracking-wide font-mono text-red-400';
            if (confBar) confBar.className = 'h-full bg-gradient-to-r from-amber-500 to-red-500 transition-all duration-500';
        } else {
            badge.className = 'text-lg font-extrabold tracking-wide font-mono text-emerald-400';
            if (confBar) confBar.className = 'h-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-500';
        }
    }

    if (confVal) confVal.innerText = mlConf;
    if (probVal) probVal.innerText = `Prob: ${mlProb.toFixed(3)}`;
    if (confBar) {
        const confPercent = parseFloat(mlConf) || (mlProb * 100);
        confBar.style.width = `${Math.min(100, Math.max(5, confPercent))}%`;
    }

    if (chips) {
        if (mlFeatures.length > 0) {
            chips.innerHTML = mlFeatures.map(f =>
                `<span class="feature-chip">${escapeHtml(f)}</span>`
            ).join('');
        } else {
            chips.innerHTML = `<span class="text-xs italic" style="color:var(--text-dim);">No suspicious lexical/NLP tokens detected</span>`;
        }
    }

    // Update status to show live result
    const isPhishing = mlPred === 'PHISHING';
    const statusEl = document.getElementById('email-ml-status');
    if (statusEl) {
        statusEl.innerHTML = isPhishing
            ? `<span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span> <span class="text-red-400 font-bold">⚠ Live detection: PHISHING signal detected</span>`
            : `<span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> <span class="text-emerald-400">Live detection active — content appears legitimate</span>`;
    }
}

// ============================================================
// Inline URL AI/ML Card — Real-Time Only Renderer
// Updates: url-ml-* element IDs only (no gauge, no findings)
// ============================================================
function renderUrlMlCard(result) {
    const mlPred = result.mlPrediction || 'LEGITIMATE';
    const mlConf = result.mlConfidence || '0.0%';
    const mlProb = (result.mlProbability !== undefined && result.mlProbability !== null) ? result.mlProbability : 0.0;
    const mlFeatures = result.mlTopFeatures || [];

    const badge = document.getElementById('url-ml-prediction-badge');
    const confVal = document.getElementById('url-ml-confidence-val');
    const probVal = document.getElementById('url-ml-prob-val');
    const confBar = document.getElementById('url-ml-confidence-bar');
    const chips = document.getElementById('url-ml-feature-chips');

    if (badge) {
        badge.innerText = mlPred;
        if (mlPred === 'PHISHING') {
            badge.className = 'text-lg font-extrabold tracking-wide font-mono text-red-400';
            if (confBar) confBar.className = 'h-full bg-gradient-to-r from-amber-500 to-red-500 transition-all duration-500';
        } else {
            badge.className = 'text-lg font-extrabold tracking-wide font-mono text-emerald-400';
            if (confBar) confBar.className = 'h-full bg-gradient-to-r from-cyan-500 to-teal-500 transition-all duration-500';
        }
    }

    if (confVal) confVal.innerText = mlConf;
    if (probVal) probVal.innerText = `Prob: ${mlProb.toFixed(3)}`;
    if (confBar) {
        const confPercent = parseFloat(mlConf) || (mlProb * 100);
        confBar.style.width = `${Math.min(100, Math.max(5, confPercent))}%`;
    }

    if (chips) {
        if (mlFeatures.length > 0) {
            chips.innerHTML = mlFeatures.map(f =>
                `<span class="feature-chip">${escapeHtml(f)}</span>`
            ).join('');
        } else {
            chips.innerHTML = `<span class="text-xs italic" style="color:var(--text-dim);">No suspicious lexical/NLP tokens detected</span>`;
        }
    }

    // Update status to show live result
    const isPhishing = mlPred === 'PHISHING';
    const statusEl = document.getElementById('url-ml-status');
    if (statusEl) {
        statusEl.innerHTML = isPhishing
            ? `<span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span> <span class="text-red-400 font-bold">⚠ Live detection: PHISHING URL signal detected</span>`
            : `<span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> <span class="text-emerald-400">Live detection active — URL appears legitimate</span>`;
    }
}

// ============================================================
// Inline card reset helpers
// ============================================================
function resetEmailMlCard() {
    const badge = document.getElementById('email-ml-prediction-badge');
    const confVal = document.getElementById('email-ml-confidence-val');
    const probVal = document.getElementById('email-ml-prob-val');
    const confBar = document.getElementById('email-ml-confidence-bar');
    const chips = document.getElementById('email-ml-feature-chips');
    const statusEl = document.getElementById('email-ml-status');

    if (badge) { badge.innerText = '—'; badge.className = 'text-lg font-extrabold tracking-wide font-mono text-slate-500'; }
    if (confVal) { confVal.innerText = '— %'; confVal.className = 'text-lg font-extrabold font-mono text-slate-500'; }
    if (probVal) probVal.innerText = 'Prob: —';
    if (confBar) { confBar.style.width = '0%'; confBar.className = 'h-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-500'; }
    if (chips) chips.innerHTML = `<span class="text-xs text-slate-500 italic">Enter email content to see live token analysis</span>`;
    if (statusEl) statusEl.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-slate-600"></span> Awaiting input to begin live prediction…`;
}

function resetUrlMlCard() {
    const badge = document.getElementById('url-ml-prediction-badge');
    const confVal = document.getElementById('url-ml-confidence-val');
    const probVal = document.getElementById('url-ml-prob-val');
    const confBar = document.getElementById('url-ml-confidence-bar');
    const chips = document.getElementById('url-ml-feature-chips');
    const statusEl = document.getElementById('url-ml-status');

    if (badge) { badge.innerText = '—'; badge.className = 'text-lg font-extrabold tracking-wide font-mono text-slate-500'; }
    if (confVal) { confVal.innerText = '— %'; confVal.className = 'text-lg font-extrabold font-mono text-slate-500'; }
    if (probVal) probVal.innerText = 'Prob: —';
    if (confBar) { confBar.style.width = '0%'; confBar.className = 'h-full bg-gradient-to-r from-cyan-500 to-teal-500 transition-all duration-500'; }
    if (chips) chips.innerHTML = `<span class="text-xs text-slate-500 italic">Enter a URL to see live token analysis</span>`;
    if (statusEl) statusEl.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-slate-600"></span> Awaiting URL input to begin live prediction…`;
}

// Status helpers for inline cards
function setEmailMlStatus(state) {
    const el = document.getElementById('email-ml-status');
    if (!el) return;
    if (state === 'scanning') {
        el.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span> <span class="text-cyan-400">Scanning in real-time…</span>`;
    } else if (state === 'error') {
        el.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span> <span class="text-amber-400">Real-time scan unavailable</span>`;
    }
}

function setUrlMlStatus(state) {
    const el = document.getElementById('url-ml-status');
    if (!el) return;
    if (state === 'scanning') {
        el.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span> <span class="text-cyan-400">Scanning URL in real-time…</span>`;
    } else if (state === 'error') {
        el.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span> <span class="text-amber-400">Real-time scan unavailable</span>`;
    }
}

// ============================================================
// Full Scan Result Rendering — ONLY called on manual button click
// Updates: gauge, layer scores, findings table, advisory, ML verdict card in results section
// ============================================================
function renderScanResults(result) {
    // Score is strictly capped between 0 and 15
    const score = Math.min(15.0, Math.max(0, result.overallRiskScore));
    const classification = result.classification;

    // Score Value & Label
    const scoreVal = document.getElementById('gauge-score-value');
    const riskLabel = document.getElementById('gauge-risk-label');
    scoreVal.innerText = score.toFixed(1);

    riskLabel.className = 'text-xs font-extrabold px-3 py-1 rounded-full mt-1 ' +
        (classification === 'SAFE' ? 'badge-safe' : (classification === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-dangerous'));
    riskLabel.innerText = classification;

    updateScoreGauge(score, classification);

    // Execution time
    document.getElementById('scan-time-label').innerText = (result.totalExecutionTimeMs || 0) + ' ms';

    // Layer Scores
    const l1 = result.layerResults.find(l => l.layerNumber === 1);
    const l2 = result.layerResults.find(l => l.layerNumber === 2);
    const l3 = result.layerResults.find(l => l.layerNumber === 3);
    const l4 = result.layerResults.find(l => l.layerNumber === 4);
    const l5 = result.layerResults.find(l => l.layerNumber === 5);

    document.getElementById('l1-score-pill').innerText = l1 ? l1.score.toFixed(1) : '0.0';
    document.getElementById('l2-score-pill').innerText = l2 ? l2.score.toFixed(1) : '0.0';
    document.getElementById('l3-score-pill').innerText = l3 ? l3.score.toFixed(1) : '0.0';
    document.getElementById('l4-score-pill').innerText = l4 ? l4.score.toFixed(1) : '0.0';
    const l5Pill = document.getElementById('l5-score-pill');
    if (l5Pill) l5Pill.innerText = l5 ? l5.score.toFixed(1) : '0.0';

    // AI/ML Classification Engine Card in results section (full scan verdict)
    const mlPred = result.mlPrediction || 'LEGITIMATE';
    const mlConf = result.mlConfidence || '0.0%';
    const mlProb = (result.mlProbability !== undefined && result.mlProbability !== null) ? result.mlProbability : 0.0;
    const mlFeatures = result.mlTopFeatures || [];

    const mlBadge = document.getElementById('ml-prediction-badge');
    const mlConfVal = document.getElementById('ml-confidence-val');
    const mlProbVal = document.getElementById('ml-prob-val');
    const mlConfBar = document.getElementById('ml-confidence-bar');
    const mlChips = document.getElementById('ml-feature-chips');

    if (mlBadge) {
        mlBadge.innerText = mlPred;
        if (mlPred === 'PHISHING') {
            mlBadge.className = 'text-lg font-extrabold tracking-wide font-mono text-red-400';
            if (mlConfBar) mlConfBar.className = 'h-full bg-gradient-to-r from-amber-500 to-red-500 transition-all duration-500';
        } else {
            mlBadge.className = 'text-lg font-extrabold tracking-wide font-mono text-emerald-400';
            if (mlConfBar) mlConfBar.className = 'h-full bg-gradient-to-r from-teal-500 to-emerald-500 transition-all duration-500';
        }
    }

    if (mlConfVal) mlConfVal.innerText = mlConf;
    if (mlProbVal) mlProbVal.innerText = `Prob: ${mlProb.toFixed(3)}`;
    if (mlConfBar) {
        const confPercent = parseFloat(mlConf) || (mlProb * 100);
        mlConfBar.style.width = `${Math.min(100, Math.max(5, confPercent))}%`;
    }

    if (mlChips) {
        if (mlFeatures.length > 0) {
            mlChips.innerHTML = mlFeatures.map(f =>
                `<span class="feature-chip">${escapeHtml(f)}</span>`
            ).join('');
        } else {
            mlChips.innerHTML = `<span class="text-xs italic" style="color:var(--text-dim);">No suspicious lexical/NLP tokens detected</span>`;
        }
    }

    // Explainable AI (XAI) Threat Reasoning Card Population
    const geminiVerdictBadge = document.getElementById('gemini-verdict-badge');
    const geminiTacticTag = document.getElementById('gemini-tactic-tag');
    const geminiReasoningText = document.getElementById('gemini-reasoning-text');

    if (geminiVerdictBadge) {
        const gVerdict = result.geminiThreatVerdict || (classification === 'DANGEROUS' ? 'PHISHING' : (classification === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'SAFE'));
        geminiVerdictBadge.innerText = gVerdict;
        if (gVerdict === 'PHISHING') {
            geminiVerdictBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-red-950 text-red-300 border border-red-700';
        } else if (gVerdict === 'SUSPICIOUS') {
            geminiVerdictBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-700';
        } else {
            geminiVerdictBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700';
        }
    }

    if (geminiTacticTag) {
        geminiTacticTag.innerText = result.geminiPrimaryTactic || 'Social Engineering Analysis';
    }

    if (geminiReasoningText) {
        if (result.geminiAiReasoning) {
            geminiReasoningText.innerText = `"${result.geminiAiReasoning}"`;
        } else {
            geminiReasoningText.innerText = classification === 'DANGEROUS' ?
                `"Explainable AI: Content exhibits high-risk phishing behavior and deceptive manipulation tactics designed to extract sensitive information."` :
                `"Explainable AI: Communication structure and domain parameters analyzed. No immediate deceptive intent identified."`;
        }
    }

    // Threat Intelligence Status Pill in Findings Table Header
    const gsbPill = document.getElementById('gsb-status-pill');
    if (gsbPill) {
        gsbPill.classList.remove('hidden');
        if (result.googleSafeBrowsingFlagged) {
            gsbPill.className = 'px-2.5 py-0.5 rounded text-[11px] font-mono font-bold badge-dangerous';
            gsbPill.innerHTML = `<i class="fa-solid fa-triangle-exclamation mr-1"></i> Threat Feed: Malicious Alert!`;
        } else {
            gsbPill.className = 'px-2.5 py-0.5 rounded text-[11px] font-mono font-bold badge-safe';
            gsbPill.innerHTML = `<i class="fa-solid fa-shield-halved mr-1"></i> Threat Feed: Verified Clean`;
        }
    }

    // Recommendations
    const recsList = document.getElementById('recs-list');
    recsList.innerHTML = '';
    if (result.recommendations && result.recommendations.length > 0) {
        result.recommendations.forEach(r => {
            const li = document.createElement('li');
            li.className = 'flex items-start gap-2';
            li.innerHTML = `<i class="fa-solid fa-circle-dot mt-1 text-xs" style="color:var(--neon-cyan);flex-shrink:0;"></i><span>${escapeHtml(r)}</span>`;
            recsList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.className = 'flex items-start gap-2';
        li.innerHTML = `<i class="fa-solid fa-circle-dot mt-1 text-xs" style="color:var(--neon-cyan);flex-shrink:0;"></i><span>No threat indicators flagged. Normal communication.</span>`;
        recsList.appendChild(li);
    }

    // Detailed Findings Table
    const tbody = document.getElementById('findings-tbody');
    tbody.innerHTML = '';

    let totalFindings = 0;
    if (result.layerResults) {
        result.layerResults.forEach(lr => {
            if (lr.indicators) {
                lr.indicators.forEach(ind => {
                    totalFindings++;
                    const tr = document.createElement('tr');
                    tr.className = 'terminal-row';

                    const sev = (ind.severity || 'INFO').toUpperCase();
                    const sevClass = sev === 'CRITICAL' ? 'sev-critical' :
                                     sev === 'HIGH'     ? 'sev-high'     :
                                     sev === 'MEDIUM'   ? 'sev-medium'   :
                                     sev === 'LOW'      ? 'sev-low'      : 'sev-info';

                    const scoreColor = ind.scoreContribution > 2 ? 'var(--accent-red)' :
                                       ind.scoreContribution > 0 ? 'var(--accent-amber)' : 'var(--text-dim)';

                    tr.innerHTML = `
                        <td style="color:#93C5FD;white-space:nowrap;font-weight:600;">${escapeHtml(ind.layer || '')}</td>
                        <td style="color:#ffffff;font-weight:600;">${escapeHtml(ind.title || '')}</td>
                        <td><span class="${sevClass}">${sev}</span></td>
                        <td style="color:${scoreColor};font-weight:700;">+${(ind.scoreContribution || 0).toFixed(1)}</td>
                        <td style="color:var(--accent-cyan);word-break:break-word;overflow-wrap:anywhere;line-height:1.4;">${escapeHtml(ind.evidence || '')}</td>
                        <td style="color:var(--text-main);line-height:1.5;">${escapeHtml(ind.description || '')}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        });
    }

    document.getElementById('findings-count').innerText = `${totalFindings} Finding(s)`;

    if (totalFindings === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-10 text-center font-mono text-sm font-bold" style="color:var(--accent-cyan);">✓ CLEAN — No threat indicators triggered in any detection layer.</td></tr>`;
    }
}

// ============================================================
// Attachments Handling
// ============================================================
function addAttachmentRow() {
    addAttachmentItem('', 0, 'application/octet-stream');
}

function addAttachmentItem(filename, size, mime) {
    const container = document.getElementById('attachments-container');
    const id = 'att-' + Date.now() + Math.random().toString(36).substr(2, 4);

    const div = document.createElement('div');
    div.id = id;
    div.className = 'flex flex-wrap items-center gap-2 card-sub p-2.5 rounded-lg text-xs font-mono';
    div.innerHTML = `
        <input type="text" placeholder="Filename (e.g. document.pdf.exe)" value="${filename}" class="att-name rounded px-3 py-2 flex-1 font-semibold">
        <input type="number" placeholder="Size in bytes" value="${size > 0 ? size : ''}" class="att-size rounded px-3 py-2 w-32">
        <input type="text" placeholder="MIME Type (optional)" value="${mime}" class="att-mime rounded px-3 py-2 w-48">
        <button type="button" onclick="document.getElementById('${id}').remove()" class="bg-red-950 text-red-300 border border-red-700 hover:bg-red-900 px-3 py-2 rounded font-bold">✕</button>
    `;
    container.appendChild(div);
}

function getAttachmentsData() {
    const items = [];
    document.querySelectorAll('#attachments-container > div').forEach(div => {
        const name = div.querySelector('.att-name').value.trim();
        const size = parseInt(div.querySelector('.att-size').value) || 0;
        const mime = div.querySelector('.att-mime').value.trim();
        if (name) {
            items.push({ filename: name, sizeBytes: size, contentType: mime });
        }
    });
    return items;
}

// Chart.js Gauge — Neon Cybernetic Style (Scale 0 - 15)
function initScoreGauge(score, classification) {
    const canvas = document.getElementById('scoreGaugeCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const cappedScore = Math.min(score, 15);

    scoreGaugeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [cappedScore, Math.max(0, 15 - cappedScore)],
                backgroundColor: [getColorForClassification(classification), 'rgba(255,255,255,0.05)'],
                borderWidth: 0,
                circumference: 260,
                rotation: 230
            }]
        },
        options: {
            responsive: false,
            cutout: '80%',
            plugins: {
                tooltip: { enabled: false }
            },
            animation: { duration: 700, easing: 'easeOutQuart' }
        }
    });
}

function updateScoreGauge(score, classification) {
    if (scoreGaugeChart) {
        const cappedScore = Math.min(score, 15);
        scoreGaugeChart.data.datasets[0].data = [cappedScore, Math.max(0, 15 - cappedScore)];
        scoreGaugeChart.data.datasets[0].backgroundColor[0] = getColorForClassification(classification);
        scoreGaugeChart.update();
    }
}

function getColorForClassification(c) {
    if (c === 'DANGEROUS') return '#EF4444';   // Hazard red
    if (c === 'SUSPICIOUS') return '#F59E0B';  // Electric amber
    return '#00F5D4';                           // DevTools cyan (safe)
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// ============================================================
// Admin Panel — Database Scan History Management
// ============================================================
let cachedDatabaseScans = [];

async function loadDatabaseHistory() {
    try {
        const res = await fetch('/api/scan/db-history');
        if (!res.ok) return;
        cachedDatabaseScans = await res.json();
        renderDatabaseHistory(cachedDatabaseScans);
    } catch (err) {
        console.warn('Could not fetch Admin Panel database history:', err);
    }
}

function renderDatabaseHistory(scans) {
    const tbody = document.getElementById('db-history-tbody');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="px-4 py-8 text-center text-slate-400 italic text-sm">
                    No scans saved in the Admin Panel yet. Run an email or URL scan above to automatically record it!
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = '';
    scans.forEach((scan, index) => {
        const tr = document.createElement('tr');
        tr.className = 'terminal-row';

        const classification = scan.classification || 'SAFE';
        const badgeClass = classification === 'DANGEROUS' ? 'badge-dangerous' :
                          (classification === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-safe');

        const typeBadgeStyle = scan.scanType === 'URL'
            ? 'background:rgba(0,245,212,0.10);color:var(--accent-cyan);border:1px solid rgba(0,245,212,0.25);'
            : 'background:rgba(59,130,246,0.10);color:#93C5FD;border:1px solid rgba(59,130,246,0.25);';

        const displayTarget = scan.inputTarget || scan.subject || scan.sender || 'Scan Record';
        const dateStr = scan.createdAt ? new Date(scan.createdAt).toLocaleString() : 'Recent';

        tr.innerHTML = `
            <td><span class="text-[11px] font-mono font-bold px-2 py-0.5 rounded" style="${typeBadgeStyle}">${escapeHtml(scan.scanType || 'EMAIL')}</span></td>
            <td class="font-semibold text-white max-w-xs truncate" title="${escapeHtml(displayTarget)}">${escapeHtml(displayTarget)}</td>
            <td><span class="text-xs font-bold font-mono px-2.5 py-0.5 rounded ${badgeClass}">${classification}</span></td>
            <td class="font-mono font-bold" style="color:${classification === 'DANGEROUS' ? 'var(--accent-red)' : (classification === 'SUSPICIOUS' ? 'var(--accent-amber)' : 'var(--accent-cyan)')}">${(scan.overallRiskScore || 0).toFixed(1)} / 15</td>
            <td style="color:var(--text-main);">${dateStr}</td>
            <td class="text-right">
                <button onclick="viewSavedScan(${index})" class="text-xs font-mono font-bold px-3 py-1.5 rounded-lg bg-[#141B2D] text-[#00F5D4] border border-[#222B3D] hover:border-[#00F5D4] transition">
                    <i class="fa-solid fa-eye mr-1"></i> View Audit
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function viewSavedScan(index) {
    const scan = cachedDatabaseScans[index];
    if (!scan) return;

    // Convert database entity into frontend scan result structure
    const layer1Indicators = (scan.indicators || []).filter(i => i.layer && i.layer.toLowerCase().includes('1'));
    const layer2Indicators = (scan.indicators || []).filter(i => i.layer && i.layer.toLowerCase().includes('2'));
    const layer3Indicators = (scan.indicators || []).filter(i => i.layer && i.layer.toLowerCase().includes('3'));
    const layer4Indicators = (scan.indicators || []).filter(i => i.layer && i.layer.toLowerCase().includes('4'));

    const reconstructed = {
        scanId: scan.scanId,
        scanType: scan.scanType,
        overallRiskScore: scan.overallRiskScore,
        classification: scan.classification,
        totalExecutionTimeMs: scan.totalExecutionTimeMs || 0,
        summary: scan.summary,
        recommendations: scan.summary ? [scan.summary] : ["Loaded from Admin Panel audit record."],
        layerResults: [
            {
                layerNumber: 1,
                layerName: "Layer 1: Aho-Corasick Keywords & Sender Verification",
                score: layer1Indicators.reduce((sum, item) => sum + (item.scoreContribution || 0), 0),
                indicators: layer1Indicators
            },
            {
                layerNumber: 2,
                layerName: "Layer 2: Regex-Based Linguistic & Behavioral Analysis",
                score: layer2Indicators.reduce((sum, item) => sum + (item.scoreContribution || 0), 0),
                indicators: layer2Indicators
            },
            {
                layerNumber: 3,
                layerName: "Layer 3: Heuristic URL Analysis & Threat Intelligence",
                score: layer3Indicators.reduce((sum, item) => sum + (item.scoreContribution || 0), 0),
                indicators: layer3Indicators
            },
            {
                layerNumber: 4,
                layerName: "Layer 4: Attachment & Payload Analysis",
                score: layer4Indicators.reduce((sum, item) => sum + (item.scoreContribution || 0), 0),
                indicators: layer4Indicators
            }
        ]
    };

    // Switch tool view
    if (scan.scanType === 'URL') {
        switchMainTool('url-tool');
        const urlInput = document.getElementById('input-target-url');
        if (urlInput) urlInput.value = scan.inputTarget || '';
    } else {
        switchMainTool('email-tool');
        if (scan.sender) document.getElementById('input-sender').value = scan.sender;
        if (scan.subject) document.getElementById('input-subject').value = scan.subject;
    }

    renderScanResults(reconstructed);

    const resSec = document.getElementById('results-section');
    if (resSec) {
        resSec.classList.remove('hidden');
        resSec.scrollIntoView({ behavior: 'smooth' });
    }
}
