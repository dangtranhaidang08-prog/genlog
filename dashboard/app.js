// Real-time AI Security SOC Monitoring Dashboard Logic
document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const streamTbody = document.getElementById("streamTbody");
    const streamCount = document.getElementById("streamCount");
    const btnToggleStream = document.getElementById("btnToggleStream");
    const streamBtnText = document.getElementById("streamBtnText");
    const streamIcon = document.getElementById("streamIcon");
    const btnClearStream = document.getElementById("btnClearStream");

    // Threshold Controls (in Sidebar)
    const thresholdSlider = document.getElementById("thresholdSlider");
    const thresholdDisplay = document.getElementById("thresholdDisplay");

    // Detail Modal Elements
    const detailModal = document.getElementById("detailModal");
    const modalClose = document.getElementById("modalClose");
    const modalUrl = document.getElementById("modalUrl");
    const modalBodyGroup = document.getElementById("modalBodyGroup");
    const modalBody = document.getElementById("modalBody");
    const modalPrediction = document.getElementById("modalPrediction");
    const modalIndicators = document.getElementById("modalIndicators");

    let isStreaming = true;
    let pollInterval = setInterval(fetchStreamEvents, 1000);
    btnToggleStream.className = "btn btn-warning";
    streamBtnText.textContent = "Pause Stream";
    let totalMonitored = 0;

    // Category Doughnut Chart Setup
    let categoryChart;
    const categoryCounts = {
        "UNION": 0,
        "Boolean": 0,
        "Time-based": 0,
        "Error-based": 0,
        "JSON": 0,
        "Normal": 0
    };

    function initCharts() {
        const catCtx = document.getElementById("categoryChart").getContext("2d");
        categoryChart = new Chart(catCtx, {
            type: "doughnut",
            data: {
                labels: Object.keys(categoryCounts),
                datasets: [{
                    data: Object.values(categoryCounts),
                    backgroundColor: [
                        "#10b981", // UNION
                        "#8b5cf6", // Boolean
                        "#ef4444", // Time-based
                        "#f59e0b", // Error-based
                        "#ec4899", // JSON
                        "#3b82f6"  // Normal
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "right",
                        labels: { color: "#94a3b8", font: { size: 11 } }
                    }
                },
                cutout: "70%"
            }
        });
    }

    initCharts();

    // Fetch SOC Detection Threshold Config
    async function fetchSocStats() {
        try {
            const resp = await fetch("/api/stats");
            if (!resp.ok) return;
            const data = await resp.json();

            if (thresholdSlider && data.threshold !== undefined && Math.abs(parseFloat(thresholdSlider.value) - data.threshold) > 0.01) {
                thresholdSlider.value = data.threshold;
                if (thresholdDisplay) thresholdDisplay.textContent = parseFloat(data.threshold).toFixed(2);
            }
        } catch (e) {
            console.error("Stats fetch error:", e);
        }
    }

    // Stream Polling
    async function fetchStreamEvents() {
        try {
            const resp = await fetch("/api/stream");
            if (!resp.ok) return;
            const data = await resp.json();
            if (data && data.events && data.events.length > 0) {
                data.events.forEach(evt => appendStreamRow(evt));
            }
        } catch (e) {
            console.error("Stream fetch error:", e);
        }
    }

    function appendStreamRow(event) {
        totalMonitored++;
        streamCount.textContent = totalMonitored;

        const isSQLi = event.label === 1 || String(event.label_str).toUpperCase().includes("SQL");
        const isThreat = isSQLi || String(event.action || "").includes("THREAT") || String(event.action || "").includes("BLOCKED");

        const badgeClass = isSQLi ? "badge-blocked" : "badge-safe";
        const badgeText = isSQLi ? "SQL INJECTION" : "NORMAL";
        const actionClass = isThreat ? "color: var(--accent-red); font-weight: 600;" : "color: var(--accent-green);";

        const displayPayload = event.body ? `${event.path} [Body: ${event.body.substring(0, 60)}]` : (event.url || event.path || '/');

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="font-mono">${event.timestamp || new Date().toLocaleTimeString()}</td>
            <td class="font-mono">${event.source_ip || "127.0.0.1"}</td>
            <td><strong style="color: ${event.method === 'POST' ? '#8b5cf6' : '#3b82f6'};">${event.method || 'GET'}</strong></td>
            <td class="font-mono" style="max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(displayPayload)}
            </td>
            <td><span class="badge ${badgeClass}">${badgeText}</span></td>
            <td style="${actionClass}">${escapeHtml(event.action || (isThreat ? 'CRITICAL THREAT' : 'SAFE (NORMAL)'))}</td>
        `;

        tr.dataset.event = JSON.stringify(event);
        tr.addEventListener("click", () => showDetailModal(event));

        streamTbody.insertBefore(tr, streamTbody.firstChild);

        if (streamTbody.children.length > 50) {
            streamTbody.removeChild(streamTbody.lastChild);
        }

        updateCharts(event, isSQLi);
    }

    function updateCharts(event, isSQLi) {
        const atkType = String(event.attack_type || "").toLowerCase();
        if (atkType.includes("json")) categoryCounts["JSON"]++;
        else if (atkType.includes("union")) categoryCounts["UNION"]++;
        else if (atkType.includes("boolean")) categoryCounts["Boolean"]++;
        else if (atkType.includes("time")) categoryCounts["Time-based"]++;
        else if (atkType.includes("error")) categoryCounts["Error-based"]++;
        else categoryCounts["Normal"]++;

        categoryChart.data.datasets[0].data = Object.values(categoryCounts);
        categoryChart.update("none");
    }

    // Modal Inspection for Table Rows
    function showDetailModal(evt) {
        modalUrl.textContent = evt.url || `${evt.path || ''}?${evt.query || ''}`;

        if (evt.body) {
            modalBodyGroup.style.display = "block";
            modalBody.textContent = evt.body;
        } else {
            modalBodyGroup.style.display = "none";
        }

        const isSQLi = evt.label === 1 || String(evt.label_str).toUpperCase().includes("SQL");
        const prob = evt.confidence !== undefined ? (evt.confidence * 100).toFixed(2) : "99.85";

        modalPrediction.innerHTML = `
            <span class="badge ${isSQLi ? 'badge-blocked' : 'badge-safe'}">${isSQLi ? 'SQL INJECTION' : 'NORMAL'}</span>
            <span style="margin-left: 0.75rem; color: var(--text-muted);">Confidence: <strong>${prob}%</strong></span>
            <span style="margin-left: 0.75rem; color: var(--text-muted);">Latency: <strong>${evt.latency_ms || 0.1} ms</strong></span>
        `;

        modalIndicators.innerHTML = "";
        const indicators = evt.indicators || detectIndicators(evt.url || evt.query || evt.body || "");
        indicators.forEach(ind => {
            const li = document.createElement("li");
            li.textContent = ind;
            modalIndicators.appendChild(li);
        });

        detailModal.classList.add("active");
    }

    modalClose.addEventListener("click", () => detailModal.classList.remove("active"));
    detailModal.addEventListener("click", (e) => {
        if (e.target === detailModal) detailModal.classList.remove("active");
    });

    // Alert Threshold Slider Handler (in Sidebar)
    if (thresholdSlider) {
        thresholdSlider.addEventListener("input", () => {
            if (thresholdDisplay) thresholdDisplay.textContent = parseFloat(thresholdSlider.value).toFixed(2);
        });

        thresholdSlider.addEventListener("change", async () => {
            const newThreshold = parseFloat(thresholdSlider.value);
            try {
                await fetch("/api/config", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ threshold: newThreshold })
                });
            } catch (e) {
                console.error("Threshold update error:", e);
            }
        });
    }

    // Stream Controls
    btnToggleStream.addEventListener("click", () => {
        isStreaming = !isStreaming;
        if (isStreaming) {
            btnToggleStream.className = "btn btn-warning";
            streamBtnText.textContent = "Pause Stream";
            pollInterval = setInterval(fetchStreamEvents, 1000);
        } else {
            btnToggleStream.className = "btn btn-primary";
            streamBtnText.textContent = "Live Stream";
            clearInterval(pollInterval);
        }
    });

    btnClearStream.addEventListener("click", () => {
        streamTbody.innerHTML = "";
        totalMonitored = 0;
        streamCount.textContent = "0";
    });

    // Initial Fetch
    fetchSocStats();
    fetchStreamEvents();

    // Helper functions
    function escapeHtml(str) {
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function detectIndicators(queryStr) {
        const decoded = decodeURIComponent(queryStr);
        const inds = [];
        if (decoded.includes("'")) inds.push("Single quote (')");
        if (decoded.includes('"')) inds.push('Double quote (")');
        if (/or\s+['"]?\w+['"]?\s*=\s*['"]?\w+/i.test(decoded) || decoded.includes("1=1")) inds.push("Tautology / OR condition");
        if (/union\s+select/i.test(decoded)) inds.push("UNION SELECT keyword sequence");
        if (/--|#|\/\*/.test(decoded)) inds.push("SQL comment (-- or # or /*)");
        if (decoded.toLowerCase().includes("information_schema")) inds.push("Information Schema query");
        if (/sleep|benchmark/i.test(decoded)) inds.push("Time-based Blind SQLi function");
        if (/case\s+when/i.test(decoded) || decoded.includes("1/0")) inds.push("Error-based SQLi / Division by zero");
        return inds.length ? inds : ["Clean HTTP payload structure"];
    }
});
