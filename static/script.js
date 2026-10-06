document.addEventListener("DOMContentLoaded", () => {
    // Global State
    let isCapturing = false;
    let isDemoMode = false;
    let lastPacketId = 0;
    let allPackets = [];
    let pollTimer = null;
    let timeSeriesHistory = []; // { time: '14:02:05', count: 5 }

    // DOM Element References
    const btnStart = document.getElementById("btnStart");
    const btnStop = document.getElementById("btnStop");
    const btnClear = document.getElementById("btnClear");
    const btnToggleDemo = document.getElementById("btnToggleDemo");
    
    const statusIndicator = document.getElementById("statusIndicator");
    const statusText = document.getElementById("statusText");
    const modeBadge = document.getElementById("modeBadge");
    const errorAlert = document.getElementById("errorAlert");
    const alertMsg = document.getElementById("alertMsg");

    const statTotal = document.getElementById("statTotal");
    const statTcp = document.getElementById("statTcp");
    const statUdp = document.getElementById("statUdp");
    const statIcmp = document.getElementById("statIcmp");
    const statOther = document.getElementById("statOther");

    const filterIp = document.getElementById("filterIp");
    const filterProtocol = document.getElementById("filterProtocol");
    const filterPort = document.getElementById("filterPort");
    const btnResetFilter = document.getElementById("btnResetFilter");

    const packetTableBody = document.getElementById("packetTableBody");
    const visiblePacketCount = document.getElementById("visiblePacketCount");

    const detailModal = document.getElementById("detailModal");
    const modalClose = document.getElementById("modalClose");
    const modalCloseBtn = document.getElementById("modalCloseBtn");
    
    const modalPktId = document.getElementById("modalPktId");
    const modalProtoBadge = document.getElementById("modalProtoBadge");
    const modalSummary = document.getElementById("modalSummary");
    const modalTime = document.getElementById("modalTime");
    const modalSrcIp = document.getElementById("modalSrcIp");
    const modalDstIp = document.getElementById("modalDstIp");
    const modalSrcPort = document.getElementById("modalSrcPort");
    const modalDstPort = document.getElementById("modalDstPort");
    const modalLength = document.getElementById("modalLength");
    const modalRawDetails = document.getElementById("modalRawDetails");

    // Initialize Chart.js Instances
    let protocolChart, timelineChart;
    initCharts();

    // Event Listeners
    btnStart.addEventListener("click", startCapture);
    btnStop.addEventListener("click", stopCapture);
    btnClear.addEventListener("click", clearData);
    btnToggleDemo.addEventListener("click", toggleDemoMode);

    filterIp.addEventListener("input", applyFilters);
    filterProtocol.addEventListener("change", applyFilters);
    filterPort.addEventListener("input", applyFilters);
    btnResetFilter.addEventListener("click", () => {
        filterIp.value = "";
        filterProtocol.value = "ALL";
        filterPort.value = "";
        applyFilters();
    });

    modalClose.addEventListener("click", closeModal);
    modalCloseBtn.addEventListener("click", closeModal);
    detailModal.addEventListener("click", (e) => {
        if (e.target === detailModal) closeModal();
    });

    // Initial Status Check
    fetchStatus();
    // Start Polling Interval (Every 750ms)
    pollTimer = setInterval(pollServer, 750);

    // API Calls & Handlers
    async function fetchStatus() {
        try {
            const res = await fetch("/api/status");
            const data = await res.json();
            updateUIStatus(data);
        } catch (err) {
            console.error("Error fetching status:", err);
        }
    }

    async function startCapture() {
        try {
            const res = await fetch("/api/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ demo_mode: isDemoMode })
            });
            const data = await res.json();
            updateUIStatus(data);
        } catch (err) {
            console.error("Error starting capture:", err);
        }
    }

    async function stopCapture() {
        try {
            const res = await fetch("/api/stop", { method: "POST" });
            const data = await res.json();
            updateUIStatus(data);
        } catch (err) {
            console.error("Error stopping capture:", err);
        }
    }

    async function clearData() {
        try {
            await fetch("/api/clear", { method: "POST" });
            allPackets = [];
            lastPacketId = 0;
            timeSeriesHistory = [];
            
            // Clear UI
            packetTableBody.innerHTML = `
                <tr id="emptyRow">
                    <td colspan="8" class="text-center empty-msg">No packets captured yet. Click "Start Capture" to monitor network traffic.</td>
                </tr>
            `;
            visiblePacketCount.textContent = "0";
            statTotal.textContent = "0";
            statTcp.textContent = "0";
            statUdp.textContent = "0";
            statIcmp.textContent = "0";
            statOther.textContent = "0";

            updateCharts({ total: 0, tcp: 0, udp: 0, icmp: 0, other: 0 }, 0);
        } catch (err) {
            console.error("Error clearing data:", err);
        }
    }

    async function toggleDemoMode() {
        try {
            const res = await fetch("/api/toggle_demo", { method: "POST" });
            const data = await res.json();
            isDemoMode = data.is_demo_mode;
            fetchStatus();
        } catch (err) {
            console.error("Error toggling demo mode:", err);
        }
    }

    async function pollServer() {
        // Fetch new packets
        try {
            const packetsRes = await fetch(`/api/packets?since_id=${lastPacketId}`);
            const packetsData = await packetsRes.json();

            if (packetsData.packets && packetsData.packets.length > 0) {
                const newPackets = packetsData.packets;
                allPackets.push(...newPackets);
                lastPacketId = packetsData.last_id;

                renderNewPackets(newPackets);
            }

            // Fetch statistics
            const statsRes = await fetch("/api/stats");
            const statsData = await statsRes.json();
            updateStatsUI(statsData, packetsData.packets ? packetsData.packets.length : 0);

        } catch (err) {
            console.error("Polling error:", err);
        }
    }

    function updateUIStatus(data) {
        isCapturing = data.is_capturing;
        isDemoMode = data.is_demo_mode;

        if (isCapturing) {
            statusIndicator.className = "status-badge status-active";
            statusText.textContent = "LIVE CAPTURE ACTIVE";
            btnStart.disabled = true;
            btnStop.disabled = false;
        } else {
            statusIndicator.className = "status-badge status-stopped";
            statusText.textContent = "CAPTURE STOPPED";
            btnStart.disabled = false;
            btnStop.disabled = true;
        }

        if (isDemoMode) {
            modeBadge.textContent = "DEMO MODE (Simulated Traffic)";
            btnToggleDemo.textContent = "Switch to Real Mode";
        } else {
            modeBadge.textContent = "REAL CAPTURE MODE";
            btnToggleDemo.textContent = "Switch to Demo Mode";
        }

        // Handle error alert banner
        if (data.capture_error) {
            alertMsg.textContent = data.capture_error;
            errorAlert.classList.remove("hidden");
        } else {
            errorAlert.classList.add("hidden");
        }
    }

    function updateStatsUI(stats, newlyCapturedCount) {
        statTotal.textContent = stats.total.toLocaleString();
        statTcp.textContent = stats.tcp.toLocaleString();
        statUdp.textContent = stats.udp.toLocaleString();
        statIcmp.textContent = stats.icmp.toLocaleString();
        statOther.textContent = stats.other.toLocaleString();

        updateCharts(stats, newlyCapturedCount);
    }

    function getProtoBadgeClass(proto) {
        switch (proto) {
            case "TCP": return "proto-tcp";
            case "UDP": return "proto-udp";
            case "ICMP": return "proto-icmp";
            default: return "proto-other";
        }
    }

    function renderNewPackets(newPackets) {
        const emptyRow = document.getElementById("emptyRow");
        if (emptyRow) {
            packetTableBody.innerHTML = "";
        }

        const ipFilter = filterIp.value.toLowerCase().trim();
        const protoFilter = filterProtocol.value.toUpperCase();
        const portFilter = filterPort.value.trim();

        // Render each new packet
        newPackets.forEach(pkt => {
            const tr = document.createElement("tr");
            tr.dataset.pktId = pkt.id;
            tr.onclick = () => openPacketModal(pkt);

            // Filter check
            let isVisible = true;
            if (protoFilter !== "ALL" && pkt.protocol !== protoFilter) isVisible = false;
            if (ipFilter && !pkt.src_ip.toLowerCase().includes(ipFilter) && !pkt.dst_ip.toLowerCase().includes(ipFilter)) isVisible = false;
            if (portFilter && String(pkt.src_port) !== portFilter && String(pkt.dst_port) !== portFilter) isVisible = false;

            if (!isVisible) {
                tr.style.display = "none";
            }

            tr.innerHTML = `
                <td class="code-font">${pkt.id}</td>
                <td class="code-font">${pkt.time}</td>
                <td class="code-font">${pkt.src_ip}</td>
                <td class="code-font">${pkt.dst_ip}</td>
                <td><span class="proto-badge ${getProtoBadgeClass(pkt.protocol)}">${pkt.protocol}</span></td>
                <td class="code-font">${pkt.src_port}</td>
                <td class="code-font">${pkt.dst_port}</td>
                <td class="code-font">${pkt.length}</td>
            `;

            // Prepend new packets at the top of the table
            packetTableBody.insertBefore(tr, packetTableBody.firstChild);
        });

        // Limit DOM table size to 250 rows for smoothness
        while (packetTableBody.children.length > 250) {
            packetTableBody.removeChild(packetTableBody.lastChild);
        }

        updateVisibleCount();
    }

    function applyFilters() {
        const ipFilter = filterIp.value.toLowerCase().trim();
        const protoFilter = filterProtocol.value.toUpperCase();
        const portFilter = filterPort.value.trim();

        const rows = packetTableBody.querySelectorAll("tr");
        let visibleCount = 0;

        rows.forEach(tr => {
            if (tr.id === "emptyRow") return;

            const pktId = parseInt(tr.dataset.pktId, 10);
            const pkt = allPackets.find(p => p.id === pktId);

            if (!pkt) return;

            let isVisible = true;
            if (protoFilter !== "ALL" && pkt.protocol !== protoFilter) isVisible = false;
            if (ipFilter && !pkt.src_ip.toLowerCase().includes(ipFilter) && !pkt.dst_ip.toLowerCase().includes(ipFilter)) isVisible = false;
            if (portFilter && String(pkt.src_port) !== portFilter && String(pkt.dst_port) !== portFilter) isVisible = false;

            if (isVisible) {
                tr.style.display = "";
                visibleCount++;
            } else {
                tr.style.display = "none";
            }
        });

        visiblePacketCount.textContent = visibleCount;
    }

    function updateVisibleCount() {
        const rows = packetTableBody.querySelectorAll("tr:not([style*='display: none']):not(#emptyRow)");
        visiblePacketCount.textContent = rows.length;
    }

    // Modal Operations
    function openPacketModal(pkt) {
        modalPktId.textContent = pkt.id;
        modalProtoBadge.textContent = pkt.protocol;
        modalProtoBadge.className = `proto-badge ${getProtoBadgeClass(pkt.protocol)}`;
        modalSummary.textContent = pkt.summary;
        modalTime.textContent = pkt.time;
        modalSrcIp.textContent = pkt.src_ip;
        modalDstIp.textContent = pkt.dst_ip;
        modalSrcPort.textContent = pkt.src_port;
        modalDstPort.textContent = pkt.dst_port;
        modalLength.textContent = `${pkt.length} Bytes`;

        // Format detailed key-values
        let formattedDetails = `Summary: ${pkt.summary}\n`;
        formattedDetails += `Protocol: ${pkt.protocol}\n`;
        formattedDetails += `Packet Size: ${pkt.length} Bytes\n\n`;
        formattedDetails += `--- HEADER FIELDS ---\n`;
        for (const [key, val] of Object.entries(pkt.details || {})) {
            formattedDetails += `${key}: ${val}\n`;
        }

        modalRawDetails.textContent = formattedDetails;
        detailModal.classList.remove("hidden");
    }

    function closeModal() {
        detailModal.classList.add("hidden");
    }

    // Chart Initialization & Updates
    function initCharts() {
        const ctxProto = document.getElementById("protocolChart").getContext("2d");
        protocolChart = new Chart(ctxProto, {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP", "ICMP", "Other"],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ["#0f172a", "#475569", "#94a3b8", "#e2e8f0"],
                    borderWidth: 1,
                    borderColor: "#ffffff"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom" }
                }
            }
        });

        const ctxTime = document.getElementById("timelineChart").getContext("2d");
        timelineChart = new Chart(ctxTime, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Packets Captured Rate",
                    data: [],
                    borderColor: "#0f172a",
                    backgroundColor: "rgba(15, 23, 42, 0.05)",
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true },
                    x: { display: true }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    function updateCharts(stats, newlyCapturedCount) {
        // Doughnut Chart update
        protocolChart.data.datasets[0].data = [stats.tcp, stats.udp, stats.icmp, stats.other];
        protocolChart.update();

        // Timeline Chart update
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        timeSeriesHistory.push({ time: now, count: newlyCapturedCount });

        // Keep last 15 time points
        if (timeSeriesHistory.length > 15) {
            timeSeriesHistory.shift();
        }

        timelineChart.data.labels = timeSeriesHistory.map(item => item.time);
        timelineChart.data.datasets[0].data = timeSeriesHistory.map(item => item.count);
        timelineChart.update();
    }
});
