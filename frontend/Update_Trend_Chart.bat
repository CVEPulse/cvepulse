@echo off
title CVEPulse Auto-Refresh Chart Setup
color 0B
echo ==========================================
echo     CVEPulse Auto-Refresh Chart Installer
echo ==========================================
echo.

REM === Step 1: Navigate to frontend directory ===
cd /d "%~dp0"

echo [1/3] Creating auto-refresh script.js ...
(
echo // ===== MOCK CVE TREND DATA (auto-refresh version) =====
echo let mockData = {
echo   results: [
echo     { id: "CVE-2025-1001", description: "Remote code execution in XYZ.", priority: "Emergency", sources: ["Reddit", "NVD"], published: "2025-11-03" },
echo     { id: "CVE-2025-1002", description: "Zero-day in Chrome browser sandbox escape.", priority: "Zero-Day", sources: ["The Hacker News", "Reddit"], published: "2025-11-04" },
echo     { id: "CVE-2025-1003", description: "Privilege escalation in Windows driver.", priority: "Critical", sources: ["BleepingComputer"], published: "2025-11-05" }
echo   ]
echo };
echo.
echo // ===== LOAD MOCK DATA =====
echo function loadData() {
echo   renderSummaryBar(mockData);
echo   renderTrendChart(mockData);
echo   renderTable(mockData);
echo   document.getElementById("lastUpdated").textContent = "Last Updated: " + new Date().toLocaleString();
echo }
echo.
echo // ===== AUTO REFRESH (simulate data changes) =====
echo setInterval(() => {
echo   const randomPriority = ["Emergency","Zero-Day","Critical","High","Medium"][Math.floor(Math.random()*5)];
echo   const today = new Date().toISOString().slice(0,10);
echo   const newCVE = {
echo     id: "CVE-2025-" + Math.floor(2000 + Math.random()*1000),
echo     description: "Auto-generated " + randomPriority + " CVE update.",
echo     priority: randomPriority,
echo     sources: ["NVD","Reddit","The Hacker News"].slice(0, Math.floor(Math.random()*3)+1),
echo     published: today
echo   };
echo   mockData.results.push(newCVE);
echo   if(mockData.results.length > 20) mockData.results.shift(); // keep last 20
echo   loadData();
echo   console.log("[+] Auto-refresh added new CVE:", newCVE.id);
echo }, 10000); // every 10 seconds
echo.
echo // ===== SUMMARY BAR =====
echo function renderSummaryBar(data) {
echo   const counts = { Emergency: 0, "Zero-Day": 0, Critical: 0, High: 0, Medium: 0 };
echo   data.results.forEach(cve => { if (counts[cve.priority] !== undefined) counts[cve.priority]++; });
echo   document.getElementById("countEmergency").textContent = counts["Emergency"];
echo   document.getElementById("countZeroDay").textContent = counts["Zero-Day"];
echo   document.getElementById("countCritical").textContent = counts["Critical"];
echo   document.getElementById("countHigh").textContent = counts["High"];
echo   document.getElementById("countMedium").textContent = counts["Medium"];
echo }
echo.
echo // ===== TREND CHART =====
echo function renderTrendChart(data) {
echo   const now = new Date();
echo   const days = Array.from({ length: 7 }, (_, i) => {
echo     const d = new Date(now);
echo     d.setDate(d.getDate() - (6 - i));
echo     return d.toISOString().slice(0, 10);
echo   });
echo   const emergencyCounts = Array(7).fill(0);
echo   const zeroDayCounts = Array(7).fill(0);
echo   data.results.forEach(cve => {
echo     const date = cve.published?.slice(0,10);
echo     if (!date) return;
echo     const idx = days.indexOf(date);
echo     if (idx === -1) return;
echo     if (cve.priority === "Emergency") emergencyCounts[idx]++;
echo     if (cve.priority === "Zero-Day") zeroDayCounts[idx]++;
echo   });
echo   const ctx = document.getElementById("trendChart").getContext("2d");
echo   if (window.trendChartInstance) window.trendChartInstance.destroy();
echo   window.trendChartInstance = new Chart(ctx, {
echo     type: "line",
echo     data: {
echo       labels: days,
echo       datasets: [
echo         { label: "Emergency", data: emergencyCounts, borderColor: "#ff3b30", backgroundColor: "rgba(255,59,48,0.15)", borderWidth: 2, tension: 0.4, fill: true, pointRadius: 5 },
echo         { label: "Zero-Day", data: zeroDayCounts, borderColor: "#00bcd4", backgroundColor: "rgba(0,188,212,0.1)", borderWidth: 2, tension: 0.4, fill: true, pointRadius: 5 }
echo       ]
echo     },
echo     options: {
echo       responsive: true,
echo       plugins: { legend: { labels: { color: "#9ba6b1" } } },
echo       scales: { x: { ticks: { color: "#9ba6b1" } }, y: { beginAtZero: true, ticks: { color: "#9ba6b1" } } }
echo     }
echo   });
echo }
echo.
echo // ===== TABLE =====
echo function renderTable(data) {
echo   const tbody = document.querySelector("#cveTable tbody");
echo   tbody.innerHTML = "";
echo   data.results.slice().reverse().forEach(cve => {
echo     const row = document.createElement("tr");
echo     row.innerHTML = `
echo       <td>${cve.id}</td>
echo       <td>${cve.description}</td>
echo       <td><span class="badge">${cve.priority}</span></td>
echo       <td>${cve.sources ? cve.sources.join(", ") : "N/A"}</td>
echo       <td>${cve.published || "N/A"}</td>
echo     `;
echo     tbody.appendChild(row);
echo   });
echo }
echo.
echo window.onload = loadData;
) > script.js

echo [2/3] Appending chart style to style.css ...
(
echo.
echo /* ===== CHART STYLE ===== */
echo #trendChart {
echo   width: 100%% !important;
echo   max-height: 180px;
echo }
echo canvas {
echo   background: transparent;
echo }
echo .chartjs-render-monitor {
echo   animation: fadeIn 1s ease-in-out;
echo }
echo @keyframes fadeIn {
echo   from { opacity: 0; transform: translateY(10px); }
echo   to { opacity: 1; transform: translateY(0); }
echo }
) >> style.css

echo [3/3] Launching local server for preview...
python -m http.server 5500
pause
