const API_URL = "http://127.0.0.1:8000/api/trending";

let GLOBAL_DATA = { results: [], last_updated: null, window_days: 14 };

const PRIORITY_ORDER = ["Emergency", "Zero-Day", "Critical", "High", "Medium"];
const PRIORITY_WEIGHT = Object.fromEntries(PRIORITY_ORDER.map((p, i) => [p, i]));

// Helpers
const mapSeverityToPriority = (sev) => {
  const s = (sev || "Medium").toString().toLowerCase();
  if (s.startsWith("crit")) return "Critical";
  if (s.startsWith("high")) return "High";
  return "Medium";
};
const getPriority = (cve) => cve.priority || mapSeverityToPriority(cve.severity);
const isoDay = (v) => (v ? new Date(v).toISOString().slice(0, 10) : "");

const buzzScore = (cve) => {
  const srcs = Array.isArray(cve.sources) ? cve.sources : [];
  const extra = srcs.filter((s) => s !== "NVD").length;
  const sigs = Array.isArray(cve.signals) ? cve.signals.length : 0;
  return extra * 2 + sigs;
};
const visibilityLabel = (cve) => {
  const score = buzzScore(cve);
  if (score >= 5) return "Highly Discussed";
  if (score >= 2) return "Moderately Discussed";
  return "Emerging";
};

// Fetch + initial render
async function loadData() {
  try {
    const res = await fetch(API_URL, { cache: "no-store" });
    if (!res.ok) throw new Error(`API error ${res.status}`);
    GLOBAL_DATA = await res.json();

    renderSummaryBar(GLOBAL_DATA);
    renderTrendChart(GLOBAL_DATA);

    const sel = document.getElementById("priorityFilter");
    if (sel && !sel.dataset._initialized) {
      sel.value = "Top";
      sel.dataset._initialized = "1";
      sel.addEventListener("change", () => renderTable(GLOBAL_DATA));
    }

    renderTable(GLOBAL_DATA);

    const ts = GLOBAL_DATA.last_updated || new Date().toISOString();
    const stampEl = document.getElementById("lastUpdated");
    if (stampEl) stampEl.textContent = "Last Updated: " + new Date(ts).toLocaleString();
  } catch (err) {
    console.error(err);
    const stampEl = document.getElementById("lastUpdated");
    if (stampEl) stampEl.textContent = "Last Updated: API unavailable";
  }
}

// Summary bar
function renderSummaryBar(data) {
  const counts = { Emergency: 0, "Zero-Day": 0, Critical: 0, High: 0, Medium: 0 };
  (data.results || []).forEach((cve) => {
    const p = getPriority(cve);
    if (counts[p] !== undefined) counts[p]++;
  });
  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  };
  set("countEmergency", counts["Emergency"]);
  set("countZeroDay", counts["Zero-Day"]);
  set("countCritical", counts["Critical"]);
  set("countHigh", counts["High"]);
  set("countMedium", counts["Medium"]);
}

// Trend chart
function renderTrendChart(data) {
  const results = data.results || [];
  if (!results.length) { maybeDestroyTrend(); return; }

  const allDays = Array.from(new Set(results.map((r) => isoDay(r.published)).filter(Boolean))).sort();
  const last7 = allDays.slice(-7);
  if (!last7.length) { maybeDestroyTrend(); return; }

  const emergencyCounts = last7.map((d) =>
    results.filter((r) => isoDay(r.published) === d && getPriority(r) === "Emergency").length
  );
  const zeroDayCounts = last7.map((d) =>
    results.filter((r) => isoDay(r.published) === d && getPriority(r) === "Zero-Day").length
  );

  const ctx = document.getElementById("trendChart").getContext("2d");
  if (window.trendChartInstance) window.trendChartInstance.destroy();

  window.trendChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: last7,
      datasets: [
        {
          label: "Emergency",
          data: emergencyCounts,
          borderColor: "#ff3b30",
          backgroundColor: "rgba(255,59,48,0.15)",
          borderWidth: 2,
          tension: 0.35,
          fill: true,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
        {
          label: "Zero-Day",
          data: zeroDayCounts,
          borderColor: "#00bcd4",
          backgroundColor: "rgba(0,188,212,0.10)",
          borderWidth: 2,
          tension: 0.35,
          fill: true,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { color: "#9ba6b1" } } },
      scales: {
        x: { ticks: { color: "#9ba6b1" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: {
          beginAtZero: true,
          ticks: { color: "#9ba6b1", precision: 0, stepSize: 1 },
          grid: { color: "rgba(255,255,255,0.05)" },
        },
      },
    },
  });
}
function maybeDestroyTrend(){ if (window.trendChartInstance){ window.trendChartInstance.destroy(); window.trendChartInstance=null; } }

// Table
function renderTable(data) {
  const tbody = document.querySelector("#cveTable tbody");
  if (!tbody) return;

  const sel = document.getElementById("priorityFilter");
  const selected = sel && sel.value ? sel.value : "Top";

  let allow = ["Emergency","Zero-Day","Critical","High","Medium"];
  if (selected === "Top") allow = ["Emergency","Zero-Day","Critical","High"];
  else if (selected === "Emergency") allow = ["Emergency"];
  else if (selected === "Zero-Day") allow = ["Zero-Day"];
  else if (selected === "Critical") allow = ["Critical"];
  else if (selected === "High") allow = ["High"];
  // "All" shows everything

  let rows = (data.results || []).filter((cve) => allow.includes(getPriority(cve)));

  rows.sort((a, b) => {
    const wa = PRIORITY_WEIGHT[getPriority(a)] ?? 999;
    const wb = PRIORITY_WEIGHT[getPriority(b)] ?? 999;
    if (wa !== wb) return wa - wb;
    const da = new Date(a.published || 0).getTime();
    const db = new Date(b.published || 0).getTime();
    return db - da;
  });

  tbody.innerHTML = "";
  rows.forEach((cve) => {
    const sources = Array.isArray(cve.sources) ? cve.sources.join(", ") : "NVD";
    const desc = cve.description || "No description available";
    const published = cve.published ? isoDay(cve.published) : "N/A";
    const priority = getPriority(cve);
    const signals =
      Array.isArray(cve.signals) && cve.signals.length
        ? `<div class="source-list">Signals: ${cve.signals.join(" · ")}</div>`
        : "";

    const vis = visibilityLabel(cve);
    const visBadge = `<span class="vis-badge vis-${vis.replace(/\s+/g,'-').toLowerCase()}">${vis}</span>`;

    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${cve.id}</td>
      <td>${desc}<div class="vis-wrap">${visBadge}</div>${signals}</td>
      <td><span class="badge">${priority}</span></td>
      <td>${sources}</td>
      <td>${published}</td>
    `;
    tbody.appendChild(row);
  });
}

// Guard: ensure default is Top
document.addEventListener("DOMContentLoaded", () => {
  const sel = document.getElementById("priorityFilter");
  if (sel) {
    const valid = ["Top","Emergency","Zero-Day","Critical","High","All"];
    if (!valid.includes(sel.value)) sel.value = "Top";
  }
});

window.onload = loadData;
