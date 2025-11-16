/* ----------------------------------------------------
   DOM ELEMENTS
---------------------------------------------------- */
const API_URL = "https://cvepulse.onrender.com/api/trending";

const tbody = document.getElementById("tbody");
const totalCves = document.getElementById("total");
const lastUpdated = document.getElementById("lastUpdated");

const sevCritical = document.getElementById("sev-critical");
const sevHigh = document.getElementById("sev-high");
const sevMedium = document.getElementById("sev-medium");
const sevLow = document.getElementById("sev-low");

const searchBox = document.getElementById("search");
const sortSelect = document.getElementById("sort");

const trendContainer = document.getElementById("trend-scores");

const themeToggle = document.getElementById("themeToggle");

/* ----------------------------------------------------
   GLOBAL DATA STORE
---------------------------------------------------- */
let cveData = [];
let filteredData = [];

/* ----------------------------------------------------
   FETCH DATA
---------------------------------------------------- */
async function fetchData() {
  try {
    const res = await fetch(API_URL);
    const json = await res.json();

    cveData = json.cves || [];
    filteredData = [...cveData];

    updateSummary(json);
    renderTable(filteredData);

  } catch (err) {
    console.error("Fetch error:", err);
  }
}

/* ----------------------------------------------------
   SUMMARY COUNTERS
---------------------------------------------------- */
function updateSummary(meta) {
  totalCves.textContent = meta.count || filteredData.length || 0;

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  filteredData.forEach(cve => {
    const cvss = Number(cve.cvss || 0);

    if (cvss >= 9) counts.critical++;
    else if (cvss >= 7) counts.high++;
    else if (cvss >= 4) counts.medium++;
    else counts.low++;
  });

  sevCritical.textContent = `Critical: ${counts.critical}`;
  sevHigh.textContent = `High: ${counts.high}`;
  sevMedium.textContent = `Medium: ${counts.medium}`;
  sevLow.textContent = `Low: ${counts.low}`;

  lastUpdated.textContent = meta.last_updated
    ? new Date(meta.last_updated).toUTCString()
    : "—";
}

/* ----------------------------------------------------
   RENDER TABLE
---------------------------------------------------- */
function renderTable(data) {
  tbody.innerHTML = "";

  data.forEach(cve => {
    const tr = document.createElement("tr");

    /* Determine severity class */
    const cvss = Number(cve.cvss || 0);
    let sevClass = "cvss-low";
    if (cvss >= 9) sevClass = "cvss-critical";
    else if (cvss >= 7) sevClass = "cvss-high";
    else if (cvss >= 4) sevClass = "cvss-medium";

    /* Source icons */
    const srcIcons = cve.sources
      .map(s => `<span class="source-icon">${s}</span>`)
      .join("");

    /* Trend badge */
    const trendScore = cve.trend_score || 0;

    /* Published / posted date */
    let published = "—";
    if (cve.published && cve.published !== "Unknown") {
      published = new Date(cve.published).toUTCString();
    } else if (cve.posted_time) {
      published = new Date(cve.posted_time).toUTCString();
    }

    tr.innerHTML = `
      <td class="col-cve">
        <div class="cve-id">${cve.id}</div>
        <div class="cvss-badge ${sevClass}">
          CVSS: ${cvss || "N/A"}
        </div>
        <span class="trend-badge">🔥 ${trendScore}</span>
      </td>

      <td class="col-desc">${cve.description}</td>

      <td class="col-src">${srcIcons}</td>

      <td class="col-date">${published}</td>
    `;

    tbody.appendChild(tr);
  });
}

/* ----------------------------------------------------
   SEARCH FILTER
---------------------------------------------------- */
searchBox.addEventListener("input", () => {
  const term = searchBox.value.toLowerCase();

  filteredData = cveData.filter(cve =>
    cve.id.toLowerCase().includes(term) ||
    (cve.description || "").toLowerCase().includes(term)
  );

  renderTable(filteredData);
  updateSummary({ count: filteredData.length });
});

/* ----------------------------------------------------
   SORTING
---------------------------------------------------- */
sortSelect.addEventListener("change", () => {
  const val = sortSelect.value;

  if (val === "published_desc") {
    filteredData.sort((a, b) => new Date(b.published || 0) - new Date(a.published || 0));
  }
  if (val === "published_asc") {
    filteredData.sort((a, b) => new Date(a.published || 0) - new Date(b.published || 0));
  }
  if (val === "cvss_desc") {
    filteredData.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
  }
  if (val === "cvss_asc") {
    filteredData.sort((a, b) => (a.cvss || 0) - (b.cvss || 0));
  }
  if (val === "trend_desc") {
    filteredData.sort((a, b) => (b.trend_score || 0) - (a.trend_score || 0));
  }

  renderTable(filteredData);
});

/* ----------------------------------------------------
   DARK/LIGHT THEME
---------------------------------------------------- */
themeToggle.addEventListener("click", () => {
  const html = document.documentElement;

  if (html.getAttribute("data-theme") === "light") {
    html.setAttribute("data-theme", "dark");
    themeToggle.textContent = "🌙";
  } else {
    html.setAttribute("data-theme", "light");
    themeToggle.textContent = "☀️";
  }
});

/* ----------------------------------------------------
   INIT
---------------------------------------------------- */
fetchData();
setInterval(fetchData, 900_000); // auto-refresh every 15 min
