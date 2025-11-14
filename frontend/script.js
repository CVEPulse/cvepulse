// frontend/script.js
const API = "https://cvepulse.onrender.com/api/trending"; // your Render API
const tableBody = document.querySelector("#cveTableBody");
const sortSelect = document.querySelector("#sortSelect");
const lastUpdatedEl = document.querySelector("#lastUpdated");
const summarySplitEl = document.querySelector("#summarySplit");

function sevTag(cvss) {
  if (cvss >= 9) return `<span class="sev sev-critical">Critical</span>`;
  if (cvss >= 7) return `<span class="sev sev-high">High</span>`;
  if (cvss >= 4) return `<span class="sev sev-medium">Medium</span>`;
  return `<span class="sev sev-low">Low</span>`;
}

function sourceChips(sources) {
  return sources.map(s => `<span class="chip">${s}</span>`).join(" ");
}

function publishedText(p) {
  return p && p !== "Unknown" ? p.split("T")[0] : "—";
}

function render(data) {
  // Summary
  lastUpdatedEl.textContent = data.last_updated ? new Date(data.last_updated).toUTCString() : "—";

  const counts = {critical:0, high:0, medium:0, low:0};
  data.cves.forEach(x => {
    const c = x.cvss || 0;
    if (c >= 9) counts.critical++;
    else if (c >= 7) counts.high++;
    else if (c >= 4) counts.medium++;
    else counts.low++;
  });
  summarySplitEl.innerHTML =
    `Critical: <b>${counts.critical}</b> · High: <b>${counts.high}</b> · Medium: ${counts.medium} · Low: ${counts.low}`;

  // Default sort: Trending (score)
  applySort(data.cves, sortSelect.value);
}

function applySort(rows, mode) {
  const sorted = [...rows];
  if (mode === "Trending (score)") {
    sorted.sort((a,b) => (b.trend_score - a.trend_score) || (b.cvss - a.cvss));
  } else if (mode === "Published (Newest → Oldest)") {
    sorted.sort((a,b) => new Date(b.published||0) - new Date(a.published||0));
  } else if (mode === "CVSS (High → Low)") {
    sorted.sort((a,b) => (b.cvss - a.cvss) || (b.trend_score - a.trend_score));
  }

  tableBody.innerHTML = sorted.map(x => `
    <tr>
      <td class="id">
        <a href="https://nvd.nist.gov/vuln/detail/${x.id}" target="_blank">${x.id}</a>
        ${x.cvss ? ` <span class="cvss">${x.cvss.toFixed(1)}</span>` : ``}
        ${x.cvss >= 9 ? `<span class="pill danger">Critical</span>` : ``}
        ${x.kev ? `<span class="pill kev">KEV</span>` : ``}
      </td>
      <td class="desc">${x.description}</td>
      <td class="srcs">${sourceChips(x.sources)}</td>
      <td class="pub">${publishedText(x.published)}</td>
    </tr>
  `).join("");
}

async function load() {
  try {
    const r = await fetch(API, {cache: "no-store"});
    const data = await r.json();
    render(data);
  } catch (e) {
    console.error(e);
    tableBody.innerHTML = `<tr><td colspan="4">Failed to load data</td></tr>`;
  }
}

sortSelect.addEventListener("change", () => {
  // re-sort current table without re-fetch
  Array.from(tableBody.parentElement.parentElement.querySelectorAll("tr"));
  // fetch then re-render to rely on canonical data & keep simple
  load();
});

load();
setInterval(load, 15 * 60 * 1000); // auto-refresh 15 mins
