// ---- CONFIG ----
const API_BASE = "https://cvepulse.onrender.com";   // your Render backend

const $ = (q) => document.querySelector(q);

const fmtDate = (isoOrUnknown) => {
  if (!isoOrUnknown || isoOrUnknown === "Unknown") return "—";
  const d = new Date(isoOrUnknown);
  return isNaN(d) ? "—" : d.toISOString().slice(0,10);
};

const sevClass = (score) => {
  if (typeof score !== "number") return "";
  if (score >= 9.0) return "crit";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "med";
  return "low";
};

const updateSummary = (data) => {
  $("#total").textContent = data.count ?? 0;
  $("#lastUpdated").textContent = data.last_updated ?? "—";

  const counts = {critical:0,high:0,medium:0,low:0};
  (data.cves||[]).forEach(c => {
    const s = typeof c.cvss === "number" ? c.cvss : null;
    if (s === null) return;
    if (s >= 9) counts.critical++;
    else if (s >= 7) counts.high++;
    else if (s >= 4) counts.medium++;
    else counts.low++;
  });
  $("#sev-critical").textContent = `Critical: ${counts.critical}`;
  $("#sev-high").textContent     = `High: ${counts.high}`;
  $("#sev-medium").textContent   = `Medium: ${counts.medium}`;
  $("#sev-low").textContent      = `Low: ${counts.low}`;
};

const buildRow = (item) => {
  const tr = document.createElement("tr");

  // CVE + CVSS badge (same line)
  const cveTd = document.createElement("td");
  const idSpan = document.createElement("span");
  idSpan.className = "cve-id";
  idSpan.textContent = item.id || "(no id)";
  cveTd.appendChild(idSpan);

  if (typeof item.cvss === "number") {
    const badge = document.createElement("span");
    badge.className = `cvss-badge ${sevClass(item.cvss)}`;
    badge.textContent = `CVSS ${item.cvss.toFixed(1)}`;
    cveTd.appendChild(badge);
  } else {
    const badge = document.createElement("span");
    badge.className = "cvss-badge";
    badge.textContent = "CVSS n/a";
    cveTd.appendChild(badge);
  }

  // Description
  const descTd = document.createElement("td");
  descTd.textContent = item.description || "(Mentioned in news/social sources)";

  // Sources
  const srcTd = document.createElement("td");
  const srcs = item.sources || [];
  if (srcs.length === 0) {
    srcTd.textContent = "—";
  } else {
    srcs.forEach(s => {
      const chip = document.createElement("span");
      const norm = (s || "").toLowerCase();
      chip.className = "source-chip";
      if (norm.includes("nvd")) chip.classList.add("nvd");
      if (norm.includes("hackernews") || norm === "thn") chip.classList.add("thn");
      if (norm.includes("bleeping")) chip.classList.add("bc");
      if (norm.includes("netsec")) chip.classList.add("netsec");
      if (norm.includes("cyber")) chip.classList.add("rcs");
      chip.textContent = s;
      srcTd.appendChild(chip);
    });
  }

  // Published / Posted
  const dateTd = document.createElement("td");
  const posted = item.posted || item.posted_date || null;
  const pub = item.published || null;
  dateTd.textContent = fmtDate(posted || pub);

  tr.appendChild(cveTd);
  tr.appendChild(descTd);
  tr.appendChild(srcTd);
  tr.appendChild(dateTd);
  return tr;
};

const fillTable = (data) => {
  const tbody = $("#tbody");
  tbody.innerHTML = "";
  const list = data.cves || [];
  if (!list.length) {
    $("#emptyRow").style.display = "";
    return;
  }
  $("#emptyRow").style.display = "none";
  list.forEach(item => tbody.appendChild(buildRow(item)));
};

const applySort = (data, mode) => {
  const arr = [...(data.cves || [])];
  const getDate = (i) => new Date(i.posted || i.posted_date || i.published || 0).getTime();
  switch(mode){
    case "published_asc":  arr.sort((a,b)=> getDate(a)-getDate(b));break;
    case "cvss_desc":      arr.sort((a,b)=> (b.cvss??-1)-(a.cvss??-1));break;
    case "cvss_asc":       arr.sort((a,b)=> (a.cvss??-1)-(b.cvss??-1));break;
    case "trend_desc":     arr.sort((a,b)=> (b.trend_score??0)-(a.trend_score??0));break;
    case "published_desc":
    default:               arr.sort((a,b)=> getDate(b)-getDate(a));break;
  }
  return {...data, cves:arr};
};

async function load() {
  try{
    const res = await fetch(`${API_BASE}/api/trending`, {cache:"no-store"});
    const data = await res.json();
    updateSummary(data);
    fillTable(applySort(data, $("#sort").value));
  }catch(e){
    console.error(e);
    $("#tbody").innerHTML = `<tr class="empty-row"><td colspan="4">Couldn’t reach API. Check the Render service and CORS.</td></tr>`;
  }
}

$("#sort").addEventListener("change", load);
document.addEventListener("visibilitychange", ()=>{ if(!document.hidden) load(); });
load();
