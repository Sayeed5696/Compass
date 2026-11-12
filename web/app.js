"use strict";
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
let lastResult = null;
let lastCveData = null;
let ME = null;
let CSRF = null;
let activeJob = null;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function esc(v) { return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

async function api(path, opts = {}) {
  const o = Object.assign({ credentials: "same-origin" }, opts);
  o.headers = Object.assign({}, opts.headers || {});
  const method = (o.method || "GET").toUpperCase();
  if (method !== "GET") {
    o.headers["X-Compass-CSRF"] = CSRF || "";
    if (o.body && !o.headers["Content-Type"]) o.headers["Content-Type"] = "application/json";
  }
  const r = await fetch(path, o);
  let d = {};
  try { d = await r.json(); } catch (_) { /* no body */ }
  if (r.status === 401) { window.location.replace("/login"); throw new Error("Your session has ended. Please sign in again."); }
  if (r.status === 403 && d.must_change) { window.location.replace("/login?change=1"); throw new Error(d.error); }
  if (!r.ok) throw new Error(d.error || `The server returned HTTP ${r.status}.`);
  return d;
}
const post = (p, b) => api(p, { method: "POST", body: JSON.stringify(b || {}) });
const del = p => api(p, { method: "DELETE" });

// ------------------------------------------------------------ navigation
const PAGE_TITLES = { investigation: "Investigation", email: "Email header analysis", cve: "CVE / Vulnerabilities", reports: "My history", settings: "Settings", about: "About" };
function goPage(name) {
  $$(".nav").forEach(x => x.classList.toggle("active", x.dataset.page === name));
  $$(".page").forEach(x => x.classList.toggle("active", x.id === `page-${name}`));
  const tp = $("#topbarPage"); if (tp) tp.textContent = PAGE_TITLES[name] || "";
  if (name === "settings") renderSettings();
  if (name === "reports") loadSavedReports();
}

// ------------------------------------------------------------ status colours
// Red: failed, error or malicious. Amber: partial, rate-limited, no API key.
// Blue: checked, nothing found. Green: live, done or consistent. Grey: not checked.
const LEGEND = [
  ["bad", "Red", "Failed, error or malicious. A source broke or timed out, or a provider flagged the indicator."],
  ["warn", "Amber", "Partial. Rate limited, no API key, wildcard DNS, or a result that needs a second look."],
  ["none", "Blue", "Checked, nothing found. The source answered and had no record."],
  ["ok", "Green", "Live, done or consistent. Resolves today, or the source returned results."],
  ["muted", "Grey", "Not checked. Skipped, over a limit, or not available in this mode."],
];
const legendHtml = (compact = false) => compact
  ? `<div class="legend compact">${LEGEND.map(([c, n, t]) => `<span class="legend-item" title="${esc(t)}">${stag(n, c)}<span>${esc(t.split(".")[0])}</span></span>`).join("")}</div>`
  : LEGEND.map(([c, n, t]) => `<div class="legend-row">${stag(n, c)}<p>${esc(t)}</p></div>`).join("");
$$(".nav").forEach(b => b.onclick = () => goPage(b.dataset.page));
// The Compass mark and name always lead home (the Investigation page).
document.addEventListener("click", e => {
  const home = e.target.closest("[data-home]");
  if (!home || e.ctrlKey || e.metaKey || e.shiftKey || e.button) return;
  e.preventDefault();
  goPage("investigation");
  window.scrollTo({ top: 0, behavior: "smooth" });
  const box = $("#iocInput");
  if (box) setTimeout(() => box.focus({ preventScroll: true }), 250);
});
$$(".examples button").forEach(b => b.onclick = () => { $("#iocInput").value = b.textContent; investigate(); });
$("#iocInput").addEventListener("keydown", e => { if (e.key === "Enter") investigate(); });
$("#investigateBtn").onclick = () => investigate();
document.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault(); goPage("investigation"); $("#iocInput").focus(); $("#iocInput").select();
  }
  if (e.key === "Escape") closeUrlhausRelationships();
});

// ------------------------------------------------------------ session / user
function renderUser() {
  if (!ME) return;
  $("#userName").textContent = (ME.display_name && ME.display_name.trim()) || ME.username;
  $("#userRole").textContent = ME.role === "admin" ? "Administrator" : "Analyst";
  $("#userBlock").title = `Signed in as ${ME.username}`;
}
$("#signOutBtn").onclick = async () => {
  try { await post("/api/auth/logout"); } catch (_) { /* already signed out */ }
  window.location.replace("/login");
};

// ------------------------------------------------------------ active mode toggle
const MODE_HINT_OFF = "Off: Compass never contacts the target. It only queries third-party sources.";
const MODE_HINT_ON = "On: Compass also reads the target's live certificate and tries common subdomain names. The target can see this server's IP address.";
function syncMode() {
  const on = $("#activeToggle").checked;
  $("#modeHint").textContent = on ? MODE_HINT_ON : MODE_HINT_OFF;
  $("#modeHint").classList.toggle("warn", on);
  try { localStorage.setItem("compass_active", on ? "1" : "0"); } catch (_) { /* storage unavailable */ }
}
try { $("#activeToggle").checked = localStorage.getItem("compass_active") === "1"; } catch (_) { /* storage unavailable */ }
$("#activeToggle").addEventListener("change", syncMode);
syncMode();

// ------------------------------------------------------------ status line
function showStatus(msg, bad = false, refresh = false) {
  const x = $("#status");
  x.classList.remove("hidden");
  x.classList.toggle("bad", !!bad);
  x.innerHTML = esc(msg) + (refresh ? ` <button class="inline-btn" id="refreshBtn" type="button">Run again with live data</button>` : "");
  if (refresh) $("#refreshBtn").onclick = () => investigate({ ioc: lastResult?.ioc?.original || lastResult?.ioc?.normalized, refresh: true });
}
function hideStatus() { $("#status").classList.add("hidden"); }

// ------------------------------------------------------------ investigation
async function investigate(opts = {}) {
  const ioc = String(opts.ioc ?? $("#iocInput").value).trim();
  if (!ioc) { showStatus("Enter an IP, domain, URL or hash."); return; }
  if (activeJob) { showStatus("An investigation is already running. Wait for it to finish."); return; }
  $("#iocInput").value = opts.file ? "" : ioc;
  $("#results").innerHTML = "";
  hideStatus();
  goPage("investigation");
  const body = { ioc, active: $("#activeToggle").checked, refresh: !!opts.refresh };
  if (opts.file) body.file = opts.file;
  const btn = $("#investigateBtn");
  btn.disabled = true;
  activeJob = "starting";
  try {
    const start = await post("/api/investigate", body);
    activeJob = start.job_id;
    const job = await pollJob(start.job_id, opts.file ? opts.file.name : ioc);
    if (job.status === "failed") throw new Error(job.error || "The investigation failed.");
    const r = job.result;
    lastResult = r;
    $("#progress").innerHTML = "";
    renderResult(r);
    if (["md5", "sha1", "sha256"].includes(r?.ioc?.type) || r.file) activateResultTab("threats");
    showStatus(r.message || "Investigation complete.", false, !!r.cached);
    loadSavedReports(true);
  } catch (e) {
    $("#progress").innerHTML = "";
    showStatus(e.message, true);
  } finally {
    activeJob = null;
    btn.disabled = false;
  }
}

async function pollJob(id, label) {
  let failures = 0;
  for (;;) {
    let j;
    try { j = await api(`/api/jobs/${id}`); failures = 0; }
    catch (e) { if (++failures > 4) throw e; await sleep(1500); continue; }
    renderProgress(j, label);
    if (j.status === "done" || j.status === "failed") return j;
    await sleep(j.elapsed < 4 ? 600 : 1000);
  }
}

const STATE_TEXT = { queued: "Waiting", running: "Running", done: "Done", failed: "Failed", not_configured: "No API key", skipped: "Skipped", rate_limited: "Rate limited" };
function srcDetail(e) {
  if (e.status === "done") {
    const parts = [];
    if (e.count != null) parts.push(`${e.count} found`);
    if (e.note) parts.push(e.note);
    return parts.join(". ") || "Done";
  }
  if (e.status === "running") return "Running…";
  if (e.status === "queued") return "Waiting";
  return e.error || STATE_TEXT[e.status] || e.status;
}
function srcRow(e) {
  const empty = e.status === "done" && e.count === 0 ? " empty" : "";
  return `<div class="src ${esc(e.status)}${empty}"><span class="src-state" aria-hidden="true"></span><span class="src-label">${esc(e.label)}</span><span class="src-detail" title="${esc(srcDetail(e))}">${esc(srcDetail(e))}</span></div>`;
}
function renderProgress(job, label) {
  const ev = job.events || [];
  const groups = { pipeline: [], discovery: [], intel: [] };
  ev.forEach(e => (groups[e.group] = groups[e.group] || []).push(e));
  const finished = ev.filter(e => !["queued", "running"].includes(e.status)).length;
  const pct = ev.length ? Math.round(finished / ev.length * 100) : 4;
  const head = job.status === "queued" ? "Waiting for a free slot on the server…" : `${finished} of ${ev.length || "?"} steps finished, ${Math.round(job.elapsed)} s elapsed`;
  const section = (title, list) => list.length ? `<div class="src-group"><h3>${title}</h3>${list.map(srcRow).join("")}</div>` : "";
  $("#progress").innerHTML = `<div class="card progress-card"><div class="card-head"><div><h2>Investigating <span class="mono">${esc(label)}</span></h2><p class="muted">${esc(head)}</p></div><span class="pill">${$("#activeToggle").checked ? "Active checks on" : "Passive"}</span></div><div class="progress-bar"><span style="width:${pct}%"></span></div><div class="card-body src-columns">${section("Pipeline", groups.pipeline)}${section("Discovery sources", groups.discovery)}${section("Threat-intel providers", groups.intel)}</div></div>`;
}

// ------------------------------------------------------------ data tables
const TABLES = {};
// Toggles are checkboxes beside the filter box. Only one can be ticked at a
// time (ticking one unticks the others), so two filters can never combine
// into an empty table.
function tableBlock(id, cfg) {
  const toggles = cfg.toggles || (cfg.toggle ? [cfg.toggle] : []);
  TABLES[id] = Object.assign({ q: "", on: -1, limit: 1500, pred: null }, cfg, { toggles });
  const t = TABLES[id];
  if (Number.isInteger(cfg.defaultOn)) t.on = cfg.defaultOn;
  const boxes = toggles.map((tg, i) => {
    const n = tg.count === undefined ? t.rows.filter(tg.fn).length : tg.count;
    return `<label class="chk"><input type="checkbox" data-tbl-toggle="${id}" data-idx="${i}"${t.on === i ? " checked" : ""}>${tg.dot ? `<span class="dot ${tg.dot}" aria-hidden="true"></span>` : ""}${esc(tg.label)}<span class="chk-count">(${n})</span></label>`;
  }).join("");
  return `<div class="tbl-wrap"><div class="tbl-tools"><input class="tbl-filter" data-tbl="${id}" placeholder="Filter rows" aria-label="Filter rows">${boxes}<span class="tbl-count" id="tc-${id}"></span><button class="tbl-csv three-d" type="button" data-csv="${id}">Download CSV</button></div><div class="tbl-scroll"><table class="table data"><thead><tr>${t.columns.map(c => `<th>${esc(c.label)}</th>`).join("")}</tr></thead><tbody id="tb-${id}">${tableRows(id)}</tbody></table></div></div>`;
}
function cellText(c, r) { return c.csv ? c.csv(r) : (r[c.key] ?? ""); }
function filteredRows(id) {
  const t = TABLES[id], q = t.q.trim().toLowerCase();
  const tg = t.on >= 0 ? t.toggles[t.on] : null;
  return t.rows.filter(r => (!tg || tg.fn(r)) && (!t.pred || t.pred(r)) && (!q || t.columns.some(c => String(cellText(c, r)).toLowerCase().includes(q))));
}
function refreshTable(id) { const tb = document.getElementById(`tb-${id}`); if (tb) tb.innerHTML = tableRows(id); }
function tableRows(id) {
  const t = TABLES[id], rows = filteredRows(id);
  setTimeout(() => { const el = document.getElementById(`tc-${id}`); if (el) el.textContent = `${rows.length} of ${t.rows.length} shown` + (rows.length > t.limit ? ` (first ${t.limit} on screen; CSV has all)` : ""); }, 0);
  if (!rows.length) return `<tr><td colspan="${t.columns.length}" class="empty">${esc(t.rows.length ? "No rows match this filter." : (t.empty || "Nothing to show."))}</td></tr>`;
  return rows.slice(0, t.limit).map(r => `<tr${t.rowCls ? ` class="${t.rowCls(r) || ""}"` : ""}>${t.columns.map(c => `<td class="${c.cls || ""}">${c.render ? c.render(r) : esc(r[c.key] ?? "—")}</td>`).join("")}</tr>`).join("");
}
function csvCell(v) {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // stop spreadsheet formula injection
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function downloadCSV(id) {
  const t = TABLES[id];
  const lines = [t.columns.map(c => csvCell(c.label)).join(",")].concat(filteredRows(id).map(r => t.columns.map(c => csvCell(cellText(c, r))).join(",")));
  downloadText(t.filename, "﻿" + lines.join("\r\n"), "text/csv;charset=utf-8");
}
document.addEventListener("input", e => {
  const id = e.target.dataset && e.target.dataset.tbl;
  if (id && TABLES[id]) { TABLES[id].q = e.target.value; document.getElementById(`tb-${id}`).innerHTML = tableRows(id); }
});
document.addEventListener("change", e => {
  const id = e.target.dataset && e.target.dataset.tblToggle;
  if (!id || !TABLES[id]) return;
  const idx = Number(e.target.dataset.idx || 0);
  TABLES[id].on = e.target.checked ? idx : -1;
  $$(`[data-tbl-toggle="${id}"]`).forEach(x => { if (Number(x.dataset.idx || 0) !== idx) x.checked = false; });
  refreshTable(id);
});
document.addEventListener("click", e => {
  const csv = e.target.closest("[data-csv]");
  if (csv) { downloadCSV(csv.dataset.csv); return; }
  const piv = e.target.closest(".pivot");
  if (piv) { e.preventDefault(); $("#iocInput").value = piv.dataset.ioc; window.scrollTo({ top: 0, behavior: "smooth" }); investigate({ ioc: piv.dataset.ioc }); return; }
  const cv = e.target.closest(".cve-pivot");
  if (cv) { e.preventDefault(); goPage("cve"); $("#cveInput").value = cv.dataset.cve; searchCve(cv.dataset.cve); }
});

const pivot = v => `<button class="pivot mono" type="button" data-ioc="${esc(v)}" title="Investigate ${esc(v)}">${esc(v)}</button>`;
const chips = (list, cls = "") => (list || []).map(x => `<span class="chip ${cls}">${esc(x)}</span>`).join("");
const tag = (text, cls) => `<span class="tag ${cls}">${esc(text)}</span>`;
// Status tag with a coloured dot. The word is always shown, so the meaning
// survives projectors, print and colour-blindness.
function stag(text, cls, title) { return `<span class="tag ${cls} has-dot"${title ? ` title="${esc(title)}"` : ""}><span class="dot" aria-hidden="true"></span>${esc(text)}</span>`; }
const NONE_WORDS = new Set(["Unavailable", "None", "Not found", "No records", "—", "Unknown"]);
const kvVal = v => NONE_WORDS.has(String(v ?? "")) ? `<span class="v-none">${esc(v)}</span>` : esc(v);
const dash = v => (v === null || v === undefined || v === "") ? "—" : esc(v);
function fmtDate(v) { if (!v) return "—"; const d = new Date(v * (typeof v === "number" && v < 1e12 ? 1000 : 1)); return isNaN(d) ? esc(v) : d.toLocaleString(); }
function filenameFor(r, part) { return `compass-${safeFilename(r.ioc?.normalized || "investigation")}-${part}.csv`; }

// ------------------------------------------------------------ result rendering
function renderResult(r) {
  const i = r.ioc, type = i.type;
  const d = r.discovery && !r.discovery.error ? r.discovery : null;
  const tabs = [["overview", "Overview", overview(r)]];
  if (d && d.kind === "domain") {
    tabs.push(["subdomains", `Subdomains (${d.stats.subdomains})`, subdomainPanel(d, r)]);
    tabs.push(["ips", `Linked IPs (${d.stats.ips})`, ipsPanel(d, r)]);
    tabs.push(["related", `Related (${d.stats.related})`, relatedPanel(d, r)]);
  }
  if (d && d.kind === "ip") {
    tabs.push(["domains", `Domains on this IP (${d.stats.domains})`, ipDomainsPanel(d, r)]);
    tabs.push(["exposure", "Network & exposure", exposurePanel(d, r)]);
  }
  if (type === "domain" || type === "url") tabs.push(["dns", "DNS", dnsPanel(r)]);
  if ((type === "domain" || type === "url") && !(d && d.kind === "ip")) tabs.push(["network", "Network", networkPanel(r)]);
  if ((type === "ip" || type === "ipv6") && !d) tabs.push(["network", "Network", networkPanel(r)]);
  if (type === "domain" || type === "url") tabs.push(["history", "Website history", `<div id="whPanel">${r.webhistory ? "" : `<div class="empty na">Open this tab to load the site's history from the Wayback Machine.</div>`}</div>`]);
  tabs.push(["threats", "Threat intel", threatPanel(r.providers || [])]);
  if (d) {
    const failed = (d.sources || []).filter(s => s.status === "failed").length + (r.providers || []).filter(p => p.status === "FAILED").length;
    tabs.push(["sources", failed ? `Sources · ${failed} failed` : "Sources", sourcesPanel(r)]);
  }

  const modePill = r.mode ? `<span class="pill">${r.mode === "active" ? "Active checks" : "Passive"}</span>` : "";
  const cachedPill = r.cached ? `<span class="pill">From cache</span>` : "";
  let html = `<div class="card"><div class="card-body result-head"><div><div class="type">${esc(type)}</div><div class="ioc-title mono">${esc(i.normalized)}</div>${i.original && i.original.trim() !== i.normalized ? `<div class="muted small">Entered as ${esc(i.original.trim())}</div>` : ""}</div><div class="result-pills">${modePill}${cachedPill}</div>${r.file ? `<div class="grid result-file"><div class="kv"><b>File</b><span>${esc(r.file.name || "")}</span></div><div class="kv"><b>MD5</b><span class="mono">${esc(r.file.hashes?.md5 || r.file.ioc || "")}</span></div><div class="kv"><b>File size</b><span>${esc(r.file.size || 0)} bytes</span></div></div>` : ""}</div></div>`;
  html += `<div class="card"><div class="card-body"><div class="tabs" role="tablist">${tabs.map((t, n) => `<button class="tab${n ? "" : " active"}${t[0] === "sources" && /failed/.test(t[1]) ? " tab-bad" : ""}" data-tab="${t[0]}" role="tab">${esc(t[1])}</button>`).join("")}<button class="tab report-btn" type="button" id="reportBtn">Open report</button></div>`;
  html += tabs.map((t, n) => `<div class="tab-panel${n ? "" : " active"}" id="tab-${t[0]}">${t[2]}</div>`).join("");
  html += `</div></div>`;
  $("#results").innerHTML = html;
  $$("#results .tab[data-tab]").forEach(t => t.onclick = () => activateResultTab(t.dataset.tab));
  $("#reportBtn").onclick = () => openReport(investigationReportHtml(lastResult));
  if (r.webhistory) renderWebHistory(r.webhistory);
}
function activateResultTab(name) {
  const t = document.querySelector(`#results .tab[data-tab="${name}"]`);
  if (!t) return;
  $$("#results .tab").forEach(x => x.classList.remove("active"));
  $$("#results .tab-panel").forEach(x => x.classList.remove("active"));
  t.classList.add("active");
  const panel = document.querySelector(`#tab-${name}`);
  if (panel) panel.classList.add("active");
  if (name === "history") loadWebHistory();
}

// ------------------------------------------------------------ website history (Wayback Machine)
let whLoading = false;
async function loadWebHistory(force = false) {
  const r = lastResult;
  if (!r || whLoading) return;
  if (r.webhistory && !force) return;
  const target = r.ioc.type === "url" ? r.ioc.normalized : r.ioc.normalized;
  whLoading = true;
  $("#whPanel").innerHTML = `<div class="loading-row"><span class="spinner" aria-hidden="true"></span>Asking the Wayback Machine for <b class="mono">${esc(target)}</b>. Busy sites can take up to a minute…</div>`;
  try {
    const d = await api(`/api/webhistory?target=${encodeURIComponent(target)}`);
    if (lastResult !== r) return;
    r.webhistory = d;
    renderWebHistory(d);
  } catch (e) {
    if (lastResult === r) $("#whPanel").innerHTML = `<div class="notice bad-note">${stag("Failed", "bad")} Could not load the website history: ${esc(e.message)} <button class="inline-btn" type="button" id="whRetry">Try again</button></div>`;
    const b = $("#whRetry"); if (b) b.onclick = () => loadWebHistory(true);
  } finally { whLoading = false; }
}
function fmtSize(n) { if (!n) return ""; return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`; }
function whChange(v) {
  if (v.kind === "redirect") {
    if (v.redirect_to) return `${v.offsite ? stag("Redirects off-site", "warn") : stag("Redirect", "muted")} ${v.redirect_host ? pivot(v.redirect_host) : ""}<div class="mono small muted wrap-any">${esc(v.redirect_to)}</div>`;
    return stag("Redirect", "muted");
  }
  if (v.kind === "gone") return stag(`Page error (${v.status})`, "none");
  const d = v.size_delta;
  const delta = d ? ` <span class="muted">(${d > 0 ? "+" : "−"}${fmtSize(Math.abs(d))})</span>` : "";
  return `Content changed${v.size ? `: ${esc(fmtSize(v.size))}${delta}` : ""}${v.mime && v.mime !== "text/html" ? ` <span class="muted small">${esc(v.mime)}</span>` : ""}`;
}
function whChangeText(v) {
  if (v.kind === "redirect") return `Redirect${v.redirect_to ? " to " + v.redirect_to : ""}`;
  if (v.kind === "gone") return `Page error (${v.status})`;
  return "Content changed";
}
function renderWebHistory(d) {
  const box = $("#whPanel");
  if (!box) return;
  if (d.status === "failed") {
    box.innerHTML = `<div class="notice bad-note">${stag("Failed", "bad")} The Wayback Machine did not answer: ${esc((d.errors || []).join("; "))} <button class="inline-btn" type="button" id="whRetry">Try again</button></div>`;
    $("#whRetry").onclick = () => { lastResult.webhistory = null; loadWebHistory(true); };
    return;
  }
  if (d.status === "empty") {
    box.innerHTML = `<div class="empty">${stag("Nothing found", "none")} The Wayback Machine has no captures of <b class="mono">${esc(d.url)}</b>.</div>`;
    return;
  }
  const maxDays = Math.max(1, ...d.years.map(y => y.days));
  const bars = d.years.map(y => `<button type="button" class="yr" data-year="${y.year}" aria-pressed="false" title="${y.days} days with captures in ${y.year}"><span class="yr-n">${y.days}</span><span class="yr-bar" style="height:${Math.max(4, Math.round(y.days / maxDays * 96))}px"></span><span class="yr-l">${y.year}</span></button>`).join("");
  const partial = d.status === "partial" ? `<div class="notice warn-note">${stag("Partial", "warn")} Some archive queries failed: ${esc(d.errors.join("; "))}</div>` : "";
  const trunc = d.truncated ? `<div class="notice warn-note">${stag("Partial", "warn")} This site has more than ${d.version_count} versions; the most recent ${d.version_count} are listed.</div>` : "";
  const table = tableBlock("wh", {
    filename: `compass-${safeFilename(d.target)}-website-history.csv`,
    empty: "No versions found.",
    toggles: [{ label: "Redirects to other sites", dot: "warn", fn: v => !!v.offsite }, { label: "Page errors", dot: "none", fn: v => v.kind === "gone" }],
    rows: d.versions,
    rowCls: v => v.offsite ? "row-warn" : "",
    columns: [
      { label: "Captured (IST)", key: "ist", cls: "nowrap-cell mono small", csv: v => v.ist },
      { label: "Captured (UTC)", key: "utc", cls: "nowrap-cell mono small", csv: v => v.utc, render: v => esc(v.utc.replace("T", " ").replace("Z", "")) },
      { label: "HTTP", key: "status", cls: "mono" },
      { label: "What changed", render: whChange, csv: whChangeText },
      { label: "Content hash", key: "digest", cls: "mono small", render: v => `<span title="${esc(v.digest)}">${esc(v.digest.slice(0, 4))}…${esc(v.digest.slice(-4))}</span>` },
      { label: "Snapshot", render: v => `<a class="snap-link" href="${esc(v.snapshot)}" target="_blank" rel="noopener noreferrer">Open snapshot</a>`, csv: v => v.snapshot },
    ],
  });
  box.innerHTML = `<p class="panel-lede">How <b class="mono">${esc(d.url)}</b> looked over time, from the Wayback Machine. Only captures where the page content changed are listed. Snapshots open on web.archive.org, so the site itself is never contacted.</p>${partial}${trunc}
    <div class="stats">${statTile(d.first?.ist?.replace(/,.*/, "") || "—", "First capture")}${statTile(d.latest?.ist?.replace(/,.*/, "") || "—", "Latest capture")}${statTile(d.days_captured, "Days with captures")}${statTile(d.version_count, "Distinct versions")}${d.redirects_offsite ? statTile(d.redirects_offsite, "Redirects to other sites", "warn") : ""}</div>
    <div class="yr-head"><h3>Days with captures, per year</h3><span class="muted small" id="whYearHint">Select a year to list only its versions.</span></div>
    <div class="yr-chart" role="group" aria-label="Filter by year">${bars}</div>${table}`;
  $$("#whPanel .yr").forEach(b => b.onclick = () => {
    const y = Number(b.dataset.year), t = TABLES.wh, same = t.year === y;
    t.year = same ? null : y;
    t.pred = t.year ? (v => v.year === t.year) : null;
    $$("#whPanel .yr").forEach(x => { const on = Number(x.dataset.year) === t.year; x.classList.toggle("on", on); x.setAttribute("aria-pressed", String(on)); });
    $("#whYearHint").textContent = t.year ? `Showing ${t.year}. Select it again to show all years.` : "Select a year to list only its versions.";
    refreshTable("wh");
  });
}
function dnsValues(records) { return (records || []).map(x => typeof x === "string" ? x : (x?.data || "")).filter(Boolean); }
function domainRdap(r) { const inf = r.infrastructure || {}; return r.ioc.type === "url" ? inf.domain?.rdap : inf.rdap; }
function ageText(created) {
  if (!created) return null;
  const t = Date.parse(created);
  if (!Number.isFinite(t)) return null;
  const days = Math.floor((Date.now() - t) / 86400000);
  const when = new Date(t).toISOString().slice(0, 10);
  if (days < 0) return { text: when, fresh: false };
  const span = days < 60 ? `${days} days ago` : days < 730 ? `${Math.round(days / 30)} months ago` : `${Math.round(days / 365)} years ago`;
  return { text: `${when} (${span})`, fresh: days < 30 };
}

function statTile(value, label, cls = "") { return `<div class="stat ${cls}"><b>${esc(value)}</b><span>${esc(label)}</span></div>`; }
function overview(r) {
  const i = r.ioc, inf = r.infrastructure || {}, type = i.type;
  const d = r.discovery && !r.discovery.error ? r.discovery : null;
  let tiles = "";
  let notes = "";
  if (d && d.kind === "domain") {
    const via = d.shared_hosting?.cdn ? `Behind ${d.shared_hosting.cdn}` : (d.shared_hosting?.target_ips || []).length ? "Direct hosting" : "Not resolving";
    const inactive = (d.subdomains || []).filter(s => s.live === false).length;
    tiles = statTile(d.stats.subdomains, `subdomains found: ${d.stats.live} live, ${inactive} inactive`) + statTile(d.stats.ips, "linked IPs") + statTile(d.stats.related, "related domains") + statTile(via, "how the site is served", d.shared_hosting?.cdn ? "accent" : "");
    if ((d.origin_candidates || []).length) tiles += statTile(d.origin_candidates.length, "possible origin servers", "warn");
  }
  if (d && d.kind === "ip") {
    const flags = [];
    if (d.anonymity.tor) flags.push("Tor exit"); if (d.anonymity.vpn) flags.push("VPN"); if (d.anonymity.proxy) flags.push("Proxy");
    tiles = statTile(d.stats.domains, `domains seen, ${d.stats.current} point here now`) + statTile(d.network.asn || "Unknown", d.network.as_name || "network") + statTile((d.exposure.ports || []).length, "open ports (Shodan)") + statTile(flags.join(", ") || "None", "anonymity flags", flags.length ? "warn" : "");
  }
  if (r.discovery && r.discovery.error) notes += `<div class="notice bad-note">${stag("Failed", "bad")} Discovery could not run: ${esc(r.discovery.error)}</div>`;
  if (inf && inf.error) notes += `<div class="notice bad-note">${stag("Failed", "bad")} Infrastructure lookups failed: ${esc(inf.error)}</div>`;
  if (d && (d.notes || []).length) notes += `<ul class="notes">${d.notes.map(n => `<li>${esc(n)}</li>`).join("")}</ul>`;
  if (d && d.kind === "ip" && d.shared_hosting?.reason) notes = `<div class="notice warn-note">${esc(d.shared_hosting.reason)}</div>` + notes;

  const kv = [];
  if (type === "ip" || type === "ipv6") {
    const g = geoIntel(inf.geoip);
    kv.push(["Reverse DNS", inf.reverse_dns || g.hostname || "Not found"]);
    kv.push(["RDAP network", inf.rdap?.name || inf.rdap?.handle || g.org || "Unavailable"]);
    kv.push(["CIDR range", inf.rdap?.startAddress && inf.rdap?.endAddress ? `${inf.rdap.startAddress} – ${inf.rdap.endAddress}` : (d?.network?.prefix || "Unavailable")]);
    kv.push(["Country", g.country || d?.network?.country || "Unavailable"]);
    kv.push(["ASN", g.asn || d?.network?.asn || "Unavailable"]);
  }
  const rdap = (type === "domain" || type === "url") ? domainRdap(r) : null;
  const age = rdap ? ageText(rdap.created) : null;
  if (type === "domain") {
    kv.push(["Domain", i.normalized]);
    if (d && d.apex && d.apex !== i.normalized) kv.push(["Registered domain", d.apex]);
    kv.push(["Resolved IPv4", dnsValues(inf.dns?.A).join(", ") || "None"]);
    kv.push(["Resolved IPv6", dnsValues(inf.dns?.AAAA).join(", ") || "None"]);
    kv.push(["Registered", age ? age.text : "Unavailable"]);
    kv.push(["RDAP status", (inf.rdap?.status || []).join(", ") || "Unavailable"]);
    kv.push(["TLS issuer", issuer(inf.tls)]);
  }
  if (type === "url") {
    kv.push(["Scheme", inf.url_parts?.scheme]); kv.push(["Hostname", inf.url_parts?.hostname]); kv.push(["Port", inf.url_parts?.port || "Default"]); kv.push(["Path", inf.url_parts?.path]);
    kv.push(["Resolved IPv4", dnsValues(inf.domain?.dns?.A).join(", ") || "None"]);
    kv.push(["Registered", age ? age.text : "Unavailable"]);
    kv.push(["TLS issuer", issuer(inf.domain?.tls)]);
  }
  if (["md5", "sha1", "sha256"].includes(type)) kv.push(["Hash type", type.toUpperCase()], ["Value", i.normalized]);
  const ageWarn = age && age.fresh ? `<div class="notice warn-note">This domain was registered ${esc(age.text)}. Newly registered domains are common in phishing and fraud.</div>` : "";
  return `${tiles ? `<div class="stats">${tiles}</div>` : ""}${ageWarn}${notes}<div class="grid">${kv.map(([k, v]) => `<div class="kv"><b>${esc(k)}</b><span>${kvVal(v)}</span></div>`).join("")}</div>`;
}

const REL_SHORT = {
  "A record (target)": "Target A record", "A record (parent domain)": "Parent A record", "Subdomain IP (live)": "Subdomain (live)",
  "Subdomain IP (passive)": "Subdomain (passive DNS)", "Historical A record": "Historical", "Mail server (MX)": "Mail server",
  "Name server (NS)": "Name server", "Mail sender (SPF)": "SPF sender", "Seen in urlscan scan": "urlscan scan"
};
function subStatus(s) {
  return s.wildcard ? stag("Wildcard", "warn", "Resolves only to the wildcard address, which answers for any name, so this proves nothing.")
    : s.live ? stag("Live", "ok", "Resolves in DNS today.")
    : s.live === false ? stag("Inactive", "none", "Checked: no DNS record today. Old names are still useful leads.")
    : stag("Not checked", "muted", "Over the DNS lookup limit, so it was not checked.");
}
function subStatusText(s) { return s.wildcard ? "Wildcard" : s.live ? "Live" : s.live === false ? "Inactive (no DNS record today)" : "Not checked"; }
function subdomainPanel(d, r) {
  const status = subStatus, statusText = subStatusText;
  const legend = `<div class="legend compact">${stag("Live", "ok")}<span>resolves today</span>${stag("Inactive", "none")}<span>checked, no DNS record today</span>${stag("Wildcard", "warn")}<span>answer proves nothing</span>${stag("Not checked", "muted")}<span>over the lookup limit</span></div>`;
  const table = tableBlock("subs", {
    filename: filenameFor(r, "subdomains"),
    empty: "No subdomains were found by the configured sources.",
    toggles: [
      { label: "Live only", dot: "ok", fn: s => s.live && !s.wildcard },
      { label: "Inactive only", dot: "none", fn: s => s.live === false },
    ],
    rows: d.subdomains,
    columns: [
      { label: "Subdomain", key: "name", render: s => pivot(s.name), cls: "nowrap-cell" },
      { label: "Status", render: status, csv: statusText },
      { label: "Resolves to", cls: "nowrap-cell", render: s => (s.ips.length ? s.ips.slice(0, 4).map(ip => pivot(ip)).join("<br>") + (s.ips.length > 4 ? ` <span class="muted">+${s.ips.length - 4}</span>` : "") : "—") + (s.cdn ? " " + tag(s.cdn, "cdn") : ""), csv: s => s.ips.join("; ") },
      { label: "CNAME", render: s => s.cname.length ? `<span class="mono small">${esc(s.cname.join(" → "))}</span>` : "—", csv: s => s.cname.join(" > ") },
      { label: "Found by", render: s => chips(s.sources), csv: s => s.sources.join("; ") },
      { label: "First seen", key: "first_seen", cls: "nowrap-cell" },
      { label: "Last seen", key: "last_seen", cls: "nowrap-cell" },
    ],
  });
  const wc = d.wildcard?.detected ? `<div class="notice warn-note">Wildcard DNS: any name under ${esc(d.apex)} resolves to ${esc(d.wildcard.ips.join(", "))}. Names that only resolve to these addresses are marked Wildcard.</div>` : "";
  return `<p class="panel-lede">Every name under <b class="mono">${esc(d.apex)}</b> that Compass found, checked against live DNS. Select a name to investigate it. Inactive names are kept on purpose: old subdomains often point to earlier hosting.</p>${legend}${wc}${table}`;
}
function ipFlags(x) {
  const out = [];
  if (x.cdn) out.push(tag(x.cdn, "cdn"));
  else if (x.hosting) out.push(tag(x.hosting, "muted"));
  if (x.tor) out.push(tag("Tor exit", "bad"));
  if (x.vpn) out.push(tag("VPN", "warn"));
  if (x.proxy) out.push(tag("Proxy", "warn"));
  if (x.abuser) out.push(tag("Abuse reports", "bad"));
  if (x.datacenter && !x.cdn && !x.hosting) out.push(tag("Datacenter", "muted"));
  return out.join(" ") || "—";
}
function ipFlagText(x) { return [x.cdn, x.hosting, x.tor && "Tor exit", x.vpn && "VPN", x.proxy && "Proxy", x.abuser && "Abuse reports", x.datacenter && "Datacenter"].filter(Boolean).join("; "); }
function vulnCell(list) { if (!list || !list.length) return "—"; return list.slice(0, 3).map(v => `<button class="cve-pivot mono" type="button" data-cve="${esc(v)}">${esc(v)}</button>`).join(" ") + (list.length > 3 ? ` <span class="muted">+${list.length - 3}</span>` : ""); }
function ipsPanel(d, r) {
  const table = tableBlock("ips", {
    filename: filenameFor(r, "linked-ips"),
    empty: "No IPs are linked to this domain.",
    toggle: { label: "Hide CDN IPs", fn: x => !x.cdn },
    rows: d.ips,
    columns: [
      { label: "IP", key: "ip", render: x => pivot(x.ip), cls: "nowrap-cell" },
      { label: "How it's linked", render: x => chips(x.relations.map(v => REL_SHORT[v] || v)), csv: x => x.relations.join("; ") },
      { label: "Hostnames", render: x => x.host_count ? `<span class="mono small">${esc(x.hosts.slice(0, 3).join(", "))}</span>${x.host_count > 3 ? ` <span class="muted">+${x.host_count - 3}</span>` : ""}` : "—", csv: x => x.hosts.join("; ") },
      { label: "Network", render: x => x.asn ? `<b>${esc(x.asn)}</b><div class="muted small">${esc(x.as_name || x.org || "")}</div>` : "—", csv: x => [x.asn, x.as_name || x.org].filter(Boolean).join(" ") },
      { label: "Country", render: x => dash(x.country), csv: x => x.country || "" },
      { label: "Flags", render: ipFlags, csv: ipFlagText },
      { label: "Open ports", render: x => x.ports.length ? `<span class="mono small">${esc(x.ports.join(", "))}</span>` : "—", csv: x => x.ports.join("; ") },
      { label: "Known CVEs", render: x => vulnCell(x.vulns), csv: x => x.vulns.join("; ") },
      { label: "Last seen", key: "last_seen", cls: "nowrap-cell" },
    ],
  });
  let origins = "";
  if ((d.origin_candidates || []).length) {
    origins = `<div class="card inset"><div class="card-head"><h2>Possible origin servers</h2><span class="pill">${d.origin_candidates.length}</span></div><div class="card-body"><p class="panel-lede">The site sits behind ${esc(d.shared_hosting.cdn)}. These non-CDN IPs are linked to the domain and may be the real server. Confirm before acting on them.</p><table class="table data"><thead><tr><th>IP</th><th>Why it is listed</th><th>Network</th></tr></thead><tbody>${d.origin_candidates.map(o => `<tr><td class="nowrap-cell">${pivot(o.ip)}</td><td>${esc(o.reason)}</td><td>${esc([o.asn, o.as_name].filter(Boolean).join(" "))}</td></tr>`).join("")}</tbody></table></div></div>`;
  }
  return `<p class="panel-lede">IPs connected to <b class="mono">${esc(d.target)}</b> today or in the past. Flags come from RIPEstat, Shodan InternetDB, ipapi.is and the Tor exit list.</p>${origins}${table}`;
}
function relatedPanel(d, r) {
  const m = d.mail || {};
  const mail = `<div class="card inset"><div class="card-head"><h2>Mail infrastructure</h2></div><div class="card-body grid">
    <div class="kv"><b>Mail servers (MX)</b><span class="mono">${esc((m.mx || []).join(", ") || "None")}</span></div>
    <div class="kv"><b>SPF record</b><span class="mono small">${esc(m.spf || "None")}</span></div>
    <div class="kv"><b>SPF sender ranges</b><span class="mono small">${esc((m.spf_ranges || []).join(", ") || "None")}</span></div>
    <div class="kv"><b>SPF includes</b><span class="mono small">${esc((m.spf_includes || []).join(", ") || "None")}</span></div>
    <div class="kv"><b>DMARC</b><span class="mono small">${esc(m.dmarc || "None")}</span></div>
    <div class="kv"><b>Name servers</b><span class="mono small">${esc((m.ns || []).join(", ") || "None")}</span></div></div></div>`;
  const table = tableBlock("related", {
    filename: filenameFor(r, "related-domains"),
    empty: "No related domains were found outside this domain.",
    rows: d.related_domains,
    columns: [
      { label: "Domain", key: "name", render: x => pivot(x.name) },
      { label: "Relationship", render: x => chips(x.relations), csv: x => x.relations.join("; ") },
      { label: "Via", render: x => `<span class="mono small">${esc(x.via.join(", ") || "—")}</span>`, csv: x => x.via.join("; ") },
      { label: "Registered domain", key: "apex", render: x => `<span class="mono small">${esc(x.apex)}</span>` },
      { label: "Found by", render: x => chips(x.sources), csv: x => x.sources.join("; ") },
    ],
  });
  return `<p class="panel-lede">Domains outside <b class="mono">${esc(d.apex)}</b> that share a certificate or a dedicated IP with it, plus the domain's mail setup.</p>${table}${mail}`;
}
function ipDomainsPanel(d, r) {
  const cur = x => x.current ? stag("Yes", "ok") : x.current === false ? stag("No", "none") : stag("Not checked", "muted");
  const banner = d.shared_hosting?.reason ? `<div class="notice warn-note">${esc(d.shared_hosting.reason)}</div>` : "";
  const top = (d.apex_counts || []).slice(0, 12).map(a => `<span class="chip">${esc(a.apex)} <b>${esc(a.count)}</b></span>`).join("");
  const table = tableBlock("ipdomains", {
    filename: filenameFor(r, "domains-on-ip"),
    empty: "No domains have been seen on this IP by the configured sources.",
    toggles: [{ label: "Still pointing here", dot: "ok", fn: x => x.current }, { label: "No longer here", dot: "none", fn: x => x.current === false }],
    rows: d.domains,
    columns: [
      { label: "Domain", key: "name", render: x => pivot(x.name) },
      { label: "Points here now", render: cur, csv: x => x.current ? "Yes" : x.current === false ? "No" : "Not checked" },
      { label: "Registered domain", key: "apex", render: x => `<span class="mono small">${esc(x.apex)}</span>` },
      { label: "Found by", render: x => chips(x.sources), csv: x => x.sources.join("; ") },
      { label: "First seen", key: "first_seen", cls: "nowrap-cell" },
      { label: "Last seen", key: "last_seen", cls: "nowrap-cell" },
    ],
  });
  return `<p class="panel-lede">Domains that resolve, or used to resolve, to <b class="mono">${esc(d.target)}</b>.</p>${banner}${top ? `<div class="chip-row"><span class="muted small">Most common registered domains</span>${top}</div>` : ""}${table}`;
}
function exposurePanel(d, r) {
  const n = d.network || {}, x = d.exposure || {}, a = d.anonymity || {};
  const flag = (on, label) => `<div class="kv"><b>${label}</b><span>${a.checked ? (on ? stag("Yes", "bad") : stag("No", "none")) : stag("Not checked", "muted")}</span></div>`;
  return `${networkPanel(r)}
  <h3>Network</h3><div class="grid">
    <div class="kv"><b>ASN</b><span>${dash(n.asn)}</span></div><div class="kv"><b>AS name</b><span>${dash(n.as_name)}</span></div>
    <div class="kv"><b>Announced prefix</b><span class="mono">${dash(n.prefix)}</span></div><div class="kv"><b>Provider type</b><span>${n.cdn ? `CDN (${esc(n.cdn)})` : n.hosting ? esc(n.hosting) : esc(n.company_type || "Unknown")}</span></div>
    <div class="kv"><b>Reverse DNS</b><span class="mono">${dash(d.ptr)}</span></div></div>
  <h3>Exposure (Shodan InternetDB)</h3>${x.available ? `<div class="grid">
    <div class="kv"><b>Open ports</b><span class="mono">${esc((x.ports || []).join(", ") || "None")}</span></div>
    <div class="kv"><b>Known CVEs</b><span>${(x.vulns || []).length ? x.vulns.map(v => `<button class="cve-pivot mono" type="button" data-cve="${esc(v)}">${esc(v)}</button>`).join(" ") : "None"}</span></div>
    <div class="kv"><b>Software (CPE)</b><span class="mono small">${esc((x.cpes || []).join(", ") || "None")}</span></div>
    <div class="kv"><b>Tags</b><span>${esc((x.tags || []).join(", ") || "None")}</span></div></div>` : `<div class="empty">${stag("Nothing found", "none")} Shodan has no scan data for this IP.</div>`}
  <h3>Anonymity</h3><div class="grid">${flag(a.tor, "Tor exit node")}${flag(a.vpn, "VPN")}${flag(a.proxy, "Proxy")}${flag(a.datacenter, "Datacenter / hosting")}${flag(a.abuser, "Abuse reports")}</div>`;
}
// One mapping from a source / provider state to the colour scheme.
function sourceState(s) {
  if (s.status === "done") return s.count === 0 ? ["Nothing found", "none"] : ["Done", "ok"];
  if (s.status === "failed") return ["Failed", "bad"];
  if (s.status === "rate_limited") return ["Rate limited", "warn"];
  if (s.status === "not_configured") return ["No API key", "warn"];
  if (s.status === "skipped") return ["Not checked", "muted"];
  return [STATE_TEXT[s.status] || s.status, "muted"];
}
function providerState(p) {
  if (p.status === "COMPLETED") return ["Done", "ok"];
  if (p.status === "NOT_CONFIGURED") return ["No API key", "warn"];
  if (p.status === "NOT_FOUND") return ["No record", "none"];
  if (p.status === "NOT_SUPPORTED") return ["Not checked", "muted"];
  return ["Failed", "bad"];
}
function sourcesPanel(r) {
  const d = r.discovery || {};
  const row = (label, st, count, ms, detail) => `<tr class="${st[1] === "bad" ? "row-bad" : ""}"><td>${esc(label)}</td><td>${stag(st[0], st[1])}</td><td>${count ?? "—"}</td><td>${ms != null ? (ms / 1000).toFixed(1) + " s" : "—"}</td><td class="small${st[1] === "bad" ? " bad-text" : ""}">${detail}</td></tr>`;
  const rows = (d.sources || []).map(s => row(s.label, sourceState(s), s.count, s.ms, esc(s.note || s.error || "") + (s.status === "not_configured" ? ` <button class="inline-btn" type="button" data-goto="settings">Add a key in Settings</button>` : ""))).join("");
  const prov = (r.providers || []).map(p => row(p.provider, providerState(p), null, null, esc(p.error || p.assessment?.summary || "") + (p.status === "NOT_CONFIGURED" ? ` <button class="inline-btn" type="button" data-goto="settings">Add a key in Settings</button>` : ""))).join("");
  const failed = (d.sources || []).filter(s => s.status === "failed").concat((r.providers || []).filter(p => p.status === "FAILED"));
  const banner = failed.length ? `<div class="notice bad-note">${stag(`${failed.length} failed`, "bad")} ${esc(failed.map(x => x.label || x.provider).join(", "))} did not answer, so their data is missing from this result. The rest of the investigation completed. <button class="inline-btn" type="button" id="srcRetry">Run again with live data</button></div>` : "";
  return `${legendHtml(true)}${banner}<p class="panel-lede">Mode: <b>${d.mode === "active" ? "active checks" : "passive only"}</b>. Discovery took ${esc(d.duration_s ?? "?")} s and finished at ${esc(d.generated_at ? new Date(d.generated_at).toLocaleString() : "—")}.</p>
  <div class="tbl-scroll"><table class="table data"><thead><tr><th>Source</th><th>Result</th><th>Items</th><th>Time</th><th>Details</th></tr></thead><tbody>${rows}${prov}</tbody></table></div>`;
}
document.addEventListener("click", e => {
  const g = e.target.closest("[data-goto]");
  if (g) { goPage(g.dataset.goto); return; }
  if (e.target.id === "srcRetry" && lastResult) investigate({ ioc: lastResult.ioc?.original || lastResult.ioc?.normalized, refresh: true });
});

function certName(value) {
  if (!value) return "Unavailable";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    const parts = [];
    const walk = v => {
      if (Array.isArray(v)) { v.forEach(walk); return; }
      if (v && typeof v === "object") Object.entries(v).forEach(([k, val]) => { if (val !== null && val !== undefined && typeof val !== "object") parts.push(`${k}=${val}`); else if (typeof val === "object") walk(val); });
    };
    walk(value);
    return parts.length ? parts.join(", ") : "Unavailable";
  }
  if (typeof value === "object") return Object.entries(value).map(([k, v]) => `${k}=${typeof v === "object" ? certName(v) : v}`).join(", ");
  return String(value);
}
function issuer(t) { return t?.issuerText || (t?.issuer ? certName(t.issuer) : "Unavailable"); }
function geoIntel(g) {
  const x = g || {};
  return { country: x.country || x.countryCode || "", asn: x.asn || "", org: x.organization || "", hostname: x.hostname || "", city: x.city || "", region: x.region || "", source: x.source || "" };
}
function dnsPanel(r) {
  const inf = r.infrastructure || {}, d = r.ioc.type === "domain" ? inf.dns : r.ioc.type === "url" ? inf.domain?.dns : null;
  if (!d) return `<div class="empty na">DNS data not applicable.</div>`;
  const errs = (d.errors || []).length ? `<div class="notice bad-note">${stag("Failed", "bad")} Some DNS lookups failed: ${esc(d.errors.join("; "))}</div>` : "";
  return `${errs}<div class="dns-grid">${Object.entries(d).filter(([k]) => ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"].includes(k)).map(([k, v]) => `<div class="kv"><b>${esc(k)}</b>${Array.isArray(v) && v.length ? v.map(x => `<div class="mono small dns-val">${esc(typeof x === "string" ? x : x.data || "")}</div>`).join("") : `<span class="v-none">No records</span>`}</div>`).join("")}</div>`;
}
function networkPanel(r) {
  const inf = r.infrastructure || {}, ips = r.ioc.type === "domain" ? inf.resolved_ips : r.ioc.type === "url" ? inf.domain?.resolved_ips : null;
  let html = "";
  if (r.ioc.type === "ip" || r.ioc.type === "ipv6") {
    const g = geoIntel(inf.geoip);
    html += `<div class="grid"><div class="kv"><b>RDAP</b><span>${esc(inf.rdap?.name || "Unavailable")}</span></div><div class="kv"><b>Country</b><span>${esc(g.country || "Unavailable")}</span></div><div class="kv"><b>City / region</b><span>${esc([g.city, g.region].filter(Boolean).join(", ") || "Unavailable")}</span></div><div class="kv"><b>Organization</b><span>${esc(g.org || "Unavailable")}</span></div><div class="kv"><b>GeoIP source</b><span>${esc(g.source || "No GeoIP source available")}</span></div></div>`;
  }
  if (ips && Object.keys(ips).length) {
    html += `<h3>Current IPs</h3><table class="table data"><thead><tr><th>IP</th><th>Reverse DNS</th><th>RDAP</th><th>Country</th><th>ASN</th><th>Organization</th></tr></thead><tbody>${Object.entries(ips).map(([ip, x]) => { const g = geoIntel(x.geoip); return `<tr><td>${pivot(ip)}</td><td>${esc(x.reverse_dns || g.hostname || "—")}</td><td>${esc(x.rdap?.name || "—")}</td><td>${esc(g.country || "—")}</td><td>${esc(g.asn || "—")}</td><td>${esc(g.org || "—")}</td></tr>`; }).join("")}</tbody></table>`;
  }
  const tls = r.ioc.type === "url" ? inf.domain?.tls : inf.tls;
  if (tls) html += `<h3>TLS certificate</h3><p class="muted small">${esc(tls.source || "")}</p><div class="grid"><div class="kv"><b>Subject</b><span>${esc(tls.subjectText || certName(tls.subject || "—"))}</span></div><div class="kv"><b>Issuer</b><span>${esc(tls.issuerText || certName(tls.issuer || "—"))}</span></div><div class="kv"><b>Valid until</b><span>${esc(tls.notAfter || "—")}</span></div><div class="kv"><b>Names on certificate</b><span class="mono small">${esc((tls.subjectAltNames || []).join(", ") || "—")}</span></div></div>`;
  return html || `<div class="empty na">Network enrichment is not applicable.</div>`;
}

// ------------------------------------------------------------ threat intel (unchanged logic)
function threatPanel(ps) {
  const passed = (ps || []).filter(p => p.status === "COMPLETED");
  const failedP = (ps || []).filter(p => p.status === "FAILED");
  const failNote = failedP.length ? `<div class="notice bad-note">${stag("Failed", "bad")} ${esc(failedP.map(p => `${p.provider}: ${p.error || "query failed"}`).join("; "))}</div>` : "";
  if (!passed.length) return failNote + ((ps || []).some(p => p.status === "NOT_CONFIGURED")
    ? `<div class="empty warn">${stag("No API keys", "warn")} No threat-intelligence results were returned. Add provider API keys in Settings to get verdicts. <button class="inline-btn" type="button" data-goto="settings">Open Settings</button></div>`
    : `<div class="empty">${stag("Nothing found", "none")} No provider had a record for this indicator.</div>`);
  const a = lastResult?.threat_assessment || {};
  const cls = threatClass;
  const verdictClass = threatClass(a.verdict);
  let html = failNote + `<div class="threat-verdict ${verdictClass}"><div><div class="verdict-label">Overall verdict</div><div class="verdict-value">${esc(a.verdict || "INSUFFICIENT DATA")}</div></div><div class="verdict-confidence">Confidence: <b>${esc(a.confidence || "LOW")}</b></div><div class="verdict-summary">${esc(a.summary || "")}</div></div>`;
  html += `<div class="provider-grid">${passed.map(p => { const x = p.assessment || {}; const related = p.provider === "urlhaus" ? (p.data?.related || {}) : null; const relatedCount = Number(related?.count || 0); const relatedIpCount = (related?.ips || []).length; return `<div class="provider-card"><div class="provider-head"><b>${esc(p.provider)}</b><span class="${cls(x.verdict)}">Checked</span></div><div class="provider-verdict ${cls(x.verdict)}">${esc(x.verdict || "UNKNOWN")}</div><div class="provider-summary">${esc(x.summary || "")}</div>${(x.evidence || []).length ? `<ul class="evidence">${x.evidence.map(e => `<li>${esc(e)}</li>`).join("")}</ul>` : ""}${p.provider === "urlhaus" && relatedCount ? `<button class="three-d relationship-action" type="button" onclick="showUrlhausRelationships()">View related URLs &amp; IPs <span>(${relatedCount} URLs, ${relatedIpCount} IPs)</span></button>` : ""}</div>`; }).join("")}</div>`;
  html += `<div id="urlhausRelationshipModal" class="modal-backdrop hidden" role="dialog" aria-modal="true" aria-labelledby="urlhausRelationshipTitle" onclick="if(event.target===this)closeUrlhausRelationships()"><div class="modal-card" role="document"><div class="modal-head"><div><h2 id="urlhausRelationshipTitle">URLhaus: related URLs &amp; IPs</h2><p class="muted">Malware URLs are shown as text, not links, so they cannot be opened by accident.</p></div><div class="modal-actions"><button class="three-d relationship-newtab" type="button" onclick="openUrlhausRelationshipsNewTab()">Open full list in new tab</button><button class="modal-close three-d" type="button" aria-label="Close" onclick="closeUrlhausRelationships()">× <span>Close</span></button></div></div><div id="urlhausRelationshipContent"></div></div></div>`;
  return html;
}
function defang(u) { return String(u || "").replace(/^http/i, "hxxp").replace(/\./g, "[.]"); }
function urlhausRows(urls) {
  return urls.map((u, i) => `<tr><td>${i + 1}</td><td class="mono relation-url">${esc(defang(u.url || "—"))}</td><td>${esc(u.host || "—")}</td><td>${esc(u.status || "—")}</td><td>${esc(u.date_added || "—")}</td><td>${esc((u.tags || []).join(", ") || "—")}</td></tr>`).join("");
}
function showUrlhausRelationships() {
  const modal = $("#urlhausRelationshipModal"), content = $("#urlhausRelationshipContent");
  const p = (lastResult?.providers || []).find(x => x.provider === "urlhaus" && x.status === "COMPLETED");
  const rel = p?.data?.related || {};
  if (!modal || !content) return;
  const urls = rel.urls || [], ips = rel.ips || [];
  const ipList = ips.length ? ips.map(ip => `<span class="relation-chip mono">${esc(ip)}</span>`).join("") : `<span class="muted">No IP addresses were directly present in the URLhaus records.</span>`;
  const rows = urlhausRows(urls);
  content.innerHTML = `<div class="relation-summary"><div class="kv"><b>Related URLs</b><span>${urls.length}</span></div><div class="kv"><b>Related IPs</b><span>${ips.length}</span></div></div><div class="relation-section"><h3>Related IPs</h3><div class="relation-chips">${ipList}</div></div><div class="relation-section"><h3>URLhaus URLs (defanged)</h3>${rows ? `<div class="table-scroll"><table class="table relation-table"><thead><tr><th>#</th><th>URL</th><th>Host</th><th>Status</th><th>Added</th><th>Tags</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="empty">No related URLs returned by URLhaus.</div>`}</div>`;
  modal.classList.remove("hidden");
  document.body.classList.add("modal-open");
}
function closeUrlhausRelationships() { const m = $("#urlhausRelationshipModal"); if (m) { m.classList.add("hidden"); document.body.classList.remove("modal-open"); } }
function openUrlhausRelationshipsNewTab() {
  const p = (lastResult?.providers || []).find(x => x.provider === "urlhaus" && x.status === "COMPLETED");
  const rel = p?.data?.related || {}; const urls = rel.urls || [], ips = rel.ips || [];
  const w = window.open("", "_blank");
  if (!w) { showStatus("Your browser blocked the new tab. Allow pop-ups for Compass.", true); return; }
  w.document.write(`<!doctype html><html><head><title>Compass: URLhaus relationships</title><meta charset="utf-8"><style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f7fa;color:#1f3447}header{position:sticky;top:0;background:#fff;border-bottom:1px solid #d7e0e8;padding:18px 24px}h1{margin:0 0 6px;font-size:22px}.muted{color:#63798c}main{padding:20px 24px}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d7e0e8}th,td{text-align:left;padding:10px;border-bottom:1px solid #e2e8ee;vertical-align:top}th{background:#eef3f7;font-size:12px}.relation-url{word-break:break-all;font-family:Consolas,monospace}</style></head><body><header><h1>URLhaus related URLs &amp; IPs</h1><div class="muted">${urls.length} related URLs, ${ips.length} related IPs. URLs are defanged.</div></header><main><h2>Related IPs</h2><p>${ips.length ? ips.map(esc).join(", ") : "None"}</p><h2>URLhaus URLs</h2><table><thead><tr><th>#</th><th>URL</th><th>Host</th><th>Status</th><th>Added</th><th>Tags</th></tr></thead><tbody>${urlhausRows(urls) || '<tr><td colspan="6">No related URLs returned.</td></tr>'}</tbody></table></main></body></html>`);
  w.document.close();
}

// ------------------------------------------------------------ file hashing
const dz = $("#dropzone");
dz.onclick = () => $("#fileInput").click();
dz.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#fileInput").click(); } };
$("#fileInput").onchange = e => e.target.files[0] && sendFile(e.target.files[0]);
["dragenter", "dragover"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add("drag"); }));
["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("drag"); }));
dz.addEventListener("drop", e => e.dataTransfer.files[0] && sendFile(e.dataTransfer.files[0]));
function md5Hex(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const add32 = (a, b) => (a + b) >>> 0;
  const rol = (x, n) => (x << n) | (x >>> (32 - n));
  const F = (x, y, z) => (x & y) | (~x & z), G = (x, y, z) => (x & z) | (y & ~z), H = (x, y, z) => x ^ y ^ z, I = (x, y, z) => y ^ (x | ~z);
  const S1 = [7, 12, 17, 22], S2 = [5, 9, 14, 20], S3 = [4, 11, 16, 23], S4 = [6, 10, 15, 21];
  const K = new Uint32Array(64); for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
  const len = bytes.length, total = Math.ceil((len + 9) / 64) * 64, msg = new Uint8Array(total); msg.set(bytes); msg[len] = 0x80;
  const bitLen = len * 8; for (let i = 0; i < 8; i++) msg[total - 8 + i] = Math.floor(bitLen / Math.pow(256, i)) & 255;
  let a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
  for (let off = 0; off < total; off += 64) {
    const m = new Uint32Array(16); for (let j = 0; j < 16; j++) m[j] = (msg[off + 4 * j]) | (msg[off + 4 * j + 1] << 8) | (msg[off + 4 * j + 2] << 16) | (msg[off + 4 * j + 3] << 24);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g, sh;
      if (i < 16) { f = F(b, c, d); g = i; sh = S1[i & 3]; }
      else if (i < 32) { f = G(b, c, d); g = (5 * i + 1) & 15; sh = S2[i & 3]; }
      else if (i < 48) { f = H(b, c, d); g = (3 * i + 5) & 15; sh = S3[i & 3]; }
      else { f = I(b, c, d); g = (7 * i) & 15; sh = S4[i & 3]; }
      const t = add32(add32(add32(a, f), m[g]), K[i]);
      const nb = add32(b, rol(t, sh)); a = d; d = c; c = b; b = nb;
    }
    a0 = add32(a0, a); b0 = add32(b0, b); c0 = add32(c0, c); d0 = add32(d0, d);
  }
  const word = x => [x & 255, (x >>> 8) & 255, (x >>> 16) & 255, (x >>> 24) & 255].map(v => v.toString(16).padStart(2, "0")).join("");
  return word(a0) + word(b0) + word(c0) + word(d0);
}
async function sendFile(file) {
  // Files are identified by MD5 only, computed in the browser. File bytes never leave this PC.
  if (file.size > 10 * 1024 * 1024) { showStatus("Files above 10 MB are rejected."); return; }
  showStatus(`Hashing ${file.name} locally…`);
  try {
    const md5 = md5Hex(new Uint8Array(await file.arrayBuffer()));
    $("#fileInput").value = "";
    await investigate({ ioc: md5, file: { name: file.name, size: file.size } });
  } catch (e) { showStatus(e.message, true); $("#fileInput").value = ""; }
}

// ------------------------------------------------------------ CVE / vulnerability intelligence
let cveResults = [];
let cveRelevanceOrder = [];
function cveStatus(msg, bad = false) { const x = $("#cveStatus"); x.classList.remove("hidden"); x.classList.toggle("bad", !!bad); x.textContent = msg; }
function cveSeverityClass(s) { return String(s || "").toLowerCase(); }
function cveRow(v) {
  const cv = v.cvss || {}, sev = esc(cv.severity || "UNKNOWN"), cls = cveSeverityClass(cv.severity || "unknown");
  return `<div class="cve-row" data-cve="${esc(v.id)}" tabindex="0"><div class="cve-row-head"><div class="cve-id">${esc(v.id)}</div><div><span class="severity ${cls}">${sev}</span> <span class="pill">CVSS ${esc(cv.score ?? "N/A")}</span>${v.kev ? ` <span class="pill kev-badge">CISA KEV</span>` : ""}</div></div><div class="cve-meta"><span class="pill">Published ${esc((v.published || "").slice(0, 10) || "N/A")}</span><span class="pill">Modified ${esc((v.lastModified || "").slice(0, 10) || "N/A")}</span><span class="pill">CVSS v${esc(cv.version || "-")}</span></div><div class="cve-desc">${esc(v.description || "No English description available.")}</div></div>`;
}
function cveSortRank(v) { return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[String(v?.cvss?.severity || "UNKNOWN").toUpperCase()] || 0; }
function cveScore(v) { const n = Number(v?.cvss?.score); return Number.isFinite(n) ? n : -1; }
function cveDate(v, key) { const t = Date.parse(v?.[key] || ""); return Number.isFinite(t) ? t : 0; }
function sortCveResults(sort) {
  const arr = cveResults;
  if (sort === "relevance") { const rank = new Map(cveRelevanceOrder.map((id, i) => [id, i])); arr.sort((a, b) => (rank.get(a.id) ?? 99999) - (rank.get(b.id) ?? 99999)); }
  else if (sort === "severity_desc") arr.sort((a, b) => cveSortRank(b) - cveSortRank(a) || cveScore(b) - cveScore(a) || cveDate(b, "lastModified") - cveDate(a, "lastModified"));
  else if (sort === "cvss_desc") arr.sort((a, b) => cveScore(b) - cveScore(a) || cveSortRank(b) - cveSortRank(a) || cveDate(b, "lastModified") - cveDate(a, "lastModified"));
  else if (sort === "published_desc") arr.sort((a, b) => cveDate(b, "published") - cveDate(a, "published"));
  else if (sort === "modified_desc") arr.sort((a, b) => cveDate(b, "lastModified") - cveDate(a, "lastModified"));
  else if (sort === "kev_first") arr.sort((a, b) => Number(!!b.kev) - Number(!!a.kev) || cveSortRank(b) - cveSortRank(a) || cveScore(b) - cveScore(a));
  if (lastCveData) lastCveData.results = arr;
  renderCveList(lastCveData, false);
}
function renderCveList(data, resetOrder = true) {
  cveResults = data.results || [];
  lastCveData = data;
  if (resetOrder) cveRelevanceOrder = cveResults.map(v => v.id);
  const source = `NVD: ${esc(data.sources?.nvd || "unknown")}. CISA KEV: ${esc(data.sources?.cisaKev || "unknown")}.`;
  if (!cveResults.length) { $("#cveResults").innerHTML = `<div class="card"><div class="cve-empty">No vulnerabilities found.<br><span class="muted">${source}</span></div></div>`; return; }
  $("#cveResults").innerHTML = `<div class="card"><div class="card-body"><div class="cve-summary"><div class="cve-stat"><b>${esc(data.totalResults ?? cveResults.length)}</b> total matches</div><div class="cve-stat"><b>${esc(cveResults.length)}</b> displayed</div><div class="cve-stat">${source}</div><button class="three-d cve-report" type="button" id="cveReportBtn">Open report</button></div><div class="cve-list">${cveResults.map(cveRow).join("")}</div></div></div><div id="cveDetail"></div>`;
  $$(".cve-row").forEach(x => { x.onclick = () => showCveDetail(cveResults.find(v => v.id === x.dataset.cve)); x.onkeydown = e => { if (e.key === "Enter") x.click(); }; });
  $("#cveReportBtn").onclick = () => openReport(cveReportHtml(lastCveData));
}
function showCveDetail(v) {
  if (!v) return;
  const cv = v.cvss || {}, kev = v.kevDetails;
  const affected = (v.affected || []).slice(0, 30).map(a => `<div class="kv"><b>CPE</b><span class="mono">${esc(a.cpe)}${a.versionEndExcluding ? `<br>Before ${esc(a.versionEndExcluding)}` : ""}${a.versionEndIncluding ? `<br>Up to ${esc(a.versionEndIncluding)}` : ""}</span></div>`).join("");
  const refs = (v.references || []).map(r => { const safe = /^https?:\/\//i.test(String(r.url || "")); return `<li class="cve-links">${safe ? `<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.url)}</a>` : esc(r.url)}${r.tags?.length ? ` <span class="muted">[${esc(r.tags.join(", "))}]</span>` : ""}</li>`; }).join("");
  $("#cveDetail").innerHTML = `<div class="cve-detail"><button class="cve-back" type="button" id="cveBack">← Back to results</button><h3>${esc(v.id)} ${v.kev ? `<span class="pill kev-badge">CISA KEV</span>` : ""}</h3><div class="cve-detail-grid"><div class="kv"><b>Severity</b><span class="severity ${cveSeverityClass(cv.severity)}">${esc(cv.severity || "UNKNOWN")}</span></div><div class="kv"><b>CVSS</b><span>${esc(cv.score ?? "N/A")} (v${esc(cv.version || "-")})</span></div><div class="kv"><b>Published</b><span>${esc(v.published || "N/A")}</span></div><div class="kv"><b>Last modified</b><span>${esc(v.lastModified || "N/A")}</span></div><div class="kv"><b>CWE</b><span>${esc((v.cwe || []).join(", ") || "Not specified")}</span></div><div class="kv"><b>Status</b><span>${esc(v.vulnStatus || "Unknown")}</span></div></div><div class="cve-detail" style="margin-top:14px"><h3>Description</h3><div class="cve-desc">${esc(v.description || "No description available.")}</div></div>${cv.vector ? `<div class="kv" style="margin-top:10px"><b>CVSS vector</b><span class="mono">${esc(cv.vector)}</span></div>` : ""}${kev ? `<div class="cve-detail" style="margin-top:14px;border-color:#e6a6ae"><h3 style="color:var(--bad)">CISA Known Exploited Vulnerability</h3><div class="cve-detail-grid"><div class="kv"><b>Vendor / product</b><span>${esc(kev.vendorProject || "N/A")}, ${esc(kev.product || "N/A")}</span></div><div class="kv"><b>Date added</b><span>${esc(kev.dateAdded || "N/A")}</span></div><div class="kv"><b>Ransomware use</b><span>${esc(kev.knownRansomwareCampaignUse || "Unknown")}</span></div><div class="kv"><b>Due date</b><span>${esc(kev.dueDate || "N/A")}</span></div></div><p class="cve-desc">${esc(kev.vulnerabilityName || "")}</p><p class="cve-desc"><b>Required action:</b> ${esc(kev.requiredAction || "Apply vendor mitigations/updates.")}</p></div>` : ""}${affected ? `<div class="cve-detail" style="margin-top:14px"><h3>Affected CPEs</h3><div class="grid">${affected}</div></div>` : ""}${refs ? `<div class="cve-detail" style="margin-top:14px"><h3>References</h3><ul>${refs}</ul></div>` : ""}</div>`;
  $("#cveBack").onclick = () => { $("#cveDetail").innerHTML = ""; };
  $("#cveDetail").scrollIntoView({ behavior: "smooth", block: "start" });
}
async function searchCve(qOverride = null) {
  const q = qOverride === null ? $("#cveInput").value.trim() : qOverride;
  const sort = $("#cveSort").value;
  cveStatus("Querying NVD and CISA KEV…");
  $("#cveResults").innerHTML = "";
  try {
    const isCve = /^CVE-\d{4}-\d{4,}$/i.test(q);
    const params = new URLSearchParams({ sort, limit: "25" });
    if (isCve) params.set("cve", q.toUpperCase()); else if (q) params.set("q", q);
    const data = await api(`/api/cve/search?${params.toString()}`);
    renderCveList(data);
    cveStatus(`CVE search complete. ${data.count} result(s) displayed and saved to your history.`);
    loadSavedReports(true);
  } catch (e) {
    cveStatus(`CVE search failed: ${e.message}`, true);
    $("#cveResults").innerHTML = `<div class="card"><div class="cve-empty">Unable to retrieve vulnerability data.<br>${esc(e.message)}</div></div>`;
  }
}
$("#cveSearchBtn").onclick = () => searchCve();
$("#cveInput").addEventListener("keydown", e => { if (e.key === "Enter") searchCve(); });
$("#cveLatestBtn").onclick = () => { $("#cveInput").value = ""; searchCve(""); };
$("#cveSort").addEventListener("change", () => { if (lastCveData && cveResults.length) { sortCveResults($("#cveSort").value); cveStatus(`Sorted by ${$("#cveSort").selectedOptions[0].text}.`); } });

// ------------------------------------------------------------ my history (server-side, per user)
const HISTORY_TYPES = {
  Investigation: { tab: "Investigations", none: "investigations", box: "#savedInvestigationReports", pill: "IOC", col: "Verdict" },
  Email: { tab: "Email analyses", none: "email analyses", box: "#savedEmailReports", pill: "Email", col: "Result" },
  CVE: { tab: "CVE searches", none: "CVE searches", box: "#savedCveReports", pill: "CVE", col: "Results" },
};
let HISTORY = { Investigation: [], Email: [], CVE: [] };
let activeReportTab = "Investigation";
async function loadSavedReports(silent = false) {
  try {
    const d = await api("/api/history");
    HISTORY = {};
    Object.keys(HISTORY_TYPES).forEach(t => { HISTORY[t] = d.items.filter(x => x.type === t); });
  } catch (e) {
    if (!silent) $("#savedInvestigationReports").innerHTML = `<div class="empty err">${stag("Failed", "bad")} Could not load your history: ${esc(e.message)}</div>`;
    return;
  }
  const total = Object.values(HISTORY).reduce((n, l) => n + l.length, 0);
  $("#reportCount").textContent = `${total} record${total === 1 ? "" : "s"}`;
  $("#clearReportsBtn").disabled = !total;
  $$(".report-tab").forEach(b => { const t = b.dataset.reportTab; b.textContent = `${HISTORY_TYPES[t].tab} (${HISTORY[t].length})`; });
  Object.keys(HISTORY_TYPES).forEach(renderReportList);
}
// Threat verdicts: red = malicious, amber = suspicious / not enough data,
// green = known-good, blue = checked and nothing found.
function threatClass(v) {
  const s = String(v || "").toUpperCase();
  if (s === "MALICIOUS") return "bad";
  if (s === "SUSPICIOUS" || s === "INSUFFICIENT DATA" || s === "SCANNER / NOISE") return "warn";
  if (s.startsWith("BENIGN")) return "ok";
  if (s.startsWith("NO ") || s === "NOT_FOUND" || s === "UNKNOWN") return "none";
  if (s === "OBSERVED") return "muted";
  return "muted";
}
function verdictClass(v) {
  const s = String(v || "").toUpperCase();
  if (s === "CONSISTENT") return "ok";
  if (s === "INCONSISTENT") return "warn";
  if (/^\d+ HIGH RISK$/.test(s)) return s.startsWith("0 ") ? "none" : "bad";
  return threatClass(v);
}
function renderReportList(type) {
  const meta = HISTORY_TYPES[type];
  const box = $(meta.box);
  const items = HISTORY[type] || [];
  if (!items.length) {
    box.innerHTML = `<div class="empty na"><b>No ${meta.none} yet.</b><br>They are saved here automatically when you run them.</div>`;
    return;
  }
  const shown = h => type === "CVE" ? (h.summary || "—") : (h.verdict || "—");
  box.innerHTML = `<div class="report-table"><div class="report-table-head"><span>Search</span><span>Type</span><span>${meta.col}</span><span>Date &amp; time</span><span>Actions</span></div>${items.map(h => `<div class="report-table-row"><div><div class="saved-report-title${type === "Email" ? "" : " mono"}">${esc(h.title)}</div><div class="saved-report-meta">${esc(h.summary || "")}</div></div><div><span class="report-type-pill">${meta.pill}</span></div><div><span class="report-verdict ${type === "CVE" ? "muted" : verdictClass(h.verdict)}">${esc(shown(h))}</span></div><div class="saved-report-meta">${esc(fmtDate(h.created_at))}</div><div class="saved-report-actions"><button class="three-d" type="button" data-hid="${h.id}" data-act="open">Open</button><button class="three-d" type="button" data-hid="${h.id}" data-act="view">Report</button><button class="three-d" type="button" data-hid="${h.id}" data-act="download">Download</button><button class="three-d delete-report" type="button" data-hid="${h.id}" data-act="delete">Delete</button></div></div>`).join("")}</div>`;
}
async function historyItem(id) { return api(`/api/history/${id}`); }
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-hid]");
  if (!b) return;
  const id = b.dataset.hid, act = b.dataset.act;
  try {
    if (act === "delete") {
      if (!confirm("Delete this record from your history? This cannot be undone.")) return;
      await del(`/api/history/${id}`);
      await loadSavedReports();
      return;
    }
    const item = await historyItem(id);
    const snap = item.snapshot;
    if (act === "open") {
      const saved = `Loaded from your history (saved ${fmtDate(item.created_at)}).`;
      if (item.type === "Investigation") {
        lastResult = snap; goPage("investigation"); $("#iocInput").value = item.query || ""; $("#progress").innerHTML = "";
        renderResult(snap); showStatus(saved, false, true);
      } else if (item.type === "Email") {
        goPage("email"); lastEmail = snap; renderEmail(snap); pageStatus("#emailStatus", saved);
      } else {
        goPage("cve"); $("#cveInput").value = item.query === "Latest 30 days" ? "" : item.query; renderCveList(snap); cveStatus(saved);
      }
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    const html = item.type === "Investigation" ? investigationReportHtml(snap, item.created_at)
      : item.type === "Email" ? emailReportHtml(snap, item.created_at)
      : cveReportHtml(snap, item.created_at);
    if (act === "view") openReport(html);
    if (act === "download") downloadText(`compass-${safeFilename(item.title)}.html`, html, "text/html");
  } catch (err) { alert(err.message); }
});
$("#clearReportsBtn").onclick = async () => {
  if (!confirm("Delete all of your saved investigations, email analyses and CVE searches? This cannot be undone.")) return;
  try { await del("/api/history"); await loadSavedReports(); } catch (e) { alert(e.message); }
};
function switchReportTab(type) {
  activeReportTab = type;
  $$(".report-tab").forEach(b => { const on = b.dataset.reportTab === type; b.classList.toggle("active", on); b.setAttribute("aria-selected", String(on)); });
  $$(".report-panel").forEach(p => p.classList.toggle("active", p.id === `report-panel-${type}`));
}
$$(".report-tab").forEach(b => b.onclick = () => switchReportTab(b.dataset.reportTab));

// ------------------------------------------------------------ settings
async function renderSettings() {
  if (!ME) return;
  const isAdmin = ME.role === "admin";
  $("#settingsLede").textContent = isAdmin ? "Your account, API keys and the people who can use Compass." : "Your account. API keys and users are managed by your Compass administrator.";
  $("#accountSettings").innerHTML = `<div class="card"><div class="card-head"><h2>My account</h2><span class="pill">${isAdmin ? "Administrator" : "Analyst"}</span></div><div class="card-body account-grid">
    <div class="grid account-facts"><div class="kv"><b>Name</b><span>${esc(ME.display_name)}</span></div><div class="kv"><b>Username</b><span class="mono">${esc(ME.username)}</span></div><div class="kv"><b>Last sign-in</b><span>${esc(fmtDate(ME.last_login))}</span></div></div>
    <form id="pwForm" class="pw-form" autocomplete="off"><h3>Change password</h3><input type="text" name="username" value="${esc(ME.username)}" autocomplete="username" hidden>
      <label>Current password<input type="password" name="current" autocomplete="current-password" required></label>
      <label>New password<input type="password" name="next" autocomplete="new-password" minlength="8" required></label>
      <label>Confirm new password<input type="password" name="next2" autocomplete="new-password" minlength="8" required></label>
      <div class="actions"><button class="save" type="submit">Change password</button></div><div class="form-msg" id="pwMsg"></div></form></div></div>`;
  $("#pwForm").onsubmit = async e => {
    e.preventDefault();
    const f = e.target, msg = $("#pwMsg");
    if (f.next.value !== f.next2.value) { msg.textContent = "The two new passwords don't match."; msg.className = "form-msg bad"; return; }
    try { await post("/api/auth/password", { current_password: f.current.value, new_password: f.next.value }); f.reset(); msg.textContent = "Password changed. Other sessions for your account were signed out."; msg.className = "form-msg ok"; }
    catch (err) { msg.textContent = err.message; msg.className = "form-msg bad"; }
  };
  if (!isAdmin) { $("#adminSettings").innerHTML = ""; return; }
  $("#adminSettings").innerHTML = `<div id="keySettings"></div><div id="userSettings"></div>`;
  await Promise.all([loadKeySettings(), loadUserSettings()]);
}

const KEY_GROUPS = [["intel", "Threat-intelligence providers", "Verdicts on IPs, domains, URLs and hashes."], ["discovery", "Discovery sources", "Optional keys that add subdomain and passive DNS data or raise free limits. crt.sh, CertSpotter, Wayback, RIPEstat, Shodan InternetDB and the Tor list need no key."], ["cve", "Vulnerability data", ""]];
async function loadKeySettings() {
  const data = await api("/api/settings/providers");
  const list = Object.values(data);
  $("#keySettings").innerHTML = KEY_GROUPS.map(([cat, title, help]) => {
    const items = list.filter(p => (p.category || "intel") === cat);
    if (!items.length) return "";
    return `<div class="card"><div class="card-head"><div><h2>${esc(title)}</h2>${help ? `<p class="muted small">${esc(help)}</p>` : ""}</div></div><div class="card-body settings-grid">${items.map(p => `<div class="setting"><div class="setting-head"><h3>${esc(p.label)}</h3>${p.configured ? tag("Key saved", "ok") : p.key_required ? tag("No key", "muted") : tag("Works without a key", "muted")}</div><small>${esc(p.help || "")}</small><input id="key-${esc(p.name)}" type="password" placeholder="${p.configured ? "Enter a new key to replace the saved one" : "Paste API key"}" autocomplete="off" spellcheck="false"><div class="actions"><button class="save" type="button" data-key-save="${esc(p.name)}">${p.configured ? "Replace key" : "Save key"}</button>${p.configured ? `<button type="button" data-key-del="${esc(p.name)}">Remove</button>` : ""}</div></div>`).join("")}</div></div>`;
  }).join("");
}
document.addEventListener("click", async e => {
  const s = e.target.closest("[data-key-save]"), d = e.target.closest("[data-key-del]");
  if (!s && !d) return;
  try {
    if (s) {
      const name = s.dataset.keySave, key = document.getElementById(`key-${name}`).value.trim();
      if (!key) { alert("Paste the API key first."); return; }
      await post(`/api/settings/providers/${name}`, { api_key: key });
    } else {
      if (!confirm("Remove this API key? Compass will stop querying this source.")) return;
      await del(`/api/settings/providers/${d.dataset.keyDel}`);
    }
    await loadKeySettings();
  } catch (err) { alert(err.message); }
});

async function loadUserSettings() {
  const { users } = await api("/api/admin/users");
  const row = u => {
    const self = u.id === ME.id;
    return `<tr><td><b>${esc(u.display_name)}</b><div class="muted small mono">${esc(u.username)}</div></td><td>${u.role === "admin" ? tag("Administrator", "accent") : tag("Analyst", "muted")}</td><td>${u.active ? (u.must_change ? tag("Must change password", "warn") : tag("Active", "ok")) : tag("Disabled", "bad")}</td><td class="small">${esc(fmtDate(u.last_login))}</td><td class="user-actions">${self ? `<span class="muted small">This is you</span>` : `<button type="button" data-user="${u.id}" data-uact="reset">Reset password</button><button type="button" data-user="${u.id}" data-uact="role" data-role="${u.role === "admin" ? "analyst" : "admin"}">${u.role === "admin" ? "Make analyst" : "Make admin"}</button><button type="button" data-user="${u.id}" data-uact="${u.active ? "disable" : "enable"}">${u.active ? "Disable" : "Enable"}</button><button type="button" class="danger-lite" data-user="${u.id}" data-uact="delete" data-name="${esc(u.username)}">Delete</button>`}</td></tr>`;
  };
  $("#userSettings").innerHTML = `<div class="card"><div class="card-head"><div><h2>Users</h2><p class="muted small">Each user signs in with their own account and sees only their own history. New accounts must choose their own password at first sign-in.</p></div><span class="pill">${users.length} account${users.length === 1 ? "" : "s"}</span></div><div class="card-body">
    <form id="addUserForm" class="inline-form"><label>Username<input name="username" required pattern="[A-Za-z0-9._\\-]{3,32}" autocomplete="off" spellcheck="false"></label><label>Name<input name="display_name" autocomplete="off"></label><label>Role<select name="role"><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label><button class="primary small-btn" type="submit">Add user</button></form>
    <div id="userMsg"></div>
    <details class="bulk"><summary>Add many trainees at once</summary><form id="bulkForm"><label>Usernames, one per line<textarea name="usernames" rows="5" placeholder="trainee01&#10;trainee02&#10;trainee03"></textarea></label><div class="inline-form"><label>Role<select name="role"><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label><button class="primary small-btn" type="submit">Create accounts</button></div></form><div id="bulkMsg"></div></details>
    <div class="tbl-scroll"><table class="table data users-table"><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th>Actions</th></tr></thead><tbody>${users.map(row).join("")}</tbody></table></div></div></div>`;
  $("#addUserForm").onsubmit = async e => {
    e.preventDefault();
    const f = e.target;
    try {
      const d = await post("/api/admin/users", { username: f.username.value.trim(), display_name: f.display_name.value.trim(), role: f.role.value });
      const user = d.user.username;
      await loadUserSettings();
      $("#userMsg").innerHTML = credentialNotice(`Account created for ${user}.`, [{ username: user, password: d.temp_password }]);
    } catch (err) { $("#userMsg").innerHTML = `<div class="form-msg bad">${esc(err.message)}</div>`; }
  };
  $("#bulkForm").onsubmit = async e => {
    e.preventDefault();
    const f = e.target;
    try {
      const d = await post("/api/admin/users/bulk", { usernames: f.usernames.value, role: f.role.value });
      const ok = d.results.filter(x => x.ok), bad = d.results.filter(x => !x.ok);
      await loadUserSettings();
      $("#userMsg").innerHTML = credentialNotice(`${ok.length} account${ok.length === 1 ? "" : "s"} created.`, ok) + (bad.length ? `<div class="form-msg bad">${bad.map(x => `${esc(x.username)}: ${esc(x.error)}`).join("<br>")}</div>` : "");
    } catch (err) { $("#bulkMsg").innerHTML = `<div class="form-msg bad">${esc(err.message)}</div>`; }
  };
}
let LAST_CREDS = [];
function credentialNotice(title, creds) {
  LAST_CREDS = creds;
  if (!creds.length) return `<div class="form-msg">${esc(title)}</div>`;
  return `<div class="cred-notice"><div class="cred-head"><b>${esc(title)}</b><span class="muted small">Temporary passwords are shown only once. Each user must change theirs at first sign-in.</span><button type="button" class="three-d" id="credCsv">Download as CSV</button></div><table class="table"><thead><tr><th>Username</th><th>Temporary password</th></tr></thead><tbody>${creds.map(c => `<tr><td class="mono">${esc(c.username)}</td><td class="mono cred-pw">${esc(c.password)}</td></tr>`).join("")}</tbody></table></div>`;
}
document.addEventListener("click", async e => {
  if (e.target.id === "credCsv") {
    const lines = ["Username,Temporary password"].concat(LAST_CREDS.map(c => `${csvCell(c.username)},${csvCell(c.password)}`));
    downloadText(`compass-new-accounts-${new Date().toISOString().slice(0, 10)}.csv`, "﻿" + lines.join("\r\n"), "text/csv;charset=utf-8");
    return;
  }
  const b = e.target.closest("[data-uact]");
  if (!b) return;
  const id = b.dataset.user, act = b.dataset.uact;
  try {
    if (act === "reset") {
      if (!confirm("Reset this user's password? They will be signed out and must use the new temporary password.")) return;
      const d = await post(`/api/admin/users/${id}`, { action: "reset_password" });
      const name = b.closest("tr").querySelector(".mono").textContent;
      await loadUserSettings();
      $("#userMsg").innerHTML = credentialNotice(`Password reset for ${name}.`, [{ username: name, password: d.temp_password }]);
      return;
    }
    if (act === "delete") {
      if (!confirm(`Delete ${b.dataset.name}? Their search history is deleted too. This cannot be undone.`)) return;
      await del(`/api/admin/users/${id}`);
    } else if (act === "role") {
      await post(`/api/admin/users/${id}`, { action: "update", role: b.dataset.role });
    } else {
      await post(`/api/admin/users/${id}`, { action: "update", active: act === "enable" });
    }
    await loadUserSettings();
  } catch (err) { alert(err.message); }
});

// ------------------------------------------------------------ reports
function safeFilename(v) { return String(v || "report").replace(/[^a-z0-9._-]+/gi, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "report"; }
function downloadText(filename, text, type) { const blob = new Blob([text], { type }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
function openReport(html) {
  if (!html) { alert("There is no data to build a report from yet."); return; }
  const w = window.open("", "_blank");
  if (!w) { alert("Allow pop-ups for Compass to view reports."); return; }
  w.document.write(html); w.document.close(); w.focus();
}
function reportStamp(savedAt) {
  const now = new Date();
  const saved = savedAt ? new Date(savedAt * 1000) : null;
  const who = ME ? `${ME.display_name} (${ME.username})` : "Unknown analyst";
  return `<div class="facts stamp"><div class="fact"><b>Prepared by</b>${esc(who)}</div><div class="fact"><b>Report generated</b>${esc(now.toLocaleString())}<br><span class="muted">${esc(now.toISOString())} UTC</span></div>${saved ? `<div class="fact"><b>Data collected</b>${esc(saved.toLocaleString())}<br><span class="muted">${esc(saved.toISOString())} UTC</span></div>` : ""}<div class="fact"><b>Tool</b>Compass ${esc($("#aboutVersion").textContent)}</div></div>`;
}
function reportShell(title, subtitle, body, savedAt) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title><style>body{font-family:Segoe UI,Arial,sans-serif;background:#f4f7fa;color:#172b3a;margin:0;line-height:1.55}.wrap{max-width:1150px;margin:0 auto;padding:38px}header{border-bottom:3px solid #2f6fed;padding-bottom:18px;margin-bottom:22px}h1{font-size:28px;margin:0 0 5px;color:#173b5e}h2{font-size:17px;margin:28px 0 10px;color:#173b5e;border-bottom:1px solid #dbe3ea;padding-bottom:7px}.meta{color:#647687;font-size:13px}.box{border:1px solid #dbe3ea;border-radius:10px;padding:16px;margin:12px 0;background:#fff}.summary{font-size:14px;color:#40576a}.verdict{font-size:25px;font-weight:900}.bad{color:#c20e4d}.warn{color:#8a5a00}.ok{color:#0e793c}.none{color:#004493}.muted{color:#52525b}.mono{font-family:Consolas,monospace;word-break:break-all}table{width:100%;border-collapse:collapse;background:#fff;font-size:13px}th,td{padding:8px 10px;border:1px solid #dbe3ea;text-align:left;vertical-align:top}th{background:#eef4fa;color:#173b5e}.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.fact{background:#f8fafc;border:1px solid #e0e7ec;border-radius:8px;padding:11px}.fact b{display:block;color:#647687;font-size:11px;text-transform:uppercase;margin-bottom:4px}.stamp{margin-bottom:8px}ul{margin:6px 0;padding-left:20px}@media(max-width:700px){.wrap{padding:20px}.facts{grid-template-columns:1fr}}@media print{body{background:#fff}.wrap{max-width:none;padding:0}}</style></head><body><div class="wrap"><header><h1>${esc(title)}</h1><div class="meta">${esc(subtitle)}</div></header>${reportStamp(savedAt)}${body}</div></body></html>`;
}
function rtable(head, rows, empty) { return `<table><tr>${head.map(h => `<th>${esc(h)}</th>`).join("")}</tr>${rows.length ? rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${head.length}">${esc(empty)}</td></tr>`}</table>`; }
function investigationReportHtml(r, savedAt) {
  if (!r) return null;
  savedAt = savedAt || r.finished_at;
  const a = r.threat_assessment || {}, inf = r.infrastructure || {};
  const vc = a.verdict === "MALICIOUS" ? "bad" : a.verdict === "SUSPICIOUS" ? "warn" : a.verdict === "NO STRONG MALICIOUS SIGNAL" ? "ok" : "muted";
  const providers = (r.providers || []).filter(p => p.status === "COMPLETED").map(p => { const x = p.assessment || {}; return [`<b>${esc(p.provider)}</b>`, `<span class="${verdictClass(x.verdict)}">${esc(x.verdict || "UNKNOWN")}</span>`, esc(x.summary || "")]; });
  const dns = inf.dns || inf.domain?.dns || {};
  const dnsRows = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"].filter(k => (dns[k] || []).length).map(k => [`<b>${k}</b>`, (dns[k] || []).map(x => `<span class="mono">${esc(typeof x === "string" ? x : x.data || "")}</span>`).join("<br>")]);
  const g = geoIntel(inf.geoip);
  const facts = [`<div class="fact"><b>IOC type</b>${esc(r.ioc.type || "")}</div>`, `<div class="fact"><b>IOC</b><span class="mono">${esc(r.ioc.normalized || "")}</span></div>`, `<div class="fact"><b>Mode</b>${r.mode === "active" ? "Active checks (target contacted)" : "Passive (target not contacted)"}</div>`];
  if (r.file) facts.push(`<div class="fact"><b>File</b>${esc(r.file.name || "")}, ${esc(r.file.size || 0)} bytes</div><div class="fact"><b>MD5</b><span class="mono">${esc(r.file.hashes?.md5 || r.file.ioc || "")}</span></div>`);
  if (r.ioc.type === "ip" || r.ioc.type === "ipv6") facts.push(`<div class="fact"><b>Country</b>${esc(g.country || "Unavailable")}</div><div class="fact"><b>ASN</b>${esc(g.asn || "Unavailable")}</div><div class="fact"><b>Organization</b>${esc(g.org || "Unavailable")}</div>`);
  const rdap = domainRdap(r); const age = rdap ? ageText(rdap.created) : null;
  if (age) facts.push(`<div class="fact"><b>Domain registered</b>${esc(age.text)}</div>`);
  let disc = "";
  const d = r.discovery && !r.discovery.error ? r.discovery : null;
  if (d && d.kind === "domain") {
    disc += `<h2>Discovery summary</h2><div class="box summary">${esc(d.stats.subdomains)} subdomains (${esc(d.stats.live)} live), ${esc(d.stats.ips)} linked IPs and ${esc(d.stats.related)} related domains for <span class="mono">${esc(d.apex)}</span>.${d.shared_hosting?.cdn ? ` Served through ${esc(d.shared_hosting.cdn)}.` : ""}${(d.notes || []).length ? `<ul>${d.notes.map(n => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}</div>`;
    disc += `<h2>Subdomains</h2>` + rtable(["Subdomain", "Status", "Resolves to", "Found by", "First seen", "Last seen"], d.subdomains.slice(0, 1000).map(s => [`<span class="mono">${esc(s.name)}</span>`, subStatusText(s), `<span class="mono">${esc(s.ips.join(", "))}</span>${s.cdn ? ` (${esc(s.cdn)})` : ""}`, esc(s.sources.join(", ")), esc(s.first_seen || "—"), esc(s.last_seen || "—")]), "None found");
    disc += `<h2>Linked IPs</h2>` + rtable(["IP", "How it's linked", "Network", "Country", "Flags", "Open ports", "Known CVEs"], d.ips.map(x => [`<span class="mono">${esc(x.ip)}</span>`, esc(x.relations.join(", ")), esc([x.asn, x.as_name].filter(Boolean).join(" ")), esc(x.country || "—"), esc(ipFlagText(x) || "—"), esc(x.ports.join(", ") || "—"), esc(x.vulns.join(", ") || "—")]), "None found");
    if ((d.origin_candidates || []).length) disc += `<h2>Possible origin servers</h2>` + rtable(["IP", "Why it is listed", "Network"], d.origin_candidates.map(o => [`<span class="mono">${esc(o.ip)}</span>`, esc(o.reason), esc([o.asn, o.as_name].filter(Boolean).join(" "))]), "None");
    disc += `<h2>Related domains</h2>` + rtable(["Domain", "Relationship", "Via", "Found by"], d.related_domains.map(x => [`<span class="mono">${esc(x.name)}</span>`, esc(x.relations.join(", ")), `<span class="mono">${esc(x.via.join(", "))}</span>`, esc(x.sources.join(", "))]), "None found");
    const m = d.mail || {};
    disc += `<h2>Mail infrastructure</h2>` + rtable(["Item", "Value"], [["MX", `<span class="mono">${esc((m.mx || []).join(", ") || "None")}</span>`], ["SPF", `<span class="mono">${esc(m.spf || "None")}</span>`], ["DMARC", `<span class="mono">${esc(m.dmarc || "None")}</span>`], ["Name servers", `<span class="mono">${esc((m.ns || []).join(", ") || "None")}</span>`]], "None");
  }
  if (d && d.kind === "ip") {
    disc += `<h2>Discovery summary</h2><div class="box summary">${esc(d.stats.domains)} domains seen on <span class="mono">${esc(d.target)}</span>, ${esc(d.stats.current)} still point here. Network: ${esc([d.network.asn, d.network.as_name].filter(Boolean).join(" ") || "unknown")}.${d.shared_hosting?.reason ? `<br><b>${esc(d.shared_hosting.reason)}</b>` : ""}</div>`;
    disc += `<h2>Exposure and anonymity</h2>` + rtable(["Item", "Value"], [["Open ports", esc((d.exposure.ports || []).join(", ") || "None")], ["Known CVEs", esc((d.exposure.vulns || []).join(", ") || "None")], ["Tor exit node", d.anonymity.tor ? "Yes" : "No"], ["VPN", d.anonymity.vpn ? "Yes" : "No"], ["Proxy", d.anonymity.proxy ? "Yes" : "No"], ["Datacenter", d.anonymity.datacenter ? "Yes" : "No"]], "None");
    disc += `<h2>Domains on this IP</h2>` + rtable(["Domain", "Points here now", "Registered domain", "Found by", "First seen", "Last seen"], d.domains.map(x => [`<span class="mono">${esc(x.name)}</span>`, x.current ? "Yes" : x.current === false ? "No" : "Not checked", esc(x.apex), esc(x.sources.join(", ")), esc(x.first_seen || "—"), esc(x.last_seen || "—")]), "None found");
  }
  const wh = r.webhistory;
  if (wh && (wh.versions || []).length) {
    disc += `<h2>Website history (Wayback Machine)</h2><div class="box summary">First capture ${esc(wh.first?.ist || "—")}, latest ${esc(wh.latest?.ist || "—")}. ${esc(wh.days_captured)} days with captures, ${esc(wh.version_count)} distinct versions${wh.redirects_offsite ? `, ${esc(wh.redirects_offsite)} redirects to other sites` : ""}.</div>`
      + rtable(["Captured (IST)", "Captured (UTC)", "HTTP", "What changed", "Content hash", "Snapshot"], wh.versions.slice(0, 300).map(v => [esc(v.ist), esc(v.utc), esc(v.status), esc(whChangeText(v)), `<span class="mono">${esc(v.digest)}</span>`, `<span class="mono">${esc(v.snapshot)}</span>`]), "None");
  }
  if (d) disc += `<h2>Sources consulted</h2>` + rtable(["Source", "Result", "Items", "Details"], (d.sources || []).map(s => [esc(s.label), `<span class="${sourceState(s)[1]}">${esc(sourceState(s)[0])}</span>`, esc(s.count ?? "—"), esc(s.note || s.error || "")]), "None");
  return reportShell("Compass investigation report", `${r.ioc.type || "IOC"}: ${r.ioc.normalized || ""}`, `<div class="box"><div class="meta">Overall threat-intel verdict</div><div class="verdict ${vc}">${esc(a.verdict || "INSUFFICIENT DATA")}</div><div class="summary"><b>Confidence:</b> ${esc(a.confidence || "LOW")}. ${esc(a.summary || "")}</div></div><h2>Investigation summary</h2><div class="facts">${facts.join("")}</div><h2>Threat intelligence</h2>${rtable(["Source", "Verdict", "Assessment"], providers, "No provider results")}${dnsRows.length ? `<h2>DNS records</h2>${rtable(["Type", "Records"], dnsRows, "")}` : ""}${disc}<p class="meta">Analyst-facing findings only. Raw provider payloads are excluded. Passive-DNS and certificate data reflect what third-party sources observed and should be corroborated before action.</p>`, savedAt);
}
function cveReportHtml(data, savedAt) {
  if (!data) return null;
  const rows = (data.results || []).map(v => { const cv = v.cvss || {}; return [`<span class="mono"><b>${esc(v.id)}</b></span>`, esc(cv.severity || "UNKNOWN"), esc(cv.score ?? "N/A"), v.kev ? "Yes" : "No", esc((v.published || "").slice(0, 10)), esc(v.description || "")]; });
  return reportShell("Compass CVE / vulnerability report", `Query: ${data.query || "Latest vulnerabilities"}`, `<div class="box"><div class="summary"><b>Results:</b> ${esc(data.results?.length || 0)} displayed. <b>NVD:</b> ${esc(data.sources?.nvd || "unknown")}. <b>CISA KEV:</b> ${esc(data.sources?.cisaKev || "unknown")}.</div></div><h2>Vulnerabilities</h2>${rtable(["CVE", "Severity", "CVSS", "CISA KEV", "Published", "Description"], rows, "No vulnerabilities found")}<p class="meta">Raw NVD/CISA API payloads are excluded.</p>`, savedAt);
}

// ------------------------------------------------------------ boot
(async () => {
  try {
    const me = await api("/api/me");
    ME = me.user; CSRF = me.csrf;
    renderUser();
    $("#aboutVersion").textContent = me.version;
  } catch (e) {
    window.location.replace("/login");
    return;
  }
  loadSavedReports(true);
})();
