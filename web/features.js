"use strict";
// Compass: email header analysis page.
// Loaded after app.js and uses its helpers (api, post, esc, stag, pivot, tableBlock…).

let lastEmail = null;
let emailMode = "paste";
let emlFile = null;

function pageStatus(sel, msg, bad = false) {
  const x = $(sel);
  x.classList.remove("hidden");
  x.classList.toggle("bad", !!bad);
  x.innerHTML = (bad ? stag("Error", "bad") + " " : "") + esc(msg);
}
function hideEl(sel) { $(sel).classList.add("hidden"); }
function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  const ta = document.createElement("textarea");
  ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); } finally { ta.remove(); }
  return Promise.resolve();
}
const STATE_WORD = { ok: "ok", warn: "warn", bad: "bad", none: "none", muted: "muted" };
const st = s => STATE_WORD[s] || "muted";

$("#colourLegend").innerHTML = legendHtml();

// ============================================================ email header analysis
function setEmailMode(m) {
  emailMode = m;
  $$("[data-email-mode]").forEach(b => { const on = b.dataset.emailMode === m; b.classList.toggle("active", on); b.setAttribute("aria-selected", String(on)); });
  $("#emailPaste").hidden = m !== "paste";
  $("#emailEml").hidden = m !== "eml";
}
$$("[data-email-mode]").forEach(b => b.onclick = () => setEmailMode(b.dataset.emailMode));
const emlDrop = $("#emlDrop");
emlDrop.onclick = () => $("#emlInput").click();
emlDrop.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#emlInput").click(); } };
$("#emlInput").onchange = e => pickEml(e.target.files[0]);
["dragenter", "dragover"].forEach(ev => emlDrop.addEventListener(ev, e => { e.preventDefault(); emlDrop.classList.add("drag"); }));
["dragleave", "drop"].forEach(ev => emlDrop.addEventListener(ev, e => { e.preventDefault(); emlDrop.classList.remove("drag"); }));
emlDrop.addEventListener("drop", e => e.dataTransfer.files[0] && pickEml(e.dataTransfer.files[0]));

function pickEml(f) {
  if (!f) return;
  if (/\.msg$/i.test(f.name)) {
    pageStatus("#emailStatus", "Outlook .msg files are not supported yet. In Outlook, save the message as .eml (or drag it to a folder in Windows), then upload that file.", true);
    return;
  }
  if (f.size > 18 * 1024 * 1024) { pageStatus("#emailStatus", "That file is larger than 18 MB.", true); return; }
  emlFile = f;
  $("#emlName").textContent = `Selected: ${f.name} (${fmtSize(f.size)})`;
  hideEl("#emailStatus");
}
function b64FromBuffer(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
$("#emailBtn").onclick = () => analyseEmail();
$("#emailClear").onclick = () => {
  $("#emailHeaders").value = ""; emlFile = null; $("#emlInput").value = ""; $("#emlName").textContent = "";
  $("#emailResults").innerHTML = ""; hideEl("#emailStatus"); lastEmail = null;
};
async function analyseEmail() {
  const btn = $("#emailBtn");
  let body;
  if (emailMode === "eml") {
    if (!emlFile) { pageStatus("#emailStatus", "Choose an .eml file first.", true); return; }
    body = { eml_b64: b64FromBuffer(await emlFile.arrayBuffer()), name: emlFile.name };
  } else {
    const t = $("#emailHeaders").value;
    if (!t.trim()) { pageStatus("#emailStatus", "Paste the email headers first.", true); return; }
    body = { headers: t };
  }
  btn.disabled = true;
  pageStatus("#emailStatus", "Analysing the headers and checking DKIM keys…");
  try {
    const r = await post("/api/email/analyze", body);
    lastEmail = r;
    renderEmail(r);
    pageStatus("#emailStatus", "Analysis complete and saved to your history.");
    loadSavedReports(true);
  } catch (e) {
    pageStatus("#emailStatus", e.message, true);
  } finally {
    btn.disabled = false;
  }
}

function addrHtml(a) {
  if (!a || !a.address) return `<span class="v-none">None</span>`;
  return `${a.name ? `${esc(a.name)} · ` : ""}<button class="pivot mono" type="button" data-ioc="${esc(a.domain)}" title="Investigate ${esc(a.domain)}">${esc(a.address)}</button>`;
}
function ipHtml(x) {
  if (!x) return "";
  return x.public ? pivot(x.ip) : `<span class="mono small">${esc(x.ip)}</span> <span class="muted small">(internal)</span>`;
}
const TRUST = {
  recipient: ["Trusted: your mail server", "ok"],
  provider: ["Added by a mail provider", "muted"],
  sender: ["Sender side: can be forged", "warn"],
};
function checkRow(c) {
  return `<div class="check-row"><div class="check-state">${stag(c.label, st(c.state))}</div><div class="check-body"><h3>${esc(c.title)}</h3><p>${esc(c.text)}</p>${c.lookalike_of ? `<div class="check-actions">${c.pivot ? `<button class="inline-btn" type="button" data-ioc="${esc(c.pivot)}" data-pivot-btn="1">Investigate ${esc(c.pivot)}</button>` : ""}</div>` : c.pivot ? `<div class="check-actions"><button class="inline-btn" type="button" data-ioc="${esc(c.pivot.split("@").pop())}" data-pivot-btn="1">Investigate ${esc(c.pivot.split("@").pop())}</button></div>` : ""}</div></div>`;
}
// Only what an investigator needs: the verdict, why, the key details, the
// data-request details and (collapsed) the route.
function emailFindings(r) {
  const mid = (r.message_id && r.message_id.checks) || [];
  const authAll = r.authentication || [];
  // Failed checks are findings on their own; amber ones (unverified, not
  // aligned) become a single line, since Key details already lists each one.
  const failed = authAll.filter(a => a.state === "bad").map(a => Object.assign({}, a, { title: `${a.name} failed` }));
  const soft = authAll.filter(a => a.state === "warn");
  const unverified = soft.some(a => /unverified/i.test(a.label));
  const merged = soft.length ? [{
    state: "warn", label: unverified ? "Unverified" : "Check",
    title: unverified ? "Sender checks were not written by your mail server" : "Sender checks need a second look",
    text: unverified
      ? `${soft.map(a => a.name).join(", ")} show a pass, but those results were recorded by ${r.auth_server || "another server"}, not your own mail server, so the sender could have written them.`
      : soft.map(a => `${a.name}: ${a.label.toLowerCase()}`).join("; ") + ". " + (soft[0].text || ""),
  }] : [];
  const order = { bad: 0, warn: 1 };
  return mid.concat(r.mismatches || [], failed, merged)
    .filter(c => c.state === "bad" || c.state === "warn")
    .sort((x, y) => order[x.state] - order[y.state]);
}
function renderEmail(r) {
  const f = r.fields || {};
  const found = emailFindings(r);
  const reds = found.filter(c => c.state === "bad").length, ambers = found.length - reds;
  const banner = `<div class="verdict-banner ${st(r.verdict_state)}">${stag(r.verdict, st(r.verdict_state))}<div class="vb-text"><div class="vb-head">${esc(r.headline)}</div><p>${reds ? `${reds} sign${reds === 1 ? "" : "s"} of spoofing` : "No signs of spoofing"}${ambers ? `, ${ambers} detail${ambers === 1 ? "" : "s"} to check` : ""}. ${r.full_message ? "Full .eml analysed." : "Headers only."}</p></div><div class="vb-actions"><button class="three-d" type="button" id="emailReportBtn">Open report</button><button class="three-d" type="button" id="emailDownloadBtn">Download report</button></div></div>`;
  const findings = `<div class="card"><div class="card-head"><h2>Findings</h2></div><div class="card-body">${found.length ? found.map(checkRow).join("") : `<div class="empty">${stag("None found", "none")} Nothing in these headers suggests spoofing.</div>`}</div></div>`;
  const same = (x, y) => x && y && x.address && x.address === y.address;
  const o = r.origin || {};
  const proof = ((r.message_id || {}).checks || []).find(c => c.id === "dkim" && c.state === "ok");
  const rows = [
    ["From", addrHtml(f.from)],
    f.reply_to && f.reply_to.address && !same(f.reply_to, f.from) ? ["Reply-To", addrHtml(f.reply_to)] : null,
    f.return_path && f.return_path.address && !same(f.return_path, f.from) ? ["Return-Path", addrHtml(f.return_path)] : null,
    ["Subject", f.subject ? esc(f.subject) : `<span class="v-none">None</span>`],
    ["Sent", f.date ? `${esc(f.date.ist)}<br><span class="muted small">${esc(f.date.utc)}</span>` : `<span class="v-none">${esc(f.date_raw || "Not stated")}</span>`],
    ["Sender checks", `<span class="auth-chips">${(r.authentication || []).map(x => `<span class="auth-chip" title="${esc(x.text)}"><b>${esc(x.name)}</b>${stag(x.label, st(x.state))}</span>`).join("")}</span>`],
    ["Originating IP", `${o.ip ? pivot(o.ip) : `<span class="v-none">Not available</span>`}<div class="muted small">${esc(o.text || "")}</div>`, true],
    ["Message-ID", `${f.message_id ? `<span class="mono small wrap-any">${esc(f.message_id)}</span>` : `<span class="v-none">None</span>`}${proof ? ` ${stag("Verified by DKIM", "ok", proof.text)}` : ""}`, true],
  ].filter(Boolean);
  const details = `<div class="card"><div class="card-head"><h2>Key details</h2></div><div class="card-body"><div class="grid">${rows.map(([k, v, wide]) => `<div class="kv${wide ? " wide" : ""}"><b>${esc(k)}</b><span>${v}</span></div>`).join("")}</div></div></div>`;
  const q = r.request || {};
  const reqText = `Provider: ${q.provider || "Unknown"}\nAccount: ${q.account || "Unknown"}\nMessage-ID: ${q.message_id || "None"}\nSent (UTC): ${q.sent?.utc || "Unknown"}\nSent (IST): ${q.sent?.ist || "Unknown"}`;
  const req = `<div class="card"><div class="card-head req-head"><div><h2>For your data request</h2><p class="muted small">The provider needs the Message-ID and the exact time to find this message in its logs.</p></div><button class="three-d" type="button" id="copyReqBtn">Copy details</button></div><div class="card-body"><div class="grid"><div class="kv"><b>Provider</b><span>${esc(q.provider || "Unknown")}</span></div><div class="kv"><b>Account</b><span class="mono">${esc(q.account || "Unknown")}</span></div><div class="kv"><b>Sent (UTC)</b><span class="mono">${esc(q.sent?.utc || "Unknown")}</span></div></div><div class="muted small" id="copyReqMsg"></div></div></div>`;
  const hops = r.hops || [];
  const hopRows = hops.map(h => {
    const tr = h.trust === "provider" && h.provider ? [`Added by ${h.provider}`, "muted"] : TRUST[h.trust] || ["—", "muted"];
    const from = h.from_raw ? `<div class="mono small">${esc(h.from_rdns || h.from_host || "")}</div>${(h.from_ips || []).map(ipHtml).join(" ")}` : `<span class="v-none">Not recorded</span>`;
    return `<tr class="${h.trust === "sender" ? "row-warn" : ""}"><td class="mono">${h.hop}</td><td>${from}</td><td class="mono small">${esc(h.by || "—")}</td><td class="nowrap-cell mono small">${esc(h.time ? h.time.ist.replace(" IST", "") : "—")}</td><td class="mono small">${h.delay_s == null ? "—" : esc(h.delay_s + " s")}</td><td>${stag(tr[0], tr[1])}</td></tr>`;
  }).join("");
  const route = hops.length ? `<details class="card route"><summary><h2>Route the email took</h2><span class="muted small">${hops.length} server${hops.length === 1 ? "" : "s"}, from the sender (hop 1) to the mailbox. Select to show.</span></summary><div class="card-body"><div class="tbl-scroll"><table class="table data"><thead><tr><th>Hop</th><th>From</th><th>Received by</th><th>Time (IST)</th><th>Delay</th><th>Can you trust it?</th></tr></thead><tbody>${hopRows}</tbody></table></div>${o.delivered_by ? `<p class="small route-note">Delivered to the recipient's server by ${pivot(o.delivered_by)}${o.delivered_by_host ? ` <span class="mono small">(${esc(o.delivered_by_host)})</span>` : ""}. That IP belongs to the last sending server, which may be a mail provider rather than the sender.</p>` : ""}</div></details>` : "";
  $("#emailResults").innerHTML = banner + findings + details + req + route;
  $("#emailReportBtn").onclick = () => openReport(emailReportHtml(r));
  $("#emailDownloadBtn").onclick = () => downloadText(`compass-email-${safeFilename((f.subject || "analysis").slice(0, 50))}.html`, emailReportHtml(r), "text/html");
  $("#copyReqBtn").onclick = async () => { try { await copyText(reqText); $("#copyReqMsg").textContent = "Copied, including the Message-ID."; } catch (_) { $("#copyReqMsg").textContent = "Could not copy; select the values instead."; } };
}

document.addEventListener("click", e => {
  const pb = e.target.closest("[data-pivot-btn]");
  if (pb) { e.preventDefault(); $("#iocInput").value = pb.dataset.ioc; window.scrollTo({ top: 0, behavior: "smooth" }); investigate({ ioc: pb.dataset.ioc }); }
});

// ============================================================ reports
function emailReportHtml(r, savedAt) {
  if (!r) return null;
  const f = r.fields || {}, q = r.request || {}, o = r.origin || {};
  const addr = a => a && a.address ? `${esc(a.name ? a.name + " " : "")}&lt;<span class="mono">${esc(a.address)}</span>&gt;` : "None";
  const same = (x, y) => x && y && x.address && x.address === y.address;
  const cls = s => ({ ok: "ok", warn: "warn", bad: "bad", none: "none" }[s] || "muted");
  const facts = [["From", addr(f.from)]];
  if (f.reply_to && f.reply_to.address && !same(f.reply_to, f.from)) facts.push(["Reply-To", addr(f.reply_to)]);
  if (f.return_path && f.return_path.address && !same(f.return_path, f.from)) facts.push(["Return-Path", addr(f.return_path)]);
  facts.push(["Subject", esc(f.subject || "None")], ["Sent", f.date ? `${esc(f.date.ist)}<br>${esc(f.date.utc)}` : esc(f.date_raw || "Unknown")],
    ["Message-ID", `<span class="mono">${esc(f.message_id || "None")}</span>`],
    ["Originating IP", `${o.ip ? `<span class="mono"><b>${esc(o.ip)}</b></span>. ` : "Not available. "}${esc(o.text || "")}`],
    ["Sender checks", (r.authentication || []).map(a => `${esc(a.name)}: <span class="${cls(a.state)}"><b>${esc(a.label)}</b></span>`).join("<br>")],
    ["Analysed from", `${r.source === "eml" ? ".eml file" + (r.file_name ? ": " + esc(r.file_name) : "") : "Pasted headers"} (${r.full_message ? "full message" : "headers only"})`]);
  const found = emailFindings(r);
  const hops = rtable(["Hop", "From", "Received by", "Time (IST)", "Delay", "Trust"], (r.hops || []).map(h => [esc(h.hop), `<span class="mono">${esc(h.from_rdns || h.from_host || "Not recorded")}</span> ${esc((h.from_ips || []).map(x => x.ip).join(", "))}`, `<span class="mono">${esc(h.by || "—")}</span>`, esc(h.time?.ist || "—"), esc(h.delay_s == null ? "—" : h.delay_s + " s"), esc(h.trust === "recipient" ? "Trusted: recipient's server" : h.trust === "provider" ? `Added by ${h.provider || "a mail provider"}` : "Sender side: can be forged")]), "No Received headers");
  const body = `<div class="box"><div class="meta">Assessment</div><div class="verdict ${cls(r.verdict_state)}">${esc(r.verdict)}</div><div class="summary">${esc(r.headline)}. Compass reports consistency, not proof that an email is genuine.</div></div>
    <h2>Findings</h2>${rtable(["Result", "Check", "Details"], found.map(c => [`<span class="${cls(c.state)}"><b>${esc(c.label)}</b></span>`, esc(c.title), esc(c.text)]), "None found: nothing in these headers suggests spoofing")}
    <h2>Key details</h2><div class="facts">${facts.map(([k, v]) => `<div class="fact"><b>${esc(k)}</b>${v}</div>`).join("")}</div>
    <h2>For a data request</h2><div class="facts"><div class="fact"><b>Provider</b>${esc(q.provider || "Unknown")}</div><div class="fact"><b>Account</b><span class="mono">${esc(q.account || "Unknown")}</span></div><div class="fact"><b>Message-ID</b><span class="mono">${esc(q.message_id || "None")}</span></div><div class="fact"><b>Sent</b>${esc(q.sent?.utc || "Unknown")}<br>${esc(q.sent?.ist || "")}</div></div>
    <h2>Route the email took</h2>${hops}
    <p class="meta">Received headers below the recipient's own servers can be forged by the sender. Corroborate with the provider's records before action.</p>`;
  return reportShell("Compass email header report", `${f.subject || "(no subject)"}, from ${(f.from || {}).address || "unknown sender"}`, body, savedAt || (Date.parse(r.analyzed_at) / 1000));
}
