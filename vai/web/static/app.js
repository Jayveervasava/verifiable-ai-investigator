"use strict";
/* Verifiable AI Investigator - plain JS UI (no build step, no external libraries). */

const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (h) => (h ? h.slice(0, 8) + "…" + h.slice(-4) : "");
const hhmm = (ts) => String(ts || "").slice(11, 16);
const SRC = { windows: "Windows", linux: "Linux", aws: "AWS" };
const COLOR = { windows: "#4aa3ff", linux: "#a78bfa", aws: "#f59e6b" };

const ui = { cid: null, data: null, timer: null, why: null, whyOpen: false, approveOpen: false,
             mode: "edit", step: 3, msg: "", msgCls: "", expanded: {}, busy: false };

async function api(path, opts = {}) {
  const r = await fetch("/api" + path, { credentials: "same-origin", ...opts });
  if (r.status === 401 && !path.startsWith("/login")) { showLogin(); throw new Error("Please sign in"); }
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : null;
  if (!r.ok) throw new Error((data && data.detail) || r.statusText);
  return data;
}
const post = (p, body) => api(p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

/* ---------- login ---------- */
function showLogin() { $("#login").hidden = false; $("#app").hidden = true; }
function showApp() { $("#login").hidden = true; $("#app").hidden = false; route(); }

$("#loginform").addEventListener("submit", async (e) => {
  e.preventDefault();
  try { await post("/login", { password: $("#pw").value }); $("#loginerr").textContent = ""; showApp(); }
  catch (err) { $("#loginerr").textContent = err.message; }
});
$("#logout").addEventListener("click", async (e) => { e.preventDefault(); await post("/logout"); showLogin(); });

/* ---------- router ---------- */
window.addEventListener("hashchange", route);
function stopPoll() { if (ui.timer) { clearInterval(ui.timer); ui.timer = null; } }

async function route() {
  stopPoll();
  const parts = (location.hash || "#/cases").replace(/^#\//, "").split("/");
  const page = parts[0] || "cases";
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.p === (page === "case" ? "cases" : page)));
  try {
    if (page === "case") await pageCase(decodeURIComponent(parts[1] || ""));
    else if (page === "evidence") await pageEvidence(parts[1]);
    else if (page === "ledger") await pageLedger(parts[1]);
    else await pageCases();
  } catch (err) { if (err.message !== "Please sign in") $("#page").innerHTML = `<div class="card bad">${esc(err.message)}</div>`; }
}

function badge(cls, text) { return `<span class="badge ${cls}">${esc(text)}</span>`; }
function statusBadges(status, approved, custody, approvedBy) {
  let h = "";
  if (status === "new") return badge("b-idle", "Not investigated yet");
  if (status === "running") h += badge("b-warn", "Investigation running");
  if (status === "error") h += badge("b-bad", "Run failed");
  if (custody) {
    const m = { ok: "b-ok", chain: "b-ok", broken: "b-bad", incomplete: "b-bad", unchecked: "b-idle" }[custody.state] || "b-idle";
    h += badge(m, custody.label);
  }
  h += approved ? badge("b-ok", "Approved by " + (approvedBy || "officer")) : badge("b-warn", "Awaiting officer approval");
  return h;
}

/* ---------- cases list ---------- */
async function pageCases() {
  const list = await api("/cases");
  $("#page").innerHTML = `<div class="top"><div><h1>Cases</h1><div class="sub">Demo cases use synthetic data only.</div></div></div>
  <div class="cases">${list.map((c) => `<div class="card"><h2><a href="#/case/${encodeURIComponent(c.id)}">${esc(c.title)}</a></h2>
    <div class="sub">Victim: ${esc(c.victim)} · Opened ${esc(c.opened || "")}</div>
    <div class="sub" style="margin:8px 0">${esc(c.note || "")}</div>
    <div>${statusBadges(c.status, c.approved, null, null).replace(/^<span/, '<span style="margin-left:0"')}</div>
    <div class="sub" style="margin-top:8px">${c.files} evidence file(s)${c.records ? " · " + c.records + " records · " + (c.techniques || []).length + " technique(s)" : ""}</div>
    <a class="btn primary" href="#/case/${encodeURIComponent(c.id)}" style="text-decoration:none">Open case</a></div>`).join("")}</div>`;
}

/* ---------- case page ---------- */
async function loadCase(cid) {
  ui.data = await api("/cases/" + encodeURIComponent(cid) + "?events=linked");
  return ui.data;
}

async function pageCase(cid) {
  if (ui.cid !== cid) Object.assign(ui, { cid, why: null, whyOpen: false, approveOpen: false, msg: "", expanded: {}, step: 3, mode: "edit" });
  await loadCase(cid);
  renderCase();
  if (ui.data.view.status === "running") startPoll();
}

function startPoll() {
  stopPoll();
  ui.timer = setInterval(async () => {
    try {
      await loadCase(ui.cid);
      renderCase();
      if (ui.data.view.status !== "running") stopPoll();
    } catch (e) { stopPoll(); }
  }, 600);
}

function techChips(d, tid) {
  const names = d.view.technique_names || {};
  let h = `<span class="chip">${esc(tid)} ${esc(names[tid] || "")}</span>`;
  const seen = new Set();
  (d.legal || []).filter((l) => l.technique_id === tid).forEach((l) => {
    const k = l.act + l.section; if (seen.has(k)) return; seen.add(k);
    h += `<span class="chip">${esc(l.act.replace(" 2000", ""))} s.${esc(l.section)}</span>`;
  });
  return h;
}

function timelineHtml(d) {
  if (!d.findings.length) return `<div class="mut">No timeline yet. Press “Run investigation”.</div>`;
  const byId = Object.fromEntries(d.events.map((e) => [e.id, e]));
  const rows = d.findings.map((f) => {
    const evs = f.event_ids.map((i) => byId[i]).filter(Boolean).sort((a, b) => a.ts_utc.localeCompare(b.ts_utc));
    return { f, evs };
  }).sort((a, b) => (a.evs[0]?.ts_utc || "").localeCompare(b.evs[0]?.ts_utc || ""));
  return `<div class="tl">${rows.map(({ f, evs }) => {
    const e0 = evs[0] || {};
    const open = ui.expanded[f.id];
    return `<div class="ev" style="--c:${COLOR[e0.source] || "#4aa3ff"}">
      <div class="t">${hhmm(e0.ts_utc)} · ${esc(SRC[e0.source] || "")} · ${esc(e0.host || "")} · ${f.event_ids.length} record(s) · confidence ${esc(f.confidence)}</div>
      <div class="x">${esc(f.title)}</div>${techChips(d, f.technique_id)}
      <button class="link" data-act="toggle-ev" data-f="${esc(f.id)}">${open ? "hide records" : "show records"}</button>
      ${open ? `<div class="evlist">${evs.map((e) => `<div>${esc(e.id)} · ${hhmm(e.ts_utc)} · ${esc(e.host)} · ${esc(e.user)} · ${esc(e.ip)} · ${esc(e.action)}</div>`).join("")}</div>` : ""}
    </div>`;
  }).join("")}</div>`;
}

function stepIcon(s) {
  return { verified: '<span class="ok">✔</span>', recorded: '<span style="color:#4aa3ff">●</span>', broken: '<span class="bad">✖</span>',
           missing: '<span class="warn">⚠</span>', pending: '<span class="mut">○</span>', after_break: '<span class="mut">–</span>' }[s] || "";
}
const stateText = { verified: "", recorded: "recorded, not verified yet", broken: "does not match the ledger", missing: "planned but no ledger record",
                    pending: "planned", after_break: "after the break, cannot be trusted" };

function stepsHtml(v) {
  const rows = v.plan.map((p) => `<div class="step ${p.state === "broken" ? "broken" : ""}"><span class="ic">${stepIcon(p.state)}</span>
    <div>${p.n}. ${esc(p.description)}<div class="mut" style="font-size:12px">${esc(stateText[p.state] || "")}</div>
    ${p.hash ? `<div class="hash">#${p.seq} ${esc(short(p.hash))}</div>` : ""}</div></div>`);
  v.entries.filter((e) => e.unplanned).forEach((e) => rows.push(`<div class="step unplanned"><span class="ic bad">✖</span>
    <div>Unplanned step in the ledger<div class="mut" style="font-size:12px">entry #${e.seq} was not in the agent's plan</div><div class="hash">#${e.seq} ${esc(short(e.hash))}</div></div></div>`));
  return rows.join("");
}

function chainText(v) {
  if (v.status === "running") return `<span class="warn">Running…</span>`;
  if (!v.verification) return `<span class="mut">Not verified yet</span>`;
  if (v.verification.ok) return `<span class="ok">Chain intact</span>`;
  const st = v.plan.find((p) => p.seq === v.verification.broken_at);
  return `<span class="bad">Chain broken at ${st ? "step " + st.n : "entry #" + v.verification.broken_at}</span>`;
}

function verifyMsg(v) {
  let h = "";
  const x = v.verification, c = v.completeness;
  if (x) {
    const st = v.plan.find((p) => p.seq === x.broken_at);
    h += x.ok ? `<div class="ok">Chain check: all ${x.checked} ledger entries match. Nothing was changed after it was saved. (${esc(x.on)})</div>`
      : `<div class="bad">Chain check failed: entry #${x.broken_at}${st ? " (step " + st.n + ")" : ""} does not match the ledger. Something was edited, removed or inserted after saving. (${esc(x.on)})</div>`;
  }
  if (c) {
    if (c.ok) h += `<div class="ok">Completeness check: every planned step has a ledger record and no unplanned step was found.</div>`;
    else if (c.missing_steps.length) h += `<div class="bad">Completeness check failed: planned step(s) ${c.missing_steps.join(", ")} have no ledger record. The agent log is incomplete.</div>`;
    else h += `<div class="bad">Completeness check failed: an unplanned or altered entry was found at #${c.broken_at}.</div>`;
  }
  return h || `<span class="mut">Not verified yet.</span>`;
}

function conclusionHtml(d) {
  const v = d.view;
  if (v.status === "new") return `<div class="mut">No investigation yet. Press “Run investigation” and watch the agent steps appear in the ledger.</div>`;
  if (!v.conclusion) return `<div class="mut">${v.status === "error" ? "The run failed: " + esc(v.error) : "The agent is working…"}</div>`;
  return `<div class="ai">${esc(v.conclusion.text)}<br><span class="mut">Evidence: ${v.stats.linked} linked records · every source file is hash-recorded in the ledger</span></div>`;
}

function whyHtml() {
  if (!ui.whyOpen) return "";
  if (!ui.why) return `<div class="panel mut">Loading…</div>`;
  return `<div class="panel"><div class="mut" style="margin-bottom:6px">Why the AI reached this conclusion</div>
    ${ui.why.map((w, i) => `<div>${i + 1}. ${esc(w.reason)} <span class="hash">→ records ${esc((w.record_ids || []).join(", "))}</span>
      <div class="lim">Limitation: ${esc(w.limitation)}</div></div>`).join("")}</div>`;
}

function approveHtml(d) {
  const v = d.view;
  if (!ui.approveOpen || d.approved) return "";
  return `<div class="panel"><div class="mut" style="margin-bottom:6px">Officer approval. The system re-checks the chain and completeness first.</div>
    <label>Officer name <input id="officer" type="text" value="${esc(d.officer)}"></label>
    <div style="margin-top:8px"><label><input id="agree" type="checkbox"> I have read the conclusion, the record IDs and the limitations.</label></div>
    <button class="btn primary" data-act="approve-go">Approve and generate report</button></div>`;
}

function renderCase() {
  const d = ui.data, v = d.view, s = v.stats, base = "/api/cases/" + encodeURIComponent(d.id);
  const done = v.status === "done", running = v.status === "running";
  const verifiedTxt = s.steps_verified == null ? `${s.steps_total} recorded` : `${s.steps_verified} / ${s.steps_total}`;
  const verCls = s.steps_verified == null ? "" : (s.steps_verified === s.steps_total ? "ok" : "bad");
  const stepOpts = v.plan.map((p) => `<option value="${p.n}" ${p.n === ui.step ? "selected" : ""}>step ${p.n}</option>`).join("");
  const legalRows = (v.legal || []).map((l) => `<div class="row" title="${esc(l.reason)}"><span>${esc(l.offence)}</span><span>${esc(l.act.replace(" 2000", ""))} s.${esc(l.section)}</span></div>`).join("")
    + (done ? `<div class="row"><span>Electronic evidence certificate</span><span>BSA 2023 s.63</span></div>` : "");
  $("#page").innerHTML = `
  <div class="top"><div><h1>${esc(d.title)}</h1><div class="sub">Victim: ${esc(d.victim)} · Opened ${esc(v.opened || "")} · Officer: ${esc(d.officer)} (demo name)</div></div>
    <div>${statusBadges(v.status, d.approved, done ? v.custody : null, v.approved_by)}</div></div>
  <div class="stats">
    <div class="card stat"><div class="n">${s.records ?? "—"}</div><div class="l">Log records (Windows · Linux · AWS)</div></div>
    <div class="card stat"><div class="n">${s.linked ?? "—"}</div><div class="l">Linked attack records</div></div>
    <div class="card stat"><div class="n">${s.techniques ?? "—"}</div><div class="l">MITRE ATT&amp;CK techniques</div></div>
    <div class="card stat"><div class="n ${verCls}">${verifiedTxt}</div><div class="l">AI steps verified in ledger</div></div></div>
  <div class="g"><div>
    <div class="card"><div class="ct"><span>Attack timeline (cross-platform)</span><span>UTC</span></div>${timelineHtml(d)}</div>
    <div class="card"><div class="ct"><span>AI agent conclusion</span><span>${v.conclusion ? "Confidence: " + esc(v.conclusion.confidence) : ""}</span></div>
      ${conclusionHtml(d)}
      <button class="btn primary" data-act="run" ${running ? "disabled" : ""}>${v.status === "new" ? "Run investigation" : "Run again (new ledger)"}</button>
      <button class="btn" data-act="approve-open" ${done && !d.approved ? "" : "disabled"}>Approve…</button>
      ${d.approved ? `<a class="btn good" href="${base}/report" target="_blank" style="text-decoration:none">Download report (PDF)</a>` : ""}
      <button class="btn" data-act="s63" ${done ? "" : "disabled"}>Section 63 certificate (draft)</button>
      <button class="btn" data-act="why" ${done ? "" : "disabled"}>Ask AI why</button>
      ${approveHtml(d)}${whyHtml()}</div>
    <div class="card"><div class="ct"><span>Verify for court</span><span>${v.custody ? esc(v.custody.label) : ""}</span></div>
      <div class="mut" style="line-height:1.5">Re-computes every hash in the custody ledger and checks that no evidence record or AI step was changed, removed or added after it was saved.</div>
      <div class="msg">${verifyMsg(v)}</div>
      <button class="btn good" data-act="verify" ${done ? "" : "disabled"}>Verify chain</button>
      <button class="btn good" data-act="complete" ${done ? "" : "disabled"}>Check completeness</button>
      <button class="btn" data-act="export" ${done && !v.tampered ? "" : "disabled"}>Export evidence package</button>
      <div class="tamper"><span>Simulate tampering (on a copy):</span>
        <select id="mode"><option value="edit" ${ui.mode === "edit" ? "selected" : ""}>edit a step</option><option value="delete" ${ui.mode === "delete" ? "selected" : ""}>delete a step</option><option value="insert" ${ui.mode === "insert" ? "selected" : ""}>insert a fake step after</option></select>
        <select id="step">${stepOpts}</select>
        <button class="btn danger" data-act="tamper" ${done && !v.tampered ? "" : "disabled"}>Simulate tampering</button>
        ${v.tampered ? `<button class="btn" data-act="restore">Restore original</button>` : ""}</div>
      <div class="mut" style="font-size:12px;margin-top:8px">Tip: delete or insert after the LAST step. “Verify chain” stays green, but “Check completeness” catches it.</div>
      <div class="msg ${ui.msgCls}">${esc(ui.msg)}</div>
      <div class="hash">Merkle root: ${esc(v.merkle_root || "-")}</div></div>
  </div><div>
    <div class="card"><div class="ct"><span>AI agent steps · custody ledger</span><span>${chainText(v)}</span></div>${stepsHtml(v)}
      <a href="#/ledger/${encodeURIComponent(d.id)}" style="font-size:12px">Open full custody ledger</a></div>
    <div class="card law"><div class="ct"><span>Legal mapping</span><span>Suggested · officer to confirm</span></div>${legalRows || '<div class="mut">Appears after the investigation runs.</div>'}</div>
  </div></div>`;
}

function setMsg(text, cls) { ui.msg = text; ui.msgCls = cls || ""; }
async function refresh() { await loadCase(ui.cid); renderCase(); }

async function act(name, el) {
  const base = "/cases/" + encodeURIComponent(ui.cid);
  try {
    if (name === "toggle-ev") { const f = el.dataset.f; ui.expanded[f] = !ui.expanded[f]; renderCase(); return; }
    if (name === "run") {
      const fresh = ui.data.view.status === "done";
      if (fresh && !confirm("Run again with a NEW ledger? The current ledger file is kept in the archive folder, not deleted.")) return;
      setMsg(""); ui.why = null; ui.whyOpen = false;
      await post(base + "/run?fresh=" + fresh);
      await refresh(); startPoll(); return;
    }
    if (name === "verify") { await post(base + "/verify"); setMsg(""); await refresh(); return; }
    if (name === "complete") { await post(base + "/completeness"); setMsg(""); await refresh(); return; }
    if (name === "tamper") {
      const r = await post(base + "/tamper-demo", { mode: ui.mode, step: ui.step });
      setMsg(r.note + " Now press “Verify chain” and “Check completeness”.", "warn"); await refresh(); return;
    }
    if (name === "restore") { await post(base + "/restore-demo"); setMsg("Original ledger restored.", "ok"); await refresh(); return; }
    if (name === "why") {
      ui.whyOpen = !ui.whyOpen; if (ui.whyOpen && !ui.why) { renderCase(); ui.why = await api(base + "/why"); } renderCase(); return;
    }
    if (name === "s63") { window.open("/api" + base + "/s63", "_blank"); return; }
    if (name === "export") { location.href = "/api" + base + "/export"; return; }
    if (name === "approve-open") { ui.approveOpen = !ui.approveOpen; renderCase(); return; }
    if (name === "approve-go") {
      if (!$("#agree").checked) { setMsg("Tick the box to confirm you reviewed the conclusion.", "warn"); renderCase(); return; }
      await post(base + "/approve", { officer: $("#officer").value });
      ui.approveOpen = false; setMsg("Approved. The approval is recorded in the ledger.", "ok"); await refresh(); return;
    }
  } catch (err) { setMsg(err.message, "bad"); renderCase(); }
}

document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (el && !el.disabled) act(el.dataset.act, el);
});
document.addEventListener("change", (e) => {
  if (e.target.id === "mode") ui.mode = e.target.value;
  if (e.target.id === "step") ui.step = parseInt(e.target.value, 10);
});

/* ---------- evidence intake ---------- */
async function pageEvidence(selected) {
  const list = await api("/cases");
  const cid = selected ? decodeURIComponent(selected) : list[0].id;
  const d = await api("/cases/" + encodeURIComponent(cid) + "?events=none");
  const files = d.view.files || [];
  $("#page").innerHTML = `<div class="top"><div><h1>Evidence intake</h1><div class="sub">Every file is hashed (SHA-256) and written to the custody ledger the moment it is uploaded. Use public or synthetic data only.</div></div></div>
  <div class="card"><label>Case <select id="evcase">${list.map((c) => `<option value="${esc(c.id)}" ${c.id === cid ? "selected" : ""}>${esc(c.title)}</option>`).join("")}</select></label>
    <div class="drop" style="margin-top:12px"><input id="evfile" type="file"> <button class="btn primary" id="evgo" style="margin:0 0 0 8px">Upload and hash</button>
    <div class="msg" id="evmsg"></div></div></div>
  <div class="card"><div class="ct"><span>Files for this case</span><span>${files.length}</span></div>
    <table><tr><th>File</th><th>Size</th><th>SHA-256</th><th>Records read</th><th>In ledger</th></tr>
    ${files.map((f) => `<tr><td>${esc(f.name)}<div class="mut" style="font-size:11px">${f.kind === "upload" ? "uploaded" : "demo file"}</div></td><td>${f.bytes}</td>
      <td class="hash">${esc(f.sha256)}</td><td>${f.parsed}</td><td>${f.ledgered ? "yes, entry #" + f.seq : "not yet (recorded when the investigation runs)"}</td></tr>`).join("")}</table></div>`;
  $("#evcase").addEventListener("change", (e) => { location.hash = "#/evidence/" + encodeURIComponent(e.target.value); });
  $("#evgo").addEventListener("click", async () => {
    const f = $("#evfile").files[0]; const m = $("#evmsg");
    if (!f) { m.textContent = "Choose a file first."; m.className = "msg warn"; return; }
    try {
      const r = await api("/cases/" + encodeURIComponent(cid) + "/evidence", { method: "POST", headers: { "X-Filename": f.name }, body: f });
      m.textContent = r.message; m.className = "msg ok"; await pageEvidence(encodeURIComponent(cid));
      $("#evmsg").textContent = r.message; $("#evmsg").className = "msg ok";
    } catch (err) { m.textContent = err.message; m.className = "msg bad"; }
  });
}

/* ---------- custody ledger ---------- */
async function pageLedger(selected) {
  const list = await api("/cases");
  const cid = selected ? decodeURIComponent(selected) : list[0].id;
  const L = await api("/cases/" + encodeURIComponent(cid) + "/ledger");
  const brokenAt = L.verification && !L.verification.ok ? L.verification.broken_at : null;
  $("#page").innerHTML = `<div class="top"><div><h1>Custody ledger</h1><div class="sub">Each row contains the hash of the row before it. Changing, removing or adding any row breaks the chain.</div></div></div>
  <div class="card"><label>Case <select id="lcase">${list.map((c) => `<option value="${esc(c.id)}" ${c.id === cid ? "selected" : ""}>${esc(c.title)}</option>`).join("")}</select></label>
    <div class="hash" style="margin-top:8px">Merkle root: ${esc(L.merkle_root || "-")}</div><div class="msg" id="lmsg"></div></div>
  <div class="card">${L.entries.length ? `<table><tr><th>#</th><th>Kind</th><th>Actor</th><th>Time (UTC)</th><th>Payload hash</th><th>Previous hash</th><th>Hash</th><th></th></tr>
    ${L.entries.map((e) => `<tr class="${brokenAt === e.seq ? "bad" : ""}"><td>${e.seq}</td><td>${esc(e.kind)}${e.step ? " (step " + e.step + ")" : ""}</td><td>${esc(e.actor)}</td><td>${esc(e.ts)}</td>
      <td class="hash">${esc(short(e.payload_hash))}</td><td class="hash">${esc(short(e.prev_hash))}</td><td class="hash">${esc(short(e.hash))}</td>
      <td><button class="link" data-proof="${e.seq}">proof</button></td></tr>`).join("")}</table>`
      : `<div class="mut">The ledger is empty. Run the investigation or upload evidence first.</div>`}</div>`;
  $("#lcase").addEventListener("change", (e) => { location.hash = "#/ledger/" + encodeURIComponent(e.target.value); });
  document.querySelectorAll("[data-proof]").forEach((b) => b.addEventListener("click", async () => {
    try {
      const r = await api("/cases/" + encodeURIComponent(cid) + "/proof/" + b.dataset.proof);
      $("#lmsg").className = r.valid ? "msg ok" : "msg bad";
      $("#lmsg").textContent = `Entry #${r.proof.seq}: Merkle proof with ${r.proof.path.length} step(s) is ${r.valid ? "valid" : "NOT valid"} for the root above.`;
    } catch (err) { $("#lmsg").className = "msg bad"; $("#lmsg").textContent = err.message; }
  }));
}

/* ---------- start ---------- */
(async () => {
  try { const me = await api("/me"); if (me.authenticated) showApp(); else showLogin(); }
  catch (e) { showLogin(); }
})();
