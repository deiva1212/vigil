/* Vigil console — dependency-free single-page app. */
(() => {
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const LEVELS = ["informational", "low", "medium", "high", "critical"];
const RANK = Object.fromEntries(LEVELS.map((l, i) => [l, i]));

const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtNum = n => Number(n || 0).toLocaleString();
const ago = t => {
  if (!t) return "never";
  const s = (Date.now() - new Date(t)) / 1000;
  if (s < 0 || new Date(t).getFullYear() < 2000) return "never";
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
};
const fmtTime = t => {
  const d = new Date(t);
  return isNaN(d) ? "" : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
};
const sev = l => `<span class="sev c-${esc(l)}">${esc(l)}</span>`;
const scoreCls = n => n >= 80 ? "good" : n >= 50 ? "mid" : "bad";

// ------------------------------------------------------------- session
const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch {} },
};
let token = store.get("vigil.token");
let me = null;

async function api(method, path, body, raw) {
  const opts = { method, headers: { Authorization: "Bearer " + token } };
  if (body !== undefined) {
    if (typeof body === "string") { opts.body = body; opts.headers["Content-Type"] = "text/plain"; }
    else { opts.body = JSON.stringify(body); opts.headers["Content-Type"] = "application/json"; }
  }
  const r = await fetch(path, opts);
  if (r.status === 401) { showLogin(); throw new Error("Your session has ended. Sign in again."); }
  if (raw) return r;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
const can = role => me && ({ viewer: 1, analyst: 2, admin: 3 })[me.role] >= ({ viewer: 1, analyst: 2, admin: 3 })[role];

function showLogin() {
  token = null; store.set("vigil.token", null);
  closeStream();
  $("#app").hidden = true; $("#login").hidden = false;
  $("#login-form [name=username]").focus();
}

$("#login-form").addEventListener("submit", async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  $("#login-error").textContent = "";
  try {
    const r = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: f.get("username"), password: f.get("password") }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    token = d.token; store.set("vigil.token", token);
    e.target.reset();
    boot();
  } catch (err) { $("#login-error").textContent = err.message; }
});

// ------------------------------------------------------------- UI helpers
function toast(html, level, onclick) {
  const t = document.createElement("div");
  t.className = "toast" + (level ? " c-" + level : "");
  t.innerHTML = html;
  if (onclick) t.addEventListener("click", onclick);
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 6000);
}
const ok = msg => toast(esc(msg));
const fail = err => toast("<b>Couldn't complete that.</b><small>" + esc(err.message || err) + "</small>", "critical");

function openDrawer(title, html) {
  $("#drawer-title").textContent = title;
  $("#drawer-body").innerHTML = html;
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#drawer-body").scrollTop = 0;
}
function closeDrawer() { $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); }
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

const kv = obj => {
  const keys = Object.keys(obj || {}).filter(k => !k.startsWith("_")).sort();
  if (!keys.length) return `<p class="muted">No fields.</p>`;
  return `<dl class="kv">${keys.map(k => `<dt>${esc(k)}</dt><dd>${k === "file.diff" ? `<pre class="raw">${esc(obj[k])}</pre>` : esc(obj[k])}</dd>`).join("")}</dl>`;
};
const table = (cols, rows, rowAttrs) => rows.length ? `<div class="tablewrap"><table><thead><tr>${cols.map(c => `<th class="${c.cls || ""}">${esc(c.h)}</th>`).join("")}</tr></thead><tbody>${
  rows.map((r, i) => `<tr ${rowAttrs ? rowAttrs(r, i) : ""}>${cols.map(c => `<td class="${c.cls || ""}">${c.f(r)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>` : `<p class="empty">Nothing here yet.</p>`;

function blist(items, labelFn, colorFn) {
  if (!items || !items.length) return `<p class="empty">No data in this period.</p>`;
  const max = Math.max(...items.map(i => i.value), 1);
  return `<ul class="blist">${items.map(i => `<li><span class="lbl" title="${esc(labelFn(i))}">${esc(labelFn(i))}</span><span>${fmtNum(i.value)}</span><span class="track"><i style="width:${(i.value / max * 100).toFixed(1)}%;${colorFn ? "--c:" + colorFn(i) : ""}"></i></span></li>`).join("")}</ul>`;
}

// ------------------------------------------------------------- live stream
let es = null, refreshTimer = null;
function closeStream() { if (es) { es.close(); es = null; } }
function openStream() {
  closeStream();
  es = new EventSource("/api/stream?token=" + encodeURIComponent(token));
  es.onopen = () => { $("#live").classList.add("on"); $("#live-text").textContent = "Live"; };
  es.onerror = () => { $("#live").classList.remove("on"); $("#live-text").textContent = "Reconnecting"; };
  es.onmessage = m => {
    let msg; try { msg = JSON.parse(m.data); } catch { return; }
    if (msg.type === "alert") {
      const a = msg.data;
      if (RANK[a.level] >= RANK.medium) toast(`<b>${esc(a.rule_title)}</b><small>${esc(a.hostname)} — ${esc(a.description).slice(0, 140)}</small>`, a.level, () => { location.hash = "#/alerts"; showAlert(a.id); });
    }
    if (["alert", "command", "agent"].includes(msg.type)) {
      clearTimeout(refreshTimer);
      refreshTimer = setTimeout(() => { if (["overview", "alerts", "agents", "response"].includes(currentPage) && !$("#drawer").classList.contains("open")) render(); updateOpenCount(); }, 1500);
    }
  };
}
async function updateOpenCount() {
  try {
    const d = await api("GET", "/api/alerts?status=open&min_level=high&limit=1000");
    $("#nav-open").textContent = d.length || "";
  } catch {}
}

// ------------------------------------------------------------- router
const pages = {};
let currentPage = "overview";
async function render() {
  const [name, ...rest] = location.hash.replace(/^#\//, "").split("/");
  currentPage = pages[name] ? name : "overview";
  $$(".side a").forEach(a => a.classList.toggle("active", a.dataset.nav === currentPage));
  $(".side").classList.remove("open");
  const page = pages[currentPage];
  $("#page-title").textContent = page.title;
  document.title = page.title + " — Vigil";
  try { await page.render($("#view"), rest.map(decodeURIComponent)); }
  catch (e) { $("#view").innerHTML = `<p class="error">${esc(e.message)}</p>`; }
}
window.addEventListener("hashchange", () => { closeDrawer(); render(); });

// global click delegation (CSP forbids inline handlers)
const actions = {};
document.addEventListener("click", e => {
  const el = e.target.closest("[data-action]");
  if (!el) return;
  const fn = actions[el.dataset.action];
  if (fn) { e.preventDefault(); fn(el, e); }
});
actions["close-drawer"] = closeDrawer;
actions.menu = () => $(".side").classList.toggle("open");
actions.logout = async () => { try { await api("POST", "/api/logout"); } catch {} showLogin(); };

// ============================================================ overview
pages.overview = {
  title: "Overview",
  async render(v) {
    const [{ stats: s, rules, cves }, open] = await Promise.all([
      api("GET", "/api/stats"),
      api("GET", "/api/alerts?status=open&min_level=medium&limit=8"),
    ]);
    const crit = s.by_level.critical || 0, high = s.by_level.high || 0;
    const agentsActive = s.agents.active || 0, agentsTotal = s.agents.total || 0;
    const sentence = `<b>${fmtNum(s.open_alerts)}</b> open alerts in the last 24 hours` +
      (crit || high ? `, including <span class="sevtxt c-critical">${crit} critical</span> and <span class="sevtxt c-high">${high} high</span>` : `, none of them high or critical`) +
      `. <b>${agentsActive}</b> of ${agentsTotal} agents are reporting, at ${s.eps.toFixed(1)} events per second.`;

    // pressure strip: alerts per hour stacked by severity is approximated by
    // total per hour coloured by the hour's share; we fetch per-level series.
    const perHour = await hourlyBySeverity();
    const maxH = Math.max(1, ...perHour.map(h => LEVELS.reduce((a, l) => a + (h[l] || 0), 0)));
    const now = new Date();
    const strip = perHour.map((h, i) => {
      const tot = LEVELS.reduce((a, l) => a + (h[l] || 0), 0);
      const hr = new Date(now - (23 - i) * 3600e3).getHours();
      return `<div class="col ${tot ? "" : "zero"}" title="${hr}:00 — ${tot} alerts">${LEVELS.map(l => h[l] ? `<span class="c-${l}" style="height:${(h[l] / maxH * 100).toFixed(2)}%"></span>` : "").join("")}</div>`;
    }).join("");
    const axis = perHour.map((_, i) => { const h = new Date(now - (23 - i) * 3600e3).getHours(); return `<span>${i % 3 === 2 ? String(h).padStart(2, "0") + ":00" : ""}</span>`; }).join("");
    const evMax = Math.max(1, ...s.event_timeline);
    const pts = s.event_timeline.map((c, i) => `${(i / 23 * 100).toFixed(2)},${(40 - c / evMax * 36).toFixed(2)}`);
    const spark = `<svg class="spark" viewBox="0 0 100 42" preserveAspectRatio="none" aria-label="Events per hour"><path class="area" d="M0,42 L${pts.join(" L")} L100,42 Z"/><path d="M${pts.join(" L")}"/></svg>`;

    const vulnTotal = s.vulns.total || 0;
    v.innerHTML = `
      <p class="status-line">${sentence}</p>
      <div class="grid">
        <section class="panel span-8">
          <h2>Alert pressure, last 24 hours <small>${fmtNum(s.alerts)} alerts, ${fmtNum(s.events_last_hour)} events in the last hour</small></h2>
          <div class="strip">${strip}</div>
          <div class="strip-axis">${axis}</div>
          ${spark}
          <div class="legend">${LEVELS.slice(1).map(sev).join("")}<span class="hint">Line: events ingested per hour</span></div>
        </section>
        <section class="panel span-4">
          <h2>Needs attention <a href="#/alerts">All alerts</a></h2>
          ${open.length ? table([
            { h: "Alert", f: a => `<b>${esc(a.rule_title)}</b><span class="muted">${esc(a.hostname)} ${a.count > 1 ? "×" + a.count : ""}</span>`, cls: "desc" },
            { h: "When", f: a => ago(a.last_seen), cls: "nowrap muted" },
          ], open, a => `class="click rail c-${esc(a.level)}" data-action="alert" data-id="${esc(a.id)}"`) : `<p class="empty">No open medium-or-higher alerts. Quiet shift.</p>`}
        </section>
        <section class="panel span-4"><h2>Top detections</h2>${blist(s.top_rules, i => i.label || i.key)}</section>
        <section class="panel span-4"><h2>Most alerted hosts</h2>${blist(s.top_agents, i => i.key)}</section>
        <section class="panel span-4"><h2>ATT&amp;CK tactics seen <a href="#/mitre">Map</a></h2>${blist(s.tactics, i => i.key.replace(/-/g, " "), () => "var(--sev-high)")}</section>
        <section class="panel span-4"><h2>Event sources <small>recent sample</small></h2>${blist(s.top_sources, i => i.key)}</section>
        <section class="panel span-4"><h2>Exposure</h2>
          <dl class="kv">
            <dt>Vulnerabilities</dt><dd><a href="#/vulns">${fmtNum(vulnTotal)} findings</a>${vulnTotal ? ` — ${LEVELS.slice(1).reverse().filter(l => s.vulns[l]).map(l => `<span class="sevtxt c-${l}">${s.vulns[l]} ${l}</span>`).join(", ")}` : ""}</dd>
            <dt>Configuration score</dt><dd><a href="#/compliance"><span class="score ${scoreCls(s.avg_sca)}">${s.avg_sca}%</span> average across agents</a></dd>
            <dt>Agents</dt><dd><a href="#/agents">${agentsActive} active</a>${s.agents.disconnected ? `, <span class="st-disconnected">${s.agents.disconnected} disconnected</span>` : ""}</dd>
            <dt>Detection content</dt><dd><a href="#/rules">${rules} rules</a>, ${fmtNum(cves)} CVE feed entries</dd>
            <dt>Events stored</dt><dd>${fmtNum(s.total_events)}</dd>
          </dl>
        </section>
        <section class="panel span-4"><h2>Alerts by severity <small>24h</small></h2>${blist(LEVELS.slice().reverse().map(l => ({ key: l, value: s.by_level[l] || 0 })).filter(i => i.value), i => i.key, i => `var(--sev-${i.key})`)}</section>
      </div>`;
  },
};

async function hourlyBySeverity() {
  const alerts = await api("GET", "/api/alerts?hours=24&limit=5000");
  const out = Array.from({ length: 24 }, () => ({}));
  const now = Date.now();
  for (const a of alerts) {
    const age = Math.floor((now - new Date(a.timestamp)) / 3600e3);
    if (age >= 0 && age < 24) out[23 - age][a.level] = (out[23 - age][a.level] || 0) + Math.max(1, a.count);
  }
  return out;
}

// ============================================================ alerts
const alertFilters = { q: "", min_level: "", status: "open", kind: "", hours: "" };
pages.alerts = {
  title: "Alerts",
  async render(v) {
    const qs = new URLSearchParams(Object.entries(alertFilters).filter(([, x]) => x)).toString();
    const alerts = await api("GET", "/api/alerts?limit=500&" + qs);
    const sel = (name, opts) => `<label>${esc(name[1])}<select data-filter="${name[0]}">${opts.map(([val, lbl]) => `<option value="${esc(val)}" ${alertFilters[name[0]] === val ? "selected" : ""}>${esc(lbl)}</option>`).join("")}</select></label>`;
    v.innerHTML = `
      <form class="bar" id="alert-filter">
        <label class="grow">Search<input class="grow" name="q" value="${esc(alertFilters.q)}" placeholder="Rule, host, IP, user, technique…"></label>
        ${sel(["min_level", "Severity"], [["", "Any"], ["low", "Low and above"], ["medium", "Medium and above"], ["high", "High and above"], ["critical", "Critical"]])}
        ${sel(["status", "Status"], [["", "Any"], ["open", "Open"], ["acknowledged", "Acknowledged"], ["closed", "Closed"]])}
        ${sel(["kind", "Source"], [["", "Any"], ["sigma", "Sigma rule"], ["correlation", "Correlation"], ["vulnerability", "Vulnerability"], ["sca", "Configuration"], ["system", "Agent health"]])}
        ${sel(["hours", "Period"], [["", "All time"], ["1", "Last hour"], ["24", "Last 24 hours"], ["168", "Last 7 days"]])}
        <button class="btn" type="submit">Apply</button>
        <button class="btn" type="button" data-action="export-csv">Export CSV</button>
      </form>
      ${can("analyst") ? `<div class="bar" id="bulk" hidden><span class="muted" id="bulk-n"></span><button class="btn small" data-action="bulk" data-status="acknowledged">Acknowledge</button><button class="btn small" data-action="bulk" data-status="closed">Close</button></div>` : ""}
      <p class="hint">${alerts.length} alert${alerts.length === 1 ? "" : "s"}${alerts.length === 500 ? " (showing the newest 500)" : ""}. Repeats of the same detection within a minute are folded into one alert.</p>
      ${table([
        ...(can("analyst") ? [{ h: "", f: a => `<input type="checkbox" class="pick" value="${esc(a.id)}" aria-label="Select alert">` }] : []),
        { h: "Severity", f: a => sev(a.level), cls: "nowrap" },
        { h: "Alert", f: a => `<b>${esc(a.rule_title)}</b>${esc(a.description)}`, cls: "desc" },
        { h: "Host", f: a => esc(a.hostname), cls: "nowrap" },
        { h: "ATT&CK", f: a => (a.mitre || []).map(t => `<span class="tag">${esc(t)}</span>`).join("") },
        { h: "Count", f: a => fmtNum(a.count), cls: "right" },
        { h: "Status", f: a => `<span class="status-${esc(a.status)}">${esc(a.status)}</span>`, cls: "nowrap" },
        { h: "Last seen", f: a => `<span title="${esc(fmtTime(a.last_seen))}">${ago(a.last_seen)}</span>`, cls: "nowrap muted" },
      ], alerts, a => `class="click rail c-${esc(a.level)}" data-action="alert" data-id="${esc(a.id)}"`)}`;
    $("#alert-filter").addEventListener("submit", e => {
      e.preventDefault();
      alertFilters.q = e.target.q.value.trim();
      $$("[data-filter]", e.target).forEach(s => alertFilters[s.dataset.filter] = s.value);
      render();
    });
    $$("[data-filter]", v).forEach(s => s.addEventListener("change", () => { alertFilters[s.dataset.filter] = s.value; render(); }));
    $$(".pick", v).forEach(c => {
      c.addEventListener("click", e => e.stopPropagation());
      c.addEventListener("change", () => {
        const n = $$(".pick:checked").length;
        $("#bulk").hidden = !n; $("#bulk-n").textContent = n + " selected";
      });
    });
  },
};
actions.alert = el => showAlert(el.dataset.id);
actions.bulk = async el => {
  const ids = $$(".pick:checked").map(c => c.value);
  try { const r = await api("POST", "/api/alerts/bulk", { ids, status: el.dataset.status }); ok(`${r.updated} alerts marked ${el.dataset.status}.`); render(); updateOpenCount(); }
  catch (e) { fail(e); }
};
actions["export-csv"] = async () => {
  try {
    const qs = new URLSearchParams(Object.entries(alertFilters).filter(([, x]) => x)).toString();
    const r = await api("GET", "/api/export/alerts.csv?" + qs, undefined, true);
    const url = URL.createObjectURL(await r.blob());
    const a = Object.assign(document.createElement("a"), { href: url, download: "vigil-alerts.csv" });
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  } catch (e) { fail(e); }
};

async function showAlert(id) {
  let d;
  try { d = await api("GET", "/api/alerts/" + encodeURIComponent(id)); } catch (e) { return fail(e); }
  const a = d.alert, f = a.fields || {};
  const realAgent = a.agent_id && !a.agent_id.startsWith("syslog:");
  const quick = [];
  if (can("analyst") && realAgent) {
    if (f["source.ip"]) quick.push(`<button class="btn small" data-action="respond" data-agent="${esc(a.agent_id)}" data-act="block_ip" data-k="ip" data-v="${esc(f["source.ip"])}">Block ${esc(f["source.ip"])}</button>`);
    if (f["process.pid"] && a.kind === "sigma") quick.push(`<button class="btn small" data-action="respond" data-agent="${esc(a.agent_id)}" data-act="kill_process" data-k="pid" data-v="${esc(f["process.pid"])}">Kill process ${esc(f["process.pid"])}</button>`);
    if (f["file.path"] && f["event.action"] !== "deleted") quick.push(`<button class="btn small" data-action="respond" data-agent="${esc(a.agent_id)}" data-act="quarantine_file" data-k="path" data-v="${esc(f["file.path"])}">Quarantine file</button>`);
  }
  const status = can("analyst") ? `<div class="actions">
      ${a.status !== "acknowledged" ? `<button class="btn small" data-action="alert-status" data-id="${esc(a.id)}" data-status="acknowledged">Acknowledge</button>` : ""}
      ${a.status !== "closed" ? `<button class="btn small" data-action="alert-status" data-id="${esc(a.id)}" data-status="closed">Close</button>` : ""}
      ${a.status !== "open" ? `<button class="btn small" data-action="alert-status" data-id="${esc(a.id)}" data-status="open">Reopen</button>` : ""}
    </div>` : "";
  openDrawer(a.rule_title, `
    <section>
      <p>${sev(a.level)} <span class="status-${esc(a.status)}">${esc(a.status)}</span> <span class="muted">score ${a.score}, seen ${fmtNum(a.count)} time${a.count === 1 ? "" : "s"}</span></p>
      <p>${esc(a.description)}</p>
      <dl class="kv">
        <dt>Host</dt><dd>${realAgent ? `<a href="#/agents/${esc(a.agent_id)}">${esc(a.hostname)}</a>` : esc(a.hostname)}</dd>
        <dt>First seen</dt><dd>${esc(fmtTime(a.timestamp))}</dd>
        <dt>Last seen</dt><dd>${esc(fmtTime(a.last_seen))}</dd>
        <dt>Rule</dt><dd>${esc(a.rule_id)} (${esc(a.kind)})</dd>
        <dt>ATT&amp;CK</dt><dd>${(a.mitre || []).map(t => `<a class="tag" href="https://attack.mitre.org/techniques/${esc(t.replace(".", "/"))}/" target="_blank" rel="noopener noreferrer">${esc(t)}</a>`).join("") || "—"}</dd>
        <dt>Compliance</dt><dd>${(a.compliance || []).map(c => `<span class="tag">${esc(c)}</span>`).join("") || "—"}</dd>
      </dl>
    </section>
    ${status ? `<section><h3>Triage</h3>${status}
      <form id="note-form" class="bar" style="margin-top:10px"><input class="grow" name="note" placeholder="Add an investigation note"><button class="btn small">Add note</button></form>
      ${a.note ? `<pre class="raw">${esc(a.note)}</pre>` : ""}</section>` : (a.note ? `<section><h3>Notes</h3><pre class="raw">${esc(a.note)}</pre></section>` : "")}
    ${quick.length ? `<section><h3>Respond</h3><div class="actions">${quick.join("")}</div></section>` : ""}
    ${d.commands && d.commands.length ? `<section><h3>Automatic response</h3>${table([
      { h: "Action", f: c => esc(c.action) }, { h: "Status", f: c => esc(c.status) }, { h: "Result", f: c => esc(c.result), cls: "desc" }], d.commands)}</section>` : ""}
    <section><h3>Fields</h3>${kv(f)}</section>
    <section><h3>Matching events <small class="muted">${d.events.length} of ${(a.event_ids || []).length}</small></h3>
      ${d.events.length ? d.events.map(e => `<pre class="raw">${esc(fmtTime(e.timestamp))}  ${esc(e.raw || JSON.stringify(e.fields))}</pre>`).join("") : `<p class="muted">The source events have aged out of memory. Search the archive under Event search.</p>`}
    </section>`);
  const nf = $("#note-form");
  if (nf) nf.addEventListener("submit", async e => {
    e.preventDefault();
    if (!e.target.note.value.trim()) return;
    try { await api("PATCH", "/api/alerts/" + encodeURIComponent(a.id), { note: e.target.note.value }); ok("Note added."); showAlert(a.id); } catch (err) { fail(err); }
  });
}
actions["alert-status"] = async el => {
  try {
    await api("PATCH", "/api/alerts/" + encodeURIComponent(el.dataset.id), { status: el.dataset.status });
    ok("Alert marked " + el.dataset.status + ".");
    showAlert(el.dataset.id); updateOpenCount();
    if (currentPage === "alerts" || currentPage === "overview") render();
  } catch (e) { fail(e); }
};
actions.respond = async el => {
  const label = el.textContent.trim();
  if (!confirm(`${label} on this agent?`)) return;
  const args = { [el.dataset.k]: el.dataset.v };
  if (el.dataset.act === "block_ip") args.timeout = "1h";
  try { await api("POST", "/api/commands", { agent_id: el.dataset.agent, action: el.dataset.act, args }); ok("Queued: " + label + ". The agent picks it up on its next heartbeat."); }
  catch (e) { fail(e); }
};

// ============================================================ events
const evState = { q: "", category: "", hours: "24" };
pages.events = {
  title: "Event search",
  async render(v) {
    v.innerHTML = `
      <form class="bar" id="ev-form">
        <label class="grow">Query<input class="grow mono" name="q" value="${esc(evState.q)}" placeholder='source.ip:203.0.113.* -user.name:root "failed password"' autocomplete="off"></label>
        <label>Category<select name="category">${["", "log", "fim", "process", "network", "response", "agent"].map(c => `<option value="${c}" ${evState.category === c ? "selected" : ""}>${c || "Any"}</option>`).join("")}</select></label>
        <label>Period<select name="hours">${[["1", "Last hour"], ["24", "Last 24 hours"], ["168", "Last 7 days"], ["720", "Last 30 days"]].map(([h, l]) => `<option value="${h}" ${evState.hours === h ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <button class="btn primary">Search</button>
      </form>
      <p class="hint">Words match anywhere. <code>field:value</code> matches a field (wildcards with <code>*</code>), <code>-term</code> excludes, <code>field&gt;=400</code> compares numbers, <code>agent:</code> and <code>category:</code> filter the source.</p>
      <div id="ev-results"><p class="empty">Searching…</p></div>`;
    $("#ev-form").addEventListener("submit", e => {
      e.preventDefault();
      evState.q = e.target.q.value.trim(); evState.category = e.target.category.value; evState.hours = e.target.hours.value;
      runSearch();
    });
    runSearch();
  },
};
let lastEvents = [];
async function runSearch() {
  const box = $("#ev-results");
  try {
    const d = await api("GET", "/api/events?limit=300&" + new URLSearchParams(evState));
    lastEvents = d.events || [];
    box.innerHTML = `<p class="hint">${lastEvents.length} events in ${d.took_ms} ms (${esc(d.source)}).</p>` + table([
      { h: "Time", f: e => esc(fmtTime(e.timestamp)), cls: "nowrap muted" },
      { h: "Host", f: e => esc(e.hostname), cls: "nowrap" },
      { h: "Category", f: e => `<span class="tag">${esc(e.category)}${e.fields["log.service"] ? ":" + esc(e.fields["log.service"]) : ""}</span>`, cls: "nowrap" },
      { h: "Event", f: e => `<span class="mono">${esc((e.raw || "").slice(0, 260))}</span>`, cls: "desc" },
    ], lastEvents, (e, i) => `class="click" data-action="event" data-i="${i}"`);
  } catch (e) { box.innerHTML = `<p class="error">${esc(e.message)}</p>`; }
}
actions.event = el => {
  const e = lastEvents[+el.dataset.i];
  openDrawer("Event", `<section><dl class="kv"><dt>Time</dt><dd>${esc(fmtTime(e.timestamp))}</dd><dt>Host</dt><dd>${esc(e.hostname)}</dd><dt>Category</dt><dd>${esc(e.category)}</dd><dt>Source</dt><dd>${esc(e.source)}</dd><dt>ID</dt><dd class="mono">${esc(e.id)}</dd></dl></section>
    <section><h3>Raw</h3><pre class="raw">${esc(e.raw)}</pre></section><section><h3>Decoded fields</h3>${kv(e.fields)}</section>`);
};

// ============================================================ agents
pages.agents = {
  title: "Agents",
  async render(v, [id]) {
    if (id) return renderAgent(v, id);
    const agents = await api("GET", "/api/agents");
    v.innerHTML = `
      <div class="bar"><span class="grow hint">${agents.length} endpoints and agentless devices. Add an endpoint from <a href="#/settings">Settings</a>.</span></div>
      ${table([
        { h: "Status", f: a => `<span class="dotst st-${esc(a.status)}">${esc(a.status)}</span>`, cls: "nowrap" },
        { h: "Name", f: a => `<b>${esc(a.name)}</b>` },
        { h: "OS", f: a => esc(a.os) },
        { h: "IP", f: a => esc(a.ip), cls: "nowrap" },
        { h: "Group", f: a => `<span class="tag">${esc(a.group)}</span>` },
        { h: "Version", f: a => esc(a.version) },
        { h: "Events", f: a => fmtNum(a.event_count), cls: "right" },
        { h: "Config score", f: a => a.sca_score || a.os === "syslog device" ? (a.os === "syslog device" ? "—" : `<span class="score ${scoreCls(a.sca_score)}">${a.sca_score}%</span>`) : "—", cls: "right" },
        { h: "Vulns", f: a => a.vuln_count ? `<span class="sevtxt c-high">${a.vuln_count}</span>` : "0", cls: "right" },
        { h: "Last seen", f: a => ago(a.last_seen), cls: "nowrap muted" },
      ], agents, a => `class="click" data-action="goto" data-href="#/agents/${esc(a.id)}"`)}`;
  },
};
actions.goto = el => { location.hash = el.dataset.href; };

let agentTab = "overview";
async function renderAgent(v, id) {
  const d = await api("GET", "/api/agents/" + encodeURIComponent(id));
  const a = d.agent, inv = d.inventory || {}, sca = d.sca, vulns = d.vulnerabilities || [];
  const real = !a.id.startsWith("syslog:");
  const tabs = [["overview", "Overview"], ["alerts", `Alerts (${d.alerts.length})`], ["vulns", `Vulnerabilities (${vulns.length})`], ["sca", "Configuration"],
    ["packages", `Packages (${(inv.packages || []).length})`], ["processes", `Processes (${(inv.processes || []).length})`], ["ports", `Ports (${(inv.ports || []).length})`]];
  const h = a.health || {};
  let body = "";
  switch (agentTab) {
    case "overview": body = `<div class="grid"><section class="panel span-6"><h2>Endpoint</h2><dl class="kv">
        <dt>Status</dt><dd><span class="dotst st-${esc(a.status)}">${esc(a.status)}</span>, last seen ${ago(a.last_seen)}</dd>
        <dt>Agent ID</dt><dd class="mono">${esc(a.id)}</dd><dt>Hostname</dt><dd>${esc(a.hostname)}</dd>
        <dt>OS</dt><dd>${esc(inv.os_release || a.os)} ${esc(a.arch)}</dd><dt>Kernel</dt><dd>${esc(inv.kernel || "—")}</dd>
        <dt>IP</dt><dd>${esc(a.ip)}${h.ip ? ` (local ${esc(h.ip)})` : ""}</dd><dt>Group</dt><dd>${esc(a.group)}</dd>
        <dt>Enrolled</dt><dd>${esc(fmtTime(a.enrolled_at))}</dd><dt>Agent version</dt><dd>${esc(a.version)}</dd>
        <dt>Interactive users</dt><dd>${(inv.users || []).map(esc).join("<br>") || "—"}</dd></dl></section>
      <section class="panel span-6"><h2>Agent health</h2><dl class="kv">
        <dt>Events sent</dt><dd>${fmtNum(h.sent)}</dd><dt>Queue</dt><dd>${fmtNum(h.queue_len)}</dd>
        <dt>Spooled offline</dt><dd>${fmtNum(h.spooled)}</dd><dt>Dropped</dt><dd>${fmtNum(h.dropped)}</dd>
        <dt>Uptime</dt><dd>${h.uptime_sec ? Math.round(h.uptime_sec / 60) + " min" : "—"}</dd>
        <dt>Files monitored</dt><dd>${fmtNum(h.fim_files)}</dd><dt>Log sources</dt><dd>${fmtNum(h.log_sources)}</dd>
        <dt>Config score</dt><dd>${sca ? `<span class="score ${scoreCls(a.sca_score)}">${a.sca_score}%</span>` : "—"}</dd></dl>
        ${real && can("analyst") ? `<h3 style="margin:16px 0 8px">Run now</h3><div class="actions">
          <button class="btn small" data-action="agent-cmd" data-id="${esc(a.id)}" data-act="run_inventory">Collect inventory</button>
          <button class="btn small" data-action="agent-cmd" data-id="${esc(a.id)}" data-act="run_sca">Run configuration scan</button>
          <button class="btn small" data-action="agent-cmd" data-id="${esc(a.id)}" data-act="run_fim">Run file integrity scan</button>
          <button class="btn small" data-action="agent-cmd" data-id="${esc(a.id)}" data-act="restart_agent">Restart agent</button></div>` : ""}
        ${can("admin") ? `<h3 style="margin:16px 0 8px">Administration</h3><form class="bar" id="group-form"><label>Group<input name="group" value="${esc(a.group)}"></label><button class="btn small">Move to group</button><button class="btn small danger" type="button" data-action="agent-delete" data-id="${esc(a.id)}">Remove agent</button></form>` : ""}
      </section></div>`; break;
    case "alerts": body = table([
      { h: "Severity", f: x => sev(x.level) }, { h: "Alert", f: x => `<b>${esc(x.rule_title)}</b>${esc(x.description)}`, cls: "desc" },
      { h: "Status", f: x => esc(x.status) }, { h: "Last seen", f: x => ago(x.last_seen), cls: "nowrap muted" }],
      d.alerts, x => `class="click rail c-${esc(x.level)}" data-action="alert" data-id="${esc(x.id)}"`); break;
    case "vulns": body = vulnTable(vulns, false); break;
    case "sca": body = sca ? `<p class="hint">${esc(sca.policy)}, scanned ${ago(sca.timestamp)}.</p>` + table([
      { h: "Result", f: c => `<span class="${c.result === "passed" ? "st-active" : c.result === "failed" ? "sevtxt c-critical" : "muted"}">${esc(c.result.replace("_", " "))}</span>`, cls: "nowrap" },
      { h: "Check", f: c => `<b>${esc(c.title)}</b>${esc(c.result === "failed" ? c.remediation : c.rationale)}`, cls: "desc" },
      { h: "Controls", f: c => (c.compliance || []).map(x => `<span class="tag">${esc(x)}</span>`).join("") }],
      [...sca.results].sort((x, y) => (x.result === "failed" ? 0 : 1) - (y.result === "failed" ? 0 : 1))) : `<p class="empty">No configuration scan yet.</p>`; break;
    case "packages": body = table([{ h: "Package", f: p => esc(p.name) }, { h: "Version", f: p => esc(p.version) }, { h: "Source", f: p => esc(p.source) }], inv.packages || []); break;
    case "processes": body = table([{ h: "PID", f: p => p.pid, cls: "right" }, { h: "PPID", f: p => p.ppid, cls: "right" }, { h: "User", f: p => esc(p.user) }, { h: "Name", f: p => esc(p.name) }, { h: "Command line", f: p => `<span class="mono">${esc(p.cmdline)}</span>`, cls: "desc" }], inv.processes || []); break;
    case "ports": body = table([{ h: "Protocol", f: p => esc(p.protocol) }, { h: "Listening on", f: p => esc(p.local) }, { h: "PID", f: p => p.pid || "—" }], inv.ports || []); break;
  }
  v.innerHTML = `<p><a href="#/agents">Agents</a> / <b>${esc(a.name)}</b></p>
    <div class="tabs">${tabs.map(([k, l]) => `<button data-action="agent-tab" data-tab="${k}" class="${agentTab === k ? "on" : ""}">${esc(l)}</button>`).join("")}</div>${body}`;
  const gf = $("#group-form");
  if (gf) gf.addEventListener("submit", async e => {
    e.preventDefault();
    try { await api("PATCH", "/api/agents/" + encodeURIComponent(a.id), { group: e.target.group.value.trim() }); ok("Agent moved. It picks up the group's configuration on its next heartbeat."); render(); } catch (err) { fail(err); }
  });
}
actions["agent-tab"] = el => { agentTab = el.dataset.tab; render(); };
actions["agent-cmd"] = async el => {
  try { await api("POST", "/api/commands", { agent_id: el.dataset.id, action: el.dataset.act, args: {} }); ok("Queued. The agent picks it up within a heartbeat."); }
  catch (e) { fail(e); }
};
actions["agent-delete"] = async el => {
  if (!confirm("Remove this agent? Its credentials stop working; reinstalling re-enrolls it.")) return;
  try { await api("DELETE", "/api/agents/" + encodeURIComponent(el.dataset.id)); ok("Agent removed."); location.hash = "#/agents"; } catch (e) { fail(e); }
};

// ============================================================ vulnerabilities
function vulnTable(rows, withHost) {
  return table([
    { h: "Severity", f: x => sev(String(x.severity).toLowerCase()), cls: "nowrap" },
    { h: "CVE", f: x => `<a href="${esc((x.references || [])[0] || "https://nvd.nist.gov/vuln/detail/" + x.cve)}" target="_blank" rel="noopener noreferrer">${esc(x.cve)}</a>`, cls: "nowrap" },
    { h: "CVSS", f: x => x.cvss.toFixed(1), cls: "right" },
    ...(withHost ? [{ h: "Host", f: x => `<a href="#/agents/${esc(x.agent_id)}">${esc(x.hostname)}</a>` }] : []),
    { h: "Package", f: x => `<b>${esc(x.package)}</b> ${esc(x.version)}` },
    { h: "Fixed in", f: x => esc(x.fixed || "—") },
    { h: "Summary", f: x => esc(x.summary), cls: "desc" },
  ], rows, x => `class="rail c-${esc(String(x.severity).toLowerCase())}"`);
}
pages.vulns = {
  title: "Vulnerabilities",
  async render(v) {
    const d = await api("GET", "/api/vulnerabilities");
    const by = {}; d.findings.forEach(f => by[f.severity] = (by[f.severity] || 0) + 1);
    v.innerHTML = `<p class="status-line"><b>${fmtNum(d.findings.length)}</b> vulnerable packages found across your agents${d.findings.length ? ": " + ["critical", "high", "medium", "low"].filter(l => by[l]).map(l => `<span class="sevtxt c-${l}">${by[l]} ${l}</span>`).join(", ") : ""}.</p>
      <p class="hint">Matched against ${fmtNum(d.feed_entries)} feed entries using Debian version ordering. The bundled feed compares upstream versions only; distro backports can cause false positives, so load OSV or distro security-tracker data into <code>feeds/</code> for production.
      ${can("admin") ? ` <button class="link" data-action="feed-reload">Reload feeds</button>` : ""}</p>
      ${vulnTable(d.findings, true)}`;
  },
};
actions["feed-reload"] = async () => { try { const r = await api("POST", "/api/feeds/reload"); ok(`Loaded ${r.entries} feed entries. Agents are re-scanned on their next inventory.`); render(); } catch (e) { fail(e); } };

// ============================================================ compliance
let fwTab = "PCI-DSS";
pages.compliance = {
  title: "Compliance",
  async render(v) {
    const d = await api("GET", "/api/compliance");
    const fw = d.frameworks.find(f => f.framework === fwTab) || d.frameworks[0];
    const scaRows = d.sca || [];
    v.innerHTML = `
      <div class="grid">
      <section class="panel span-12"><h2>Alerts as evidence, by control <small>last 30 days</small></h2>
        <div class="tabs">${d.frameworks.map(f => `<button data-action="fw-tab" data-fw="${esc(f.framework)}" class="${f.framework === fw.framework ? "on" : ""}">${esc(f.framework)} (${f.alerts})</button>`).join("")}</div>
        <p class="hint">Each alert is mapped to the controls it is evidence for, through its ATT&amp;CK tactics and the rule's own <code>compliance:</code> list. Treat this as a starting point to review with your auditor.</p>
        ${table([
          { h: "Control", f: c => `<b>${esc(c.control)}</b>`, cls: "nowrap" },
          { h: "Alerts", f: c => fmtNum(c.alerts), cls: "right" },
          { h: "By severity", f: c => LEVELS.slice().reverse().filter(l => c.levels[l]).map(l => `<span class="sevtxt c-${l}">${c.levels[l]} ${l}</span>`).join(", ") },
          { h: "Detections", f: c => (c.rules || []).map(esc).join("; "), cls: "desc" },
        ], (fw && fw.controls) || [])}
      </section>
      <section class="panel span-12"><h2>Configuration assessment by agent</h2>
        ${scaRows.length ? scaRows.map(s => `<details><summary><b>${esc(s.name)}</b> <span class="score ${scoreCls(s.score)}">${s.score}%</span> <span class="muted">${s.passed} of ${s.total} checks passed, ${esc(s.policy)}, ${ago(s.when)}</span></summary>
          ${s.failed && s.failed.length ? table([
            { h: "Failed check", f: c => `<b>${esc(c.title)}</b>${esc(c.remediation)}`, cls: "desc" },
            { h: "Controls", f: c => (c.compliance || []).map(x => `<span class="tag">${esc(x)}</span>`).join("") }], s.failed) : `<p class="muted">All applicable checks pass.</p>`}
        </details>`).join("") : `<p class="empty">No configuration scans reported yet.</p>`}
      </section></div>`;
  },
};
actions["fw-tab"] = el => { fwTab = el.dataset.fw; render(); };

// ============================================================ ATT&CK map
pages.mitre = {
  title: "ATT&CK map",
  async render(v) {
    const cols = await api("GET", "/api/mitre?hours=168");
    const max = Math.max(1, ...cols.flatMap(c => (c.techniques || []).map(t => t.count)));
    v.innerHTML = `<p class="hint">Techniques detected in the last 7 days, by tactic. Colour shows the highest severity, depth shows volume. Select a technique to see its alerts.</p>
      <div class="mitre">${cols.map(c => `<div class="tac ${c.count ? "hot" : ""}"><h3><span>${esc(c.tactic.replace(/-/g, " "))}</span><span class="muted">${c.count || ""}</span></h3>
        ${(c.techniques || []).length ? c.techniques.map(t => `<button class="tech c-${esc(t.max_level)}" style="--heat:${Math.round(18 + t.count / max * 62)};text-align:left;font:inherit;color:inherit;cursor:pointer" data-action="tech" data-t="${esc(t.technique)}">${esc(t.name)}<b>${esc(t.technique)}, ${fmtNum(t.count)}</b></button>`).join("") : `<span class="none">Nothing detected</span>`}
      </div>`).join("")}</div>`;
  },
};
actions.tech = el => { alertFilters.q = el.dataset.t.toLowerCase(); alertFilters.status = ""; alertFilters.hours = "168"; location.hash = "#/alerts"; };

// ============================================================ rules
let ruleQ = "", lastRules = [];
const RULE_TEMPLATE = `title: Suspicious wget to /tmp
id: custom-0001
name: wget_to_tmp
status: experimental
description: A process downloaded a file into /tmp with wget.
level: medium
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    process.name: wget
    CommandLine|contains:
      - ' -O /tmp/'
      - ' -P /tmp'
  condition: selection
falsepositives:
  - Package installers
`;
pages.rules = {
  title: "Detection rules",
  async render(v) {
    const d = await api("GET", "/api/rules");
    lastRules = d.rules;
    const q = ruleQ.toLowerCase();
    const rows = d.rules.filter(r => !q || (r.title + r.id + (r.tags || []).join(" ") + r.logsource + r.level).toLowerCase().includes(q));
    v.innerHTML = `
      <div class="bar"><label class="grow">Filter<input class="grow" id="rule-q" value="${esc(ruleQ)}" placeholder="Title, tag, technique, log source…"></label>
        ${can("analyst") ? `<button class="btn primary" data-action="rule-new">New rule</button>` : ""}
        ${can("admin") ? `<button class="btn" data-action="rule-reload">Reload from disk</button>` : ""}</div>
      ${d.errors && d.errors.length ? `<details class="panel" style="margin-bottom:16px"><summary class="error">${d.errors.length} rule problem${d.errors.length > 1 ? "s" : ""} found while loading</summary><pre class="raw">${esc(d.errors.join("\n"))}</pre></details>` : ""}
      <p class="hint">${rows.length} rules. Sigma format, so community rules from SigmaHQ work with field aliases for Sysmon and auditd names.</p>
      ${table([
        { h: "Level", f: r => sev(r.level), cls: "nowrap" },
        { h: "Rule", f: r => `<b>${esc(r.title)}</b>${esc(r.id)}${r.custom ? " (custom)" : ""}${r.response ? `, responds with ${esc(r.response.replace("_", " "))}` : ""}`, cls: "desc" },
        { h: "Type", f: r => esc(r.type) },
        { h: "Log source", f: r => esc(r.logsource || "any"), cls: "desc" },
        { h: "ATT&CK", f: r => (r.mitre || []).map(t => `<span class="tag">${esc(t)}</span>`).join("") },
        { h: "Hits", f: r => fmtNum(r.hits), cls: "right" },
        { h: "Enabled", f: r => can("admin") ? `<input type="checkbox" class="rule-toggle" data-id="${esc(r.id)}" ${r.enabled ? "checked" : ""} aria-label="Enable rule">` : (r.enabled ? "yes" : "no") },
      ], rows, r => `class="click rail c-${esc(r.level)}" data-action="rule" data-id="${esc(r.id)}"`)}`;
    const qi = $("#rule-q");
    qi.addEventListener("input", () => { ruleQ = qi.value; clearTimeout(qi.t); qi.t = setTimeout(async () => { await render(); const n = $("#rule-q"); n.focus(); n.setSelectionRange(n.value.length, n.value.length); }, 250); });
    $$(".rule-toggle", v).forEach(c => {
      c.addEventListener("click", e => e.stopPropagation());
      c.addEventListener("change", async () => {
        try { await api("PATCH", "/api/rules/" + encodeURIComponent(c.dataset.id), { enabled: c.checked }); ok(`Rule ${c.checked ? "enabled" : "disabled"}.`); } catch (e) { fail(e); c.checked = !c.checked; }
      });
    });
  },
};
actions.rule = async el => {
  try {
    const { source } = await api("GET", "/api/rules/" + encodeURIComponent(el.dataset.id));
    const r = lastRules.find(x => x.id === el.dataset.id) || {};
    ruleEditor(r.title || el.dataset.id, source, r.custom, r.id);
  } catch (e) { fail(e); }
};
actions["rule-new"] = () => ruleEditor("New rule", RULE_TEMPLATE, true);
actions["rule-reload"] = async () => { try { const r = await api("POST", "/api/rules/reload"); ok(`Loaded ${r.rules} rules.`); render(); } catch (e) { fail(e); } };
function ruleEditor(title, src, editable, id) {
  const admin = can("admin");
  openDrawer(title, `
    <section><p class="hint">${editable && admin ? "Edit the Sigma YAML, test it against recent events, then save. Saved rules apply immediately." : "Bundled rules are read-only; disable them from the list, or save a copy under a new id."}</p>
      <textarea id="rule-src" spellcheck="false">${esc(src)}</textarea></section>
    <section class="actions">
      ${can("analyst") ? `<button class="btn" data-action="rule-test">Test against recent events</button>` : ""}
      ${admin ? `<button class="btn primary" data-action="rule-save">${editable ? "Save rule" : "Save as custom rule"}</button>` : ""}
      ${admin && editable && id ? `<button class="btn danger" data-action="rule-delete" data-id="${esc(id)}">Delete rule</button>` : ""}
    </section>
    <section id="rule-out"></section>`);
}
actions["rule-test"] = async () => {
  const out = $("#rule-out");
  out.innerHTML = `<p class="muted">Testing…</p>`;
  try {
    const d = await api("POST", "/api/rules/test", $("#rule-src").value);
    out.innerHTML = `<h3>${d.count} match${d.count === 1 ? "" : "es"} in ${fmtNum(d.scanned)} recent events</h3>` +
      d.matches.slice(0, 30).map(e => `<pre class="raw">${esc(fmtTime(e.timestamp))} ${esc(e.hostname)}  ${esc(e.raw)}</pre>`).join("");
  } catch (e) { out.innerHTML = `<p class="error">${esc(e.message)}</p>`; }
};
actions["rule-save"] = async () => {
  try { const r = await api("POST", "/api/rules", $("#rule-src").value); ok(`Saved ${r.title}.`); closeDrawer(); render(); }
  catch (e) { $("#rule-out").innerHTML = `<p class="error">${esc(e.message)}</p>`; }
};
actions["rule-delete"] = async el => {
  if (!confirm("Delete this custom rule?")) return;
  try { await api("DELETE", "/api/rules/" + encodeURIComponent(el.dataset.id)); ok("Rule deleted."); closeDrawer(); render(); } catch (e) { fail(e); }
};

// ============================================================ active response
const ARGS = { block_ip: ["ip", "timeout"], unblock_ip: ["ip"], kill_process: ["pid"], quarantine_file: ["path"], restore_file: ["path"] };
pages.response = {
  title: "Active response",
  async render(v) {
    const [cmds, agents, acts] = await Promise.all([api("GET", "/api/commands"), api("GET", "/api/agents"), api("GET", "/api/actions")]);
    const real = agents.filter(a => !a.id.startsWith("syslog:"));
    v.innerHTML = `
      ${can("analyst") ? `<section class="panel" style="margin-bottom:16px"><h2>Send a response</h2>
        <form class="bar" id="cmd-form">
          <label>Agent<select name="agent_id" required>${real.map(a => `<option value="${esc(a.id)}">${esc(a.name)} (${esc(a.status)})</option>`).join("")}</select></label>
          <label>Action<select name="action" id="cmd-action">${Object.entries(acts).map(([k, d]) => `<option value="${esc(k)}" title="${esc(d)}">${esc(k.replace(/_/g, " "))}</option>`).join("")}</select></label>
          <span id="cmd-args" class="bar" style="margin:0"></span>
          <button class="btn primary">Queue response</button>
        </form>
        <p class="hint" id="cmd-desc"></p>
        <p class="hint">Agents only run actions on their local allowlist, and blocks never apply to allowlisted networks. Rules with a <code>response:</code> block trigger these automatically.</p></section>` : ""}
      <section class="panel"><h2>History</h2>${table([
        { h: "Queued", f: c => esc(fmtTime(c.created_at)), cls: "nowrap muted" },
        { h: "Agent", f: c => esc((agents.find(a => a.id === c.agent_id) || {}).name || c.agent_id) },
        { h: "Action", f: c => `<b>${esc(c.action.replace(/_/g, " "))}</b> ${esc(Object.entries(c.args || {}).filter(([k]) => k !== "alert_id").map(([k, x]) => k + "=" + x).join(" "))}`, cls: "desc" },
        { h: "By", f: c => esc(c.created_by) },
        { h: "Status", f: c => `<span class="${c.status === "succeeded" ? "st-active" : c.status === "failed" ? "sevtxt c-critical" : "muted"}">${esc(c.status)}</span>` },
        { h: "Result", f: c => esc(c.result), cls: "desc" },
      ], cmds)}</section>`;
    const form = $("#cmd-form");
    if (!form) return;
    const sync = () => {
      const act = $("#cmd-action").value;
      $("#cmd-desc").textContent = acts[act] || "";
      $("#cmd-args").innerHTML = (ARGS[act] || []).map(k => `<label>${esc(k)}<input name="arg_${k}" ${k === "timeout" ? 'placeholder="1h"' : "required"}></label>`).join("");
    };
    $("#cmd-action").addEventListener("change", sync); sync();
    form.addEventListener("submit", async e => {
      e.preventDefault();
      const f = new FormData(form), args = {};
      for (const [k, x] of f) if (k.startsWith("arg_") && x) args[k.slice(4)] = x;
      try { await api("POST", "/api/commands", { agent_id: f.get("agent_id"), action: f.get("action"), args }); ok("Response queued."); render(); } catch (err) { fail(err); }
    });
  },
};

// ============================================================ settings
let setTab = "enroll";
pages.settings = {
  title: "Settings",
  async render(v) {
    const s = await api("GET", "/api/settings");
    const tabs = [["enroll", "Add an endpoint"], ["groups", "Agent groups"], ["server", "Server"], ...(can("admin") ? [["users", "Users"], ["audit", "Audit log"]] : [])];
    let body = "";
    const origin = location.origin;
    if (setTab === "enroll") {
      const key = s.enrollment_key || "<ask an admin for the enrollment key>";
      body = `<div class="panel"><h2>Install the agent on a Linux host</h2>
        <p>Copy the <code>vigil-agent</code> binary to the host, then create <code>/etc/vigil/agent.yml</code>:</p>
        <pre class="raw">server: ${esc(origin)}
enrollment_key: ${esc(key)}
${s.fingerprint ? "server_fingerprint: " + esc(s.fingerprint) : "# server runs without TLS (development only)"}
group: default</pre>
        <p>Then start it as a service:</p>
        <pre class="raw">sudo install -m 0755 vigil-agent /usr/local/bin/
sudo install -m 0644 deploy/systemd/vigil-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vigil-agent</pre>
        <p class="hint">The fingerprint pins this server's certificate, so agents refuse impostor servers even with a self-signed certificate. The enrollment key is only needed for first registration; each agent then gets its own token. Windows and macOS use the same file at <code>C:\\ProgramData\\Vigil\\agent.yml</code> and <code>/etc/vigil/agent.yml</code>.</p>
        <h3 style="margin:18px 0 8px">Agentless devices</h3>
        <p>Point firewalls, routers and appliances at syslog <b>${esc(s.syslog || "disabled")}</b> (UDP or TCP). Each sender appears under Agents.</p></div>`;
    } else if (setTab === "groups") {
      const groups = await api("GET", "/api/groups");
      body = `<p class="hint">A group's configuration is pushed to its agents, overriding their local settings for logs, file integrity paths, intervals, configuration scans and active response. Agents restart themselves to apply it.</p>` +
        groups.map(g => `<section class="panel" style="margin-bottom:14px"><h2>${esc(g.name)} <small>${g.agents} agent${g.agents === 1 ? "" : "s"}${g.version ? ", version " + g.version : ", using local agent config"}</small></h2>
          <textarea class="group-src" data-group="${esc(g.name)}" style="min-height:${g.config ? 220 : 140}px" ${can("admin") ? "" : "readonly"} placeholder="# example
fim:
  paths: [/etc, /var/www]
logs:
  - /var/log/auth.log
  - path: /var/log/nginx/access.log
intervals:
  fim: 10m">${esc(g.config)}</textarea>
          ${can("admin") ? `<div class="actions" style="margin-top:8px"><button class="btn small" data-action="group-save" data-group="${esc(g.name)}">Save and push</button></div>` : ""}</section>`).join("") +
        (can("admin") ? `<form class="bar" id="new-group"><label>New group<input name="name" placeholder="web-servers" required></label><button class="btn">Create group</button></form>` : "");
    } else if (setTab === "server") {
      body = `<div class="panel"><dl class="kv">
        <dt>Version</dt><dd>${esc(s.version)}</dd><dt>Listening on</dt><dd>${esc(s.listen)} ${s.tls ? "(TLS)" : "(plain HTTP)"}</dd>
        <dt>Certificate fingerprint</dt><dd class="mono">${esc(s.fingerprint || "—")}</dd><dt>Syslog receiver</dt><dd>${esc(s.syslog || "disabled")}</dd>
        <dt>Lowest alert level stored</dt><dd>${esc(s.min_alert_level)}</dd><dt>Notifications</dt><dd>${s.webhook ? "webhook" : ""}${s.webhook && s.email ? " and " : ""}${s.email ? "email" : ""}${!s.webhook && !s.email ? "off" : ""}, for ${esc(s.notify_level)} and above</dd>
        <dt>Automatic response</dt><dd>${s.auto_response ? "on" : "off"}, never blocking ${esc((s.response_allowlist || []).join(", "))}</dd>
        <dt>Event retention</dt><dd>${s.retention_days} days on disk, ${fmtNum(s.max_events)} in memory</dd>
        <dt>Vulnerability feed</dt><dd>${fmtNum(s.feed_entries)} entries</dd></dl>
        <p class="hint">Change these in <code>server.yml</code> or with <code>VIGIL_*</code> environment variables, then restart the server.</p></div>`;
    } else if (setTab === "users") {
      const users = await api("GET", "/api/users");
      body = table([{ h: "User", f: u => `<b>${esc(u.username)}</b>` }, { h: "Role", f: u => esc(u.role) }, { h: "Created", f: u => esc(fmtTime(u.created)) },
        { h: "", f: u => u.username === me.username ? `<span class="muted">you</span>` : `<button class="btn small danger" data-action="user-delete" data-user="${esc(u.username)}">Remove</button>`, cls: "right" }], users) +
        `<form class="bar panel" id="user-form" style="margin-top:16px"><label>Username<input name="username" required></label><label>Password<input name="password" type="password" minlength="10" required></label>
          <label>Role<select name="role"><option value="viewer">Viewer: read only</option><option value="analyst" selected>Analyst: triage and respond</option><option value="admin">Admin: everything</option></select></label><button class="btn primary">Add user</button></form>`;
    } else if (setTab === "audit") {
      const log = await api("GET", "/api/audit");
      body = `<p class="hint">Every sign-in, enrollment, triage change, response and configuration change. Stored append-only in <code>data/audit.jsonl</code>.</p>` +
        table([{ h: "Time", f: e => esc(fmtTime(e.time)), cls: "nowrap muted" }, { h: "User", f: e => esc(e.user) }, { h: "Action", f: e => esc(e.action) }, { h: "Target", f: e => esc(e.target) },
          { h: "Details", f: e => esc(Object.entries(e.details || {}).map(([k, x]) => k + "=" + x).join(" ")), cls: "desc" }], log);
    }
    v.innerHTML = `<div class="tabs">${tabs.map(([k, l]) => `<button data-action="set-tab" data-tab="${k}" class="${setTab === k ? "on" : ""}">${esc(l)}</button>`).join("")}</div>${body}`;
    const uf = $("#user-form");
    if (uf) uf.addEventListener("submit", async e => {
      e.preventDefault(); const f = new FormData(uf);
      try { await api("POST", "/api/users", Object.fromEntries(f)); ok("User added."); render(); } catch (err) { fail(err); }
    });
    const ng = $("#new-group");
    if (ng) ng.addEventListener("submit", async e => {
      e.preventDefault();
      try { await api("PUT", "/api/groups/" + encodeURIComponent(ng.name.value.trim()), "intervals:\n  heartbeat: 10s\n"); ok("Group created."); render(); } catch (err) { fail(err); }
    });
  },
};
actions["set-tab"] = el => { setTab = el.dataset.tab; render(); };
actions["group-save"] = async el => {
  const src = $(`.group-src[data-group="${CSS.escape(el.dataset.group)}"]`).value;
  try { await api("PUT", "/api/groups/" + encodeURIComponent(el.dataset.group), src); ok("Configuration saved. Agents in this group apply it on their next heartbeat."); render(); } catch (e) { fail(e); }
};
actions["user-delete"] = async el => {
  if (!confirm(`Remove ${el.dataset.user}?`)) return;
  try { await api("DELETE", "/api/users/" + encodeURIComponent(el.dataset.user)); ok("User removed."); render(); } catch (e) { fail(e); }
};

// ------------------------------------------------------------- boot
async function boot() {
  if (!token) return showLogin();
  try {
    me = await api("GET", "/api/me");
  } catch { return; }
  $("#login").hidden = true; $("#app").hidden = false;
  $("#who").textContent = `${me.username} (${me.role})`;
  openStream();
  updateOpenCount();
  setInterval(updateOpenCount, 60000);
  if (!location.hash) location.hash = "#/overview"; else render();
}
boot();
})();
