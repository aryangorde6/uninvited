/* Uninvited website. Every page reads one file, data/snapshot.json (written by
   `python -m uninvited.export`), and draws itself from it: no backend, no third-party code.
   The same pages replay the finished experiment from the committed file, with no key.
   All text from the data goes in with textContent (through h() below), never as HTML. */

const DATA_URL = "data/snapshot.json";
const STALE_AFTER = 5 * 60;       // seconds: older than this, the page says it is a check-in snapshot, not live
const REFRESH_MS = 5 * 60 * 1000; // re-read the file every 5 minutes (it is replaced a few times a day)
const LANES_SHOWN = 30;       // newest attackers drawn before "Show all"

const ARMS = {
  control: { name: "No ban", cls: "none", stamp: "Let go" },
  ban_10m: { name: "10-minute ban", cls: "m10", stamp: "Busted · 10 min" },
  ban_12h: { name: "12-hour ban", cls: "h12", stamp: "Busted · 12 hrs" },
};
const ORDER = ["control", "ban_10m", "ban_12h"];
const REGIONS = {
  "us-east-1": "N. Virginia", "us-east-2": "Ohio", "us-west-1": "N. California", "us-west-2": "Oregon",
  "ca-central-1": "Canada", "sa-east-1": "São Paulo", "eu-central-1": "Frankfurt", "eu-west-1": "Ireland",
  "eu-west-2": "London", "eu-north-1": "Stockholm", "ap-southeast-1": "Singapore", "ap-southeast-2": "Sydney",
  "ap-northeast-1": "Tokyo",
};

let snap = null;         // the last snapshot read
let showAll = false;     // lanes: all rows, or the newest LANES_SHOWN
let stamped = false;     // the stamp animates once, on first load

/* ---------- helpers ---------- */

// Build an element. Strings become text nodes, so attacker data can never become markup.
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

// Put content into every element marked data-fill="key".
function fill(key, ...kids) {
  for (const el of document.querySelectorAll(`[data-fill="${key}"]`)) {
    el.replaceChildren(...kids.map((k) => (k instanceof Node ? k.cloneNode(true) : String(k))));
  }
}

const SVGNS = "http://www.w3.org/2000/svg";
function icon(path, label) {
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(SVGNS, "path");
  p.setAttribute("d", path);
  svg.append(p);
  return label ? h("span", { class: "arm" }, svg, label) : svg;
}
const STAR = "M12 2.5l2.9 6.1 6.6.8-4.9 4.6 1.3 6.6L12 17.3l-5.9 3.3 1.3-6.6-4.9-4.6 6.6-.8z";
const CHECK = "M9.5 16.2 5.3 12l-1.4 1.4 5.6 5.6 11-11-1.4-1.4z";
const CLOCK = "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm1 10.4 3.6 2.1-.8 1.3L11 13V7h2z";
function stars(n = 5) {
  const s = h("span", { class: "stars", "aria-hidden": "true" });
  for (let i = 0; i < n; i++) s.append(icon(STAR));
  return s;
}

// Times are shown in the viewer's own time zone, with UTC on hover.
const DATE = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "short", hour: "numeric", minute: "2-digit" });
const ZONE = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" });
function when(t, zone = true) {
  const d = new Date(t * 1000);
  const z = zone ? " " + (ZONE.formatToParts(d).find((p) => p.type === "timeZoneName")?.value || "") : "";
  const iso = d.toISOString();
  return h("time", { datetime: iso, title: iso.slice(0, 16).replace("T", " ") + " UTC" }, DATE.format(d) + z);
}
function ago(seconds) {
  if (seconds < 90) return "just now";
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 36 * 3600) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}
const nowSec = () => Date.now() / 1000;
const iso = (s) => Date.parse(s) / 1000;
const pct = (x, digits = 0) => `${(100 * x).toFixed(digits)}%`;
let countries;
try { countries = new Intl.DisplayNames(undefined, { type: "region" }); } catch { countries = null; }
const country = (code) => (code && countries ? countries.of(code) : code) || "Unknown";
const shortId = (id) => (id || "").replace(/^ip-/, "").slice(0, 4);
function serverName(name) {                       // "server-eu-central-1-14" -> "Frankfurt #14"
  const m = /^server-(.+)-(\d+)$/.exec(name || "");
  return m ? `${REGIONS[m[1]] || m[1]} #${m[2]}` : name || "";
}
const plain = (text) => text.replace(/\bban_10m\b/g, "10-minute ban").replace(/\bban_12h\b/g, "12-hour ban")
  .replace(/\bcontrol\b/g, "no ban").replace(/[{}']/g, "");

/* ---------- where the experiment stands ---------- */

function times(d) {
  const e = d.experiment;
  const from = iso(e.enrol_from), until = iso(e.enrol_until);
  const [winStart, winEnd] = e.window_hours;
  const firsts = d.attackers.map((a) => a.first_catch);
  return {
    from, until, winStart, winEnd,
    lastClose: until + winEnd * 3600,
    firstOpen: firsts.length ? Math.min(...firsts) + winStart * 3600 : null,
    firstClose: firsts.length ? Math.min(...firsts) + winEnd * 3600 : null,
  };
}

function phase(d) {
  const t = times(d), g = d.generated;
  if (g < t.from) return "before";
  if (g < t.until) return "enrolling";
  if (g < t.lastClose && d.attackers.some((a) => a.window !== "closed")) return "watching";
  return "complete";
}
const PHASE_LABEL = { before: "Starts soon", enrolling: "Running", watching: "Running · waiting for returns", complete: "Complete" };

// The snapshot is replaced at check-ins, a few times a day. Older than STALE_AFTER during the run
// means "between check-ins": normal, not a fault. A finished run is never stale.
function isStale(d) {
  const ph = phase(d);
  return (ph === "enrolling" || ph === "watching") && nowSec() - d.generated > STALE_AFTER;
}

function header(d) {
  const ph = phase(d), age = nowSec() - d.generated, stale = isStale(d);
  document.body.dataset.phase = ph;
  if (stale) document.body.dataset.stale = ""; else delete document.body.dataset.stale;
  const running = ph === "enrolling" || ph === "watching";
  // the count comes last, so on a narrow phone it is the part cut short
  fill("pill", h("span", { class: "dot" }), h("span", { class: "pill-text" }, `${running && !stale ? "Live" : PHASE_LABEL[ph]}`
    + (ph === "complete" ? "" : ` · updated ${ago(age)}`) + ` · ${d.attackers.length} caught`));
  // the full explanation is on Live only, below the hero; elsewhere the pill and "Data from" say it
  const note = document.querySelector(".notice");
  if (note && stale && document.body.dataset.page === "live") {
    note.classList.remove("error");
    note.replaceChildren(h("b", {}, "Snapshot from ", when(d.generated), ` (${ago(age)}). `),
      "This page is updated a few times a day, when new data is committed at check-ins, so it isn't a live feed. The experiment keeps running on the servers in between.");
    note.classList.add("show");
  } else if (note) note.classList.remove("show");
  fill("generated", when(d.generated));
  fill("updated", ago(age));
  fill("snapshot", when(d.generated), ph === "complete" ? " (final)" : ` (${ago(age)}; updated a few times a day)`);
}

function showError() {
  const note = document.querySelector(".notice");
  if (!note) return;
  const retry = h("button", { class: "small", type: "button" }, "Try again");
  retry.addEventListener("click", refresh);
  note.classList.add("error");
  note.replaceChildren(h("b", {}, "Couldn't load the experiment's data. "),
    snap ? "Showing the last snapshot read. " : "Check your connection, then ", retry);
  note.classList.add("show");
  if (snap) return;
  fill("pill", h("span", { class: "dot" }), h("span", { class: "pill-text" }, "No data"));
  for (const box of document.querySelectorAll("[data-lanes], [data-chart], [data-servers], [data-compare]")) {
    box.replaceChildren(h("div", { class: "empty" }, h("b", {}, "Nothing to show yet"), "The data file couldn't be loaded."));
  }
}

/* ---------- Live page ---------- */

function live(d) {
  const t = times(d), ph = phase(d);
  const rows = [...d.attackers].sort((a, b) => b.first_catch - a.first_catch);
  const regions = new Set(d.servers.map((s) => s.region));
  fill("servers", String(d.servers.length));
  fill("regions", String(regions.size));
  fill("enrolled", String(d.attackers.length));
  fill("enrol-from", when(t.from));
  fill("enrol-until", when(t.until));
  fill("phase-text", {
    before: "Enrolment hasn't opened yet.",
    enrolling: "Enrolling: every newly caught attacker joins the test.",
    watching: "Enrolment has closed. Now waiting for the last return windows.",
    complete: "The experiment is complete.",
  }[ph]);

  // the three crews
  for (const k of ORDER) {
    const a = d.totals.per_arm[k] || { enrolled: 0, closed: 0, came_back: 0 };
    fill(`crew-${k}`, String(a.enrolled));
    fill(`crew-${k}-note`, a.closed ? `${a.came_back} of ${a.closed} came back` : "no window closed yet");
  }

  // the latest catches, and the newest one as the "wanted" poster
  fill("wire", ...(rows.length ? rows.slice(0, 3).map((a) => h("li", {}, stars(),
    `${shortId(a.id)} · ${a.country || "??"} · AS${a.asn} → `, h("b", {}, ARMS[a.arm]?.stamp || a.arm))) : [h("li", {}, "No catches yet")]));
  const wanted = document.querySelector(".wanted");
  if (wanted) {
    const a = rows[0];
    wanted.hidden = !a;
    if (a) {
      fill("w-tag", shortId(a.id));
      fill("w-meta", `${country(a.country)} · AS${a.asn} · 5 failed logins in 10 min`);
      fill("w-stars", stars());
      const stamp = wanted.querySelector(".stamp");
      stamp.textContent = ARMS[a.arm]?.stamp || a.arm;
      stamp.classList.toggle("let-go", a.arm === "control");
      if (!stamped) { stamp.classList.add("slam"); stamped = true; }
    }
  }

  lanes(d, rows, t);
  serverGrid(d);
}

function lanes(d, rows, t) {
  const box = document.querySelector("[data-lanes]");
  if (!box) return;
  if (!rows.length) {
    box.replaceChildren(h("div", { class: "empty" }, h("b", {}, "No attacker caught yet"),
      d.generated < t.from ? "Enrolment opens " : "Enrolment opened ", when(t.from), ". The first attackers usually arrive within minutes."));
    return;
  }
  const span = t.winEnd;                          // a lane runs from the first catch to the window's end
  const at = (hours) => `${Math.max(0, Math.min(100, (100 * hours) / span))}%`;
  const shown = showAll ? rows : rows.slice(0, LANES_SHOWN);
  const body = shown.map((a) => {
    const arm = ARMS[a.arm] || { name: a.arm, cls: "" };
    const lane = h("div", { class: "lane", "aria-hidden": "true" });
    const part = (cls, from, to) => {
      const s = h("span", { class: cls });
      s.style.left = at(from);
      if (to != null) s.style.width = `calc(${at(to)} - ${at(from)})`;
      lane.append(s);
    };
    part("win", t.winStart, t.winEnd);
    if (a.ban_seconds > 0) part(`ban ${arm.cls}`, 0, a.ban_seconds / 3600);
    const age = (d.generated - a.first_catch) / 3600;
    if (age < span) part("now", age);
    if (a.came_back_hours != null) part("back", a.came_back_hours);

    let back;
    if (a.came_back_hours != null) back = `Yes, after ${a.came_back_hours.toFixed(1)} h`;
    else if (a.window === "closed") back = "No";
    else if (a.window === "open") back = h("span", {}, "Watching until ", when(a.first_catch + t.winEnd * 3600, false));
    else back = h("span", {}, "Window opens ", when(a.first_catch + t.winStart * 3600, false));

    return h("tr", {},
      h("td", {}, h("span", { class: "id", title: a.id }, shortId(a.id)), h("span", { class: "sub" }, "caught ", when(a.first_catch, false))),
      h("td", {}, country(a.country), h("span", { class: "sub" }, `AS${a.asn} · first on ${serverName(a.first_server)}`)),
      h("td", {}, h("span", { class: "arm" }, h("span", { class: `sw ${arm.cls}` }), arm.name),
        h("span", { class: "sub" }, a.ban_seconds ? `banned ${a.bans} time${a.bans === 1 ? "" : "s"}` : "never banned")),
      h("td", { class: "lane-col" }, lane),
      h("td", { class: "r", "data-label": "Reached SSH" }, String(a.attempts)),
      h("td", { class: "r", "data-label": "Blocked by ban" }, String(a.dropped)),
      h("td", { "data-label": "Came back" }, back));
  });
  const head = h("thead", {}, h("tr", {},
    h("th", { scope: "col" }, "Attacker"), h("th", { scope: "col" }, "From"), h("th", { scope: "col" }, "Arm"),
    h("th", { scope: "col", class: "lane-col" }, "First catch → end of return window",
      h("span", { class: "axis", "aria-hidden": "true" }, h("span", {}, "0 h"), h("span", {}, "12 h"), h("span", {}, "24 h"))),
    h("th", { scope: "col", class: "r" }, "Reached SSH"), h("th", { scope: "col", class: "r" }, "Blocked by ban"),
    h("th", { scope: "col" }, "Came back?")));
  const table = h("table", { class: "lanes" },
    h("caption", { class: "visually-hidden" }, "Every enrolled attacker, newest first: arm, attempts after the catch, and whether it came back in its return window"),
    head, h("tbody", {}, body));
  const kids = [h("div", { class: "table-wrap" }, table)];
  if (rows.length > LANES_SHOWN) {
    const more = h("button", { class: "link more", type: "button" }, showAll ? `Show the newest ${LANES_SHOWN}` : `Show all ${rows.length} attackers`);
    more.addEventListener("click", () => { showAll = !showAll; lanes(d, rows, t); });
    kids.push(more);
  }
  box.replaceChildren(...kids);
}

function serverGrid(d) {
  const box = document.querySelector("[data-servers]");
  if (!box) return;
  const level = (n) => (n >= 1000 ? 4 : n >= 100 ? 3 : n >= 10 ? 2 : n >= 1 ? 1 : 0);
  const byRegion = {};
  for (const s of d.servers) (byRegion[s.region] ||= []).push(s);
  const order = Object.keys(byRegion).sort((a, b) => Object.keys(REGIONS).indexOf(a) - Object.keys(REGIONS).indexOf(b));
  box.replaceChildren(...order.map((r) => {
    const list = byRegion[r].sort((a, b) => Number(a.name.split("-").pop()) - Number(b.name.split("-").pop()));
    const total = list.reduce((n, s) => n + s.events, 0);
    return h("div", { class: "region" },
      h("div", { class: "name" }, REGIONS[r] || r, " ", h("small", {}, `${list.length} · ${total} events`)),
      h("div", { class: "cells", "aria-hidden": "true" }, list.map((s) =>
        h("span", { class: `cell l${level(s.events)}`, title: `${serverName(s.name)}: ${s.events} events` }))));
  }));
  const total = d.servers.reduce((n, s) => n + s.events, 0);
  fill("events-total", total.toLocaleString());
  fill("heartbeat", d.last_heartbeat ? when(d.last_heartbeat) : "none yet");
  const tbody = document.querySelector("[data-server-rows]");
  if (tbody) tbody.replaceChildren(...[...d.servers].sort((a, b) => b.events - a.events).map((s) =>
    h("tr", {}, h("td", {}, serverName(s.name)), h("td", {}, s.region), h("td", { class: "r" }, String(s.events)))));
}

/* ---------- Results page ---------- */

// 95% Wilson interval for k of n: the range the true return rate plausibly sits in.
function wilson(k, n, z = 1.96) {
  if (!n) return null;
  const p = k / n, den = 1 + (z * z) / n;
  const mid = (p + (z * z) / (2 * n)) / den;
  const half = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / den;
  return [Math.max(0, mid - half), Math.min(1, mid + half)];
}

// The gate's text is report.py's output; pick out its checks and comparisons.
function parseReport(text) {
  const checks = [], compare = {};
  let detect = null;
  for (const line of (text || "").split("\n")) {
    const c = /^\s*\[(PASS|FAIL|----|info)\]\s*(.*)$/.exec(line);
    if (c) checks.push({ status: c[1], text: plain(c[2]).replace(/^Flagsmith comparison skipped.*/, "Comparison with Flagsmith's own counts: not run for this snapshot") });
    const v = /^\s*(ban_10m|ban_12h) vs control: P\(lower\) = ([\d.]+)%, difference ([+-]?[\d.]+) points, 95% interval ([+-]?[\d.]+) to ([+-]?[\d.]+): (.*)$/.exec(line);
    if (v && !compare[v[1]]) compare[v[1]] = { pLower: +v[2], diff: +v[3], lo: +v[4], hi: +v[5], call: v[6] };
    const s = /smallest drop this sample could detect: about (\d+) points/.exec(line);
    if (s && detect == null) detect = +s[1];
  }
  return { checks, compare, detect };
}
const signed = (x) => (x > 0 ? "+" : x < 0 ? "−" : "") + Math.abs(x).toFixed(1);

function results(d) {
  const t = times(d), ph = phase(d), done = ph === "complete";
  const per = (k) => d.totals.per_arm[k] || { enrolled: 0, closed: 0, came_back: 0 };
  const closed = ORDER.reduce((n, k) => n + per(k).closed, 0);
  const rep = parseReport(d.gate?.text);

  fill("status", done
    ? h("span", { class: "badge complete" }, icon(CHECK), "Complete · final")
    : h("span", { class: "badge running" }, icon(CLOCK), "Running, not final"));
  fill("closed", `${closed} of ${d.attackers.length}`);
  fill("first-open", t.firstOpen ? when(t.firstOpen) : "12 h 5 min after the first catch");
  fill("first-close", t.firstClose ? when(t.firstClose) : "24 h 5 min after the first catch");
  fill("last-close", when(t.lastClose));

  // the verdict, only once every window has closed and the gate passes
  let verdict;
  const c10 = rep.compare.ban_10m, n = Math.min(per("control").closed, per("ban_10m").closed);
  if (!d.gate?.pass) verdict = "The integrity gate failed, so no result is read until it passes.";
  else if (!done) verdict = h("span", {}, "No verdict yet. The last return window closes ", when(t.lastClose),
    ". Until then the numbers can still move, and the pre-registration rules out stopping early.");
  else if (!c10) verdict = "No return window closed in both arms, so there is nothing to compare.";
  else if (c10.call.startsWith("can't call")) verdict = `Over ${n} attackers per arm, a 10-minute ban did not measurably change how many came back 12–24 hours later (difference ${signed(c10.diff)} points, interval ${signed(c10.lo)} to ${signed(c10.hi)}).`
    + (rep.detect ? ` A difference smaller than about ${rep.detect} points can't be ruled out.` : "");
  else verdict = `A 10-minute ban ${c10.diff < 0 ? "lowered" : "raised"} the share who came back 12–24 hours later by ${Math.abs(c10.diff).toFixed(1)} points (interval ${signed(c10.lo)} to ${signed(c10.hi)}), over ${n} attackers per arm.`;
  fill("verdict", verdict);

  chart(d, per);

  // comparisons with no ban, from report.py's Beta-binomial check
  const cmp = document.querySelector("[data-compare]");
  if (cmp) {
    const items = ["ban_10m", "ban_12h"].filter((k) => rep.compare[k]).map((k) => {
      const c = rep.compare[k];
      return h("li", {}, h("b", {}, `${ARMS[k].name} vs no ban: `),
        `difference ${signed(c.diff)} points (95% interval ${signed(c.lo)} to ${signed(c.hi)}), chance it is lower ${c.pLower.toFixed(0)}%: ${c.call}${done ? "" : " (interim)"}.`);
    });
    cmp.replaceChildren(items.length ? h("ul", {}, items)
      : h("p", { class: "intro" }, "Appears once return windows close in both arms. The first closes ", t.firstClose ? when(t.firstClose) : "12 hours after the first catch", "."));
    if (rep.detect) cmp.append(h("p", {}, `With the sample so far, the smallest drop that could be detected is about ${rep.detect} points.`));
  }

  // the integrity gate
  fill("gate-badge", d.gate?.pass ? "Pass" : "Fail");
  const badge = document.querySelector(".gate-badge");
  if (badge) badge.className = `gate-badge ${d.gate?.pass ? "pass" : "fail"}`;
  const STATUS = { PASS: ["pass", "Pass"], FAIL: ["fail", "Fail"], "----": ["skip", "Skipped"], info: ["info", "Info"] };
  fill("checks", ...rep.checks.map((c) => h("li", {}, h("span", { class: `st ${STATUS[c.status][0]}` }, STATUS[c.status][1]), c.text)));
  fill("gate-text", d.gate?.text || "No gate output in this snapshot.");
}

// Return rate per arm: a dot for the rate and a bar for its 95% interval, axis from zero.
function chart(d, per) {
  const box = document.querySelector("[data-chart]");
  if (!box) return;
  const rates = ORDER.map((k) => { const a = per(k); return { k, ...a, ci: wilson(a.came_back, a.closed) }; });
  const top = Math.max(0.5, Math.ceil(10 * Math.max(0, ...rates.map((r) => (r.ci ? r.ci[1] : 0)))) / 10);
  const x = (v) => `${(100 * v) / top}%`;
  const step = top <= 0.6 ? 0.1 : 0.2, ticks = [];
  for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v);
  const rows = rates.map((r) => {
    const arm = ARMS[r.k];
    const track = h("div", { class: "track" }, ticks.map((v) => { const g = h("span", { class: "grid" }); g.style.left = x(v); return g; }));
    if (r.ci) {
      const rate = r.came_back / r.closed;
      const ci = h("span", { class: `ci ${arm.cls}` }); ci.style.left = x(r.ci[0]); ci.style.width = `calc(${x(r.ci[1])} - ${x(r.ci[0])})`;
      const pt = h("span", { class: `pt ${arm.cls}` }); pt.style.left = x(rate);
      const tip = h("span", { class: "tip" }, `${arm.name}: ${r.came_back} of ${r.closed} came back (${pct(rate, 1)}), 95% interval ${pct(r.ci[0])}–${pct(r.ci[1])}`);
      tip.style.left = x(rate);
      track.append(ci, pt, tip);
      track.setAttribute("tabindex", "0");
      track.setAttribute("aria-label", tip.textContent);
    } else {
      track.append(h("span", { class: "pending" }, "No window closed yet"));
    }
    return h("div", { class: "row" }, h("span", { class: "arm" }, h("span", { class: `sw ${arm.cls}` }), arm.name), track);
  });
  const axis = h("div", { class: "ticks", "aria-hidden": "true" }, ticks.map((v) => { const s = h("span", {}, pct(v)); s.style.left = x(v); return s; }));
  box.replaceChildren(...rows, axis);

  const tbody = document.querySelector("[data-arm-rows]");
  if (tbody) tbody.replaceChildren(...rates.map((r) => h("tr", {},
    h("th", { scope: "row" }, h("span", { class: "arm" }, h("span", { class: `sw ${ARMS[r.k].cls}` }), ARMS[r.k].name)),
    h("td", { class: "r" }, String(r.enrolled)), h("td", { class: "r" }, String(r.closed)),
    h("td", { class: "r" }, r.closed ? String(r.came_back) : "—"),
    h("td", { class: "r" }, r.ci ? pct(r.came_back / r.closed, 1) : "—"),
    h("td", { class: "r" }, r.ci ? `${pct(r.ci[0])}–${pct(r.ci[1])}` : "—"))));
}

/* ---------- Method page ---------- */

function method(d) {
  const t = times(d);
  fill("enrol-from", when(t.from));
  fill("enrol-until", when(t.until));
  fill("last-close", when(t.lastClose));
  fill("servers", String(d.servers.length));
  fill("regions", String(new Set(d.servers.map((s) => s.region)).size));
  fill("enrolled", String(d.attackers.length));
  const [a, b, c] = d.experiment.split || [];
  fill("split", `${a} / ${b} / ${c}`);
}

/* ---------- start ---------- */

function render() {
  header(snap);
  ({ live, results, method })[document.body.dataset.page]?.(snap);
}

async function refresh() {
  if (document.hidden && snap) return;
  try {
    const r = await fetch(DATA_URL, { cache: "no-cache" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    snap = await r.json();
    document.body.dataset.state = "ready";
    render();
  } catch {
    if (!snap) document.body.dataset.state = "error";
    showError();
  }
}

refresh();
setInterval(refresh, REFRESH_MS);
setInterval(() => snap && header(snap), 15 * 1000);
