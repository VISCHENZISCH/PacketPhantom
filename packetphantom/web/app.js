"use strict";
/* PacketPhantom - tableau de bord web.
 * Toutes les données réseau sont insérées via textContent (jamais en HTML). */

// ================================================================== outils

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const SVG_NS = "http://www.w3.org/2000/svg";

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) el.append(child instanceof Node ? child : String(child));
  }
  return el;
}

function svg(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  el.append(...children);
  return el;
}

const last = (values) => values[values.length - 1] ?? 0;
const sum = (values) => values.reduce((a, b) => a + b, 0);

const fmt = {
  count: (n) => Number(n ?? 0).toLocaleString("fr-FR"),
  unit(n, units, base) {
    let i = 0;
    while (Math.abs(n) >= base && i < units.length - 1) { n /= base; i += 1; }
    return `${i ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
  },
  bytes: (n) => fmt.unit(n ?? 0, ["o", "Ko", "Mo", "Go", "To"], 1024),
  bits: (n) => fmt.unit(n ?? 0, ["b/s", "Kb/s", "Mb/s", "Gb/s"], 1000),
  percent: (part, total) => `${total ? Math.round((part / total) * 100) : 0} %`,
  clock(seconds) {
    const s = Math.max(0, Math.floor(seconds));
    return [s / 3600, (s % 3600) / 60, s % 60].map((v) => String(Math.floor(v)).padStart(2, "0")).join(":");
  },
  duration(s) {
    s = Math.round(s ?? 0);
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}s`;
    return `${Math.floor(s / 3600)}h${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
  },
  time: (iso) => (iso ? iso.slice(11, 19) : ""),
  ago(ts) {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 10) return "à l'instant";
    if (s < 60) return `il y a ${Math.floor(s)} s`;
    if (s < 3600) return `il y a ${Math.floor(s / 60)} min`;
    if (s < 86400) return `il y a ${Math.floor(s / 3600)} h`;
    return new Date(ts * 1000).toLocaleDateString("fr-FR");
  },
  endpoint: (ip, port) => (port === null || port === undefined ? ip : `${ip}:${port}`),
};

const SEVERITY = { 4: "Critique", 3: "Élevée", 2: "Moyenne", 1: "Faible", 0: "Info" };
const severityPill = (sev) => h("span", { class: `status sev-${sev}` }, SEVERITY[sev] ?? "");

// ================================================================== icônes (24×24, trait)

const ICONS = {
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  list: "M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01",
  flow: "M4 7h13m0 0-3-3m3 3-3 3M20 17H7m0 0 3-3m-3 3 3 3",
  server: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
  bell: "M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0",
  chart: "M3 3v18h18M8 16v-4M13 16V8M18 16V5",
  download: "M12 3v12m0 0-4-4m4 4 4-4M5 21h14",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8",
  sun: "M12 3v2M12 19v2M5 5l1.4 1.4M17.6 17.6 19 19M3 12h2M19 12h2M5 19l1.4-1.4M17.6 6.4 19 5M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8",
  help: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3",
  arrow: "M7 17 17 7M8 7h9v9",
  play: "M7 4v16l13-8z",
  pause: "M6 4h4v16H6zM14 4h4v16h-4z",
  stop: "M6 6h12v12H6z",
  wifi: "M5 12.6a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 8.8a15 15 0 0 1 20 0M12 20h.01",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM12 8v4M12 16h.01",
  plus: "M12 5v14M5 12h14",
  radar: "M12 12 19 5M12 2a10 10 0 1 0 10 10M12 6a6 6 0 1 0 6 6M12 10a2 2 0 1 0 2 2",
  x: "M18 6 6 18M6 6l12 12",
  info: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01",
  warn: "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01",
  check: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM8 12l3 3 5-6",
  mute: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM3 3l18 18",
  trash: "M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v6M14 11v6",
  down: "M12 5v14m0 0-6-6m6 6 6-6",
};

function icon(name, solid = false) {
  return svg("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", class: solid ? "icon solid" : "icon" },
    svg("path", { d: ICONS[name] }));
}

function setIcon(el, name) {
  el.dataset.icon = name;
  el.replaceChildren(icon(name, el.classList.contains("solid")));
}

const hydrateIcons = (root = document) => $$("[data-icon]", root).forEach((el) => setIcon(el, el.dataset.icon));

// ================================================================== API

const token = (() => {
  const match = location.hash.match(/token=([^&]+)/);
  try {
    if (match) {
      sessionStorage.setItem("pp-token", match[1]);
      history.replaceState(null, "", location.pathname);
      return match[1];
    }
    return sessionStorage.getItem("pp-token") ?? "";
  } catch {
    return match ? match[1] : "";
  }
})();

function apiUrl(path, params = {}) {
  const url = new URL(path, location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== "" && value !== undefined && value !== null) url.searchParams.set(key, value);
  }
  return url;
}

async function api(path, params = {}, options = {}) {
  const response = await fetch(apiUrl(path, params), {
    ...options,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || response.statusText);
  return body;
}

// ================================================================== état & retours utilisateur

const state = {
  view: "dashboard",
  filter: "",
  sort: { flows: "last", hosts: "bytes" },
  status: null,
  statusAt: 0,
  frozen: false,
  busy: false,
  conditions: new Map(),
  notifications: [],
  unread: 0,
  rules: {},   // identifiant de règle → description (GET /api/allowlist)
};

const ruleName = (id) => state.rules[id] ?? id;

/* Fenêtre de message : tone = error | warn | info | ok. Résout avec la valeur du bouton choisi. */
const MESSAGE_TONES = {
  error: { sev: "4", icon: "warn" },
  warn: { sev: "2", icon: "warn" },
  info: { sev: "info", icon: "info" },
  ok: { sev: "ok", icon: "check" },
};

/* Les messages s'affichent l'un après l'autre : aucun n'en écrase un autre resté ouvert. */
let messageQueue = Promise.resolve();

function showMessage(options) {
  const shown = messageQueue.then(() => presentMessage(options));
  messageQueue = shown;
  return shown;
}

function presentMessage({ tone = "info", title, text, actions = [{ label: "Compris", value: true, primary: true }] }) {
  const dialog = $("#message");
  const look = MESSAGE_TONES[tone];
  dialog.dataset.sev = look.sev;
  setIcon($(".message-icon i", dialog), look.icon);
  $("#message-title").textContent = title;
  $("#message-text").textContent = text;
  return new Promise((resolve) => {
    $("#message-actions").replaceChildren(...actions.map((a) => h("button", {
      class: `btn ${a.primary ? (tone === "error" ? "btn-danger" : "btn-primary") : "btn-ghost"}`,
      type: "button",
      onclick: () => dialog.close(String(a.value)),
    }, a.label)));
    dialog.returnValue = "";
    dialog.addEventListener("close", () => resolve(dialog.returnValue), { once: true });
    dialog.showModal();
  });
}

const failure = (error) => showMessage({ tone: "error", title: "Action impossible", text: error.message });

/* Condition durable (erreur de capture, perte de paquets, connexion…) :
   signalée une seule fois tant qu'elle dure, oubliée dès qu'elle disparaît. */
function condition(key, title, text) {
  if (!text) {
    state.conditions.delete(key);
    return;
  }
  if (state.conditions.has(key)) return;
  state.conditions.set(key, text);
  showMessage({ tone: "warn", title, text });
}

/* Notification éphémère (7 s, en pause au survol) ; sev = 0-4 | ok | info. */
function notify({ sev = "info", icon: name = "info", title, text, action = null }) {
  const el = h("div", { class: "notify", role: "status", "data-sev": sev },
    h("span", { class: "tile round" }, icon(name)),
    h("div", { class: "notify-body" }, h("b", { title }, title), h("p", {}, text),
      action ? h("button", { class: "btn btn-outline btn-sm", type: "button", onclick: () => { dismiss(); action.run(); } }, action.label) : null),
    h("button", { class: "round-btn close-btn", type: "button", "aria-label": "Fermer", onclick: () => dismiss() }, icon("x")),
    h("span", { class: "notify-timer", onanimationend: () => dismiss() }));
  function dismiss() {
    el.classList.add("leaving");
  }
  // La fin du minuteur remonte aussi jusqu'ici : seule l'animation de sortie de la carte compte.
  el.addEventListener("animationend", (event) => {
    if (event.target === el && el.classList.contains("leaving")) el.remove();
  });
  $("#toasts").append(el);
  while ($("#toasts").children.length > 4) $("#toasts").firstElementChild.remove();
}

/* Centre de notifications : historique des alertes reçues en temps réel. */
const NOTIFICATIONS_KEPT = 30;

function pushNotification(alert) {
  state.notifications.unshift(alert);
  state.notifications.length = Math.min(state.notifications.length, NOTIFICATIONS_KEPT);
  state.unread += 1;
  renderBell();
  if ($("#notif-panel").open) renderNotifications();
}

function renderBell() {
  $("#bell-dot").hidden = !state.unread;
}

function renderNotifications() {
  const items = state.notifications;
  $("#notif-count").textContent = state.unread ? `${state.unread} non lue${state.unread > 1 ? "s" : ""}` : "";
  $("#notif-list").replaceChildren(...(items.length
    ? items.map((a, i) => row({
      lead: h("span", { class: `tile round tone-${a.severity}` }, icon("shield")),
      attrs: { class: `row${i < state.unread ? " unread" : ""}` },
      title: a.title,
      trailing: severityPill(a.severity),
      details: meta(`${a.src} → ${a.dst} · ${fmt.ago(a.ts)}`),
      onClick: () => { $("#notif-panel").close(); openAlert(a); },
    }))
    : [row({ lead: h("span", { class: "tile round tone-ok" }, icon("check")), title: "Aucune notification",
      details: meta("Les nouvelles alertes apparaîtront ici.") })]));
}

function openNotifications() {
  renderNotifications();
  $("#notif-panel").showModal();
  state.unread = 0;
  renderBell();
}

// ================================================================== graphiques

/* Histogramme « en bande » : 8 piliers de 15 s ; pic en orange foncé, forts en orange, période en cours en orange clair. */
const PILLS = 8;

function buildPills() {
  $("#pills").replaceChildren(...Array.from({ length: PILLS }, () =>
    h("div", { class: "pill-col" }, h("div", { class: "pill-track" }, h("span", { class: "pill-tip", hidden: "" }), h("div", { class: "pill" })),
      h("span", { class: "pill-label" }))));
}

function renderPills(bps) {
  const size = Math.floor(bps.length / PILLS);
  const buckets = Array.from({ length: PILLS }, (_, i) => sum(bps.slice(i * size, (i + 1) * size)) / size);
  const top = Math.max(...buckets, 1);
  const peak = buckets.indexOf(Math.max(...buckets));
  const now = Date.now();
  $$("#pills .pill-col").forEach((col, i) => {
    const height = `${Math.max(16, (buckets[i] / top) * 100)}%`;
    const current = i === PILLS - 1;
    const pill = $(".pill", col);
    const level = i === peak && buckets[i] > 0 ? "peak" : buckets[i] >= top * 0.6 ? "high" : "";
    pill.className = `pill ${current ? "current" : level}`;
    pill.style.height = height;
    const tip = $(".pill-tip", col);
    tip.hidden = !current;
    tip.style.setProperty("--h", height);
    tip.textContent = fmt.bits(buckets[i]);
    $(".pill-label", col).textContent = new Date(now - (PILLS - 1 - i) * size * 1000)
      .toLocaleTimeString("fr-FR", { minute: "2-digit", second: "2-digit" });
  });
}

/* Jauge en demi-disque : parts chiffré / en clair / autre (segments séparés par un espace). */
const GAUGE_GAP = 3;

function renderGauge(enc) {
  const total = enc.encrypted + enc.cleartext + enc.other;
  let start = 0;
  for (const key of ["encrypted", "cleartext", "other"]) {
    const length = total ? (enc[key] / total) * 100 : 0;
    const seg = $(`.seg-${key}`);
    seg.setAttribute("visibility", length > GAUGE_GAP ? "visible" : "hidden");
    seg.setAttribute("stroke-dasharray", `${Math.max(0, length - GAUGE_GAP)} 100`);
    seg.setAttribute("stroke-dashoffset", String(-start));
    start += length;
  }
  $("#gauge-value").textContent = total ? fmt.percent(enc.encrypted, total).replace(" ", "") : "-";
}

/* Anneau (disque) pour une répartition : 5 séries + « autres » hachuré. */
function donut(items, total, centerLabel) {
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const shown = items.slice(0, 5);
  const rest = Math.max(0, total - sum(shown.map((x) => x.value)));
  const series = [...shown.map((x, i) => ({ ...x, cls: `series-${i}` })),
    ...(rest > 0 ? [{ label: "Autres", value: rest, cls: "series-rest" }] : [])];
  let offset = 0;
  const ring = svg("svg", { viewBox: "0 0 150 150" },
    svg("circle", { class: "ring-track", cx: 75, cy: 75, r: radius }),
    ...series.map((s) => {
      const length = total ? (s.value / total) * circumference : 0;
      const arc = svg("circle", {
        class: s.cls, cx: 75, cy: 75, r: radius,
        "stroke-dasharray": `${Math.max(0, length - 2)} ${circumference}`, "stroke-dashoffset": String(-offset),
      });
      offset += length;
      return arc;
    }));
  return h("div", { class: "donut-wrap" },
    h("div", { class: "donut" }, ring, h("div", { class: "donut-center" }, h("strong", {}, fmt.count(total)), h("span", {}, centerLabel))),
    h("ul", { class: "donut-legend" }, series.map((s) =>
      h("li", {}, h("span", { class: `swatch ${s.cls}` }), h("span", { class: "name", title: s.label }, s.label),
        h("span", { class: "muted" }, fmt.percent(s.value, total))))));
}

/* Classement en bandes horizontales. */
function bands(rows) {
  if (!rows.length) return h("div", { class: "muted" }, "Aucune donnée");
  const top = Math.max(...rows.map((r) => r.value), 1);
  return h("div", { class: "rank" }, rows.flatMap((row) => {
    const fill = h("span");
    fill.style.width = `${(row.value / top) * 100}%`;
    return [h("span", { class: "name", title: row.label }, row.label), h("div", { class: "bar" }, fill),
      h("span", { class: "muted" }, row.shown)];
  }));
}

// ================================================================== état général (SSE)

const KPIS = {
  packets: { value: (s) => fmt.count(s.packets), chip: (s) => `${fmt.count(last(s.pps))}/s`, text: (s) => `${fmt.bytes(s.bytes)} capturés` },
  traffic: { value: (s) => fmt.bits(last(s.bps)), chip: (s) => `max ${fmt.bits(Math.max(...s.bps))}`, text: () => "sur 2 minutes" },
  flows: { value: (s) => fmt.count(s.flows), chip: (s) => `${fmt.count(s.hosts)} hôtes`, text: () => "conversations suivies" },
  alerts: {
    value: (s) => fmt.count(sum(Object.values(s.alerts))),
    chip: (s) => `${s.alerts["4"] ?? 0} critiques`,
    text: (s) => `${s.alerts["3"] ?? 0} élevées`,
  },
};

function renderStatus(s) {
  state.status = s;
  state.statusAt = Date.now();
  const live = s.mode === "live";
  const pending = s.unacked ?? 0;

  // Un fichier est désigné par son nom seul ; le chemin complet reste en info-bulle.
  const sourceName = s.mode === "live" || s.mode === "idle" ? s.source : s.source?.split(/[\\/]/).pop();
  $("#source-name").textContent = sourceName || "-";
  $("#source-name").title = s.source || "";
  $("#source-state").textContent = { live: "Capture en direct", file: "Lecture de fichier", done: "Fichier analysé", idle: "Capture arrêtée" }[s.mode] ?? s.mode;
  $(".source").classList.toggle("live", live);
  $("#promo-text").textContent = `${sourceName || "Interface par défaut"} · BPF ${s.bpf || "aucun"}`;
  $("#nav-badge").hidden = !pending;
  $("#nav-badge").textContent = pending > 99 ? "99+" : String(pending);
  $("#nav-badge").title = `${pending} alerte${pending > 1 ? "s" : ""} à traiter`;

  $$(".capture-icon").forEach((el) => setIcon(el, live ? "stop" : "play"));
  $$(".capture-label").forEach((el) => { el.textContent = live ? el.dataset.stop : el.dataset.start; });
  condition("capture", "Erreur de capture", s.error);
  condition("store", "Enregistrement des alertes", s.store_error);
  condition("dropped", "Paquets perdus", s.dropped
    ? `${fmt.count(s.dropped)} paquets perdus (file d'analyse saturée) - restreignez la capture avec un filtre BPF.` : "");

  for (const [key, kpi] of Object.entries(KPIS)) {
    const card = $(`[data-kpi="${key}"]`);
    $(".kpi-value", card).textContent = kpi.value(s);
    $(".chip", card).textContent = kpi.chip(s);
    $(".trend-text", card).textContent = kpi.text(s);
  }
  $('[data-kpi="alerts"]').classList.toggle("alerting", Boolean(s.alerts["4"] || s.alerts["3"]));
  renderPills(s.bps);
  $("#traffic-now").textContent = `${fmt.bits(last(s.bps))} · ${fmt.count(last(s.pps))} paquets/s`;
  renderUptime();
}

function renderUptime() {
  const s = state.status;
  if (!s) return;
  const running = s.mode === "live" || s.mode === "file";
  $("#uptime").textContent = fmt.clock(s.uptime + (running ? (Date.now() - state.statusAt) / 1000 : 0));
}

// ================================================================== tableau de bord

const HUES = 5;
const hueOf = (text) => [...text].reduce((acc, ch) => acc + ch.charCodeAt(0), 0) % HUES;

/* Ligne de liste : visuel à gauche, titre et valeur alignés, détails en dessous. */
function row({ lead, title, trailing = null, details = null, onClick, attrs = {} }) {
  return h("li", { class: "row", onclick: onClick, ...attrs }, lead,
    h("div", { class: "row-main" },
      h("div", { class: "row-line" }, h("span", { class: "row-title", title }, title), trailing),
      details));
}

function meter(fraction) {
  const fill = h("span");
  fill.style.width = `${Math.max(2, fraction * 100)}%`;
  return h("div", { class: "meter" }, fill);
}

const meta = (text) => h("span", { class: "row-meta" }, text);

function renderTalkers(talkers) {
  const top = Math.max(...talkers.map((t) => t.bytes), 1);
  $("#talkers").replaceChildren(...(talkers.length
    ? talkers.slice(0, 6).map((t) => row({
      lead: h("span", { class: `tile hue-${hueOf(t.ip)}` }, icon("server")),
      title: t.name || t.ip,
      trailing: h("span", { class: "row-value" }, fmt.bytes(t.bytes)),
      details: [meter(t.bytes / top), t.name ? meta(t.ip) : null],
      onClick: () => pivot(`ip.addr == ${t.ip}`),
    }))
    : [row({ lead: h("span", { class: "tile hue-4" }, icon("server")), title: "Aucun hôte pour l'instant",
      details: meta("Les hôtes apparaissent dès les premiers paquets.") })]));
}

function renderRecentAlerts(alerts) {
  const recent = alerts.slice(-5).reverse();
  $("#recent-alerts").replaceChildren(...(recent.length
    ? recent.map((a) => row({
      lead: h("span", { class: "event-dot" }),
      attrs: { "data-sev": a.severity },
      title: a.title,
      trailing: severityPill(a.severity),
      details: meta(`${a.category} · ${a.src} → ${a.dst} · ${fmt.ago(a.ts)}`),
      onClick: () => openAlert(a),
    }))
    : [row({ lead: h("span", { class: "event-dot" }), attrs: { "data-sev": "ok" }, title: "Aucune alerte",
      trailing: h("span", { class: "status ok-pill" }, "Sain"), details: meta("Rien de suspect détecté.") })]));

  const latest = [...alerts].reverse().find((a) => a.severity >= 3) ?? alerts[alerts.length - 1];
  const button = $("#last-alert-open");
  $("#last-alert-title").textContent = latest ? latest.title : "Aucune alerte";
  $("#last-alert-meta").textContent = latest
    ? `${SEVERITY[latest.severity]} · ${fmt.time(latest.time)} · ${latest.src} → ${latest.dst}`
    : "Le réseau semble calme.";
  button.disabled = !latest;
  button.onclick = latest ? () => openAlert(latest) : null;
}

async function refreshDashboard() {
  const after = Math.max(0, (state.status?.last_alert ?? 0) - 20);
  const [analytics, alerts] = await Promise.all([api("/api/analytics", { limit: 6 }), api("/api/alerts", { after })]);
  renderTalkers(analytics.talkers);
  renderRecentAlerts(alerts.items);
  renderGauge(analytics.encryption);
}

// ================================================================== vues en liste

const protoCell = (proto) => h("span", { class: "proto" }, proto);
const geoText = (geo) => (geo ? `${geo.country}${geo.city ? ` · ${geo.city}` : ""}` : "");
const sorter = (kind) => ({ value: state.sort[kind], set: (key) => { state.sort[kind] = key; refresh(); } });
const STATE_OK = new Set(["ESTABLISHED", "CLOSED"]);

/* columns : [{ label, cell(row) → texte|Node, cls?, sort? }] ; onClick facultatif ; rowClass(row) → classe. */
function table(columns, rows, onClick, sortState, rowClass = () => "") {
  if (!rows.length) return h("div", { class: "empty" }, "Aucune donnée pour l'instant.");
  const head = columns.map((col) => {
    const sorted = col.sort && sortState?.value === col.sort;
    const arrow = sorted ? icon("down") : null;
    arrow?.classList.add("sort-icon");
    return h("th", {
      class: [col.sort && "sortable", sorted && "sorted"].filter(Boolean).join(" "),
      onclick: col.sort ? () => sortState.set(col.sort) : undefined,
    }, col.label, arrow);
  });
  const body = rows.map((row) => h("tr", { class: [rowClass(row), !onClick && "inert"].filter(Boolean).join(" "),
    onclick: onClick ? () => onClick(row) : undefined },
    columns.map((col) => h("td", { class: col.cls }, col.cell(row) ?? ""))));
  return h("table", {}, h("thead", {}, h("tr", {}, head)), h("tbody", {}, body));
}

const COLUMNS = {
  alerts: [
    { label: "Heure", cell: (a) => fmt.time(a.time), cls: "mono" },
    { label: "Sévérité", cell: (a) => severityPill(a.severity) },
    { label: "Catégorie", cell: (a) => a.category },
    { label: "Alerte", cell: (a) => h("b", {}, a.title) },
    { label: "Source", cell: (a) => a.src, cls: "mono" },
    { label: "Destination", cell: (a) => a.dst, cls: "mono" },
    { label: "État", cell: (a) => (a.acked ? h("span", { class: "status ok-pill" }, "Acquittée") : h("span", { class: "status sev-0" }, "À traiter")) },
  ],
  allowlist: [
    { label: "Règle", cell: (e) => (e.rule ? h("b", { title: e.rule }, ruleName(e.rule)) : "Toutes") },
    { label: "Source", cell: (e) => e.src ?? "Toutes", cls: "mono" },
    { label: "Destination", cell: (e) => e.dst ?? "Toutes", cls: "mono" },
    { label: "Motif", cell: (e) => e.reason || "-" },
    { label: "Origine", cell: (e) => h("span", { class: `status ${e.origin === "api" ? "sev-1" : "sev-0"}` }, e.origin === "api" ? "Tableau de bord" : "Fichier --rules") },
    { label: "Créée", cell: (e) => (e.created ? fmt.ago(e.created) : "-") },
    { label: "", cell: (e) => (e.origin === "api"
      ? h("button", { class: "round-btn close-btn", type: "button", "aria-label": "Supprimer l'exception", onclick: () => removeAllow(e) }, icon("trash"))
      : "") },
  ],
  packets: [
    { label: "", cell: (p) => (p.severity === null ? "" : h("span", { class: `mark sev-${p.severity}` })) },
    { label: "No.", cell: (p) => p.id, cls: "num mono" },
    { label: "Heure", cell: (p) => fmt.time(p.time), cls: "mono" },
    { label: "Source", cell: (p) => p.src, cls: "mono" },
    { label: "Destination", cell: (p) => p.dst, cls: "mono" },
    { label: "Proto", cell: (p) => protoCell(p.proto) },
    { label: "Long.", cell: (p) => p.length, cls: "num" },
    { label: "Info", cell: (p) => p.info },
  ],
  flows: [
    { label: "#", cell: (f) => f.id, cls: "num mono" },
    { label: "Proto", cell: (f) => protoCell(f.app || f.l4) },
    { label: "Client", cell: (f) => fmt.endpoint(f.client, f.client_port), cls: "mono" },
    { label: "Serveur", cell: (f) => fmt.endpoint(f.server, f.server_port), cls: "mono" },
    { label: "Pays", cell: (f) => geoText(f.geo) },
    { label: "Paquets", cell: (f) => fmt.count(f.packets), cls: "num", sort: "packets" },
    { label: "Octets", cell: (f) => fmt.bytes(f.bytes), cls: "num", sort: "bytes" },
    { label: "Durée", cell: (f) => fmt.duration(f.duration), cls: "num", sort: "duration" },
    { label: "État", cell: (f) => (f.state ? h("span", { class: `status ${STATE_OK.has(f.state) ? "ok-pill" : f.state === "RESET" ? "sev-4" : "sev-2"}` }, f.state) : "-") },
    { label: "Domaine / SNI", cell: (f) => f.label },
    { label: "Vu", cell: (f) => fmt.time(f.last), cls: "mono", sort: "last" },
  ],
  hosts: [
    { label: "Adresse", cell: (x) => h("b", {}, x.ip), cls: "mono" },
    { label: "MAC", cell: (x) => x.mac || "-", cls: "mono" },
    { label: "Système", cell: (x) => (x.os ? `${x.os} ${x.os_confidence}%` : "-") },
    { label: "Localisation", cell: (x) => (x.local ? "LAN" : geoText(x.geo)) },
    { label: "Noms", cell: (x) => x.names.slice(0, 2).join(", ") },
    { label: "Émis", cell: (x) => fmt.bytes(x.bytes_tx), cls: "num" },
    { label: "Reçus", cell: (x) => fmt.bytes(x.bytes_rx), cls: "num", sort: "bytes" },
    { label: "Pairs", cell: (x) => x.peers, cls: "num", sort: "peers" },
    { label: "Services", cell: (x) => x.services.slice(0, 4).join(" ") },
    { label: "Vu", cell: (x) => fmt.time(x.last_seen), cls: "mono", sort: "last" },
  ],
};

const VIEWS = {
  dashboard: { title: "Tableau de bord", load: refreshDashboard },
  packets: {
    title: "Paquets",
    subtitle: () => (state.filter ? `Filtre : ${state.filter}` : "Derniers paquets capturés - filtrez depuis la barre de recherche."),
    load: () => api("/api/packets", { filter: state.filter, limit: 1000 }),
    render: (d) => table(COLUMNS.packets, d.items.reverse(), (p) => openPacket(p.id)),
  },
  flows: {
    title: "Flux",
    subtitle: () => "Conversations bidirectionnelles - cliquez pour suivre l'échange (déchiffré si possible).",
    load: () => api("/api/flows", { sort: state.sort.flows, limit: 1000 }),
    render: (d) => table(COLUMNS.flows, d.items, (f) => openConversation(f.id), sorter("flows")),
  },
  hosts: {
    title: "Hôtes",
    subtitle: () => "Inventaire passif : système, noms, services, localisation.",
    load: () => api("/api/hosts", { sort: state.sort.hosts, limit: 1000 }),
    render: (d) => table(COLUMNS.hosts, d.items, (x) => pivot(`ip.addr == ${x.ip}`), sorter("hosts")),
  },
  alerts: {
    title: "Alertes",
    subtitle: () => "Détections en temps réel, de la plus récente à la plus ancienne.",
    load: () => api("/api/alerts", { limit: 2000 }),
    render: (d) => table(COLUMNS.alerts, d.items.reverse(), openAlert, null, (a) => (a.acked ? "acked" : "")),
  },
  allowlist: {
    title: "Exceptions",
    subtitle: () => "Liste blanche : alertes ignorées par règle, source ou destination. Celles du fichier --rules se modifient dans le fichier.",
    load: () => api("/api/allowlist"),
    render: (d) => {
      state.rules = d.rules;
      return d.items.length
        ? table(COLUMNS.allowlist, d.items)
        : h("div", { class: "empty" }, "Aucune exception. Depuis une alerte, « Ignorer » en crée une.");
    },
  },
  analytics: {
    title: "Analyse",
    subtitle: () => "Répartitions en anneau, classements en bandes.",
    load: () => api("/api/analytics", { limit: 10 }),
    render: (d) => h("div", { class: "rank-grid" },
      h("section", { class: "card" }, h("h3", {}, "Protocoles"),
        donut(d.protocols.map((p) => ({ label: p.name, value: p.count })), state.status?.packets ?? sum(d.protocols.map((p) => p.count)), "paquets")),
      h("section", { class: "card" }, h("h3", {}, "Chiffrement"),
        donut([{ label: "Chiffré", value: d.encryption.encrypted }, { label: "En clair", value: d.encryption.cleartext }],
          d.encryption.encrypted + d.encryption.cleartext + d.encryption.other, "paquets")),
      h("section", { class: "card" }, h("h3", {}, "Pays"),
        donut(d.countries.map((c) => ({ label: `${c.code} ${c.name}`, value: c.bytes })), sum(d.countries.map((c) => c.bytes)), "octets")),
      h("section", { class: "card" }, h("h3", {}, "Hôtes les plus actifs"),
        bands(d.talkers.map((t) => ({ label: t.name ? `${t.ip}  ${t.name}` : t.ip, value: t.bytes, shown: fmt.bytes(t.bytes) })))),
      h("section", { class: "card" }, h("h3", {}, "Domaines"),
        bands(d.domains.map((x) => ({ label: x.name, value: x.count, shown: fmt.count(x.count) })))),
      h("section", { class: "card" }, h("h3", {}, "Services"),
        bands(d.services.map((x) => ({ label: x.name, value: x.count, shown: `${fmt.count(x.count)} cnx` }))))),
  },
};

async function refresh() {
  if (state.busy || state.frozen || document.hidden || $("dialog[open]")) return;
  state.busy = true;
  const view = VIEWS[state.view];
  try {
    const data = await view.load();
    if (view.render) {
      const container = $("#view");
      const scroll = container.scrollTop;
      container.replaceChildren(view.render(data));
      container.scrollTop = scroll;
      $("#list-subtitle").textContent = view.subtitle();
    }
    $(".search").classList.remove("bad");
    condition("refresh", "", "");
  } catch (error) {
    if (state.view === "packets") {
      $(".search").classList.add("bad");
      $("#list-subtitle").textContent = error.message;
    } else {
      condition("refresh", "Actualisation impossible", error.message);
    }
  } finally {
    state.busy = false;
  }
}

function showView(name) {
  state.view = name;
  const isDashboard = name === "dashboard";
  $$(".nav-item[data-view]").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $("#page-dashboard").hidden = !isDashboard;
  $("#page-list").hidden = isDashboard;
  if (!isDashboard) {
    $("#list-title").textContent = VIEWS[name].title;
    $("#list-subtitle").textContent = VIEWS[name].subtitle();
    $("#view").replaceChildren(h("div", { class: "empty" }, "Chargement…"));
  }
  refresh();
}

function pivot(filter) {
  state.filter = filter;
  $("#filter").value = filter;
  showView("packets");
}

// ================================================================== fenêtres de détail

function openModal(title, iconName, ...content) {
  $("#modal-title").textContent = title;
  setIcon($("#modal-icon i"), iconName);
  $("#modal-body").replaceChildren(...content.flat().filter(Boolean));
  $("#modal").showModal();
}

const keyValues = (pairs) => h("dl", { class: "kv" }, pairs.filter(([, v]) => v !== "" && v !== null && v !== undefined)
  .flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));

function openAlert(a) {
  const close = () => $("#modal").close();
  openModal(a.title, "shield",
    keyValues([
      ["Heure", a.time.replace("T", " ")], ["Sévérité", severityPill(a.severity)], ["Règle", `${ruleName(a.rule)} (${a.rule})`],
      ["Catégorie", a.category], ["Source", a.src], ["Destination", a.dst],
      ["État", a.acked ? "Acquittée" : "À traiter"],
    ]),
    a.detail ? h("pre", {}, a.detail) : null,
    h("div", { class: "modal-actions" },
      a.packet ? h("button", { class: "btn btn-outline", type: "button", onclick: () => { close(); openPacket(a.packet); } },
        icon("list"), "Voir le paquet") : null,
      h("button", { class: "btn btn-ghost", type: "button", onclick: () => ignoreAlert(a) }, icon("mute"), "Ignorer pour cette source"),
      a.acked ? null : h("button", { class: "btn btn-primary", type: "button", onclick: () => { close(); ackAlerts([a.id]); } },
        icon("check"), "Acquitter")));
}

async function ackAlerts(ids) {
  try {
    const { acked } = await api("/api/alerts/ack", {}, { method: "POST", body: JSON.stringify({ ids }) });
    notify({ sev: "ok", icon: "check", title: acked > 1 ? `${acked} alertes acquittées` : "Alerte acquittée", text: "Elle reste consultable dans l'historique." });
    refresh();
  } catch (error) {
    failure(error);
  }
}

async function ignoreAlert(a) {
  const choice = await showMessage({
    tone: "warn",
    title: "Ignorer ces alertes ?",
    text: `« ${ruleName(a.rule)} » ne sera plus signalée pour ${a.src}. Les alertes actuelles correspondantes seront acquittées. Vous pourrez annuler depuis Exceptions.`,
    actions: [{ label: "Annuler", value: "" }, { label: "Ignorer", value: "yes", primary: true }],
  });
  if (choice !== "yes") return;
  try {
    const { acked } = await api("/api/allowlist", {}, {
      method: "POST", body: JSON.stringify({ rule: a.rule, src: a.src, reason: `Depuis l'alerte #${a.id} : ${a.title}`.slice(0, 200) }),
    });
    $("#modal").close();
    notify({ sev: "ok", icon: "mute", title: "Exception ajoutée", text: `${ruleName(a.rule)} · ${a.src}${acked ? ` · ${acked} alerte(s) acquittée(s)` : ""}` });
    refresh();
  } catch (error) {
    failure(error);
  }
}

async function removeAllow(e) {
  const choice = await showMessage({
    tone: "warn",
    title: "Supprimer l'exception ?",
    text: `${e.rule ? ruleName(e.rule) : "Toutes les règles"} · source ${e.src ?? "toutes"} · destination ${e.dst ?? "toutes"}. Les alertes correspondantes seront de nouveau levées.`,
    actions: [{ label: "Annuler", value: "" }, { label: "Supprimer", value: "yes", primary: true }],
  });
  if (choice !== "yes") return;
  try {
    await api(`/api/allowlist/${e.id}`, {}, { method: "DELETE" });
    notify({ sev: "info", icon: "trash", title: "Exception supprimée", text: e.reason || ruleName(e.rule ?? "") });
    refresh();
  } catch (error) {
    failure(error);
  }
}

async function openPacket(id) {
  try {
    const p = await api(`/api/packets/${id}`);
    const layers = p.layers.map((layer, i) => h("details", { open: i < 4 ? "" : undefined },
      h("summary", {}, layer.name),
      h("table", {}, h("tbody", {}, layer.fields.map(([k, v]) => h("tr", {}, h("td", { class: "muted" }, k), h("td", { class: "mono" }, v)))))));
    const hex = p.hex.map(([offset, bytes, ascii]) => `${offset}  ${bytes.padEnd(49)} │${ascii}`).join("\n");
    openModal(`Paquet ${p.id} · ${p.proto}`, "list",
      keyValues([
        ["Heure", p.time], ["Source", fmt.endpoint(p.src, p.sport)], ["Destination", fmt.endpoint(p.dst, p.dport)],
        ["Longueur", `${p.length} octets`], ["Info", p.info], ["Domaine", p.domain], ["JA3", p.ja3], ["JA4", p.ja4],
        ["Flux", p.flow ? h("a", { href: "#", onclick: (e) => { e.preventDefault(); openConversation(p.flow); } }, `#${p.flow} - suivre l'échange`) : ""],
      ]),
      p.alerts.map((a) => h("div", { class: "note" }, severityPill(a.severity), " ", h("b", {}, a.title), h("pre", {}, a.detail))),
      p.application ? h("details", { open: "" }, h("summary", {}, "Données applicatives"), h("pre", {}, JSON.stringify(p.application, null, 2))) : null,
      layers,
      h("details", {}, h("summary", {}, "Hexadécimal"), h("pre", {}, hex)));
  } catch (error) {
    failure(error);
  }
}

async function openConversation(flowId) {
  try {
    const c = await api(`/api/flows/${flowId}/conversation`);
    const f = c.flow;
    const bytesFrom = (client) => fmt.bytes(sum(c.chunks.filter((x) => x.client === client).map((x) => x.size)));
    openModal(`Flux #${f.id} · ${f.app || f.l4}`, "flow",
      keyValues([
        ["Client", `${fmt.endpoint(f.client, f.client_port)} → ${bytesFrom(true)}`],
        ["Serveur", `${fmt.endpoint(f.server, f.server_port)} → ${bytesFrom(false)}`],
        ["Domaine", f.label], ["État", f.state],
      ]),
      c.note ? h("div", { class: `note ${c.decrypted ? "ok" : ""}` }, c.note) : null,
      h("div", { class: "stream" }, c.chunks.length
        ? c.chunks.map((x) => h("pre", { class: x.client ? "client" : "server" }, x.text))
        : h("div", { class: "empty" }, "Aucune donnée applicative dans les paquets conservés.")),
      h("button", { class: "btn btn-outline", type: "button", onclick: () => { $("#modal").close(); pivot(`flow == ${f.id}`); } },
        "Voir les paquets de ce flux"));
  } catch (error) {
    failure(error);
  }
}

function openHelp() {
  const rows = (pairs) => h("table", {}, h("tbody", {}, pairs.map(([k, v]) => h("tr", {}, h("td", { class: "mono" }, k), h("td", {}, v)))));
  openModal("Aide & API", "help",
    h("div", { class: "help-grid" },
      h("section", {}, h("h3", {}, "Filtre d'affichage"), rows([
        ["tls or dns", "protocoles"], ["ip.addr == 10.0.0.0/8", "adresse ou réseau"], ["port 443", "port"],
        ['domain contains "google"', "SNI / Host / DNS"], ["alert >= high", "paquets en alerte"], ["flow == 12", "une conversation"],
      ])),
      h("section", {}, h("h3", {}, "API REST (jeton Bearer)"), rows([
        ["GET /api/status", "état et compteurs"], ["GET /api/events", "flux SSE temps réel"], ["GET /api/packets?filter=", "paquets"],
        ["GET /api/flows/{id}/conversation", "échange (déchiffré)"], ["GET /api/export.pcap", "export PCAP"],
        ["POST /api/capture", "démarrer / arrêter"], ["GET /api/alerts/history", "historique filtré"],
        ["POST /api/alerts/ack", "acquitter"], ["GET|POST /api/allowlist", "exceptions"],
      ]))));
}

// ================================================================== actions

async function toggleCapture() {
  try {
    const action = state.status?.mode === "live" ? "stop" : "start";
    const s = await api("/api/capture", {}, { method: "POST", body: JSON.stringify({ action }) });
    renderStatus(s);
    notify(action === "start"
      ? { sev: "ok", icon: "radar", title: "Capture démarrée", text: `${s.source || "Interface par défaut"} · BPF ${s.bpf || "aucun"}` }
      : { sev: "info", icon: "stop", title: "Capture arrêtée", text: `${fmt.count(s.packets)} paquets analysés.` });
  } catch (error) {
    failure(error);
  }
}

function renderThemeControls() {
  const dark = window.ppTheme.current === "dark";
  $$(".theme-icon").forEach((el) => setIcon(el, dark ? "sun" : "moon"));
  $$(".theme-label").forEach((el) => { el.textContent = dark ? "Thème clair" : "Thème sombre"; });
}

function toggleFreeze() {
  state.frozen = !state.frozen;
  setIcon($(".freeze-icon"), state.frozen ? "play" : "pause");
  if (!state.frozen) refresh();
}

const ACTIONS = {
  capture: toggleCapture,
  export: () => location.assign(apiUrl("/api/export.pcap", { token, filter: state.view === "packets" ? state.filter : "" })),
  theme: () => { window.ppTheme.toggle(); renderThemeControls(); },
  help: openHelp,
  notifications: openNotifications,
  freeze: toggleFreeze,
};

// ================================================================== démarrage

function connectEvents() {
  const source = new EventSource(apiUrl("/api/events", { token }));
  source.addEventListener("status", (event) => { if (!state.frozen) renderStatus(JSON.parse(event.data)); });
  source.addEventListener("alert", (event) => {
    const alert = JSON.parse(event.data);
    pushNotification(alert);
    if (alert.severity >= 3) {
      notify({
        sev: String(alert.severity), icon: "shield", title: alert.title,
        text: `${SEVERITY[alert.severity]} · ${alert.detail.split("\n")[0]}`,
        action: { label: "Voir le paquet", run: () => openPacket(alert.packet) },
      });
    }
  });
  source.onerror = () => condition("events", "Connexion interrompue", "La connexion temps réel est coupée. Nouvelle tentative en cours…");
  source.onopen = () => condition("events", "", "");
}

function init() {
  hydrateIcons();
  renderThemeControls();
  buildPills();
  if (!token) {
    showMessage({ tone: "error", title: "Jeton absent",
      text: "Ouvrez l'adresse affichée au lancement de PacketPhantom (elle contient #token=…)." });
    return;
  }
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-view], [data-action], [data-close]");
    if (!target) return;
    event.preventDefault();
    if (target.dataset.view || "close" in target.dataset) target.closest("dialog")?.close();
    if (target.dataset.view) showView(target.dataset.view);
    else ACTIONS[target.dataset.action]?.();
  });
  $("#filter").addEventListener("keydown", (event) => {
    if (event.key === "Enter") pivot(event.target.value.trim());
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && document.activeElement !== $("#filter")) {
      event.preventDefault();
      $("#filter").focus();
    }
  });
  // Un clic sur le voile (hors du contenu) ferme la fenêtre ; le message attend un choix explicite.
  for (const dialog of $$("#modal, #notif-panel")) {
    dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); });
  }
  setInterval(renderUptime, 1000);
  setInterval(refresh, 2500);
  connectEvents();
  api("/api/allowlist").then((d) => { state.rules = d.rules; }).catch(() => { /* descriptions facultatives */ });
  showView("dashboard");
}

init();
