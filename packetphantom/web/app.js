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
};

function banner(message) {
  const el = $("#banner");
  el.hidden = !message;
  el.textContent = message ?? "";
}

function toast(alert) {
  const el = h("div", { class: "toast" },
    h("span", { class: `tile round tone-${alert.severity}` }, icon("shield")),
    h("div", {}, h("b", {}, alert.title), h("small", {}, `${SEVERITY[alert.severity]} · ${alert.detail.split("\n")[0]}`)));
  $("#toasts").append(el);
  setTimeout(() => el.remove(), 7000);
}

// ================================================================== graphiques

/* Histogramme « en bande » : 8 piliers de 15 s ; pic en orange foncé, période en cours en orange clair. */
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
    pill.className = `pill ${current ? "current" : i === peak && buckets[i] > 0 ? "peak" : ""}`;
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
  const alerts = sum(Object.values(s.alerts));

  $("#source-name").textContent = s.source || "-";
  $("#source-state").textContent = { live: "Capture en direct", file: "Lecture de fichier", done: "Fichier analysé", idle: "Capture arrêtée" }[s.mode] ?? s.mode;
  $(".source").classList.toggle("live", live);
  $("#promo-text").textContent = `${s.source || "Interface par défaut"} · BPF ${s.bpf || "aucun"}`;
  $("#nav-badge").hidden = !alerts;
  $("#nav-badge").textContent = alerts > 99 ? "99+" : String(alerts);
  $("#bell-dot").hidden = !(s.alerts["4"] || s.alerts["3"]);

  $$(".capture-icon").forEach((el) => setIcon(el, live ? "stop" : "play"));
  $$(".capture-label").forEach((el) => { el.textContent = live ? el.dataset.stop : el.dataset.start; });
  banner(s.error || (s.dropped ? `${fmt.count(s.dropped)} paquets perdus (file d'analyse saturée) - restreignez la capture avec un filtre BPF.` : ""));

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
      onClick: () => openPacket(a.packet),
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
  button.onclick = latest ? () => openPacket(latest.packet) : null;
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

/* columns : [{ label, cell(row) → texte|Node, cls?, sort? }] */
function table(columns, rows, onClick, sortState) {
  if (!rows.length) return h("div", { class: "empty" }, "Aucune donnée pour l'instant.");
  const head = columns.map((col) => h("th", {
    class: [col.sort && "sortable", col.sort && sortState?.value === col.sort && "sorted"].filter(Boolean).join(" "),
    onclick: col.sort ? () => sortState.set(col.sort) : undefined,
  }, col.label));
  const body = rows.map((row) => h("tr", { onclick: () => onClick(row) },
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
    render: (d) => table(COLUMNS.alerts, d.items.reverse(), (a) => openPacket(a.packet)),
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
  if (state.busy || state.frozen || document.hidden || $("#modal").open) return;
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
  } catch (error) {
    if (state.view === "packets") {
      $(".search").classList.add("bad");
      $("#list-subtitle").textContent = error.message;
    } else {
      banner(error.message);
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

function openModal(title, ...content) {
  $("#modal-title").textContent = title;
  $("#modal-body").replaceChildren(...content.flat().filter(Boolean));
  $("#modal").showModal();
}

const keyValues = (pairs) => h("dl", { class: "kv" }, pairs.filter(([, v]) => v !== "" && v !== null && v !== undefined)
  .flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));

async function openPacket(id) {
  try {
    const p = await api(`/api/packets/${id}`);
    const layers = p.layers.map((layer, i) => h("details", { open: i < 4 ? "" : undefined },
      h("summary", {}, layer.name),
      h("table", {}, h("tbody", {}, layer.fields.map(([k, v]) => h("tr", {}, h("td", { class: "muted" }, k), h("td", { class: "mono" }, v)))))));
    const hex = p.hex.map(([offset, bytes, ascii]) => `${offset}  ${bytes.padEnd(49)} │${ascii}`).join("\n");
    openModal(`Paquet ${p.id} · ${p.proto}`,
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
    banner(error.message);
  }
}

async function openConversation(flowId) {
  try {
    const c = await api(`/api/flows/${flowId}/conversation`);
    const f = c.flow;
    const bytesFrom = (client) => fmt.bytes(sum(c.chunks.filter((x) => x.client === client).map((x) => x.size)));
    openModal(`Flux #${f.id} · ${f.app || f.l4}`,
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
    banner(error.message);
  }
}

function openHelp() {
  const rows = (pairs) => h("table", {}, h("tbody", {}, pairs.map(([k, v]) => h("tr", {}, h("td", { class: "mono" }, k), h("td", {}, v)))));
  openModal("Aide & API",
    h("div", { class: "help-grid" },
      h("section", {}, h("h3", {}, "Filtre d'affichage"), rows([
        ["tls or dns", "protocoles"], ["ip.addr == 10.0.0.0/8", "adresse ou réseau"], ["port 443", "port"],
        ['domain contains "google"', "SNI / Host / DNS"], ["alert >= high", "paquets en alerte"], ["flow == 12", "une conversation"],
      ])),
      h("section", {}, h("h3", {}, "API REST (jeton Bearer)"), rows([
        ["GET /api/status", "état et compteurs"], ["GET /api/events", "flux SSE temps réel"], ["GET /api/packets?filter=", "paquets"],
        ["GET /api/flows/{id}/conversation", "échange (déchiffré)"], ["GET /api/export.pcap", "export PCAP"],
        ["POST /api/capture", "démarrer / arrêter"],
      ]))));
}

// ================================================================== actions

async function toggleCapture() {
  try {
    const action = state.status?.mode === "live" ? "stop" : "start";
    renderStatus(await api("/api/capture", {}, { method: "POST", body: JSON.stringify({ action }) }));
  } catch (error) {
    banner(error.message);
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
  freeze: toggleFreeze,
};

// ================================================================== démarrage

function connectEvents() {
  const source = new EventSource(apiUrl("/api/events", { token }));
  source.addEventListener("status", (event) => { if (!state.frozen) renderStatus(JSON.parse(event.data)); });
  source.addEventListener("alert", (event) => {
    const alert = JSON.parse(event.data);
    if (alert.severity >= 3) toast(alert);
  });
  source.onerror = () => banner("Connexion temps réel interrompue - nouvelle tentative…");
  source.onopen = () => banner(state.status?.error ?? "");
}

function init() {
  hydrateIcons();
  renderThemeControls();
  buildPills();
  if (!token) {
    banner("Jeton absent : ouvrez l'adresse affichée au lancement de PacketPhantom (elle contient #token=…).");
    return;
  }
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-view], [data-action]");
    if (!target) return;
    event.preventDefault();
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
  $("#modal-close").addEventListener("click", () => $("#modal").close());
  setInterval(renderUptime, 1000);
  setInterval(refresh, 2500);
  connectEvents();
  showView("dashboard");
}

init();
