"use strict";
/* PacketPhantom — tableau de bord web.
 * Toutes les données réseau sont insérées via textContent (jamais en HTML). */

// ------------------------------------------------------------------ outils

const $ = (selector) => document.querySelector(selector);

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
  duration(s) {
    s = Math.round(s ?? 0);
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}s`;
    return `${Math.floor(s / 3600)}h${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
  },
  time: (iso) => (iso ? iso.slice(11, 23) : ""),
  endpoint: (ip, port) => (port === null || port === undefined ? ip : `${ip}:${port}`),
};

const SEVERITY = { 4: "CRITIQUE", 3: "ÉLEVÉE", 2: "MOYENNE", 1: "FAIBLE", 0: "INFO" };
const sevText = (sev) => h("span", { class: `sev sev-${sev}` }, SEVERITY[sev] ?? "");
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// ------------------------------------------------------------------ API

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

// ------------------------------------------------------------------ état

const state = {
  tab: "alerts",
  filter: "",
  sort: { flows: "last", hosts: "bytes" },
  status: null,
  busy: false,
};

function banner(message) {
  const el = $("#banner");
  el.hidden = !message;
  el.textContent = message ?? "";
}

function toast(alert) {
  const el = h("div", { class: `toast sev-${alert.severity}` }, h("b", {}, `${SEVERITY[alert.severity]} · ${alert.title}`),
    alert.detail.split("\n")[0]);
  $("#toasts").append(el);
  setTimeout(() => el.remove(), 7000);
}

// ------------------------------------------------------------------ graphiques

function drawArea(canvas, series) {
  const ratio = window.devicePixelRatio || 1;
  const { width, height } = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, width * ratio);
  canvas.height = Math.max(1, height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, width, height);
  for (const { values, color } of series) {
    const top = Math.max(...values, 1);
    const step = width / Math.max(values.length - 1, 1);
    const y = (v) => height - 2 - (v / top) * (height - 6);
    ctx.beginPath();
    ctx.moveTo(0, height);
    values.forEach((v, i) => ctx.lineTo(i * step, y(v)));
    ctx.lineTo(width, height);
    ctx.closePath();
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, `${color}66`);
    gradient.addColorStop(1, `${color}05`);
    ctx.fillStyle = gradient;
    ctx.fill();
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(i * step, y(v)) : ctx.moveTo(0, y(v))));
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }
}

// ------------------------------------------------------------------ indicateurs

const KPIS = [
  { label: "Paquets", value: (s) => fmt.count(s.packets), sub: (s) => fmt.bytes(s.bytes) },
  { label: "Paquets / s", value: (s) => fmt.count(last(s.pps)), sub: (s) => `max ${fmt.count(Math.max(...s.pps))}`, series: "pps" },
  { label: "Débit", value: (s) => fmt.bits(last(s.bps)), sub: (s) => `max ${fmt.bits(Math.max(...s.bps))}`, series: "bps" },
  { label: "Flux", value: (s) => fmt.count(s.flows), sub: (s) => fmt.duration(s.uptime) },
  { label: "Hôtes", value: (s) => fmt.count(s.hosts), sub: () => "" },
  {
    label: "Alertes",
    value: (s) => fmt.count(sum(Object.values(s.alerts))),
    sub: (s) => [s.alerts["4"] && `${s.alerts["4"]} crit.`, s.alerts["3"] && `${s.alerts["3"]} élev.`].filter(Boolean).join(" · "),
    alert: (s) => Boolean(s.alerts["4"] || s.alerts["3"]),
  },
];

function renderStatus(s) {
  state.status = s;
  const badge = $("#state");
  const labels = { live: "● CAPTURE", file: "▶ LECTURE", done: "✓ TERMINÉ", idle: "■ ARRÊTÉ" };
  badge.textContent = labels[s.mode] ?? s.mode;
  badge.className = `badge ${s.mode}`;
  $("#source").textContent = [s.source, s.bpf && `BPF ${s.bpf}`, `GeoIP ${s.geo}`].filter(Boolean).join("  ·  ");
  $("#capture-toggle").textContent = s.mode === "live" ? "Arrêter" : "Capturer";
  banner(s.error || (s.dropped ? `${fmt.count(s.dropped)} paquets perdus (file d'analyse saturée) — restreignez la capture avec un filtre BPF.` : ""));

  const container = $("#kpis");
  if (!container.children.length) {
    for (const kpi of KPIS) {
      container.append(h("div", { class: "kpi" }, h("div", { class: "label" }, kpi.label), h("div", { class: "value" }),
        h("div", { class: "sub" }), kpi.series ? h("canvas") : null));
    }
  }
  KPIS.forEach((kpi, i) => {
    const card = container.children[i];
    card.classList.toggle("alert", Boolean(kpi.alert?.(s)));
    card.querySelector(".value").textContent = kpi.value(s);
    card.querySelector(".sub").textContent = kpi.sub(s);
    if (kpi.series) drawArea(card.querySelector("canvas"), [{ values: s[kpi.series], color: css("--primary") }]);
  });
  drawArea($("#traffic"), [
    { values: s.bps.map((v) => v / 8), color: css("--primary") },
    { values: s.pps, color: css("--accent") },
  ]);
  $("#traffic-now").textContent = `${fmt.bits(last(s.bps))} · ${fmt.count(last(s.pps))} paquets/s`;
}

// ------------------------------------------------------------------ tableaux

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

const protoCell = (proto) => h("span", { class: "proto tag" }, proto);
const geoText = (geo) => (geo ? `${geo.country}${geo.city ? ` · ${geo.city}` : ""}` : "");
const sorter = (kind) => ({ value: state.sort[kind], set: (key) => { state.sort[kind] = key; refresh(); } });

const COLUMNS = {
  alerts: [
    { label: "Heure", cell: (a) => fmt.time(a.time), cls: "mono" },
    { label: "Sévérité", cell: (a) => sevText(a.severity) },
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
    { label: "État", cell: (f) => f.state || "—" },
    { label: "Domaine / SNI", cell: (f) => h("span", { class: "tag" }, f.label) },
    { label: "Vu", cell: (f) => fmt.time(f.last).slice(0, 8), cls: "mono", sort: "last" },
  ],
  hosts: [
    { label: "Adresse", cell: (x) => h("b", {}, x.ip), cls: "mono" },
    { label: "MAC", cell: (x) => x.mac || "—", cls: "mono" },
    { label: "Système", cell: (x) => (x.os ? `${x.os} ${x.os_confidence}%` : "—") },
    { label: "Localisation", cell: (x) => (x.local ? "LAN" : geoText(x.geo)) },
    { label: "Noms", cell: (x) => h("span", { class: "ok" }, x.names.slice(0, 2).join(", ")) },
    { label: "Émis", cell: (x) => fmt.bytes(x.bytes_tx), cls: "num" },
    { label: "Reçus", cell: (x) => fmt.bytes(x.bytes_rx), cls: "num", sort: "bytes" },
    { label: "Pairs", cell: (x) => x.peers, cls: "num", sort: "peers" },
    { label: "Services", cell: (x) => h("span", { class: "tag" }, x.services.slice(0, 4).join(" ")) },
    { label: "Vu", cell: (x) => fmt.time(x.last_seen).slice(0, 8), cls: "mono", sort: "last" },
  ],
};

// ------------------------------------------------------------------ vues

function pivot(filter) {
  state.filter = filter;
  $("#filter").value = filter;
  selectTab("packets");
}

function rankPanel(title, rows, color) {
  const top = Math.max(...rows.map((r) => r.value), 1);
  const grid = h("div", { class: "rank" });
  for (const row of rows) {
    const fill = h("span");
    fill.style.width = `${(row.value / top) * 100}%`;
    if (color) fill.style.background = color;
    grid.append(h("span", { class: "name", title: row.label }, row.label), h("div", { class: "bar" }, fill),
      h("span", { class: "muted num" }, row.shown));
  }
  return h("section", { class: "card" }, h("h3", {}, title), rows.length ? grid : h("div", { class: "muted" }, "Aucune donnée"));
}

const VIEWS = {
  alerts: {
    load: () => api("/api/alerts", { limit: 1000 }),
    render: (data) => table(COLUMNS.alerts, data.items.reverse(), (a) => openPacket(a.packet)),
  },
  packets: {
    filter: true,
    load: () => api("/api/packets", { filter: state.filter, limit: 1000 }),
    render: (data) => {
      $("#filter-status").textContent = `${fmt.count(data.items.length)} affichés · ${fmt.count(data.last_id)} reçus`;
      return table(COLUMNS.packets, data.items.reverse(), (p) => openPacket(p.id));
    },
  },
  flows: {
    load: () => api("/api/flows", { sort: state.sort.flows, limit: 1000 }),
    render: (data) => table(COLUMNS.flows, data.items, (f) => openConversation(f.id), sorter("flows")),
  },
  hosts: {
    load: () => api("/api/hosts", { sort: state.sort.hosts, limit: 1000 }),
    render: (data) => table(COLUMNS.hosts, data.items, (x) => pivot(`ip.addr == ${x.ip}`), sorter("hosts")),
  },
  analytics: {
    load: () => api("/api/analytics", { limit: 12 }),
    render: (d) => h("div", { class: "grid" },
      rankPanel("Protocoles", d.protocols.map((p) => ({ label: p.name, value: p.count, shown: `${(p.share * 100).toFixed(1)} %` }))),
      rankPanel("Hôtes les plus actifs", d.talkers.map((t) => ({ label: t.name ? `${t.ip}  ${t.name}` : t.ip, value: t.bytes, shown: fmt.bytes(t.bytes) }))),
      rankPanel("Domaines", d.domains.map((x) => ({ label: x.name, value: x.count, shown: fmt.count(x.count) })), css("--accent")),
      rankPanel("Services", d.services.map((x) => ({ label: x.name, value: x.count, shown: `${fmt.count(x.count)} cnx` })), css("--good")),
      rankPanel("Pays", d.countries.map((c) => ({ label: `${c.code}  ${c.name}`, value: c.bytes, shown: fmt.bytes(c.bytes) })), css("--server"))),
  },
};

async function refresh() {
  if (state.busy || document.hidden || $("#modal").open) return;
  state.busy = true;
  const view = VIEWS[state.tab];
  try {
    const data = await view.load();
    const container = $("#view");
    const scroll = container.scrollTop;
    container.replaceChildren(view.render(data));
    container.scrollTop = scroll;
    $("#filter").classList.remove("bad");
  } catch (error) {
    if (state.tab === "packets") {
      $("#filter").classList.add("bad");
      $("#filter-status").textContent = error.message;
    } else {
      banner(error.message);
    }
  } finally {
    state.busy = false;
  }
}

function selectTab(tab) {
  state.tab = tab;
  for (const button of document.querySelectorAll("#tabs button")) button.classList.toggle("active", button.dataset.tab === tab);
  $("#filterbar").hidden = !VIEWS[tab].filter;
  $("#view").replaceChildren(h("div", { class: "empty" }, "Chargement…"));
  refresh();
}

// ------------------------------------------------------------------ fenêtres de détail

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
        ["Flux", p.flow ? h("a", { href: "#", onclick: (e) => { e.preventDefault(); openConversation(p.flow); } }, `#${p.flow} — suivre`) : ""],
      ]),
      p.alerts.map((a) => h("div", { class: "note" }, sevText(a.severity), " ", h("b", {}, a.title), h("pre", {}, a.detail))),
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
    const sent = sum(c.chunks.filter((x) => x.client).map((x) => x.size));
    const received = sum(c.chunks.filter((x) => !x.client).map((x) => x.size));
    openModal(`Flux #${f.id} · ${f.app || f.l4}`,
      keyValues([
        ["Client", `${fmt.endpoint(f.client, f.client_port)} → ${fmt.bytes(sent)}`],
        ["Serveur", `${fmt.endpoint(f.server, f.server_port)} → ${fmt.bytes(received)}`],
        ["Domaine", f.label], ["État", f.state],
      ]),
      c.note ? h("div", { class: `note ${c.decrypted ? "ok" : ""}` }, c.note) : null,
      h("div", { class: "stream" }, c.chunks.length
        ? c.chunks.map((x) => h("pre", { class: x.client ? "client" : "server" }, x.text))
        : h("div", { class: "empty" }, "Aucune donnée applicative dans les paquets conservés.")),
      h("button", { class: "btn ghost", type: "button", onclick: () => { $("#modal").close(); pivot(`flow == ${f.id}`); } },
        "Voir les paquets de ce flux"));
  } catch (error) {
    banner(error.message);
  }
}

// ------------------------------------------------------------------ démarrage

function connectEvents() {
  const source = new EventSource(apiUrl("/api/events", { token }));
  source.addEventListener("status", (event) => renderStatus(JSON.parse(event.data)));
  source.addEventListener("alert", (event) => {
    const alert = JSON.parse(event.data);
    if (alert.severity >= 3) toast(alert);
  });
  source.onerror = () => banner("Connexion temps réel interrompue — nouvelle tentative…");
  source.onopen = () => banner(state.status?.error ?? "");
}

function init() {
  if (!token) {
    banner("Jeton absent : ouvrez l'adresse affichée au lancement de PacketPhantom (elle contient #token=…).");
    return;
  }
  for (const button of document.querySelectorAll("#tabs button")) button.addEventListener("click", () => selectTab(button.dataset.tab));
  $("#filter").addEventListener("keydown", (event) => {
    if (event.key === "Enter") { state.filter = event.target.value.trim(); refresh(); }
  });
  $("#modal-close").addEventListener("click", () => $("#modal").close());
  $("#export").addEventListener("click", (event) => {
    event.currentTarget.href = apiUrl("/api/export.pcap", { token, filter: state.tab === "packets" ? state.filter : "" });
  });
  $("#capture-toggle").addEventListener("click", async () => {
    try {
      renderStatus(await api("/api/capture", {}, { method: "POST", body: JSON.stringify({ action: state.status?.mode === "live" ? "stop" : "start" }) }));
    } catch (error) {
      banner(error.message);
    }
  });
  setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString("fr-FR"); }, 1000);
  setInterval(refresh, 2000);
  connectEvents();
  selectTab("alerts");
}

init();
