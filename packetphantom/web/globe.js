"use strict";
/* PacketPhantom - globe du trafic : projection orthographique sur <canvas>, sans bibliothèque.
 *
 * Repère : vecteur unitaire (x vers lon 90°, y vers le pôle Nord, z vers lon 0°).
 * La vue fait tourner le globe (lacet = longitude centrale, tangage = latitude centrale) ;
 * un point est visible si sa composante z après rotation est positive.
 * Les trajets sont des arcs de grand cercle soulevés au-dessus de la surface ;
 * des « paquets » lumineux y circulent, plus nombreux quand le trafic l'est. */

(() => {
  const RAD = Math.PI / 180;
  const ARC_STEPS = 48;          // points d'échantillonnage d'un arc
  const ARC_TTL = 20_000;        // ms : un trajet sans trafic s'efface en 20 s
  const TRAVEL_MS = 1600;        // durée de vol d'un paquet
  const MAX_PARTICLES = 600;
  const AUTO_SPIN = 4 * RAD;     // rad/s quand personne ne manipule le globe
  const LIFT = 0.2;              // hauteur maximale d'un arc (antipodes), en rayons
  const MAX_SIZE = 680;          // px

  const vec = (lat, lon) => {
    const la = lat * RAD;
    const lo = lon * RAD;
    return [Math.cos(la) * Math.sin(lo), Math.sin(la), Math.cos(la) * Math.cos(lo)];
  };

  /* Arc de grand cercle a → b, soulevé d'autant plus que les points sont éloignés. */
  function arcPoints(a, b) {
    const dot = Math.min(1, Math.max(-1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    const omega = Math.acos(dot);
    const sin = Math.sin(omega) || 1;
    const lift = 0.05 + LIFT * (omega / Math.PI);
    const points = [];
    for (let i = 0; i <= ARC_STEPS; i += 1) {
      const t = i / ARC_STEPS;
      const ka = Math.sin((1 - t) * omega) / sin;
      const kb = Math.sin(t * omega) / sin;
      const h = 1 + lift * Math.sin(Math.PI * t);
      points.push([(ka * a[0] + kb * b[0]) * h, (ka * a[1] + kb * b[1]) * h, (ka * a[2] + kb * b[2]) * h]);
    }
    return points;
  }

  const placeKey = (p) => `${p.lat.toFixed(2)},${p.lon.toFixed(2)}`;
  const placeLabel = (p) => {
    if (p.country === "LAN") return "Réseau local";
    const name = p.name || p.country;
    return p.city && p.city !== name ? `${name} · ${p.city}` : name;
  };

  class Globe {
    constructor(canvas, { onHover } = {}) {
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d");
      this.onHover = onHover;
      this.land = [];                 // vecteurs des points de terre
      this.arcs = new Map();          // clé "a|b" → { from, to, points, direction, last, packets, bytes }
      this.places = new Map();        // clé lieu → { point, vec, bytes, packets, last }
      this.particles = [];
      this.home = null;
      this.lon0 = 2 * RAD;            // vue initiale : Europe
      this.lat0 = 25 * RAD;
      this.spin = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      this.drag = null;
      this.hover = null;
      this.running = false;
      this.frame = this.frame.bind(this);
      this.readColors();
      this.bindPointer();
      new ResizeObserver(() => this.resize()).observe(canvas.parentElement);
      window.addEventListener("resize", () => this.resize());
      this.resize();
    }

    // ------------------------------------------------------------ données

    setLand(dots) {
      this.land = [];
      for (let i = 0; i < dots.length; i += 2) this.land.push(vec(dots[i], dots[i + 1]));
    }

    setHome(point) {
      this.home = point && point.lat !== null ? { point, vec: vec(point.lat, point.lon) } : null;
    }

    /* Réponse de /api/geo/traffic : met à jour les trajets et lance des paquets. */
    ingest(arcs, now = performance.now()) {
      for (const arc of arcs) {
        const key = `${placeKey(arc.from)}|${placeKey(arc.to)}`;
        let entry = this.arcs.get(key);
        if (!entry) {
          entry = { from: arc.from, to: arc.to, direction: arc.direction, packets: 0, bytes: 0,
            points: arcPoints(vec(arc.from.lat, arc.from.lon), vec(arc.to.lat, arc.to.lon)) };
          this.arcs.set(key, entry);
        }
        entry.last = now;
        entry.packets += arc.packets;
        entry.bytes += arc.bytes;
        for (const end of [arc.from, arc.to]) {
          if (end.country === "LAN") continue;
          const place = this.places.get(placeKey(end)) ?? { point: end, vec: vec(end.lat, end.lon), bytes: 0, packets: 0 };
          place.bytes += arc.bytes;
          place.packets += arc.packets;
          place.last = now;
          this.places.set(placeKey(end), place);
        }
        // Échelle logarithmique : 1 paquet → 1 point lumineux, 1000 → 7 ; étalés sur la seconde.
        const count = Math.min(7, Math.ceil(Math.log2(1 + arc.packets)));
        for (let i = 0; i < count && this.particles.length < MAX_PARTICLES; i += 1) {
          this.particles.push({ arc: entry, start: now + Math.random() * 1000 });
        }
      }
    }

    /* Centre la vue sur un lieu. */
    focus(point) {
      this.lon0 = point.lon * RAD;
      this.lat0 = Math.max(-80 * RAD, Math.min(80 * RAD, point.lat * RAD));
      if (!this.running) this.draw(performance.now());
    }

    clear() {
      this.arcs.clear();
      this.places.clear();
      this.particles = [];
    }

    // ------------------------------------------------------------ rendu

    readColors() {
      const css = getComputedStyle(document.documentElement);
      const get = (name) => css.getPropertyValue(name).trim();
      this.colors = {
        ocean: get("--surface-2"), rim: get("--line"), land: get("--muted"), fg: get("--fg"),
        out: get("--primary"), in: get("--low"), transit: get("--med"), home: get("--good"), surface: get("--surface"),
      };
    }

    resize() {
      const box = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      // Tient dans la largeur de la carte et dans la hauteur de la fenêtre (en-tête de page déduit).
      const size = Math.max(240, Math.min(box.width, window.innerHeight - 300, MAX_SIZE));
      this.canvas.style.width = `${size}px`;
      this.canvas.style.height = `${size}px`;
      this.canvas.width = Math.round(size * dpr);
      this.canvas.height = Math.round(size * dpr);
      this.dpr = dpr;
      this.size = size;
      this.radius = (size / 2 - 6) / (1 + 0.05 + LIFT);   // place pour les arcs les plus hauts
      if (!this.running) this.draw(performance.now());
    }

    /* Cosinus et sinus de la vue, calculés une fois par image. */
    orient() {
      this.rot = [Math.cos(this.lon0), Math.sin(this.lon0), Math.cos(this.lat0), Math.sin(this.lat0)];
    }

    /* Rotation puis projection : [x écran, y écran, profondeur z, distance² au centre]. */
    project(v) {
      const [cl, sl, cp, sp] = this.rot;
      const x1 = v[0] * cl - v[2] * sl;
      const z1 = v[0] * sl + v[2] * cl;
      const y2 = v[1] * cp - z1 * sp;
      const z2 = v[1] * sp + z1 * cp;
      return [this.size / 2 + x1 * this.radius, this.size / 2 - y2 * this.radius, z2, x1 * x1 + y2 * y2];
    }

    /* Un point soulevé reste visible tant qu'il dépasse la silhouette du globe. */
    static visible(p) {
      return p[2] > 0 || p[3] > 1;
    }

    start() {
      if (this.running) return;
      this.running = true;
      this.readColors();
      this.lastFrame = performance.now();
      requestAnimationFrame(this.frame);
    }

    stop() {
      this.running = false;
    }

    frame(now) {
      if (!this.running) return;
      const dt = Math.min(0.1, (now - this.lastFrame) / 1000);
      this.lastFrame = now;
      if (this.spin && !this.drag && !this.hover) this.lon0 -= AUTO_SPIN * dt;
      if (!document.hidden) this.draw(now);
      requestAnimationFrame(this.frame);
    }

    draw(now) {
      const { ctx, colors, size, radius } = this;
      const c = size / 2;
      this.orient();
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, size, size);

      // Océan et contour
      ctx.beginPath();
      ctx.arc(c, c, radius, 0, Math.PI * 2);
      ctx.fillStyle = colors.ocean;
      ctx.fill();
      ctx.lineWidth = 1;
      ctx.strokeStyle = colors.rim;
      ctx.stroke();

      // Terres en pointillés, plus pâles vers le bord du disque (trois niveaux, un seul passage)
      const shades = [new Path2D(), new Path2D(), new Path2D()];
      for (const v of this.land) {
        const p = this.project(v);
        if (p[2] > 0) shades[p[2] < 0.35 ? 0 : p[2] < 0.7 ? 1 : 2].rect(p[0] - 1.1, p[1] - 1.1, 2.2, 2.2);
      }
      ctx.fillStyle = colors.land;
      [0.25, 0.45, 0.7].forEach((alpha, i) => {
        ctx.globalAlpha = alpha;
        ctx.fill(shades[i]);
      });
      ctx.globalAlpha = 1;

      this.drawArcs(now);
      this.drawPlaces(now);
      this.drawParticles(now);
    }

    drawArcs(now) {
      const { ctx, colors } = this;
      ctx.lineWidth = 1.2;
      for (const [key, arc] of this.arcs) {
        const fade = 1 - (now - arc.last) / ARC_TTL;
        if (fade <= 0) {
          this.arcs.delete(key);
          continue;
        }
        ctx.strokeStyle = colors[arc.direction];
        ctx.globalAlpha = 0.45 * fade;
        ctx.beginPath();
        let pen = false;
        for (const v of arc.points) {
          const p = this.project(v);
          if (!Globe.visible(p)) {
            pen = false;
            continue;
          }
          if (pen) ctx.lineTo(p[0], p[1]);
          else ctx.moveTo(p[0], p[1]);
          pen = true;
        }
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }

    drawPlaces(now) {
      const { ctx, colors } = this;
      const pulse = (Math.sin(now / 400) + 1) / 2;
      if (this.home) {
        const p = this.project(this.home.vec);
        if (p[2] > 0) {
          ctx.globalAlpha = 0.35 * (1 - pulse);
          ctx.fillStyle = colors.home;
          ctx.beginPath();
          ctx.arc(p[0], p[1], 6 + 10 * pulse, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
          ctx.beginPath();
          ctx.arc(p[0], p[1], 4.5, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      this.hotspots = [];
      for (const [key, place] of this.places) {
        const age = now - place.last;
        if (age > ARC_TTL * 3) {
          this.places.delete(key);
          continue;
        }
        const p = this.project(place.vec);
        if (p[2] <= 0) continue;
        const r = Math.min(9, 2.5 + Math.log10(1 + place.bytes) * 0.9);
        ctx.globalAlpha = Math.max(0.35, 1 - age / (ARC_TTL * 3));
        ctx.fillStyle = colors.out;
        ctx.beginPath();
        ctx.arc(p[0], p[1], r, 0, Math.PI * 2);
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = colors.surface;
        ctx.stroke();
        this.hotspots.push({ x: p[0], y: p[1], r, place });
      }
      ctx.globalAlpha = 1;
    }

    drawParticles(now) {
      const { ctx, colors } = this;
      const alive = [];
      for (const particle of this.particles) {
        const t = (now - particle.start) / TRAVEL_MS;
        if (t >= 1) continue;
        alive.push(particle);
        if (t < 0) continue;
        const points = particle.arc.points;
        ctx.fillStyle = colors[particle.arc.direction];
        // Tête lumineuse et courte traînée
        for (let k = 0; k < 4; k += 1) {
          const tk = t - k * 0.025;
          if (tk < 0) break;
          const p = this.project(points[Math.min(ARC_STEPS, Math.round(tk * ARC_STEPS))]);
          if (!Globe.visible(p)) break;
          ctx.globalAlpha = 1 - k * 0.25;
          ctx.beginPath();
          ctx.arc(p[0], p[1], k ? 1.6 : 2.6, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      ctx.globalAlpha = 1;
      this.particles = alive;
    }

    // ------------------------------------------------------------ interaction

    bindPointer() {
      const canvas = this.canvas;
      canvas.addEventListener("pointerdown", (event) => {
        canvas.setPointerCapture(event.pointerId);
        this.drag = { x: event.clientX, y: event.clientY, lon0: this.lon0, lat0: this.lat0 };
        this.setHover(null);
      });
      canvas.addEventListener("pointermove", (event) => {
        if (this.drag) {
          const k = 1 / this.radius;
          this.lon0 = this.drag.lon0 + (event.clientX - this.drag.x) * k;
          this.lat0 = Math.max(-80 * RAD, Math.min(80 * RAD, this.drag.lat0 + (event.clientY - this.drag.y) * k));
          if (!this.running) this.draw(performance.now());
          return;
        }
        const box = canvas.getBoundingClientRect();
        const x = event.clientX - box.left;
        const y = event.clientY - box.top;
        const hit = (this.hotspots ?? []).find((s) => (s.x - x) ** 2 + (s.y - y) ** 2 <= (s.r + 5) ** 2);
        this.setHover(hit ? { x, y, place: hit.place } : null);
      });
      const release = () => { this.drag = null; };
      canvas.addEventListener("pointerup", release);
      canvas.addEventListener("pointercancel", release);
      canvas.addEventListener("pointerleave", () => this.setHover(null));
    }

    setHover(hover) {
      this.hover = hover;
      this.canvas.style.cursor = hover ? "pointer" : this.drag ? "grabbing" : "grab";
      this.onHover?.(hover && { ...hover, label: placeLabel(hover.place.point) });
    }
  }

  Globe.placeLabel = placeLabel;
  window.Globe = Globe;
})();
