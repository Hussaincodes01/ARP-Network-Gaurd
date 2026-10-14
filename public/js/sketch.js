/* Hand-drawn renderers built on rough.js: score chart, binding timeline,
   topology "piste" and the pipeline diagram. Colours come from CSS tokens so
   light (paper) and dark (chalkboard) themes both work. */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";

  function tokens() {
    const cs = getComputedStyle(document.documentElement);
    const v = (n) => cs.getPropertyValue(n).trim();
    return {
      ink: v("--ink"), soft: v("--ink-soft"), pencil: v("--pencil"), paper: v("--paper-2"), paper3: v("--paper-3"),
      red: v("--red"), green: v("--green"), amber: v("--amber"), orange: v("--orange"), blue: v("--blue"),
      hand: v("--font-hand") || "cursive", type: v("--font-type") || "monospace",
    };
  }

  const VERDICT_COLOR = (T, v) => ({
    confirmed_spoofing: T.red, probable_spoofing: T.red, suspicious: T.orange, anomaly_not_arp: T.orange,
    pending: T.amber, likely_legitimate: T.amber, normal: T.green,
  }[v] || T.pencil);

  function setupCanvas(canvas, cssHeight) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = canvas.clientWidth || canvas.parentElement.clientWidth;
    const h = cssHeight || canvas.clientHeight || 200;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      canvas.style.height = h + "px";
    }
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h, rc: rough.canvas(canvas) };
  }

  function text(ctx, s, x, y, opt = {}) {
    const T = opt.T;
    ctx.save();
    ctx.font = `${opt.size || 15}px ${opt.mono ? T.type : T.hand}`;
    ctx.fillStyle = opt.color || T.soft;
    ctx.textAlign = opt.align || "left";
    ctx.textBaseline = opt.base || "alphabetic";
    if (opt.rotate) { ctx.translate(x, y); ctx.rotate(opt.rotate); ctx.fillText(s, 0, 0); }
    else ctx.fillText(s, x, y);
    ctx.restore();
  }

  function fmtT(t) {
    if (t >= 7200) return (t / 3600).toFixed(1) + " h";
    return Math.round(t) + " s";
  }

  function niceStep(span, target) {
    const raw = span / target;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 5, 10]) if (raw <= m * mag) return m * mag;
    return 10 * mag;
  }

  // ---------------------------------------------------------- score chart
  function drawScore(canvas, d, now) {
    const T = tokens();
    const { ctx, w, h, rc } = setupCanvas(canvas, w0(canvas) < 520 ? 210 : 260);
    const L = 46, R = 12, Tp = 14, B = 28;
    const pw = w - L - R, ph = h - Tp - B;
    const dur = Math.max(d.duration, 1);
    const X = (t) => L + (t / dur) * pw;
    const s = d.series;
    const vals = s.score.filter((v) => v != null && v > 0);
    const thr = d.threshold;
    let lo = vals.length ? Math.min(...vals) : 0.001, hi = vals.length ? Math.max(...vals) : 1;
    if (thr) { lo = Math.min(lo, thr / 4); hi = Math.max(hi, thr * 2); }
    const ylo = Math.floor(Math.log10(Math.max(lo, 1e-4))), yhi = Math.ceil(Math.log10(hi));
    const Y = (v) => Tp + ph - ((Math.log10(Math.max(v, 1e-6)) - ylo) / Math.max(yhi - ylo, 1)) * ph;
    const opt = { roughness: 0.9, bowing: 0.6, seed: 11 };

    // shaded regions
    if (d.graceEnd > 0) {
      rc.rectangle(X(0), Tp, X(Math.min(d.graceEnd, dur)) - X(0), ph,
        { ...opt, stroke: "transparent", fill: T.pencil, fillStyle: "hachure", hachureGap: 9, fillWeight: 0.8 });
      text(ctx, "Kitsune learning", X(Math.min(d.graceEnd, dur)) / 2 + L / 2, Tp + 18, { T, align: "center", size: 15, color: T.pencil });
    }
    if (d.attack && d.attack[0] != null) {
      const a0 = X(d.attack[0]), a1 = X(d.attack[1] != null ? d.attack[1] : dur);
      rc.rectangle(a0, Tp, Math.max(a1 - a0, 3), ph,
        { ...opt, stroke: "transparent", fill: T.red, fillStyle: "hachure", hachureAngle: 60, hachureGap: 10, fillWeight: 0.9 });
      text(ctx, "attack", (a0 + a1) / 2, Tp + 18, { T, align: "center", size: 15, color: T.red });
    }

    // axes
    rc.line(L, Tp + ph, L + pw, Tp + ph, { ...opt, stroke: T.ink, strokeWidth: 1.6 });
    rc.line(L, Tp, L, Tp + ph, { ...opt, stroke: T.ink, strokeWidth: 1.6 });
    for (let e = ylo; e <= yhi; e++) {
      const y = Y(Math.pow(10, e));
      ctx.strokeStyle = T.pencil; ctx.globalAlpha = 0.25; ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(L + pw, y); ctx.stroke(); ctx.globalAlpha = 1;
      text(ctx, e >= 0 ? String(Math.pow(10, e)) : Math.pow(10, e).toFixed(-e), L - 6, y + 5, { T, align: "right", size: 14, mono: true });
    }
    const step = niceStep(dur, w < 520 ? 4 : 8);
    for (let t = 0; t <= dur + 1e-6; t += step) text(ctx, fmtT(t), X(t), h - 8, { T, align: "center", size: 14, mono: true });

    // score line up to now (break at gaps)
    let seg = [];
    const segs = [];
    for (let i = 0; i < s.t.length && s.t[i] <= now; i++) {
      const v = s.score[i];
      if (v == null) { if (seg.length > 1) segs.push(seg); seg = []; continue; }
      seg.push([X(s.t[i]), Y(v)]);
    }
    if (seg.length > 1) segs.push(seg);
    for (const sg of segs) rc.linearPath(sg, { ...opt, roughness: 0.5, stroke: T.ink, strokeWidth: 1.4 });

    // threshold
    if (thr) {
      const y = Y(thr);
      rc.line(L, y, L + pw, y, { ...opt, stroke: T.red, strokeWidth: 2, strokeLineDash: [9, 7] });
      text(ctx, "threshold " + thr.toPrecision(2), L + pw - 4, y - 6, { T, align: "right", size: 14, color: T.red });
    }

    // incident flags
    for (const inc of d.incidents) {
      if (inc.first_t > now) continue;
      const x = X(inc.first_t), col = VERDICT_COLOR(T, d.verdictAt(inc, now));
      rc.line(x, Tp + ph, x, Tp + 26, { ...opt, stroke: T.ink, strokeWidth: 1.4 });
      rc.polygon([[x, Tp + 26], [x + 18, Tp + 31], [x, Tp + 37]], { ...opt, fill: col, fillStyle: "solid", stroke: T.ink, strokeWidth: 1.2 });
      text(ctx, "#" + inc.id, x + 3, Tp + 50, { T, size: 13, color: T.ink });
    }

    // playhead
    if (now < dur) {
      const x = X(now);
      rc.line(x, Tp - 4, x, Tp + ph, { ...opt, roughness: 0.3, stroke: T.blue, strokeWidth: 2 });
    }
  }

  function w0(canvas) { return canvas.clientWidth || 600; }

  // ------------------------------------------------------ binding timeline
  function drawTimeline(canvas, d, now) {
    const T = tokens();
    const rows = d.timelineRows;
    const rowH = 30;
    const { ctx, w, h, rc } = setupCanvas(canvas, Math.max(90, 34 + rows.length * rowH));
    const L = w < 520 ? 96 : 118, R = 10, Tp = 8;
    const pw = w - L - R;
    const dur = Math.max(d.duration, 1);
    const X = (t) => L + (Math.min(t, dur) / dur) * pw;
    const opt = { roughness: 1, bowing: 0.8, seed: 5 };
    if (!rows.length) {
      text(ctx, "No IP has changed owner yet.", 12, 40, { T, size: 16, color: T.pencil });
      return;
    }
    rows.forEach((row, i) => {
      const y = Tp + i * rowH;
      text(ctx, row.ip + (row.gateway ? " ⚑" : ""), 8, y + 19, { T, size: 14, mono: true, color: T.ink });
      for (let k = 0; k < row.history.length; k++) {
        const [t0, mac] = row.history[k];
        if (t0 > now) break;
        const t1 = Math.min(k + 1 < row.history.length ? row.history[k + 1][0] : now, now);
        if (t1 <= t0 && k + 1 < row.history.length) continue;
        const role = d.macRole(row.ip, mac, t0);
        const col = role === "attacker" ? T.red : role === "owner" ? T.green : T.blue;
        const x0 = X(t0), x1 = Math.max(X(t1), x0 + 3);
        rc.rectangle(x0, y + 5, x1 - x0, rowH - 11, {
          ...opt, stroke: col, strokeWidth: 1.4, fill: col,
          fillStyle: role === "attacker" ? "cross-hatch" : "hachure", hachureGap: role === "attacker" ? 5 : 7, fillWeight: 1,
        });
        if (x1 - x0 > 120) text(ctx, mac, x0 + 6, y + 19, { T, size: 12, mono: true, color: T.ink });
      }
    });
    const step = niceStep(dur, w < 520 ? 4 : 8);
    for (let t = 0; t <= dur + 1e-6; t += step) text(ctx, fmtT(t), X(t), h - 6, { T, align: "center", size: 13, mono: true, color: T.pencil });
    if (now < dur) rc.line(X(now), 0, X(now), h - 18, { roughness: 0.3, stroke: T.blue, strokeWidth: 2, seed: 2 });
  }

  // --------------------------------------------------------------- SVG helpers
  function svgEl(tag, attrs, parent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function svgText(parent, s, x, y, attrs = {}) {
    const t = svgEl("text", { x, y, "text-anchor": "middle", ...attrs }, parent);
    t.textContent = s;
    return t;
  }
  function arrowHead(rs, g, x1, y1, x2, y2, col) {
    const a = Math.atan2(y2 - y1, x2 - x1), L = 10;
    const p1 = [x2 - L * Math.cos(a - 0.45), y2 - L * Math.sin(a - 0.45)];
    const p2 = [x2 - L * Math.cos(a + 0.45), y2 - L * Math.sin(a + 0.45)];
    g.appendChild(rs.linearPath([p1, [x2, y2], p2], { stroke: col, strokeWidth: 2, roughness: 0.6, seed: 3 }));
  }

  // ------------------------------------------------------------- topology
  function drawTopology(svg, topo) {
    const T = tokens();
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const rs = rough.svg(svg);
    const g = svgEl("g", {}, svg);
    const W = 420;
    const gw = { x: W / 2 + 20, y: 104 };
    // internet cloud
    g.appendChild(rs.path("M190 40 C170 40 168 18 188 16 C192 0 220 -2 228 12 C242 0 272 6 268 24 C286 26 286 46 266 46 Z",
      { stroke: T.pencil, strokeWidth: 1.6, roughness: 1.2, seed: 4, fill: T.paper3, fillStyle: "solid" }));
    svgText(g, "internet", 228, 34, { "font-size": 15, fill: T.soft });
    g.appendChild(rs.line(gw.x, 48, gw.x, gw.y - 22, { stroke: T.pencil, strokeWidth: 1.5, seed: 4 }));
    // gateway (router with antennas)
    g.appendChild(rs.rectangle(gw.x - 40, gw.y - 20, 80, 34, { stroke: T.ink, strokeWidth: 2, fill: T.paper, fillStyle: "solid", seed: 8 }));
    g.appendChild(rs.line(gw.x - 26, gw.y - 20, gw.x - 34, gw.y - 36, { stroke: T.ink, strokeWidth: 2, seed: 8 }));
    g.appendChild(rs.line(gw.x + 26, gw.y - 20, gw.x + 34, gw.y - 36, { stroke: T.ink, strokeWidth: 2, seed: 8 }));
    for (let i = 0; i < 3; i++) g.appendChild(rs.circle(gw.x - 20 + i * 12, gw.y + 5, 4, { stroke: T.green, fill: T.green, fillStyle: "solid", seed: i }));
    svgText(g, "gateway", gw.x, gw.y - 2, { "font-size": 15, fill: T.ink });
    svgText(g, (topo.gateway.ip || "?") + "  " + (topo.gateway.mac || ""), gw.x + 4, gw.y + 30, { class: "mono" });

    const hosts = topo.hosts;
    const n = Math.max(hosts.length, 1);
    const pos = hosts.map((hst, i) => {
      const span = Math.min(360, 60 * n);
      const x = W / 2 + 10 - span / 2 + (n === 1 ? span / 2 : (i * span) / (n - 1));
      const y = 262 + (i % 2) * 34;
      return { ...hst, x, y };
    });
    const atk = topo.attacker;
    const ax = 46, ay = 150;
    for (const p of pos) {
      const poisoned = atk && topo.poisoned.has(p.ip);
      if (poisoned) {
        g.appendChild(rs.line(p.x, p.y - 16, gw.x, gw.y + 16, { stroke: T.pencil, strokeWidth: 1, strokeLineDash: [3, 5], seed: 6 }));
        const mx = (p.x + gw.x) / 2, my = (p.y - 16 + gw.y + 16) / 2;
        svgText(g, "×", mx, my + 6, { "font-size": 22, fill: T.red });
        g.appendChild(rs.curve([[p.x - 4, p.y - 18], [(p.x + ax) / 2, ay + 46], [ax + 16, ay + 10]], { stroke: T.red, strokeWidth: 2.2, roughness: 1.1, seed: 9 }));
        arrowHead(rs, g, (p.x + ax) / 2, ay + 46, ax + 16, ay + 10, T.red);
      } else {
        g.appendChild(rs.line(p.x, p.y - 16, gw.x, gw.y + 16, { stroke: T.ink, strokeWidth: 1.5, roughness: 1, seed: 6 }));
      }
    }
    if (atk) {
      g.appendChild(rs.curve([[ax + 14, ay - 14], [ax + 60, gw.y + 10], [gw.x - 40, gw.y + 4]], { stroke: T.red, strokeWidth: 2.2, seed: 10 }));
      arrowHead(rs, g, ax + 60, gw.y + 10, gw.x - 40, gw.y + 4, T.red);
      window.attackerMask(svg, ax, ay, 1.15);
      svgText(svg, "attacker", ax, ay + 34, { "font-size": 15, fill: T.red });
      svgText(svg, atk.mac, ax + 20, ay + 48, { class: "mono" });
      svgText(svg, "traffic detours here", ax + 8, ay - 34, { "font-size": 13, fill: T.red });
    }
    for (const p of pos) {
      const col = p.legit ? T.amber : (atk && topo.poisoned.has(p.ip)) ? T.red : T.ink;
      g.appendChild(rs.rectangle(p.x - 17, p.y - 16, 34, 24, { stroke: col, strokeWidth: 1.8, fill: T.paper, fillStyle: "solid", seed: 12 }));
      g.appendChild(rs.line(p.x - 10, p.y + 12, p.x + 10, p.y + 12, { stroke: col, strokeWidth: 1.8, seed: 12 }));
      svgText(g, "." + p.ip.split(".").pop(), p.x, p.y + 1, { "font-size": 14, fill: T.ink });
      svgText(g, (p.vendor || "").split(" ")[0].slice(0, 11), p.x, p.y + 28, { "font-size": 12, fill: T.soft });
    }
    if (!hosts.length) svgText(g, "waiting for hosts…", W / 2, 260, { "font-size": 16, fill: T.pencil });
  }

  // ------------------------------------------------------------- pipeline
  function drawPipeline(svg) {
    const T = tokens();
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const rs = rough.svg(svg);
    const box = (x, y, w, h, title, sub, col, seed) => {
      svg.appendChild(rs.rectangle(x, y, w, h, { stroke: col || T.ink, strokeWidth: 2, fill: T.paper, fillStyle: "solid", roughness: 1.2, seed }));
      svgText(svg, title, x + w / 2, y + 26, { "font-size": 18, fill: T.ink });
      if (sub) sub.split("\n").forEach((s, i) => svgText(svg, s, x + w / 2, y + 46 + i * 17, { "font-size": 14, fill: T.soft }));
    };
    const arrow = (x1, y1, x2, y2, seed) => {
      svg.appendChild(rs.line(x1, y1, x2, y2, { stroke: T.ink, strokeWidth: 2, seed }));
      arrowHead(rs, svg, x1, y1, x2, y2, T.ink);
    };
    box(6, 70, 140, 82, "Capture", ".pcap upload\nor live sniff", T.ink, 1);
    box(178, 70, 150, 82, "Parser", "Ethernet II,\nARP 0x0806, DHCP", T.ink, 2);
    box(366, 12, 170, 82, "Rule engine", "IP↔MAC table,\n9 explainable rules", T.blue, 3);
    box(366, 132, 170, 82, "Kitsune", "100 features, KitNET\nautoencoders", T.orange, 4);
    box(574, 70, 130, 82, "Fusion", "the verdict\ntable", T.red, 5);
    box(736, 12, 150, 82, "LLM referee", "explains only;\nnever decides", T.green, 6);
    box(736, 132, 150, 82, "Dashboard", "replay, upload,\nlive", T.ink, 7);
    arrow(146, 111, 176, 111, 11);
    arrow(328, 100, 364, 58, 12);
    arrow(328, 122, 364, 168, 13);
    arrow(536, 54, 572, 98, 14);
    arrow(536, 172, 572, 126, 15);
    arrow(704, 98, 734, 58, 16);
    arrow(704, 124, 734, 168, 17);
    arrow(812, 94, 812, 130, 18);
  }

  window.Sketch = { drawScore, drawTimeline, drawTopology, drawPipeline, tokens, VERDICT_COLOR };
})();
