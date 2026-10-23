/* Crisp XP-style charts: a Task-Manager-like anomaly monitor, a
   defrag-like "who owns each address" view and a network map. */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const FONT = 'Tahoma, "Segoe UI", Verdana, sans-serif';
  const MONO = 'Consolas, "Lucida Console", monospace';
  const SPOOF = new Set(["confirmed_spoofing", "probable_spoofing", "suspicious"]);
  const VERDICT_COLOR = {
    confirmed_spoofing: "#ff3b30", probable_spoofing: "#ff3b30", suspicious: "#ff9f1c", anomaly_not_arp: "#ff9f1c",
    pending: "#ffd23f", likely_legitimate: "#ffd23f", normal: "#2bff2b",
  };

  function setup(canvas, height) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = Math.max(canvas.clientWidth || canvas.parentElement.clientWidth || 300, 200);
    const h = height;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      canvas.style.height = h + "px";
    }
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h };
  }

  function text(ctx, s, x, y, color, opt = {}) {
    ctx.save();
    ctx.font = `${opt.bold ? "bold " : ""}${opt.size || 11}px ${opt.mono ? MONO : FONT}`;
    ctx.fillStyle = color;
    ctx.textAlign = opt.align || "left";
    ctx.textBaseline = opt.base || "alphabetic";
    ctx.fillText(s, x, y);
    ctx.restore();
  }

  const mmss = (t) => {
    t = Math.max(0, Math.round(t));
    return Math.floor(t / 60) + ":" + String(t % 60).padStart(2, "0");
  };

  function niceStep(span, target) {
    const raw = span / target;
    for (const s of [10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600]) if (raw <= s) return s;
    return 7200;
  }

  // ------------------------------------------------------------ anomaly monitor
  function drawMonitor(canvas, d, now) {
    const narrow = (canvas.clientWidth || 600) < 480;
    const maxed = canvas.closest(".maximized");
    const { ctx, w, h } = setup(canvas, maxed ? Math.max(260, Math.min(window.innerHeight - 190, 620)) : narrow ? 200 : 230);
    const L = 40, R = 8, T = 22, B = 20;
    const pw = w - L - R, ph = h - T - B;
    const dur = Math.max(d.duration, 1);
    const X = (t) => L + (Math.min(t, dur) / dur) * pw;
    const s = d.series;
    const vals = s.score.filter((v) => v != null && v > 0);
    const thr = d.threshold;
    let lo = vals.length ? Math.min(...vals) : 0.001, hi = vals.length ? Math.max(...vals) : 1;
    if (thr) { lo = Math.min(lo, thr / 4); hi = Math.max(hi, thr * 2); }
    const ylo = Math.floor(Math.log10(Math.max(lo, 1e-4))), yhi = Math.ceil(Math.log10(hi));
    const Y = (v) => T + ph - ((Math.log10(Math.max(v, 1e-6)) - ylo) / Math.max(yhi - ylo, 1)) * ph;

    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    // grid (Task Manager green)
    ctx.strokeStyle = "#0b5d1e";
    ctx.lineWidth = 1;
    for (let x = L; x <= L + pw; x += 14) { ctx.beginPath(); ctx.moveTo(Math.round(x) + 0.5, T); ctx.lineTo(Math.round(x) + 0.5, T + ph); ctx.stroke(); }
    for (let y = T; y <= T + ph; y += 14) { ctx.beginPath(); ctx.moveTo(L, Math.round(y) + 0.5); ctx.lineTo(L + pw, Math.round(y) + 0.5); ctx.stroke(); }

    // learning period
    if (d.graceEnd > 0) {
      ctx.fillStyle = "rgba(70,70,70,.75)";
      ctx.fillRect(L, T, X(d.graceEnd) - L, ph);
      if (X(d.graceEnd) - L > 120) text(ctx, "Learning what normal looks like…", (L + X(d.graceEnd)) / 2, T + ph / 2, "#d0d0d0", { align: "center", size: 12 });
    }
    // labelled attack period
    if (d.attack && d.attack[0] != null) {
      const a0 = X(d.attack[0]), a1 = X(d.attack[1] != null ? d.attack[1] : dur);
      ctx.save();
      ctx.beginPath(); ctx.rect(a0, T, a1 - a0, ph); ctx.clip();
      ctx.fillStyle = "rgba(122,26,18,.45)"; ctx.fillRect(a0, T, a1 - a0, ph);
      ctx.strokeStyle = "rgba(255,80,60,.35)"; ctx.lineWidth = 2;
      for (let x = a0 - ph; x < a1; x += 9) { ctx.beginPath(); ctx.moveTo(x, T + ph); ctx.lineTo(x + ph, T); ctx.stroke(); }
      ctx.restore();
      text(ctx, "attack", (a0 + a1) / 2, T + ph - 6, "#ff8a7a", { align: "center", size: 11, bold: true });
    }
    // y labels
    for (let e = ylo; e <= yhi; e++) {
      const v = Math.pow(10, e);
      text(ctx, e >= 0 ? String(v) : v.toFixed(-e), L - 5, Y(v) + 4, "#9c9c9c", { align: "right", size: 10, mono: true });
    }
    // x labels
    const step = niceStep(dur, narrow ? 4 : 8);
    for (let t = 0; t <= dur + 1e-6; t += step) text(ctx, mmss(t), X(t), h - 6, "#9c9c9c", { align: "center", size: 10, mono: true });

    // score line
    ctx.strokeStyle = "#2bff2b";
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    let pen = false;
    for (let i = 0; i < s.t.length && s.t[i] <= now; i++) {
      const v = s.score[i];
      if (v == null) { pen = false; continue; }
      const x = X(s.t[i]), y = Y(v);
      if (!pen) { ctx.moveTo(x, y); pen = true; } else ctx.lineTo(x, y);
    }
    ctx.stroke();

    // alarm line
    if (thr) {
      ctx.save();
      ctx.strokeStyle = "#ff3b30"; ctx.lineWidth = 1.5; ctx.setLineDash([6, 4]);
      ctx.beginPath(); ctx.moveTo(L, Y(thr)); ctx.lineTo(L + pw, Y(thr)); ctx.stroke();
      ctx.restore();
      text(ctx, "alarm line", L + pw - 4, Y(thr) - 5, "#ff6b60", { align: "right", size: 11, bold: true });
    }

    // incident flags
    for (const inc of d.incidents) {
      if (inc.first_t > now) continue;
      const x = Math.round(X(inc.first_t)) + 0.5;
      const col = VERDICT_COLOR[d.verdictAt(inc, now)] || "#fff";
      ctx.strokeStyle = col; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(x, T); ctx.lineTo(x, T + ph); ctx.stroke();
      ctx.fillStyle = col;
      ctx.fillRect(x - 9, 3, 18, 15);
      text(ctx, String(inc.id), x, 14.5, "#000", { align: "center", size: 11, bold: true });
    }
    // playhead
    if (now < dur) {
      ctx.strokeStyle = "#ffffff"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(Math.round(X(now)) + 0.5, T); ctx.lineTo(Math.round(X(now)) + 0.5, T + ph); ctx.stroke();
    }
    ctx.strokeStyle = "#2a2a2a"; ctx.strokeRect(L + 0.5, T + 0.5, pw - 1, ph - 1);
  }

  // ------------------------------------------------------------ who owns each address
  function drawOwners(canvas, d, now) {
    const rows = d.timelineRows;
    const rowH = 26;
    const { ctx, w, h } = setup(canvas, Math.max(70, 26 + rows.length * rowH));
    const L = w < 480 ? 104 : 124, R = 8, T = 6;
    const pw = w - L - R;
    const dur = Math.max(d.duration, 1);
    const X = (t) => L + (Math.min(t, dur) / dur) * pw;
    ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, w, h);
    if (!rows.length) {
      text(ctx, "No address has changed owner yet.", 10, 34, "#555", { size: 12 });
      return;
    }
    const colors = { owner: "#2f6fde", attacker: "#e2402b", new: "#3cae3c" };
    rows.forEach((row, i) => {
      const y = T + i * rowH;
      text(ctx, row.ip, 8, y + 16, "#000", { size: 12, mono: true, bold: row.gateway });
      if (row.gateway) text(ctx, "router", L - 6, y + 16, "#0046d5", { size: 10, align: "right" });
      ctx.fillStyle = "#f2f2ee"; ctx.fillRect(L, y + 3, pw, rowH - 8);
      ctx.strokeStyle = "#c8c6b8"; ctx.strokeRect(L + 0.5, y + 3.5, pw - 1, rowH - 9);
      for (let k = 0; k < row.history.length; k++) {
        const [t0, mac] = row.history[k];
        if (t0 > now) break;
        const t1 = Math.min(k + 1 < row.history.length ? row.history[k + 1][0] : now, now);
        const x0 = X(t0), x1 = Math.max(X(t1), x0 + 2);
        ctx.fillStyle = colors[d.macRole(row.ip, mac, t0)];
        ctx.fillRect(x0, y + 4, x1 - x0, rowH - 10);
      }
      // defrag-style block separators
      ctx.strokeStyle = "rgba(255,255,255,.55)";
      for (let x = L + 5; x < L + pw; x += 5) { ctx.beginPath(); ctx.moveTo(Math.round(x) + 0.5, y + 4); ctx.lineTo(Math.round(x) + 0.5, y + rowH - 6); ctx.stroke(); }
    });
    const step = niceStep(dur, w < 480 ? 4 : 8);
    for (let t = 0; t <= dur + 1e-6; t += step) text(ctx, mmss(t), X(t), h - 4, "#555", { align: "center", size: 10, mono: true });
    if (now < dur) {
      ctx.strokeStyle = "#000"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(Math.round(X(now)) + 0.5, 0); ctx.lineTo(Math.round(X(now)) + 0.5, h - 15); ctx.stroke();
    }
  }

  // ------------------------------------------------------------ network map
  function el(tag, attrs, parent, textContent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (textContent != null) n.textContent = textContent;
    if (parent) parent.appendChild(n);
    return n;
  }
  function useIcon(parent, name, x, y, size) {
    const u = el("use", { href: "#i-" + name, x: x - size / 2, y: y - size / 2, width: size, height: size }, parent);
    return u;
  }

  function drawNetMap(svg, topo) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const defs = el("defs", {}, svg);
    for (const [id, col] of [["arr-red", "#e2402b"], ["arr-green", "#2e9b2e"]]) {
      const m = el("marker", { id, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, defs);
      el("path", { d: "M0 0 L10 5 L0 10 Z", fill: col }, m);
    }
    const W = 420;
    const gw = { x: 250, y: 110 };
    const atk = topo.attacker;
    useIcon(svg, "globe", gw.x, 30, 38);
    el("text", { x: gw.x + 26, y: 34, "font-size": 12, fill: "#333" }, svg, "Internet");
    el("line", { x1: gw.x, y1: 50, x2: gw.x, y2: gw.y - 22, stroke: "#2e9b2e", "stroke-width": 2.5 }, svg);

    const hosts = topo.hosts;
    const n = Math.max(hosts.length, 1);
    const left = atk ? 130 : 40, right = 400;
    const pos = hosts.map((hst, i) => ({ ...hst, x: n === 1 ? (left + right) / 2 : left + (i * (right - left)) / (n - 1), y: 252 + (i % 2) * 30 }));
    const ax = 62, ay = 175;

    for (const p of pos) {
      const poisoned = atk && topo.poisoned.has(p.ip);
      if (poisoned) {
        el("line", { x1: p.x, y1: p.y - 18, x2: gw.x, y2: gw.y + 18, stroke: "#bbb", "stroke-width": 1.5, "stroke-dasharray": "4 4" }, svg);
        const mx = (p.x + gw.x) / 2, my = (p.y - 18 + gw.y + 18) / 2;
        el("text", { x: mx, y: my + 5, "font-size": 16, "font-weight": "bold", fill: "#e2402b", "text-anchor": "middle" }, svg, "✕");
        el("path", { d: `M${p.x - 6} ${p.y - 18} Q ${(p.x + ax) / 2} ${ay + 70} ${ax + 22} ${ay + 12}`, fill: "none", stroke: "#e2402b", "stroke-width": 2.5, "marker-end": "url(#arr-red)" }, svg);
      } else {
        el("line", { x1: p.x, y1: p.y - 18, x2: gw.x, y2: gw.y + 18, stroke: "#2e9b2e", "stroke-width": 2 }, svg);
      }
    }
    // router
    el("rect", { x: gw.x - 62, y: gw.y - 22, width: 124, height: 44, rx: 4, fill: "#fff", stroke: "#7f9db9" }, svg);
    useIcon(svg, "router", gw.x - 40, gw.y, 34);
    el("text", { x: gw.x - 18, y: gw.y - 4, "font-size": 12, "font-weight": "bold", fill: "#000" }, svg, "Router");
    el("text", { x: gw.x - 18, y: gw.y + 11, "font-size": 11, fill: "#333" }, svg, topo.gateway.ip || "?");

    if (atk) {
      el("path", { d: `M${ax + 22} ${ay - 12} Q ${ax + 70} ${gw.y + 8} ${gw.x - 64} ${gw.y + 4}`, fill: "none", stroke: "#e2402b", "stroke-width": 2.5, "marker-end": "url(#arr-red)" }, svg);
      el("rect", { x: ax - 46, y: ay - 30, width: 92, height: 84, rx: 4, fill: "#fde3de", stroke: "#e2402b", "stroke-width": 1.5 }, svg);
      useIcon(svg, "hacker", ax, ay - 6, 36);
      el("text", { x: ax, y: ay + 26, "font-size": 12, "font-weight": "bold", fill: "#c4200f", "text-anchor": "middle" }, svg, "ATTACKER");
      el("text", { x: ax, y: ay + 42, "font-size": 9.5, fill: "#333", "text-anchor": "middle", "font-family": MONO }, svg, atk.mac);
      el("rect", { x: 8, y: 6, width: 168, height: 38, rx: 3, fill: "#fff7d6", stroke: "#e2b43c" }, svg);
      el("text", { x: 16, y: 21, "font-size": 11.5, "font-weight": "bold", fill: "#c4200f" }, svg, "Traffic is going through");
      el("text", { x: 16, y: 36, "font-size": 11.5, "font-weight": "bold", fill: "#c4200f" }, svg, "the attacker!");
    }
    for (const p of pos) {
      const poisoned = atk && topo.poisoned.has(p.ip);
      useIcon(svg, poisoned ? "computer" : "computer", p.x, p.y - 2, 34);
      if (poisoned) useIcon(svg, "warn", p.x + 14, p.y - 14, 15);
      if (p.legit) useIcon(svg, "info", p.x + 14, p.y - 14, 15);
      el("text", { x: p.x, y: p.y + 24, "font-size": 11, "text-anchor": "middle", fill: "#000" }, svg, "." + p.ip.split(".").pop());
      el("text", { x: p.x, y: p.y + 36, "font-size": 9.5, "text-anchor": "middle", fill: "#555" }, svg, (p.vendor || "").split(" ")[0].slice(0, 12));
    }
    if (!hosts.length) el("text", { x: W / 2, y: 260, "font-size": 12, "text-anchor": "middle", fill: "#777" }, svg, "Waiting for devices to appear…");
  }

  window.Charts = { drawMonitor, drawOwners, drawNetMap, mmss, VERDICT_COLOR, SPOOF };
})();
