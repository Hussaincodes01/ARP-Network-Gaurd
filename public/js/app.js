/* ARPGuard dashboard: replays an analysis result (demo, upload or live
   snapshot) on a clock and draws every panel as of the playhead time. */
(function () {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const SPOOF = new Set(["confirmed_spoofing", "probable_spoofing", "suspicious"]);
  const VCLASS = { confirmed_spoofing: "v-red", probable_spoofing: "v-red", suspicious: "v-orange", anomaly_not_arp: "v-orange", pending: "v-yellow", likely_legitimate: "v-yellow", normal: "v-green" };
  const LABEL = {
    confirmed_spoofing: "Confirmed spoofing", probable_spoofing: "Probable spoofing", suspicious: "Suspicious, review",
    anomaly_not_arp: "Anomaly, not ARP-related", pending: "Rule alert, weighing evidence", likely_legitimate: "Likely legitimate change", normal: "Normal",
  };
  const RULE_NAMES = {
    gateway_mac_change: "gateway MAC change", ip_mac_conflict: "IP→MAC conflict", binding_flip_flop: "flip-flop",
    mac_multiple_ips: "one MAC, many IPs", unsolicited_reply: "unsolicited reply", eth_arp_mismatch: "Ethernet/ARP mismatch",
    arp_scan: "ARP scan", arp_flood: "ARP flood", ip_mac_change: "DHCP-backed change", binding_restored: "binding restored",
  };

  const S = {
    d: null, now: 0, playing: false, speed: 10, last: 0, lastDraw: 0, mode: "replay",
    health: null, index: null, open: new Set(), incSig: "", topoSig: "", fencer: null, live: null, llm: {},
  };

  // ------------------------------------------------------------ data prep
  function prep(r) {
    const m = r.meta;
    const s = r.series;
    let graceEnd = 0;
    for (let i = 0; i < s.score.length; i++) if (s.score[i] != null) { graceEnd = s.t[i]; break; }
    if (!s.score.some((v) => v != null)) graceEnd = m.kitsune ? m.duration : 0;
    const cum = [];
    let acc = 0;
    for (let i = 0; i < s.pps.length; i++) { acc += s.pps[i] * s.bin; cum.push(acc); }
    const incidents = r.incidents.slice().sort((a, b) => a.first_t - b.first_t);
    const spoofActors = new Set(incidents.filter((i) => SPOOF.has(i.verdict) && i.actor).map((i) => i.actor));
    const gwIp = r.gateway && r.gateway.ip;
    const firstOwner = {};
    for (const b of r.bindings) firstOwner[b.ip] = b.history.length ? b.history[0][1] : b.trusted_mac;
    const timelineRows = r.bindings
      .filter((b) => b.changes > 0 || b.ip === gwIp)
      .map((b) => ({ ip: b.ip, history: b.history, gateway: b.ip === gwIp }))
      .sort((a, b) => (b.gateway - a.gateway) || (a.history[0][0] - b.history[0][0]))
      .slice(0, 9);
    const d = {
      raw: r, meta: m, series: s, duration: m.duration, threshold: m.kitsune ? m.kitsune.threshold : null,
      graceEnd, cum, incidents, alerts: r.alerts.slice().sort((a, b) => a.t - b.t),
      arp: r.arp_events, bindings: r.bindings, hosts: r.hosts, gateway: r.gateway || {},
      attack: m.attack_window || null, timelineRows, spoofActors, firstOwner,
    };
    d.verdictAt = (inc, t) => {
      let v = inc.timeline.length ? inc.timeline[0][1] : inc.verdict;
      for (const [tt, vv] of inc.timeline) if (tt <= t) v = vv;
      return v;
    };
    d.macRole = (ip, mac, t) => {
      for (const inc of incidents) {
        if (inc.actor === mac && SPOOF.has(inc.verdict) && inc.ips.includes(ip)) return "attacker";
      }
      return firstOwner[ip] === mac ? "owner" : "new";
    };
    return d;
  }

  const upper = (arr, t, key) => { // count of items with item[key] <= t (sorted)
    let lo = 0, hi = arr.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (key(arr[mid]) <= t) lo = mid + 1; else hi = mid; }
    return lo;
  };

  // ------------------------------------------------------------ loading
  function load(result, opts = {}) {
    S.d = prep(result);
    S.open.clear();
    S.incSig = S.topoSig = "";
    S.now = opts.follow ? S.d.duration : 0;
    $("#scrubber").max = 1000;
    $("#clock-total").textContent = "of " + S.d.duration.toFixed(1) + " s";
    drawTicks();
    renderAt(S.now, true);
    if (opts.autoplay) setPlaying(true);
  }

  async function loadDemo(id) {
    const entry = S.index.demos.find((x) => x.id === id) || S.index.demos[0];
    $("#demo-blurb").textContent = entry.blurb;
    setPlaying(false);
    $("#verdict").textContent = "Loading…";
    const r = await (await fetch(entry.file)).json();
    load(r);
  }

  function drawTicks() {
    const box = $("#ticks");
    box.innerHTML = "";
    const T = window.Sketch.tokens();
    for (const inc of S.d.incidents) {
      const i = document.createElement("i");
      i.style.left = (100 * inc.first_t / Math.max(S.d.duration, 1)) + "%";
      i.style.background = window.Sketch.VERDICT_COLOR(T, inc.verdict);
      i.title = "#" + inc.id + " " + LABEL[inc.verdict];
      box.appendChild(i);
    }
  }

  // ------------------------------------------------------------ rendering
  function renderAt(t, force) {
    const d = S.d;
    if (!d) return;
    S.now = Math.max(0, Math.min(t, d.duration));
    const now = S.now;
    $("#scrubber").value = Math.round(1000 * now / Math.max(d.duration, 1e-6));
    $("#clock").textContent = "t = " + now.toFixed(1) + " s";

    // counters
    const bi = Math.min(d.cum.length - 1, Math.floor(now / d.series.bin));
    const pk = now >= d.duration ? d.meta.packets : Math.round(bi >= 0 ? d.cum[bi] : 0);
    $("#st-packets").textContent = fmt(Math.min(pk, d.meta.packets));
    $("#st-arp").textContent = fmt(upper(d.arp, now, (e) => e[0]));
    $("#st-hosts").textContent = fmt(d.hosts.filter((h) => h.first_t <= now).length);
    $("#st-alerts").textContent = fmt(upper(d.alerts, now, (a) => a.t));
    $("#st-phase").textContent = !d.meta.kitsune ? "off" : now < d.graceEnd ? "learning" : "watching";

    renderVerdict(now);
    renderTable(now);
    renderFeed(now);
    renderIncidents(now);
    const tnow = performance.now();
    if (force || tnow - S.lastDraw > 110) {
      S.lastDraw = tnow;
      window.Sketch.drawScore($("#score-canvas"), d, now);
      window.Sketch.drawTimeline($("#timeline-canvas"), d, now);
      renderTopology(now);
    }
  }

  function activeIncidents(now) {
    return S.d.incidents.filter((i) => i.first_t <= now && now <= i.last_t + (i.kind === "kitsune" ? 5 : 30));
  }

  function renderVerdict(now) {
    const d = S.d;
    const act = activeIncidents(now).map((i) => ({ inc: i, v: d.verdictAt(i, now) }));
    const rank = { confirmed_spoofing: 6, probable_spoofing: 5, suspicious: 4, anomaly_not_arp: 3, pending: 2, likely_legitimate: 1 };
    act.sort((a, b) => (rank[b.v] || 0) - (rank[a.v] || 0));
    const top = act[0];
    const past = d.incidents.filter((i) => i.last_t + 30 < now && SPOOF.has(d.verdictAt(i, now))).length;
    let v = top ? top.v : "normal";
    $("#verdict").textContent = LABEL[v];
    let sub = "";
    if (top && top.inc.actor) sub = `#${top.inc.id} · ${top.inc.actor} (${top.inc.actor_vendor})`;
    else if (top) sub = `#${top.inc.id} · Kitsune only`;
    else if (past) sub = `${past} earlier incident${past > 1 ? "s" : ""} on record`;
    else if (d.meta.kitsune && now < d.graceEnd) sub = "Kitsune is learning normal traffic";
    $("#verdict-sub").textContent = sub || " ";
    $("#lamp-red").classList.toggle("on", SPOOF.has(v));
    $("#lamp-white").classList.toggle("on", ["pending", "anomaly_not_arp", "likely_legitimate"].includes(v));
    $("#lamp-green").classList.toggle("on", v === "normal");

    // mascot
    const gw = d.gateway.ip || "the gateway";
    let pose = "guard", say = "All quiet on the piste.", red = false;
    if (v === "normal" && d.meta.kitsune && now < d.graceEnd) say = "Watching, learning what normal looks like…";
    if (SPOOF.has(v)) {
      pose = "lunge"; red = true;
      say = top.inc.gateway_involved ? `Touché! ${top.inc.actor} is posing as ${gw}.` : `Touché! ${top.inc.actor} is spoofing.`;
    } else if (v === "pending") { pose = "alert"; say = "Hm? A binding just changed…"; }
    else if (v === "anomaly_not_arp") { pose = "alert"; say = "Odd traffic, but no ARP trickery."; }
    else if (v === "likely_legitimate") { pose = "salute"; say = "Just a new device. Carry on!"; }
    S.fencer.pose(pose);
    const b = $("#bubble");
    if (b.textContent !== say) {
      b.textContent = say;
      b.classList.toggle("red", red);
      b.classList.remove("pop"); void b.offsetWidth; b.classList.add("pop");
    }
  }

  function renderTable(now) {
    const d = S.d;
    const rows = [];
    for (const b of d.bindings) {
      if (b.first_t > now) continue;
      let mac = b.history[0][1], since = b.history[0][0], changes = 0;
      for (const [t, m] of b.history) if (t <= now) { if (m !== mac) changes++; mac = m; since = t; }
      const role = d.macRole(b.ip, mac, since);
      const inc = d.incidents.find((i) => i.actor === mac && i.ips.includes(b.ip) && i.first_t <= now);
      const v = inc ? d.verdictAt(inc, now) : null;
      let status = '<span class="tag ok">ok</span>', cls = "";
      if (role === "attacker" && v && v !== "pending") { status = '<span class="tag bad">spoofed!</span>'; cls = "spoofed"; }
      else if (v === "pending") { status = '<span class="tag warn">checking</span>'; cls = "legit"; }
      else if (v === "likely_legitimate") { status = '<span class="tag new">new owner</span>'; cls = "legit"; }
      else if (changes) status = '<span class="tag ok">restored</span>';
      const vendor = (d.hosts.find((h) => h.mac === mac) || {}).vendor || "";
      rows.push(`<tr class="${cls}${b.ip === d.gateway.ip ? " gw" : ""}"><td class="mono">${esc(b.ip)}</td><td class="mono">${esc(mac)}</td>` +
        `<td>${esc(vendor)}</td><td>${changes}</td><td class="mono">${since.toFixed(1)} s</td><td>${status}</td></tr>`);
    }
    $("#arp-tbody").innerHTML = rows.join("") || '<tr><td colspan="6" class="empty">No ARP seen yet.</td></tr>';
  }

  function renderFeed(now) {
    const d = S.d;
    const n = upper(d.arp, now, (e) => e[0]);
    const items = d.arp.slice(Math.max(0, n - 12), n).reverse().map((e) => {
      const [t, kind, sha, spa, , tpa, , , flag] = e;
      let s;
      if (kind === "request") s = `who-has ${tpa} tell ${spa}`;
      else if (kind === "reply") s = `${spa} is-at ${sha} → ${tpa}`;
      else if (kind === "gratuitous") s = `announce ${spa} is-at ${sha}`;
      else if (kind === "probe") s = `probe: anyone using ${tpa}?`;
      else s = `${kind} ${spa} ${sha}`;
      const cls = flag === "spoofed_claim" || flag === "eth_arp_mismatch" ? "bad" : flag === "arp_scan" ? "scan" : "";
      return `<li class="${cls}"><span class="t">${t.toFixed(2)}</span><span>${esc(s)}${cls === "bad" ? " ⚠" : ""}</span></li>`;
    });
    $("#arp-feed").innerHTML = items.join("") || '<li><span></span><span class="dim">silence…</span></li>';
  }

  function ruleSummary(rules) {
    return Object.entries(rules || {}).filter(([k]) => k !== "binding_restored")
      .map(([k, n]) => `${RULE_NAMES[k] || k}${n > 1 ? " ×" + n : ""}`).join(", ");
  }

  function explanationHtml(inc) {
    const e = (S.llm[inc.id] && S.llm[inc.id].data) || inc.explanation;
    if (!e) return "";
    const src = e.source || {};
    const who = src.provider === "anthropic" ? `written by ${esc(src.model || "Claude")}` :
      src.provider === "ollama" ? `written by ${esc(src.model)} (Ollama)` : "rule-based template";
    const fb = src.fallback_reason ? ` (LLM unavailable: ${esc(src.fallback_reason)})` : "";
    const att = e.attacker || {};
    const victims = (e.victims || []).map((v) => `<li><code>${esc(v.ip)}</code>: ${esc(v.role)}</li>`).join("");
    const fixes = (e.fixes || []).map((f) => `<li><b>${esc(f.action)}.</b> ${esc(f.detail)}${f.command ? `<pre>${esc(f.command)}</pre>` : ""}</li>`).join("");
    const llmOk = S.health && S.health.llm && S.health.llm.provider !== "template";
    const state = S.llm[inc.id] && S.llm[inc.id].state;
    const btn = S.health ? `<button class="btn ask" data-ask="${inc.id}" ${!llmOk || state === "busy" ? "disabled" : ""}
        title="${llmOk ? "Ask the LLM for a fresh explanation" : "The server has no LLM configured (set ANTHROPIC_API_KEY)"}">${state === "busy" ? "Asking…" : "Ask the AI referee"}</button>` : "";
    return `<p class="what">${esc(e.what_happened)}</p>
      <dl>
        <dt>Attacker</dt><dd>${att.mac ? `<code>${esc(att.mac)}</code> ${att.ip ? "(" + esc(att.ip) + ")" : ""} ${esc(att.vendor || "")}<br>` : ""}<span class="dim">${esc(att.reasoning)}</span></dd>
        ${victims ? `<dt>Victims</dt><dd><ul>${victims}</ul></dd>` : ""}
        ${(e.impact || []).length ? `<dt>Impact</dt><dd><ul>${e.impact.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></dd>` : ""}
        <dt>Confidence</dt><dd>${esc((e.confidence || {}).level)}: ${esc((e.confidence || {}).reason)}</dd>
      </dl>
      ${fixes ? `<b>Fixes</b><ul>${fixes}</ul>` : ""}
      ${(e.caveats || []).length ? `<p class="dim">${e.caveats.map(esc).join(" ")}</p>` : ""}
      <div class="src">Explanation: ${who}${fb}. ${btn}</div>
      ${state === "error" ? `<p class="dim">${esc(S.llm[inc.id].error)}</p>` : ""}`;
  }

  function renderIncidents(now) {
    const d = S.d;
    const vis = d.incidents.filter((i) => i.first_t <= now);
    const sig = vis.map((i) => i.id + ":" + d.verdictAt(i, now)).join("|") + "|" + JSON.stringify(Object.keys(S.llm).map((k) => S.llm[k].state));
    if (sig === S.incSig) return;
    S.incSig = sig;
    const box = $("#incidents");
    if (!vis.length) { box.innerHTML = '<p class="empty">No incidents yet. The piste is quiet.</p>'; return; }
    box.innerHTML = vis.slice().reverse().map((inc) => {
      const v = d.verdictAt(inc, now);
      const final = v === inc.verdict;
      const e = inc.explanation || {};
      const k = inc.kitsune || {};
      const body = final ? explanationHtml(inc) : '<p class="dim">Weighing evidence: waiting for the anomaly model…</p>';
      return `<article class="incident" data-id="${inc.id}">
        <header><span class="num">#${inc.id}</span><span class="v ${VCLASS[v]}">${LABEL[v]}</span>
          <span class="when">t = ${inc.first_t.toFixed(1)} s</span></header>
        <p class="headline">${esc(final ? ((S.llm[inc.id] && S.llm[inc.id].data) || e).headline : (inc.actor ? inc.actor + " (" + inc.actor_vendor + ")" : "Kitsune anomaly"))}</p>
        <p class="rules">${inc.kind === "arp" ? "Rules: " + esc(ruleSummary(inc.rules)) + " · " : ""}Kitsune: ${k.hits || 0}/${k.scored || 0} packets above threshold</p>
        <details ${S.open.has(inc.id) ? "open" : ""}><summary>Referee's explanation</summary>${body}</details>
      </article>`;
    }).join("");
  }

  function renderTopology(now) {
    const d = S.d;
    const act = activeIncidents(now).filter((i) => i.kind === "arp");
    const spoof = act.find((i) => SPOOF.has(d.verdictAt(i, now)));
    const legit = new Set(act.filter((i) => d.verdictAt(i, now) === "likely_legitimate").flatMap((i) => i.ips));
    const attackerMac = spoof ? spoof.actor : null;
    const hosts = d.hosts
      .filter((h) => h.first_t <= now && !h.gateway && h.mac !== attackerMac && h.ips.length && h.ips[0] !== d.gateway.ip)
      .sort((a, b) => b.packets - a.packets).slice(0, 7)
      .sort((a, b) => a.ips[0].localeCompare(b.ips[0], undefined, { numeric: true }))
      .map((h) => ({ ip: h.ips[0], vendor: h.vendor, legit: legit.has(h.ips[0]) }));
    const poisoned = new Set(spoof ? [...spoof.ips, ...spoof.targets] : []);
    const sig = JSON.stringify([hosts, attackerMac, [...poisoned], document.documentElement.dataset.theme]);
    if (sig === S.topoSig) return;
    S.topoSig = sig;
    window.Sketch.drawTopology($("#topology"), {
      gateway: d.gateway, hosts, poisoned, attacker: attackerMac ? { mac: attackerMac } : null,
    });
  }

  // ------------------------------------------------------------ evaluation
  async function renderEval() {
    let ev;
    try { ev = await (await fetch("data/evaluation.json")).json(); } catch (e) { return; }
    const names = S.index.methods;
    const html = ev.map((r) => {
      const benign = !r.malicious_packets;
      const rows = Object.entries(r.methods);
      // best method; ties go to the combined system, which is listed last
      const best = benign ? rows.reduce((a, b) => (b[1].fpr <= a[1].fpr ? b : a))[0] : rows.reduce((a, b) => (b[1].f1 > a[1].f1 ? b : a))[0];
      const body = rows.map(([m, v]) => `<tr class="${m === "combined" ? "best" : ""}"><td>${esc(names[m] || m)}${m === best ? " ★" : ""}</td>
          ${benign ? "" : `<td class="num">${v.detection_rate.toFixed(3)}</td>`}
          <td class="num">${(100 * v.fpr).toFixed(2)}%</td>
          ${benign ? `<td class="num">${fmt(v.fp)}</td>` : `<td class="num">${v.precision.toFixed(3)}</td><td class="num">${v.f1.toFixed(3)}</td><td class="num">${v.time_to_detect_s == null ? "n/a" : v.time_to_detect_s.toFixed(1) + " s"}</td>`}</tr>`).join("");
      return `<div><h3>${esc(r.capture)} <small>${fmt(r.evaluated_packets)} packets scored${benign ? ", no attack" : `, ${fmt(r.malicious_packets)} malicious`}</small></h3>
        <div class="table-wrap"><table class="sketch-table"><thead><tr><th>Method</th>${benign ? "<th>False-alarm rate</th><th>False-alarm packets</th>" : "<th>Detection</th><th>FPR</th><th>Precision</th><th>F1</th><th>Time to detect</th>"}</tr></thead><tbody>${body}</tbody></table></div></div>`;
    }).join("");
    const a = ev[0] && ev[0].methods;
    const b = ev[1] && ev[1].methods;
    const note = a && b ? `<p class="note">On the attack capture, the rules alone already catch the textbook attack (F1 ${a.rules.f1.toFixed(3)}), and
      fusion matches them (F1 ${a.combined.f1.toFixed(3)}) while waiting ~${(a.combined.time_to_detect_s || 0).toFixed(1)} s for the model's confirmation.
      Fusion pays off on false alarms: rules alone flag ${(100 * a.rules.fpr).toFixed(1)}% of benign packets during the attack run and
      ${(100 * b.rules.fpr).toFixed(1)}% on the benign capture (a NIC swap and a router swap look like spoofing), against
      ${(100 * a.combined.fpr).toFixed(1)}% and ${(100 * b.combined.fpr).toFixed(1)}% combined. The plan's max×1.1 threshold caught
      ${(100 * a.kitsune_max.detection_rate).toFixed(1)}% of attack packets here; it is set by a single calibration outlier, so it swings from
      capture to capture, which is why the 99th-percentile rule is the default.
      These captures are synthetic: they show the method works, not how well it generalises.
      For the report, run <code>python -m eval.evaluate</code> on the Kitsune ARP MitM capture.</p>` : "";
    $("#eval-body").innerHTML = `<div class="eval-grid">${html}</div>${note}`;
  }

  // ------------------------------------------------------------ AI referee
  async function ask(id) {
    const inc = S.d.incidents.find((i) => i.id === id);
    if (!inc || !inc.evidence) return;
    S.llm[id] = { state: "busy" };
    S.open.add(id);
    renderIncidents(S.now);
    try {
      const res = await fetch("/api/explain", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ evidence: inc.evidence }) });
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail || res.statusText);
      S.llm[id] = { state: "done", data: body };
    } catch (e) {
      S.llm[id] = { state: "error", error: "Couldn't get an AI explanation: " + e.message };
    }
    S.incSig = "";
    renderIncidents(S.now);
  }

  // ------------------------------------------------------------ playback
  function setPlaying(p) {
    S.playing = p && !!S.d;
    if (S.playing && S.now >= S.d.duration - 0.01) S.now = 0;
    $("#play").textContent = S.playing ? "❚❚" : "▶";
    $("#play").setAttribute("aria-label", S.playing ? "Pause" : "Play");
    S.last = performance.now();
  }

  function loop(ts) {
    if (S.playing && S.d) {
      const dt = (ts - S.last) / 1000;
      S.last = ts;
      let t = S.now + dt * S.speed;
      if (t >= S.d.duration) { t = S.d.duration; setPlaying(false); }
      renderAt(t, false);
    }
    requestAnimationFrame(loop);
  }

  // ------------------------------------------------------------ upload
  async function gzipIfLarge(file) {
    const head = new Uint8Array(await file.slice(0, 2).arrayBuffer());
    const isGz = head[0] === 0x1f && head[1] === 0x8b;
    const limit = (S.health && S.health.limits.max_upload_bytes) || 4.4e6;
    if (isGz || file.size <= limit * 0.9 || !("CompressionStream" in window)) return file;
    const stream = file.stream().pipeThrough(new CompressionStream("gzip"));
    return new Blob([await new Response(stream).arrayBuffer()]);
  }

  async function upload(file) {
    const status = $("#upload-status");
    const btn = $("#upload-btn");
    btn.disabled = true;
    const t0 = Date.now();
    const tick = setInterval(() => { status.textContent = `Analysing ${file.name}… ${Math.round((Date.now() - t0) / 1000)} s (Kitsune learns first, then scores; about 700 packets/s)`; }, 500);
    try {
      const body = await gzipIfLarge(file);
      const q = new URLSearchParams({ name: file.name, kitsune: $("#kitsune-input").checked ? "true" : "false" });
      const gw = $("#gw-input").value.trim();
      if (gw) q.set("gateway", gw);
      const res = await fetch("/api/analyze?" + q, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body });
      const data = await res.json().catch(() => ({ detail: res.statusText }));
      if (!res.ok) throw new Error(data.detail || res.statusText);
      clearInterval(tick);
      const tr = data.meta.truncated_to ? ` (first ${fmt(data.meta.truncated_to)} packets)` : "";
      status.textContent = `Done: ${fmt(data.meta.packets)} packets${tr}, ${data.incidents.length} incident(s), verdict: ${data.meta.verdict_label}. Press ▶ to replay.`;
      load(data);
    } catch (e) {
      clearInterval(tick);
      status.textContent = "Upload failed: " + e.message + (S.health ? "" : " (this site has no analysis API; run ARPGuard locally)");
    } finally {
      btn.disabled = false;
    }
  }

  // ------------------------------------------------------------ live
  function renderLivePanel() {
    const box = $("#live-body");
    const h = S.health;
    if (!h || !h.live.available) {
      box.innerHTML = `<p><b>Live sniffing can't run here.</b> ${esc(h ? h.live.reason : "This deployment has no API.")}
        It needs raw-socket access on a machine plugged into your own LAN. On your computer:</p>
        <ol class="steps">
          <li><code>git clone</code> this repo, then <code>pip install -r requirements-dev.txt</code></li>
          <li><code>sudo python -m arpguard serve</code> (Windows: an Administrator prompt with Npcap installed)</li>
          <li>open <code>http://localhost:8000</code>, choose <i>Live</i>, press Start</li>
        </ol>
        <p class="hint">Or headless: <code>sudo python -m arpguard live --record data/home_benign.pcap</code> prints alerts and saves a benign capture for the evaluation. Only sniff networks you own.</p>`;
      return;
    }
    box.innerHTML = `<div class="live-row">
        <label>Interface <input type="text" id="live-iface" placeholder="default"></label>
        <label>Gateway <input type="text" id="live-gw" placeholder="auto"></label>
        <button class="btn primary" id="live-start">${h.live.running ? "Restart" : "Start sniffing"}</button>
        <button class="btn" id="live-stop">Stop</button></div>
      <p class="hint" id="live-status">${h.live.running ? "Running." : "Kitsune spends its first 6,000 packets learning; rules work immediately."}</p>`;
    $("#live-start").onclick = async () => {
      const res = await fetch("/api/live/start", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iface: $("#live-iface").value.trim() || null, gateway: $("#live-gw").value.trim() || null }) });
      const body = await res.json();
      if (!res.ok) { $("#live-status").textContent = body.detail; return; }
      $("#live-status").textContent = "Sniffing… the dashboard follows the live session.";
      clearInterval(S.live);
      S.live = setInterval(pollLive, 2000);
    };
    $("#live-stop").onclick = async () => {
      clearInterval(S.live);
      await fetch("/api/live/stop", { method: "POST" });
      $("#live-status").textContent = "Stopped.";
    };
  }

  async function pollLive() {
    try {
      const res = await fetch("/api/live/snapshot");
      if (!res.ok) return;
      const r = await res.json();
      if (r.meta.packets) load(r, { follow: true });
    } catch (e) { /* keep polling */ }
  }

  // ------------------------------------------------------------ wiring
  function setMode(mode) {
    S.mode = mode;
    $$(".mode").forEach((b) => { const on = b.dataset.mode === mode; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); });
    $$(".mode-panel").forEach((p) => p.classList.toggle("hidden", p.id !== "panel-" + mode));
    if (mode === "live") renderLivePanel();
    if (mode === "replay") loadDemo($("#demo-select").value);
  }

  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem("arpguard-theme"); } catch (e) { /* private mode */ }
    if (saved) document.documentElement.dataset.theme = saved;
    const btn = $("#theme-toggle");
    const label = () => {
      const dark = document.documentElement.dataset.theme === "dark" ||
        (!document.documentElement.dataset.theme && window.matchMedia("(prefers-color-scheme: dark)").matches);
      btn.textContent = dark ? "Switch to paper" : "Switch to chalkboard";
      return dark;
    };
    label();
    btn.onclick = () => {
      const dark = label();
      document.documentElement.dataset.theme = dark ? "light" : "dark";
      try { localStorage.setItem("arpguard-theme", document.documentElement.dataset.theme); } catch (e) { /* ignore */ }
      label();
      S.topoSig = "";
      window.Sketch.drawPipeline($("#pipeline"));
      renderAt(S.now, true);
    };
  }

  async function init() {
    initTheme();
    // canvases can't re-flow text, so redraw them once the hand-drawn fonts arrive
    if (document.fonts) document.fonts.addEventListener("loadingdone", () => { if (S.d) renderAt(S.now, true); });
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) $$("animate.boil").forEach((a) => a.remove());
    S.fencer = new window.Fencer($("#mascot"));
    window.Sketch.drawPipeline($("#pipeline"));

    try {
      const r = await fetch("/api/health");
      if (r.ok) S.health = await r.json();
    } catch (e) { S.health = null; }

    S.index = await (await fetch("data/index.json")).json();
    $("#demo-select").innerHTML = S.index.demos.map((x) => `<option value="${esc(x.id)}">${esc(x.title)}</option>`).join("");
    $("#demo-select").onchange = (e) => loadDemo(e.target.value);
    if (document.fonts) await Promise.race([document.fonts.ready, new Promise((r) => setTimeout(r, 1500))]);
    await loadDemo(S.index.demos[0].id);
    renderEval();

    $("#play").onclick = () => setPlaying(!S.playing);
    $$(".chip").forEach((c) => (c.onclick = () => {
      $$(".chip").forEach((x) => x.classList.remove("active"));
      c.classList.add("active");
      S.speed = Number(c.dataset.speed);
    }));
    $("#scrubber").oninput = (e) => { renderAt((e.target.value / 1000) * S.d.duration, true); };
    $("#next-incident").onclick = () => {
      const nxt = S.d.incidents.find((i) => i.first_t > S.now + 0.5);
      renderAt(nxt ? Math.max(0, nxt.first_t - 3) : 0, true);
    };
    $$(".mode").forEach((b) => (b.onclick = () => setMode(b.dataset.mode)));
    $("#incidents").addEventListener("toggle", (e) => {
      const card = e.target.closest(".incident");
      if (!card) return;
      const id = Number(card.dataset.id);
      if (e.target.open) S.open.add(id); else S.open.delete(id);
    }, true);
    $("#incidents").addEventListener("click", (e) => {
      const b = e.target.closest("[data-ask]");
      if (b) ask(Number(b.dataset.ask));
    });

    const fileInput = $("#file-input"), dz = $("#dropzone");
    let chosen = null;
    const choose = (f) => { chosen = f; $("#upload-btn").disabled = !f; if (f) $("#upload-status").textContent = `${f.name}, ${(f.size / 1e6).toFixed(2)} MB. Press Analyse.`; };
    fileInput.onchange = () => choose(fileInput.files[0]);
    ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("over"); }));
    ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("over"); }));
    dz.addEventListener("drop", (e) => choose(e.dataTransfer.files[0]));
    $("#upload-form").onsubmit = (e) => { e.preventDefault(); if (chosen) upload(chosen); };
    if (!S.health) $("#upload-status").textContent = "This copy of the dashboard has no analysis API. Run ARPGuard locally to analyse captures.";

    let rt;
    window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => { S.topoSig = ""; renderAt(S.now, true); }, 150); });
    document.addEventListener("keydown", (e) => {
      if (e.target.matches("input, select, textarea")) return;
      if (e.code === "Space") { e.preventDefault(); setPlaying(!S.playing); }
    });
    requestAnimationFrame(loop);
  }

  init().catch((e) => {
    console.error(e);
    $("#verdict").textContent = "Couldn't load the demo";
    $("#verdict-sub").textContent = e.message;
  });
})();
