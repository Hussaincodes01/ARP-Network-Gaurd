/* ARPGuard dashboard: replays an analysis result (demo, upload or live
   snapshot) on a clock and updates every window as of the playhead. */
(function () {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const icon = (n, s, c) => window.Icons.icon(n, s, c);
  const mmss = (t) => window.Charts.mmss(t);
  const SPOOF = window.Charts.SPOOF;

  // Plain-language names for every verdict
  const V = {
    confirmed_spoofing: { label: "ARP spoofing attack!", pill: "red", icon: "error", shield: "red", status: "bad" },
    probable_spoofing: { label: "Probable ARP spoofing", pill: "red", icon: "error", shield: "red", status: "bad" },
    suspicious: { label: "Suspicious, needs a look", pill: "orange", icon: "warn", shield: "yellow", status: "warn" },
    anomaly_not_arp: { label: "Unusual traffic (not ARP)", pill: "orange", icon: "warn", shield: "yellow", status: "warn" },
    pending: { label: "Checking a change…", pill: "yellow", icon: "info", shield: "yellow", status: "warn" },
    likely_legitimate: { label: "Harmless change", pill: "yellow", icon: "info", shield: "green", status: "ok" },
    normal: { label: "All clear", pill: "green", icon: "ok", shield: "green", status: "ok" },
  };
  const RULE_NAMES = {
    gateway_mac_change: "router's IP changed owner", ip_mac_conflict: "an IP changed owner", binding_flip_flop: "IP keeps flipping between two devices",
    mac_multiple_ips: "one device claims many IPs", unsolicited_reply: "answers nobody asked for", eth_arp_mismatch: "mismatched sender",
    arp_scan: "scanning the network for devices", arp_flood: "flood of ARP messages", ip_mac_change: "IP moved after a DHCP handout",
    binding_restored: "real owner took its IP back",
  };
  const SCHEMES = ["blue", "olive", "silver"];

  const S = {
    d: null, now: 0, playing: false, speed: 10, last: 0, lastDraw: 0, mode: "replay",
    health: null, index: null, sel: null, userPicked: false, sigs: {}, llm: {}, live: null, source: null,
    seenVerdicts: new Set(), story: [], prevNow: 0,
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
      attack: m.attack_window || null, timelineRows, firstOwner,
    };
    d.verdictAt = (inc, t) => {
      let v = inc.timeline.length ? inc.timeline[0][1] : inc.verdict;
      for (const [tt, vv] of inc.timeline) if (tt <= t) v = vv;
      return v;
    };
    d.macRole = (ip, mac) => {
      for (const inc of incidents) if (inc.actor === mac && SPOOF.has(inc.verdict) && inc.ips.includes(ip)) return "attacker";
      return firstOwner[ip] === mac ? "owner" : "new";
    };
    return d;
  }

  const upper = (arr, t, key) => {
    let lo = 0, hi = arr.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (key(arr[mid]) <= t) lo = mid + 1; else hi = mid; }
    return lo;
  };

  // ------------------------------------------------------------ the story
  const an = (word) => (/^[aeiou]/i.test(word || "") ? "An " : "A ") + (word || "");

  // A short description for the alerts list that doesn't repeat the verdict label
  function subject(d, inc, v) {
    if (v === "pending") return "a device changed its address";
    if (SPOOF.has(v)) return `${inc.actor} pretends to be ${inc.gateway_involved ? "the router" : inc.ips.join(", ")}`;
    if (inc.kind === "kitsune") {
      if (inc.related_incident) return `after-effects of event #${inc.related_incident}`;
      const talk = Object.keys(inc.talkers || {})[0];
      return talk ? "strange traffic: " + talk.replace(" > ", " → ") : "strange traffic";
    }
    return incidentStory(d, inc).title.toLowerCase();
  }

  function incidentStory(d, inc) {
    const vendor = inc.actor_vendor || "";
    const gw = d.gateway.ip;
    const rules = inc.rules || {};
    const ip = inc.ips[0] || "";
    if (inc.kind === "kitsune") {
      if (inc.related_incident) return { icon: "warn", title: `After-effects of event #${inc.related_incident}`, text: "The AI model is still settling down after the previous event. Nobody is lying about addresses." };
      const talk = Object.keys(inc.talkers || {})[0];
      return { icon: "warn", title: "Unusual traffic (not ARP)", text: `The AI model flags strange traffic${talk ? " (" + talk.replace(" > ", " → ") + ")" : ""}, but nobody is faking ARP answers. Something like a port scan.` };
    }
    if (SPOOF.has(inc.verdict)) {
      const n = new Set([...inc.ips, ...inc.targets].filter((x) => x !== gw)).size;
      return { icon: "error", title: "ARP spoofing attack!", text: `${inc.actor} (${vendor}) pretends to be ${inc.gateway_involved ? "the router and " : ""}${n} device${n === 1 ? "" : "s"}. Their traffic now flows through it.` };
    }
    if (inc.verdict === "likely_legitimate") {
      if (rules.ip_mac_change) return { icon: "info", title: "A new device joins", text: `${an(vendor)} device gets ${ip} from the router (DHCP). Harmless.` };
      if (inc.gateway_involved) return { icon: "info", title: "The router is replaced", text: `${ip} now answers from a new ${vendor} device. It changed once and traffic looks normal: harmless.` };
      return { icon: "info", title: "A device gets a new network card", text: `${ip} moved to a new ${vendor} card once, and traffic looks normal: harmless.` };
    }
    return { icon: V[inc.verdict].icon, title: V[inc.verdict].label, text: (inc.explanation || {}).headline || "" };
  }

  function buildStory(d) {
    const steps = [];
    const learn = d.meta.kitsune && d.graceEnd > 0 ? ` The AI model spends the first ${mmss(d.graceEnd)} learning what normal looks like.` : "";
    steps.push({ t: 0, icon: "ok", title: "Normal network traffic", text: "Devices browse the web, stream video and print." + learn });
    for (const inc of d.incidents) {
      const st = incidentStory(d, inc);
      steps.push({ t: inc.first_t, inc: inc.id, ...st, title: `Event #${inc.id}: ${st.title}` });
      if (inc.kind === "arp" && SPOOF.has(inc.verdict)) {
        steps.push({ t: inc.last_t + 1, icon: "ok", title: "The attacker stops", text: "No more fake answers arrive, and devices go back to talking to the real router." });
      }
    }
    return steps.sort((a, b) => a.t - b.t);
  }

  function renderStory() {
    $("#story").innerHTML = S.story.map((s, i) =>
      `<li data-i="${i}"><button data-jump="${Math.max(0, s.t - 2)}" title="Jump to ${mmss(s.t)}">${icon(s.icon, 18)}<span class="story-time">${mmss(s.t)}</span><span><b>${esc(s.title)}</b><small>${esc(s.text)}</small></span></button></li>`).join("");
  }

  // ------------------------------------------------------------ loading
  function load(result, opts = {}) {
    S.d = prep(result);
    S.sigs = {};
    S.sel = null;
    S.userPicked = false;
    S.seenVerdicts = new Set();
    S.story = buildStory(S.d);
    renderStory();
    S.now = opts.follow ? S.d.duration : 0;
    S.prevNow = S.now;
    drawTicks();
    renderAt(S.now, true);
    if (opts.autoplay) setPlaying(true);
  }

  async function loadDemo(id) {
    const entry = S.index.demos.find((x) => x.id === id) || S.index.demos[0];
    $("#demo-blurb").textContent = entry.blurb;
    setPlaying(false);
    const r = await (await fetch(entry.file)).json();
    S.source = "demo";
    load(r);
  }

  function drawTicks() {
    const box = $("#ticks");
    box.innerHTML = "";
    for (const inc of S.d.incidents) {
      const i = document.createElement("i");
      i.style.left = (100 * inc.first_t / Math.max(S.d.duration, 1)) + "%";
      i.style.borderBottomColor = window.Charts.VERDICT_COLOR[inc.verdict];
      i.title = "#" + inc.id + " " + V[inc.verdict].label;
      box.appendChild(i);
    }
  }

  // ------------------------------------------------------------ rendering
  function renderAt(t, force) {
    const d = S.d;
    if (!d) return;
    const forward = t >= S.now;
    S.now = Math.max(0, Math.min(t, d.duration));
    const now = S.now;
    $("#scrubber").value = Math.round(1000 * now / Math.max(d.duration, 1e-6));
    $("#clock").textContent = `${mmss(now)} / ${mmss(d.duration)}`;
    $("#tray-clock").textContent = (S.playing ? "▶ " : "") + mmss(now);

    const bi = Math.min(d.cum.length - 1, Math.floor(now / d.series.bin));
    const pk = now >= d.duration ? d.meta.packets : Math.round(bi >= 0 ? d.cum[bi] : 0);
    $("#st-packets").textContent = fmt(Math.min(pk, d.meta.packets));
    $("#st-arp").textContent = fmt(upper(d.arp, now, (e) => e[0]));
    $("#st-hosts").textContent = fmt(d.hosts.filter((h) => h.first_t <= now).length);
    $("#st-alerts").textContent = fmt(upper(d.alerts, now, (a) => a.t));
    $("#st-phase").textContent = !d.meta.kitsune ? "switched off" : now < d.graceEnd ? "learning normal traffic" : "watching for anomalies";

    renderStatus(now);
    renderStoryPos(now);
    renderAlerts(now);
    renderTable(now);
    renderConsole(now);
    if (forward && S.playing) notify(now);
    const tnow = performance.now();
    if (force || tnow - S.lastDraw > 120) {
      S.lastDraw = tnow;
      window.Charts.drawMonitor($("#monitor-canvas"), d, now);
      window.Charts.drawOwners($("#owners-canvas"), d, now);
      renderMap(now);
    }
    S.prevNow = now;
  }

  function activeIncidents(now) {
    return S.d.incidents.filter((i) => i.first_t <= now && now <= i.last_t + (i.kind === "kitsune" ? 5 : 30));
  }

  function topVerdict(now) {
    const d = S.d;
    const act = activeIncidents(now).map((i) => ({ inc: i, v: d.verdictAt(i, now) }));
    const rank = { confirmed_spoofing: 6, probable_spoofing: 5, suspicious: 4, anomaly_not_arp: 3, pending: 2, likely_legitimate: 1 };
    act.sort((a, b) => (rank[b.v] || 0) - (rank[a.v] || 0));
    return act[0] || null;
  }

  function meaning(top, now) {
    const d = S.d;
    if (!top) {
      const past = d.incidents.filter((i) => i.last_t + 30 < now && SPOOF.has(d.verdictAt(i, now))).length;
      if (d.meta.kitsune && now < d.graceEnd) return "Everything looks normal. The AI model is still learning what this network's normal traffic looks like; the rule checker is already watching.";
      return "Everything looks normal: no device is lying about its address." + (past ? ` (${past} earlier attack${past > 1 ? "s are" : " is"} listed under Alerts.)` : "");
    }
    const inc = top.inc, gw = d.gateway.ip;
    switch (top.v) {
      case "confirmed_spoofing":
      case "probable_spoofing":
        return `${inc.actor} is sending fake ARP answers, pretending to be ${inc.gateway_involved ? "the router (" + gw + ")" : inc.ips.join(", ")}. Devices that believe it send their traffic through the attacker, who can read or change it. See Alerts for how to fix it.`;
      case "suspicious":
        return `${inc.actor} keeps claiming addresses that belong to other devices, but the traffic itself doesn't look strange. A person should check this device.`;
      case "anomaly_not_arp":
        return "The AI model sees strange traffic, but nobody is faking ARP answers. Something else is happening (for example, a port scan). Worth a look, but it's not ARP spoofing.";
      case "pending":
        return "A device just claimed an IP address that used to belong to another device. ARPGuard is checking whether the traffic looks strange before deciding.";
      case "likely_legitimate":
        return "A device changed its address, but traffic stayed normal, so it's most likely harmless (a new device, a new network card or a replaced router).";
    }
    return "";
  }

  function renderStatus(now) {
    const top = topVerdict(now);
    const v = top ? top.v : "normal";
    const meta = V[v];
    const banner = $("#status-banner");
    const cls = meta.status;
    if (S.sigs.status !== v + (top && top.inc.id)) {
      S.sigs.status = v + (top && top.inc.id);
      banner.className = "status-banner " + cls;
      $("#status-icon").innerHTML = icon("shield-" + meta.shield, 48);
      $("#status-title").textContent = meta.label;
      $("#status-sub").textContent = top ? (top.inc.actor ? `Event #${top.inc.id} · ${top.inc.actor} (${top.inc.actor_vendor})` : `Event #${top.inc.id} · seen by the AI model only`) : "No active events";
      $("#tray-shield").innerHTML = icon("shield-" + meta.shield, 18);
      $("#tray-shield").title = "Security status: " + meta.label;
      const tb = document.querySelector("#w-status .title-bar-text");
      if (tb) tb.querySelector("svg").outerHTML = icon("shield-" + meta.shield, 16);
    }
    $("#status-meaning").textContent = meaning(top, now);
  }

  function renderStoryPos(now) {
    let cur = 0;
    S.story.forEach((s, i) => { if (s.t <= now + 0.01) cur = i; });
    if (S.sigs.story === cur) return;
    S.sigs.story = cur;
    $$("#story li").forEach((li) => {
      const i = Number(li.dataset.i);
      li.className = i === cur ? "current" : i > cur ? "future" : "past";
    });
  }

  function renderAlerts(now) {
    const d = S.d;
    const vis = d.incidents.filter((i) => i.first_t <= now);
    if (!S.userPicked) {
      const top = topVerdict(now);
      S.sel = top ? top.inc.id : (vis.length ? vis[vis.length - 1].id : null);
    }
    const sig = vis.map((i) => i.id + ":" + d.verdictAt(i, now)).join("|") + "|" + S.sel + "|" + JSON.stringify(Object.values(S.llm).map((x) => x.state));
    if (sig === S.sigs.alerts) return;
    S.sigs.alerts = sig;
    $("#alerts-tbody").innerHTML = vis.length ? vis.slice().reverse().map((inc) => {
      const v = d.verdictAt(inc, now);
      return `<tr class="clickable ${inc.id === S.sel ? "selected" : ""}" data-inc="${inc.id}" tabindex="0">
        <td>${icon(V[v].icon, 16)}</td><td>${inc.id}</td><td class="mono">${mmss(inc.first_t)}</td>
        <td class="wrap"><span class="pill ${V[v].pill}">${V[v].label}</span> ${esc(subject(d, inc, v))}</td></tr>`;
    }).join("") : `<tr><td colspan="4" class="muted">Nothing yet.</td></tr>`;
    const inc = vis.find((i) => i.id === S.sel);
    $("#alert-details").innerHTML = inc ? detailsHtml(inc, now)
      : `<p class="muted">No incidents yet. Press <b>▶ Play</b> in the Control Center to start the recording.</p>`;
  }

  function detailsHtml(inc, now) {
    const d = S.d;
    const v = d.verdictAt(inc, now);
    const head = `<h3>${icon(V[v].icon, 20)}<span>Event #${inc.id}: ${esc(V[v].label)}<br><small class="muted">started at ${mmss(inc.first_t)} into the recording</small></span></h3>`;
    if (v !== inc.verdict) {
      return head + `<p>A device just claimed an IP address that belonged to another device. ARPGuard is <b>waiting a few seconds</b> to see whether the traffic around it looks strange before deciding.</p>`;
    }
    const e = (S.llm[inc.id] && S.llm[inc.id].data) || inc.explanation;
    if (!e) return head;
    const att = e.attacker || {};
    const k = inc.kitsune || {};
    const src = e.source || {};
    const who = src.provider === "anthropic" ? `the AI (${esc(src.model || "Claude")})` : src.provider === "ollama" ? `a local AI (${esc(src.model)})` : "ARPGuard's built-in template";
    const llmOk = S.health && S.health.llm && S.health.llm.provider !== "template";
    const state = S.llm[inc.id] && S.llm[inc.id].state;
    const rules = Object.entries(inc.rules || {}).filter(([r]) => r !== "binding_restored")
      .map(([r, n]) => `<li>${esc(RULE_NAMES[r] || r)}${n > 1 ? ` (×${n})` : ""}</li>`).join("");
    return head + `
      <p><b>${esc(e.headline)}</b></p>
      <h4>What happened</h4><p>${esc(e.what_happened)}</p>
      <h4>Who is the attacker?</h4><p>${att.mac ? `<code>${esc(att.mac)}</code>${att.ip ? ` (IP ${esc(att.ip)})` : ""}${att.vendor ? `, made by ${esc(att.vendor)}` : ""}. ` : ""}${esc(att.reasoning)}</p>
      ${(e.victims || []).length ? `<h4>Who is affected?</h4><ul>${e.victims.map((x) => `<li><code>${esc(x.ip)}</code>: ${esc(x.role)}</li>`).join("")}</ul>` : ""}
      ${(e.impact || []).length ? `<h4>Why it matters</h4><ul>${e.impact.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      ${(e.fixes || []).length ? `<h4>What to do</h4><ul>${e.fixes.map((f) => `<li><b>${esc(f.action)}.</b> ${esc(f.detail)}${f.command ? `<pre>${esc(f.command)}</pre>` : ""}</li>`).join("")}</ul>` : ""}
      <h4>How sure is ARPGuard?</h4><p><b>${esc((e.confidence || {}).level)}</b>: ${esc((e.confidence || {}).reason)}.</p>
      ${(e.caveats || []).length ? `<p class="muted">${e.caveats.map(esc).join(" ")}</p>` : ""}
      <details><summary>Technical evidence</summary>
        ${rules ? `<p>Rules that fired:</p><ul>${rules}</ul>` : "<p>No ARP rule fired.</p>"}
        <p>AI model: ${fmt(k.hits)} of ${fmt(k.scored)} packets around this event were above the alarm line${k.scored ? ` (${Math.round(100 * k.hits / k.scored)}%)` : ""}.</p>
        <p>Active from ${mmss(inc.first_t)} to ${mmss(inc.last_t)}.</p>
      </details>
      <div class="src">Explanation written by ${who}.
        ${S.health ? `<button class="btn small" data-ask="${inc.id}" ${!llmOk || state === "busy" ? "disabled" : ""}
          title="${llmOk ? "Ask the AI to write a fresh explanation" : "The server has no AI key configured (ANTHROPIC_API_KEY)"}">${state === "busy" ? "Asking…" : "Ask the AI to explain"}</button>` : ""}</div>
      ${state === "error" ? `<p class="muted">${esc(S.llm[inc.id].error)}</p>` : ""}`;
  }

  function renderTable(now) {
    const d = S.d;
    const rows = [];
    for (const b of d.bindings) {
      if (b.first_t > now) continue;
      let mac = b.history[0][1], since = b.history[0][0], changes = 0;
      for (const [t, m] of b.history) if (t <= now) { if (m !== mac) changes++; mac = m; since = t; }
      const role = d.macRole(b.ip, mac);
      const inc = d.incidents.find((i) => i.actor === mac && i.ips.includes(b.ip) && i.first_t <= now);
      const v = inc ? d.verdictAt(inc, now) : null;
      let status = `<span class="tag">${icon("ok", 14)} OK</span>`, cls = "";
      if (role === "attacker" && v && v !== "pending") { status = `<span class="tag">${icon("error", 14)} <b>Fake!</b></span>`; cls = "bad"; }
      else if (v === "pending") { status = `<span class="tag">${icon("warn", 14)} Checking</span>`; cls = "warn"; }
      else if (v === "likely_legitimate") { status = `<span class="tag">${icon("info", 14)} New owner</span>`; cls = "warn"; }
      else if (changes) status = `<span class="tag">${icon("ok", 14)} Back to normal</span>`;
      const host = d.hosts.find((h) => h.mac === mac) || {};
      rows.push(`<tr class="${cls}${b.ip === d.gateway.ip ? " gw" : ""}"><td class="mono">${esc(b.ip)}${b.ip === d.gateway.ip ? " (router)" : ""}</td><td class="mono">${esc(mac)}</td>` +
        `<td>${esc(host.vendor || "")}</td><td>${changes}</td><td class="mono">${mmss(since)}</td><td>${status}</td></tr>`);
    }
    const html = rows.join("") || `<tr><td colspan="6" class="muted">No ARP messages seen yet.</td></tr>`;
    if (html !== S.sigs.table) { S.sigs.table = html; $("#arp-tbody").innerHTML = html; }
  }

  function renderConsole(now) {
    const d = S.d;
    const n = upper(d.arp, now, (e) => e[0]);
    if (S.sigs.console === n) return;
    S.sigs.console = n;
    const lines = d.arp.slice(Math.max(0, n - 13), n).map((e) => {
      const [t, kind, sha, spa, , tpa, , , flag] = e;
      let s;
      if (kind === "request") s = `who has ${tpa}? tell ${spa}`;
      else if (kind === "reply") s = `${spa} is at ${sha}  (to ${tpa})`;
      else if (kind === "gratuitous") s = `announce: ${spa} is at ${sha}`;
      else if (kind === "probe") s = `probe: is anyone using ${tpa}?`;
      else s = `${kind} ${spa} ${sha}`;
      const bad = flag === "spoofed_claim" || flag === "eth_arp_mismatch";
      const tag = bad ? `  <span class="bad">&lt;-- FAKE!</span>` : flag === "arp_scan" ? `  <span class="scan">&lt;-- scan</span>` : "";
      return `<span class="dim">[${mmss(t)}]</span> ${bad ? `<span class="bad">${esc(s)}</span>` : esc(s)}${tag}`;
    });
    $("#console").innerHTML = `<span class="ok">C:\\ARPGuard&gt; watch arp</span>\n<span class="dim">Showing the most recent ARP messages. "who has" = a question, "is at" = an answer.</span>\n` +
      (lines.join("\n") || `<span class="dim">(waiting for ARP traffic…)</span>`);
  }

  function renderMap(now) {
    const d = S.d;
    const act = activeIncidents(now).filter((i) => i.kind === "arp");
    const spoof = act.find((i) => SPOOF.has(d.verdictAt(i, now)));
    const legit = new Set(act.filter((i) => d.verdictAt(i, now) === "likely_legitimate").flatMap((i) => i.ips));
    const attackerMac = spoof ? spoof.actor : null;
    const hosts = d.hosts
      .filter((h) => h.first_t <= now && !h.gateway && h.mac !== attackerMac && h.ips.length && h.ips[0] !== d.gateway.ip)
      .sort((a, b) => b.packets - a.packets).slice(0, 6)
      .sort((a, b) => a.ips[0].localeCompare(b.ips[0], undefined, { numeric: true }))
      .map((h) => ({ ip: h.ips[0], vendor: h.vendor, legit: legit.has(h.ips[0]) }));
    const poisoned = new Set(spoof ? [...spoof.ips, ...spoof.targets] : []);
    const sig = JSON.stringify([hosts, attackerMac, [...poisoned]]);
    if (sig === S.sigs.map) return;
    S.sigs.map = sig;
    window.Charts.drawNetMap($("#netmap"), { gateway: d.gateway, hosts, poisoned, attacker: attackerMac ? { mac: attackerMac } : null });
  }

  // ------------------------------------------------------------ balloon notifications
  function notify(now) {
    const d = S.d;
    for (const inc of d.incidents) {
      if (inc.first_t > now) continue;
      const v = d.verdictAt(inc, now);
      const key = inc.id + ":" + v;
      if (S.seenVerdicts.has(key) || v === "pending") continue;
      S.seenVerdicts.add(key);
      if (now - S.prevNow > 30) continue;  // jumped, don't spam
      const st = incidentStory(d, inc);
      balloon(V[v].icon, SPOOF.has(v) ? "Security alert: " + V[v].label : st.title, st.text + " Click for details.", inc.id);
    }
  }

  let balloonTimer;
  function balloon(ic, title, text, incId) {
    const b = $("#balloon");
    $("#balloon-title").innerHTML = icon(ic, 16) + " " + esc(title);
    $("#balloon-text").textContent = text;
    b.dataset.inc = incId || "";
    b.classList.remove("hidden");
    clearTimeout(balloonTimer);
    balloonTimer = setTimeout(() => b.classList.add("hidden"), 9000);
  }

  // ------------------------------------------------------------ AI explanation
  async function ask(id) {
    const inc = S.d.incidents.find((i) => i.id === id);
    if (!inc || !inc.evidence) return;
    S.llm[id] = { state: "busy" };
    renderAlerts(S.now);
    try {
      const res = await fetch("/api/explain", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ evidence: inc.evidence }) });
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail || res.statusText);
      S.llm[id] = { state: "done", data: body };
    } catch (e) {
      S.llm[id] = { state: "error", error: "Couldn't get an AI explanation: " + e.message };
    }
    S.sigs.alerts = "";
    renderAlerts(S.now);
  }

  // ------------------------------------------------------------ playback
  function setPlaying(p) {
    S.playing = p && !!S.d;
    if (S.playing && S.now >= S.d.duration - 0.01) { S.now = 0; S.seenVerdicts.clear(); }
    $("#play").textContent = S.playing ? "❚❚ Pause" : "▶ Play";
    $("#play").setAttribute("aria-label", S.playing ? "Pause" : "Play");
    S.last = performance.now();
    if (S.d) $("#tray-clock").textContent = (S.playing ? "▶ " : "") + mmss(S.now);
  }

  function loop(ts) {
    if (S.playing && S.d) {
      const dt = Math.min((ts - S.last) / 1000, 0.25);
      S.last = ts;
      let t = S.now + dt * S.speed;
      if (t >= S.d.duration) { t = S.d.duration; setPlaying(false); }
      renderAt(t, false);
    }
    requestAnimationFrame(loop);
  }

  function jump(t) {
    S.seenVerdicts = new Set(S.d.incidents.flatMap((i) => i.timeline.filter(([tt]) => tt <= t).map(([, v]) => i.id + ":" + v)));
    renderAt(t, true);
  }

  // ------------------------------------------------------------ windows, taskbar, start menu
  const TASK_WINDOWS = ["w-control", "w-status", "w-alerts", "w-monitor", "w-map", "w-owners", "w-table", "w-cmd", "w-results", "w-help", "w-fixes"];

  function buildWindows() {
    $$(".window[data-title]").forEach((w) => {
      const bar = document.createElement("div");
      bar.className = "title-bar";
      bar.innerHTML = `<div class="title-bar-text">${icon(w.dataset.icon, 16)}<span>${esc(w.dataset.title)}</span></div>
        <div class="title-bar-controls"><button aria-label="Minimize" data-act="min"></button><button aria-label="Maximize" data-act="max"></button><button aria-label="Close" data-act="close"></button></div>`;
      w.prepend(bar);
      bar.addEventListener("dblclick", () => toggleMax(w));
      bar.querySelector('[data-act="min"]').onclick = () => { w.classList.toggle("minimized"); syncTasks(); };
      bar.querySelector('[data-act="max"]').onclick = () => toggleMax(w);
      bar.querySelector('[data-act="close"]').onclick = () => { w.classList.add("closed"); w.classList.remove("maximized"); syncTasks(); };
    });
    $("#task-buttons").innerHTML = TASK_WINDOWS.map((id) => {
      const w = document.getElementById(id);
      const short = w.dataset.title.split(":")[0].replace("ARPGuard ", "");
      return `<button class="task-btn" data-task="${id}" title="${esc(w.dataset.title)}">${icon(w.dataset.icon, 16)}<span>${esc(short)}</span></button>`;
    }).join("");
    $$(".task-btn").forEach((b) => (b.onclick = () => openWindow(b.dataset.task)));
    syncTasks();
  }

  function toggleMax(w) {
    w.classList.toggle("maximized");
    w.classList.remove("minimized");
    document.body.style.overflow = $(".window.maximized") ? "hidden" : "";
    syncTasks();
    redraw();
  }

  function syncTasks() {
    $$(".task-btn").forEach((b) => {
      const w = document.getElementById(b.dataset.task);
      b.classList.toggle("closed", w.classList.contains("closed") || w.classList.contains("minimized"));
      b.classList.toggle("active", w.classList.contains("maximized"));
    });
  }

  function openWindow(id) {
    const w = document.getElementById(id);
    if (!w) return;
    $$(".window.maximized").forEach((m) => { if (m !== w) m.classList.remove("maximized"); });
    document.body.style.overflow = $(".window.maximized") ? "hidden" : "";
    w.classList.remove("closed", "minimized");
    syncTasks();
    closeStart();
    if (!w.classList.contains("maximized")) w.scrollIntoView({ behavior: "smooth", block: "start" });
    w.animate && w.animate([{ boxShadow: "0 0 0 4px #ffc83c" }, { boxShadow: "2px 3px 10px rgba(0,0,0,.35)" }], { duration: 900 });
    redraw();
  }

  function redraw() {
    S.sigs.map = "";
    if (S.d) requestAnimationFrame(() => renderAt(S.now, true));
  }

  function toggleStart(open) {
    const m = $("#start-menu");
    const show = open != null ? open : m.classList.contains("hidden");
    m.classList.toggle("hidden", !show);
    $("#start-btn").setAttribute("aria-expanded", show);
  }
  const closeStart = () => toggleStart(false);

  function setMode(mode) {
    S.mode = mode;
    $$("[data-mode]").forEach((b) => { const on = b.dataset.mode === mode; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); });
    $$(".mode-panel").forEach((p) => p.classList.toggle("hidden", p.id !== "panel-" + mode));
    if (mode === "live") renderLivePanel();
    if (mode === "replay" && S.index && S.source !== "demo") loadDemo($("#demo-select").value);
  }

  function setHelp(page) {
    $$("[data-help]").forEach((b) => { const on = b.dataset.help === page; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); });
    $$(".help-page").forEach((p) => p.classList.toggle("hidden", p.dataset.page !== page));
  }

  function setScheme(name) {
    document.documentElement.dataset.scheme = name;
    $("#scheme-name").textContent = name[0].toUpperCase() + name.slice(1);
    try { localStorage.setItem("arpguard-scheme", name); } catch (e) { /* private mode */ }
  }

  // ------------------------------------------------------------ welcome wizard
  const pic = (inner) => `<svg class="wiz-pic" viewBox="0 0 440 130" role="img">${inner}</svg>`;
  const u = (name, x, y, s) => `<use href="#i-${name}" x="${x - s / 2}" y="${y - s / 2}" width="${s}" height="${s}"/>`;
  const bubble = (x, y, w, txt, col = "#000") => `<rect x="${x}" y="${y}" width="${w}" height="24" rx="5" fill="#ffffe1" stroke="#888"/><text x="${x + w / 2}" y="${y + 16}" font-size="11.5" text-anchor="middle" fill="${col}" font-family="Tahoma,Verdana,sans-serif">${txt}</text>`;
  const WIZ = [
    { title: "What is ARP?", body: () => pic(`${u("computer", 60, 80, 54)}${u("router", 380, 80, 54)}
        <path d="M95 70 H340" stroke="#2f6fde" stroke-width="2.5" marker-end="url(#wa)"/><path d="M340 92 H95" stroke="#2e9b2e" stroke-width="2.5" marker-end="url(#wb)"/>
        ${bubble(120, 30, 200, "Who has 192.168.1.1?")}${bubble(110, 100, 220, "192.168.1.1 is at 50:c7:bf:…", "#1d7d22")}
        <text x="60" y="122" font-size="11" text-anchor="middle">Your laptop</text><text x="380" y="122" font-size="11" text-anchor="middle">Router</text>
        <defs><marker id="wa" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#2f6fde"/></marker>
        <marker id="wb" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#2e9b2e"/></marker></defs>`) +
        `<p>Devices on a network find each other with <b>ARP</b>, a bit like a phone book. Your laptop asks <q>Who has 192.168.1.1?</q> and the router answers <q>That's me, my hardware (MAC) address is 50:c7:bf:…</q>.</p>
         <p>The laptop writes the answer down and from then on sends its internet traffic to that MAC address.</p>` },
    { title: "The problem: anyone can lie", body: () => pic(`${u("computer", 50, 70, 50)}${u("hacker", 220, 70, 50)}${u("router", 390, 70, 50)}
        <path d="M78 70 H190" stroke="#e2402b" stroke-width="3" marker-end="url(#wc)"/><path d="M250 70 H360" stroke="#e2402b" stroke-width="3" marker-end="url(#wc)"/>
        ${bubble(140, 4, 160, "I am the router!", "#c4200f")}
        <text x="50" y="112" font-size="11" text-anchor="middle">Your laptop</text><text x="220" y="112" font-size="11" text-anchor="middle" fill="#c4200f" font-weight="bold">Attacker</text><text x="390" y="112" font-size="11" text-anchor="middle">Router</text>
        <defs><marker id="wc" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#e2402b"/></marker></defs>`) +
        `<p>ARP has no password and no proof. An attacker can keep shouting <q>I am the router!</q> and everyone believes it.</p>
         <p>Your traffic then goes <b>through the attacker</b>, who passes it on so nothing looks broken, while reading or changing it. This is <b>ARP spoofing</b>, a <b>man-in-the-middle</b> attack.</p>` },
    { title: "How ARPGuard catches it", body: () =>
        `<ul>
          <li><b>The rule checker</b> keeps its own address book and notices when an IP suddenly "moves" to a different device, especially the router's.</li>
          <li><b>The AI anomaly model (Kitsune)</b> learns what normal traffic looks like, then notices when traffic suddenly behaves strangely, like when it's relayed through an attacker.</li>
          <li><b>The judge</b> combines both. A rule alarm <i>and</i> strange traffic means an <b>attack</b>. A rule alarm but normal traffic is probably a <b>harmless change</b>, like a new device.</li>
          <li><b>The explainer</b> writes what happened and how to fix it in plain English. It only explains; it never decides.</li>
        </ul>
        <p>Using both together avoids false alarms that the rules alone would raise, and pinpoints the attacker, which the AI alone can't.</p>` },
    { title: "How to use this page", body: () =>
        `<ul>
          <li>Press <b>▶ Play</b> in the <b>Control Center</b> to replay a recorded network. The <b>story</b> list tells you what's about to happen; click any step to jump there.</li>
          <li>Watch <b>Security Status</b>: the shield turns <span class="pill green">green</span>, <span class="pill yellow">yellow</span> or <span class="pill red">red</span>. A notification pops up from the taskbar when something happens.</li>
          <li>Open <b>Alerts and Explanations</b> to read each incident in plain English, with fixes.</li>
          <li>Every window starts with a yellow line explaining what it shows. Use the <b>start</b> button for help, the glossary and fixes.</li>
        </ul>
        <p>Press <b>Finish</b> to start the demo.</p>` },
  ];
  let wizPage = 0;
  function showWizard(page = 0) {
    wizPage = page;
    const p = WIZ[wizPage];
    $("#wiz-title").textContent = p.title;
    $("#wiz-content").innerHTML = p.body();
    $("#wiz-step").textContent = `Step ${wizPage + 1} of ${WIZ.length}`;
    $("#wiz-back").disabled = wizPage === 0;
    $("#wiz-next").textContent = wizPage === WIZ.length - 1 ? "Finish" : "Next >";
    $("#wizard").classList.remove("hidden");
    closeStart();
    $("#wiz-next").focus();
  }
  function closeWizard(start) {
    $("#wizard").classList.add("hidden");
    try { localStorage.setItem("arpguard-wizard-seen", "1"); } catch (e) { /* ignore */ }
    if (start && S.d && !S.playing) { openWindow("w-control"); setPlaying(true); }
  }

  // ------------------------------------------------------------ results
  async function renderResults() {
    let ev;
    try { ev = await (await fetch("data/evaluation.json")).json(); } catch (e) { return; }
    const names = { rules: "Rules only", kitsune_p99: "AI model only", kitsune_max: "AI model only (plan's max×1.1 alarm line)", combined: "ARPGuard (rules + AI)" };
    const pct = (x) => (100 * x).toFixed(1) + "%";
    const tables = ev.map((r) => {
      const benign = !r.malicious_packets;
      const rows = Object.entries(r.methods);
      const body = rows.map(([m, v]) => `<tr class="${m === "combined" ? "best" : ""}"><td>${esc(names[m] || m)}</td>
        ${benign ? `<td class="num">${pct(v.fpr)}</td><td class="num">${fmt(v.fp)}</td>`
          : `<td class="num">${pct(v.detection_rate)}</td><td class="num">${pct(v.fpr)}</td><td class="num">${v.f1.toFixed(3)}</td><td class="num">${v.time_to_detect_s == null ? "never" : v.time_to_detect_s.toFixed(1) + " s"}</td>`}</tr>`).join("");
      const headers = benign
        ? `<th title="Share of normal packets wrongly flagged">False alarm rate</th><th>Normal packets wrongly flagged</th>`
        : `<th title="Share of attack packets that were caught">Attack packets caught</th><th title="Share of normal packets wrongly flagged">False alarms</th><th title="Overall score from 0 to 1 combining catching attacks and avoiding false alarms (higher is better)">F1 score</th><th title="Seconds from the start of the attack to the first correct alarm">Time to detect</th>`;
      return `<div><h3>${benign ? "Normal network, no attack" : "Network with an ARP spoofing attack"} <span class="muted">(${esc(r.capture)}, ${fmt(r.evaluated_packets)} packets)</span></h3>
        <div class="listview"><table><thead><tr><th>Method</th>${headers}</tr></thead><tbody>${body}</tbody></table></div></div>`;
    }).join("");
    const a = ev[0] && ev[0].methods, b = ev[1] && ev[1].methods;
    const take = a && b ? `<fieldset class="group"><legend>In plain words</legend><ul class="takeaways">
        <li><b>Rules alone</b> catch ${pct(a.rules.detection_rate)} of attack packets, but also raise false alarms on harmless changes: ${pct(a.rules.fpr)} of normal packets in the attack recording and ${pct(b.rules.fpr)} in the no-attack recording (a new network card and a replaced router look like spoofing to them).</li>
        <li><b>The AI model alone</b> catches ${pct(a.kitsune_p99.detection_rate)} of attack packets and also flags harmless oddities such as a port scan.</li>
        <li><b>ARPGuard (both together)</b> catches ${pct(a.combined.detection_rate)} of attack packets with <b>no false alarms</b> on either recording, confirming the attack ${a.combined.time_to_detect_s != null ? a.combined.time_to_detect_s.toFixed(1) + " seconds" : "shortly"} after it starts.</li>
        <li>The plan's alarm-line rule (highest learning score × 1.1) depends on a single outlier, so it's unreliable. ARPGuard uses the 99th percentile × 1.1 instead.</li>
        <li>These recordings are <b>synthetic</b>: they show the method works end to end. Real-world numbers need the public Kitsune dataset (see the README).</li>
      </ul></fieldset>` : "";
    $("#results-body").innerHTML = take + `<div class="results-grid">${tables}</div>`;
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
    $("#upload-btn").disabled = true;
    $("#upload-progress").classList.remove("hidden");
    const t0 = Date.now();
    const tick = setInterval(() => { status.textContent = `Analyzing ${file.name}… ${Math.round((Date.now() - t0) / 1000)} s. The AI model learns first and then scores, at about 700 packets per second.`; }, 500);
    try {
      const body = await gzipIfLarge(file);
      const q = new URLSearchParams({ name: file.name, kitsune: $("#kitsune-input").checked ? "true" : "false" });
      const gw = $("#gw-input").value.trim();
      if (gw) q.set("gateway", gw);
      const res = await fetch("/api/analyze?" + q, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body });
      const data = await res.json().catch(() => ({ detail: res.statusText }));
      if (!res.ok) throw new Error(data.detail || res.statusText);
      const tr = data.meta.truncated_to ? ` (first ${fmt(data.meta.truncated_to)} packets)` : "";
      status.textContent = `Done: ${fmt(data.meta.packets)} packets${tr}, ${data.incidents.length} event(s). Result: ${V[data.meta.verdict].label}. Press ▶ Play to replay it.`;
      S.source = "upload";
      load(data);
    } catch (e) {
      status.textContent = "Couldn't analyze the file: " + e.message + (S.health ? "" : " (this copy of the site has no analysis server; run ARPGuard locally)");
    } finally {
      clearInterval(tick);
      $("#upload-btn").disabled = false;
      $("#upload-progress").classList.add("hidden");
    }
  }

  // ------------------------------------------------------------ live
  function renderLivePanel() {
    const box = $("#live-body");
    const h = S.health;
    if (!h || !h.live.available) {
      box.innerHTML = `<p class="infobar">${icon("info", 16)}<span><b>Live monitoring can't run on this website.</b> ${esc(h ? h.live.reason : "This copy of the site has no server.")} It needs permission to read network traffic on a computer connected to your own network.</span></p>
        <p>To watch your own network:</p>
        <ol>
          <li>Download the project and run <code>pip install -r requirements-dev.txt</code></li>
          <li>Run <code>sudo python -m arpguard serve</code> (on Windows: an Administrator prompt, with Npcap installed)</li>
          <li>Open <code>http://localhost:8000</code>, choose <b>Live monitoring</b> and press <b>Start</b></li>
        </ol>
        <p class="muted">Only monitor networks you own or manage.</p>`;
      return;
    }
    box.innerHTML = `<div class="field-row wrap">
        <label>Network adapter: <input type="text" id="live-iface" placeholder="default"></label>
        <label>Router IP: <input type="text" id="live-gw" placeholder="detect automatically"></label>
        <button class="btn default" id="live-start">${h.live.running ? "Restart" : "Start"}</button>
        <button class="btn" id="live-stop">Stop</button></div>
      <p class="muted" id="live-status">${h.live.running ? "Running." : "The rule checker works immediately; the AI model learns from the first 6,000 packets."}</p>`;
    $("#live-start").onclick = async () => {
      const res = await fetch("/api/live/start", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iface: $("#live-iface").value.trim() || null, gateway: $("#live-gw").value.trim() || null }) });
      const body = await res.json();
      if (!res.ok) { $("#live-status").textContent = body.detail; return; }
      $("#live-status").textContent = "Watching… every window now follows the live network.";
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
      if (r.meta.packets) { S.source = "live"; load(r, { follow: true }); }
    } catch (e) { /* keep polling */ }
  }

  // ------------------------------------------------------------ wiring
  async function init() {
    window.Icons.mount();
    window.Icons.hydrate();
    try { const sc = localStorage.getItem("arpguard-scheme"); if (SCHEMES.includes(sc)) setScheme(sc); } catch (e) { /* ignore */ }
    buildWindows();

    try {
      const r = await fetch("/api/health");
      if (r.ok) S.health = await r.json();
    } catch (e) { S.health = null; }
    if (!S.health) $("#upload-status").textContent = "This copy of the site has no analysis server. Run ARPGuard locally to analyze files.";

    S.index = await (await fetch("data/index.json")).json();
    $("#demo-select").innerHTML = S.index.demos.map((x) => `<option value="${esc(x.id)}">${esc(x.title)}</option>`).join("");
    $("#demo-select").onchange = (e) => loadDemo(e.target.value);
    await loadDemo(S.index.demos[0].id);
    renderResults();

    $("#play").onclick = () => setPlaying(!S.playing);
    $("#speed").onchange = (e) => { S.speed = Number(e.target.value); };
    $("#scrubber").oninput = (e) => jump((e.target.value / 1000) * S.d.duration);
    $("#story").addEventListener("click", (e) => { const b = e.target.closest("[data-jump]"); if (b) jump(Number(b.dataset.jump)); });
    $$("[data-mode]").forEach((b) => (b.onclick = () => setMode(b.dataset.mode)));
    $$("[data-help]").forEach((b) => (b.onclick = () => setHelp(b.dataset.help)));

    const pick = (row) => { if (!row) return; S.sel = Number(row.dataset.inc); S.userPicked = true; S.sigs.alerts = ""; renderAlerts(S.now); };
    $("#alerts-tbody").addEventListener("click", (e) => pick(e.target.closest("[data-inc]")));
    $("#alerts-tbody").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(e.target.closest("[data-inc]")); } });
    $("#alert-details").addEventListener("click", (e) => { const b = e.target.closest("[data-ask]"); if (b) ask(Number(b.dataset.ask)); });

    $("#balloon").onclick = (e) => {
      $("#balloon").classList.add("hidden");
      if (e.target.closest(".balloon-close")) return;
      const id = Number($("#balloon").dataset.inc);
      if (id) { S.sel = id; S.userPicked = true; S.sigs.alerts = ""; renderAlerts(S.now); openWindow("w-alerts"); }
    };
    $("#tray-shield").onclick = () => openWindow("w-status");

    $("#start-btn").onclick = (e) => { e.stopPropagation(); toggleStart(); };
    document.addEventListener("click", (e) => { if (!e.target.closest("#start-menu") && !e.target.closest("#start-btn")) closeStart(); });
    document.addEventListener("click", (e) => {
      const o = e.target.closest("[data-open]");
      if (o) { if (o.dataset.helpGo) setHelp(o.dataset.helpGo); else if (o.dataset.open === "w-help") setHelp("basics"); openWindow(o.dataset.open); }
      const m = e.target.closest("[data-mode-go]");
      if (m) { setMode(m.dataset.modeGo); openWindow("w-control"); }
      if (e.target.closest("[data-wizard]")) showWizard(0);
      if (e.target.closest("[data-scheme-next]")) { setScheme(SCHEMES[(SCHEMES.indexOf(document.documentElement.dataset.scheme) + 1) % SCHEMES.length]); redraw(); }
      if (e.target.closest("[data-restart]")) { closeStart(); setMode("replay"); openWindow("w-control"); jump(0); setPlaying(true); }
      if (e.target.closest("[data-pause]")) { closeStart(); setPlaying(false); }
    });

    $("#wiz-next").onclick = () => (wizPage < WIZ.length - 1 ? showWizard(wizPage + 1) : closeWizard(true));
    $("#wiz-back").onclick = () => showWizard(Math.max(0, wizPage - 1));
    $("#wiz-skip").onclick = () => closeWizard(false);
    $('#wizard [data-act="wiz-close"]').onclick = () => closeWizard(false);

    const fileInput = $("#file-input"), dz = $("#dropzone");
    let chosen = null;
    const choose = (f) => { chosen = f; $("#upload-btn").disabled = !f; if (f) $("#upload-status").textContent = `Selected ${f.name} (${(f.size / 1e6).toFixed(2)} MB). Press Analyze.`; };
    fileInput.onchange = () => choose(fileInput.files[0]);
    ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("over"); }));
    ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("over"); }));
    dz.addEventListener("drop", (e) => choose(e.dataTransfer.files[0]));
    $("#upload-form").onsubmit = (e) => { e.preventDefault(); if (chosen) upload(chosen); };

    let rt;
    window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(redraw, 150); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        if (!$("#wizard").classList.contains("hidden")) return closeWizard(false);
        closeStart();
        $$(".window.maximized").forEach((w) => w.classList.remove("maximized"));
        document.body.style.overflow = "";
        syncTasks();
        redraw();
        return;
      }
      if (e.target.matches("input, select, textarea, button")) return;
      if (e.code === "Space") { e.preventDefault(); setPlaying(!S.playing); }
    });

    let seen = null;
    try { seen = localStorage.getItem("arpguard-wizard-seen"); } catch (e) { /* ignore */ }
    if (!seen) showWizard(0);
    requestAnimationFrame(loop);
  }

  init().catch((e) => {
    console.error(e);
    $("#status-title").textContent = "Couldn't load the demo";
    $("#status-sub").textContent = e.message;
  });
})();
