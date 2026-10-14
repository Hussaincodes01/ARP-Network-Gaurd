/* The En Garde fencer: a line-art mascot built from jointed "tube" limbs so it
   can tween between poses (en garde, lunge, salute, alert). Ink lines are run
   through an SVG turbulence filter so they wobble like hand-drawn animation. */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";

  // Joint coordinates in a 260x230 box, fencer facing right, floor at y = 212.
  const POSES = {
    guard: {
      backFoot: [58, 212], backKnee: [80, 174], hip: [106, 140], frontKnee: [146, 170], frontFoot: [160, 212],
      neck: [114, 94], head: [124, 68], headTilt: -8,
      backShoulder: [106, 98], backElbow: [84, 86], backHand: [82, 60],
      frontShoulder: [120, 100], frontElbow: [142, 118], frontHand: [162, 108], tip: [244, 78],
    },
    lunge: {
      backFoot: [34, 212], backKnee: [66, 186], hip: [104, 152], frontKnee: [176, 166], frontFoot: [196, 212],
      neck: [128, 104], head: [142, 80], headTilt: 4,
      backShoulder: [120, 108], backElbow: [96, 122], backHand: [70, 132],
      frontShoulder: [136, 108], frontElbow: [162, 104], frontHand: [186, 102], tip: [258, 100],
    },
    salute: {
      backFoot: [80, 212], backKnee: [86, 176], hip: [106, 140], frontKnee: [132, 176], frontFoot: [140, 212],
      neck: [110, 92], head: [116, 64], headTilt: 0,
      backShoulder: [102, 98], backElbow: [92, 124], backHand: [96, 146],
      frontShoulder: [118, 98], frontElbow: [138, 112], frontHand: [138, 86], tip: [140, 6],
    },
    alert: {
      backFoot: [56, 212], backKnee: [78, 172], hip: [104, 138], frontKnee: [146, 168], frontFoot: [162, 212],
      neck: [110, 92], head: [118, 64], headTilt: -16,
      backShoulder: [104, 96], backElbow: [80, 80], backHand: [80, 52],
      frontShoulder: [118, 98], frontElbow: [140, 104], frontHand: [158, 92], tip: [226, 34],
    },
  };

  function el(tag, attrs, parent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  const lerp = (a, b, t) => a + (b - a) * t;
  const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);
  const pt = (p) => p[0].toFixed(1) + " " + p[1].toFixed(1);

  function tube(g, pts, width, cls) {
    const d = "M" + pts.map(pt).join(" L");
    el("path", { d, class: "limb-out " + (cls || ""), "stroke-width": width + 5 }, g);
    el("path", { d, class: "limb-in " + (cls || ""), "stroke-width": width }, g);
  }

  function render(svg, p) {
    let g = svg.querySelector("g.ink-layer");
    if (g) g.remove();
    g = el("g", { class: "ink-layer" }, svg);

    // floor line and shadow
    el("path", { d: "M14 213 C 70 211, 160 215, 250 212", class: "stroke", "stroke-width": 2.5, fill: "none" }, g);
    el("ellipse", { cx: (p.backFoot[0] + p.frontFoot[0]) / 2, cy: 216, rx: Math.abs(p.frontFoot[0] - p.backFoot[0]) / 2 + 22, ry: 5, class: "shadow" }, g);

    // back arm, back leg
    tube(g, [p.backShoulder, p.backElbow, p.backHand], 9, "sleeve");
    el("circle", { cx: p.backHand[0], cy: p.backHand[1], r: 5.5, class: "skin" }, g);
    tube(g, [p.hip, p.backKnee], 15, "breeches");
    tube(g, [p.backKnee, p.backFoot], 9, "sock");
    shoe(g, p.backFoot, -1);

    // torso (jacket), built around the hip->neck spine
    const dx = p.neck[0] - p.hip[0], dy = p.neck[1] - p.hip[1];
    const len = Math.hypot(dx, dy), nx = -dy / len, ny = dx / len;
    const a = [p.neck[0] + nx * 13, p.neck[1] + ny * 13], b = [p.neck[0] - nx * 14, p.neck[1] - ny * 14];
    const c = [p.hip[0] - nx * 16, p.hip[1] - ny * 16], d = [p.hip[0] + nx * 15, p.hip[1] + ny * 15];
    el("path", {
      d: `M${pt(a)} Q ${pt([(a[0] + d[0]) / 2 + nx * 5, (a[1] + d[1]) / 2 + ny * 5])} ${pt(d)} L ${pt(c)} Q ${pt([(b[0] + c[0]) / 2 - nx * 4, (b[1] + c[1]) / 2 - ny * 4])} ${pt(b)} Z`,
      class: "jacket",
    }, g);
    // hatching on the back of the jacket
    for (let i = 1; i <= 4; i++) {
      const t = i / 5;
      const s = [lerp(a[0], d[0], t), lerp(a[1], d[1], t)];
      el("path", { d: `M${pt(s)} l ${(-nx * 7).toFixed(1)} ${(-ny * 7 + 4).toFixed(1)}`, class: "hatch" }, g);
    }
    // emblem: a little shield on the chest
    const e = [lerp(b[0], c[0], 0.32) + nx * 7, lerp(b[1], c[1], 0.32) + ny * 7];
    el("path", { d: `M${e[0] - 6} ${e[1] - 6} h12 v5 q0 7 -6 10 q-6 -3 -6 -10 Z`, class: "emblem" }, g);
    el("path", { d: `M${e[0] - 3} ${e[1]} l2.5 3 l4 -5`, class: "emblem-tick" }, g);

    // front leg
    tube(g, [p.hip, p.frontKnee], 15, "breeches");
    tube(g, [p.frontKnee, p.frontFoot], 9, "sock");
    shoe(g, p.frontFoot, 1);

    // head: bib + mask with mesh
    const hx = p.head[0], hy = p.head[1];
    el("path", { d: `M${hx - 12} ${hy + 14} L ${hx + 8} ${hy + 16} L ${p.neck[0] + 6} ${p.neck[1] + 4} L ${p.neck[0] - 10} ${p.neck[1] + 2} Z`, class: "bib" }, g);
    const mask = el("g", { transform: `rotate(${p.headTilt} ${hx} ${hy})` }, g);
    el("ellipse", { cx: hx, cy: hy, rx: 17, ry: 21, class: "mask" }, mask);
    const clipId = "mesh-clip";
    if (!svg.querySelector("#" + clipId)) {
      const defs = svg.querySelector("defs") || el("defs", {}, svg);
      const cp = el("clipPath", { id: clipId }, defs);
      el("ellipse", { cx: 0, cy: 0, rx: 15, ry: 19 }, cp);
    }
    const mesh = el("g", { transform: `translate(${hx} ${hy})`, "clip-path": `url(#${clipId})` }, mask);
    for (let x = -2; x <= 16; x += 4.2) el("line", { x1: x, y1: -20, x2: x + 6, y2: 20, class: "mesh" }, mesh);
    for (let y = -18; y <= 20; y += 4.2) el("line", { x1: -1, y1: y, x2: 16, y2: y + 2, class: "mesh" }, mesh);
    el("path", { d: `M${hx - 3} ${hy - 20} Q ${hx - 8} ${hy} ${hx - 2} ${hy + 20}`, class: "stroke", "stroke-width": 2, fill: "none" }, mask);

    // front (sword) arm, glove, bell guard, blade
    tube(g, [p.frontShoulder, p.frontElbow, p.frontHand], 9, "sleeve");
    const bx = p.tip[0] - p.frontHand[0], by = p.tip[1] - p.frontHand[1];
    const bl = Math.hypot(bx, by), ux = bx / bl, uy = by / bl;
    const mid = [p.frontHand[0] + bx * 0.55 - uy * 4, p.frontHand[1] + by * 0.55 + ux * 4];
    el("path", { d: `M${pt([p.frontHand[0] + ux * 6, p.frontHand[1] + uy * 6])} Q ${pt(mid)} ${pt(p.tip)}`, class: "blade" }, g);
    el("circle", { cx: p.tip[0], cy: p.tip[1], r: 2.6, class: "tip" }, g);
    const ang = Math.atan2(uy, ux) * 180 / Math.PI;
    el("ellipse", { cx: p.frontHand[0] + ux * 7, cy: p.frontHand[1] + uy * 7, rx: 3.5, ry: 11, transform: `rotate(${ang.toFixed(1)} ${(p.frontHand[0] + ux * 7).toFixed(1)} ${(p.frontHand[1] + uy * 7).toFixed(1)})`, class: "guard" }, g);
    el("circle", { cx: p.frontHand[0], cy: p.frontHand[1], r: 7, class: "glove" }, g);
  }

  function shoe(g, foot, dir) {
    const [x, y] = foot;
    el("path", { d: `M${x - 7 * dir} ${y - 6} q ${10 * dir} -3 ${18 * dir} 2 q ${3 * dir} 3 ${-1 * dir} 5 h ${-18 * dir} Z`, class: "shoe" }, g);
  }

  class Fencer {
    constructor(svg) {
      this.svg = svg;
      this.current = JSON.parse(JSON.stringify(POSES.guard));
      this.name = "guard";
      this.anim = null;
      render(svg, this.current);
      this.idle();
    }
    pose(name, ms = 380) {
      if (name === this.name || !POSES[name]) return;
      this.name = name;
      const from = JSON.parse(JSON.stringify(this.current));
      const to = POSES[name];
      const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      cancelAnimationFrame(this.anim);
      const t0 = performance.now();
      const step = (now) => {
        const t = reduce ? 1 : Math.min(1, (now - t0) / ms);
        const k = ease(t);
        for (const key in to) {
          this.current[key] = Array.isArray(to[key])
            ? [lerp(from[key][0], to[key][0], k), lerp(from[key][1], to[key][1], k)]
            : lerp(from[key], to[key], k);
        }
        render(this.svg, this.current);
        if (t < 1) this.anim = requestAnimationFrame(step);
      };
      this.anim = requestAnimationFrame(step);
    }
    idle() {
      // a slow breathing bob while on guard
      const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (reduce) return;
      let up = false;
      setInterval(() => {
        if (this.name !== "guard") return;
        up = !up;
        const base = POSES.guard;
        const dy = up ? -2 : 0;
        for (const k of ["neck", "head", "backShoulder", "frontShoulder", "backElbow", "backHand", "frontElbow", "frontHand", "tip"]) {
          this.current[k] = [base[k][0], base[k][1] + dy];
        }
        render(this.svg, this.current);
      }, 900);
    }
  }

  // A small dark mask: the attacker, drawn in the topology.
  function attackerMask(parent, x, y, s = 1) {
    const g = el("g", { transform: `translate(${x} ${y}) scale(${s})`, class: "attacker-mask" }, parent);
    el("ellipse", { cx: 0, cy: 0, rx: 13, ry: 16, class: "mask-dark" }, g);
    for (let i = -8; i <= 8; i += 4) el("line", { x1: i, y1: -12, x2: i + 3, y2: 12, class: "mesh-dark" }, g);
    el("path", { d: "M-8 -16 l -5 -8 l 8 4 M8 -16 l 5 -8 l -8 4", class: "horns" }, g);
    return g;
  }

  window.Fencer = Fencer;
  window.attackerMask = attackerMask;
})();
