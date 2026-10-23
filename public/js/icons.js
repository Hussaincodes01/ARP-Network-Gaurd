/* Original Luna-style icons (SVG <symbol> sprite). icon("name", size) returns
   markup that references a symbol, so each icon's gradients are defined once. */
(function () {
  "use strict";
  const G = (id, stops, x2 = 0, y2 = 1) =>
    `<linearGradient id="${id}" x1="0" y1="0" x2="${x2}" y2="${y2}">` +
    stops.map(([o, c]) => `<stop offset="${o}" stop-color="${c}"/>`).join("") + `</linearGradient>`;

  const defs = [
    G("g-green", [[0, "#9be27c"], [0.5, "#3cae3c"], [1, "#1d7d22"]]),
    G("g-yellow", [[0, "#fff3a1"], [0.5, "#f7c81b"], [1, "#c98c00"]]),
    G("g-red", [[0, "#ff9a88"], [0.5, "#e2402b"], [1, "#a3170b"]]),
    G("g-blue", [[0, "#9fd0ff"], [0.5, "#2f7fe6"], [1, "#0b4ab0"]]),
    G("g-gray", [[0, "#f2f2f2"], [0.5, "#c8c8c8"], [1, "#8d8d8d"]]),
    G("g-screen", [[0, "#7fc4ff"], [1, "#1155c9"]]),
    G("g-hscreen", [[0, "#ff8a7a"], [1, "#b01b0e"]]),
    G("g-folder", [[0, "#ffe9a3"], [1, "#e7b43b"]]),
    G("g-paper", [[0, "#ffffff"], [1, "#dfe6f2"]]),
    G("g-globe", [[0, "#8fd3ff"], [1, "#1f6fd1"]]),
  ].join("");

  const shield = (fill, mark) =>
    `<path d="M16 2 L28 6 V15 C28 23 22 28 16 30 C10 28 4 23 4 15 V6 Z" fill="url(#${fill})" stroke="#163c75" stroke-width="1.4"/>
     <path d="M16 4.5 L26 7.8 V15 C26 21.5 21 25.6 16 27.4" fill="none" stroke="#fff" stroke-opacity=".45" stroke-width="1.2"/>${mark}`;
  const CHECK = `<path d="M10 16 l4 4 l8 -9" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>`;
  const BANG = `<rect x="14.4" y="8" width="3.2" height="11" rx="1.4" fill="#fff"/><circle cx="16" cy="23" r="2" fill="#fff"/>`;
  const CROSS = `<path d="M11 11 L21 21 M21 11 L11 21" stroke="#fff" stroke-width="3.2" stroke-linecap="round"/>`;
  const computer = (screen) =>
    `<rect x="3" y="4" width="26" height="18" rx="2" fill="url(#g-gray)" stroke="#555" stroke-width="1"/>
     <rect x="5.5" y="6.5" width="21" height="13" fill="url(#${screen})" stroke="#334" stroke-width=".6"/>
     <path d="M7 8 h9 l-9 6 Z" fill="#fff" opacity=".28"/>
     <rect x="12" y="22" width="8" height="3" fill="#9a9a9a"/><rect x="8" y="25" width="16" height="3" rx="1" fill="url(#g-gray)" stroke="#555" stroke-width=".8"/>`;

  const symbols = {
    "shield-green": shield("g-green", CHECK),
    "shield-yellow": shield("g-yellow", `<rect x="14.4" y="8" width="3.2" height="11" rx="1.4" fill="#5a3b00"/><circle cx="16" cy="23" r="2" fill="#5a3b00"/>`),
    "shield-red": shield("g-red", CROSS),
    "shield-blue": shield("g-blue", `<text x="16" y="20" text-anchor="middle" font-family="Tahoma,Verdana,sans-serif" font-size="8.5" font-weight="700" fill="#fff">ARP</text>`),
    "info": `<circle cx="16" cy="16" r="13" fill="url(#g-blue)" stroke="#0b3a8f"/><circle cx="16" cy="9.5" r="2.2" fill="#fff"/><rect x="14" y="13.5" width="4" height="11" rx="1.2" fill="#fff"/>`,
    "warn": `<path d="M16 3 L30 28 H2 Z" fill="url(#g-yellow)" stroke="#8a5d00" stroke-width="1.3" stroke-linejoin="round"/><rect x="14.5" y="11" width="3" height="10" rx="1.3" fill="#222"/><circle cx="16" cy="24.2" r="1.8" fill="#222"/>`,
    "error": `<circle cx="16" cy="16" r="13" fill="url(#g-red)" stroke="#7d0f06"/>${CROSS}`,
    "ok": `<circle cx="16" cy="16" r="13" fill="url(#g-green)" stroke="#145a17"/>${CHECK}`,
    "question": `<circle cx="16" cy="16" r="13" fill="url(#g-blue)" stroke="#0b3a8f"/><text x="16" y="22" text-anchor="middle" font-family="Tahoma,Verdana,sans-serif" font-size="17" font-weight="700" fill="#fff">?</text>`,
    "computer": computer("g-screen"),
    "hacker": computer("g-hscreen") + `<ellipse cx="16" cy="13" rx="4.2" ry="5" fill="#111"/><path d="M13 12.5 h2.2 M16.8 12.5 h2.2" stroke="#ff6a5a" stroke-width="1.4"/>`,
    "router": `<path d="M9 13 L6 4 M23 13 L26 4" stroke="#444" stroke-width="1.6" stroke-linecap="round"/>
      <rect x="3" y="13" width="26" height="11" rx="2.5" fill="url(#g-gray)" stroke="#444"/>
      <circle cx="9" cy="18.5" r="1.6" fill="#36c23b"/><circle cx="14" cy="18.5" r="1.6" fill="#36c23b"/><circle cx="19" cy="18.5" r="1.6" fill="#f6b21a"/>
      <rect x="22" y="17" width="4" height="3" fill="#555"/>`,
    "globe": `<circle cx="16" cy="16" r="13" fill="url(#g-globe)" stroke="#0d4a9c"/>
      <path d="M8 9 c3 1 5 4 3 7 c-2 3 1 5 3 7 M19 6 c-2 3 1 5 4 5 s4 3 2 6 c-1 2 -3 3 -2 6" fill="none" stroke="#5dc055" stroke-width="2.4" stroke-linecap="round"/>
      <ellipse cx="11" cy="10" rx="5" ry="3" fill="#fff" opacity=".3"/>`,
    "cmd": `<rect x="2" y="4" width="28" height="24" rx="1.5" fill="#1d1d1d" stroke="#666"/><rect x="2" y="4" width="28" height="5" fill="url(#g-blue)"/>
      <text x="5" y="20" font-family="Consolas,'Lucida Console',monospace" font-size="8" fill="#d9d9d9">C:\\&gt;_</text>`,
    "chart": `<rect x="2" y="4" width="28" height="24" rx="1.5" fill="#000" stroke="#666"/>
      <path d="M2 12 H30 M2 20 H30 M10 4 V28 M20 4 V28" stroke="#0a6b0a" stroke-width=".8"/>
      <path d="M3 24 L8 21 L12 23 L16 13 L20 18 L24 8 L29 11" fill="none" stroke="#2bff2b" stroke-width="1.8"/>`,
    "table": `<rect x="4" y="3" width="24" height="26" fill="url(#g-paper)" stroke="#5a6e8c"/><rect x="4" y="3" width="24" height="5" fill="#8fb3e6"/>
      <path d="M7 12 H25 M7 16 H25 M7 20 H25 M7 24 H25" stroke="#5a6e8c" stroke-width="1.4"/><path d="M13 8 V29" stroke="#a9b8cf"/>`,
    "network": `<rect x="1.5" y="4" width="12" height="9" rx="1" fill="url(#g-screen)" stroke="#334"/><rect x="18.5" y="4" width="12" height="9" rx="1" fill="url(#g-screen)" stroke="#334"/>
      <rect x="10" y="20" width="12" height="7" rx="1.5" fill="url(#g-gray)" stroke="#444"/><path d="M7.5 13 V17 H24.5 V13 M16 17 V20" fill="none" stroke="#1d5bc9" stroke-width="2"/>`,
    "timeline": `<rect x="2" y="5" width="28" height="22" fill="#fff" stroke="#5a6e8c"/>
      <rect x="4" y="8" width="11" height="4" fill="#2f6fde"/><rect x="15" y="8" width="7" height="4" fill="#e2402b"/><rect x="22" y="8" width="6" height="4" fill="#2f6fde"/>
      <rect x="4" y="14" width="18" height="4" fill="#2f6fde"/><rect x="22" y="14" width="6" height="4" fill="#3cae3c"/>
      <rect x="4" y="20" width="24" height="4" fill="#2f6fde"/>`,
    "folder": `<path d="M2 8 h10 l3 3 h15 v16 h-28 Z" fill="url(#g-folder)" stroke="#a57610"/><path d="M2 13 h28" stroke="#fff" stroke-opacity=".6"/>`,
    "upload": `<path d="M2 8 h10 l3 3 h15 v16 h-28 Z" fill="url(#g-folder)" stroke="#a57610"/><path d="M16 26 V15 M11 19 l5 -5 l5 5" fill="none" stroke="#1d7d22" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>`,
    "radar": `<circle cx="16" cy="16" r="13" fill="#0e3b1c" stroke="#145a17"/><circle cx="16" cy="16" r="8.5" fill="none" stroke="#2bd14b" stroke-width=".8"/>
      <circle cx="16" cy="16" r="4" fill="none" stroke="#2bd14b" stroke-width=".8"/><path d="M16 16 L26 9" stroke="#7dff8f" stroke-width="2"/><circle cx="22" cy="20" r="1.6" fill="#ff5b4a"/>`,
    "results": `<rect x="3" y="3" width="26" height="26" fill="url(#g-paper)" stroke="#5a6e8c"/>
      <rect x="7" y="16" width="4" height="10" fill="#e2402b"/><rect x="14" y="10" width="4" height="16" fill="#f7c81b"/><rect x="21" y="6" width="4" height="20" fill="#3cae3c"/>`,
    "help": `<rect x="6" y="3" width="20" height="26" rx="2" fill="url(#g-blue)" stroke="#0b3a8f"/><rect x="9" y="3" width="2" height="26" fill="#0b3a8f" opacity=".5"/>
      <text x="18" y="21" text-anchor="middle" font-family="Tahoma,Verdana,sans-serif" font-size="14" font-weight="700" fill="#fff">?</text>`,
    "wrench": shield("g-green", `<path d="M19.5 9.5 a4 4 0 0 0 -5 5 l-5 5 l2.2 2.2 l5 -5 a4 4 0 0 0 5 -5 l-2.4 2.4 l-2 -2 Z" fill="#fff"/>`),
    "wizard": `<rect x="3" y="3" width="26" height="26" rx="3" fill="url(#g-blue)" stroke="#0b3a8f"/><path d="M8 23 L22 9" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/>
      <path d="M22 5 l1 3 l3 1 l-3 1 l-1 3 l-1 -3 l-3 -1 l3 -1 Z" fill="#ffe36b"/>`,
    "play": `<circle cx="16" cy="16" r="13" fill="url(#g-green)" stroke="#145a17"/><path d="M13 10 L23 16 L13 22 Z" fill="#fff"/>`,
    "power": `<rect x="2" y="2" width="28" height="28" rx="5" fill="url(#g-red)" stroke="#7d0f06"/><path d="M11.5 11 a7 7 0 1 0 9 0" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/><path d="M16 7 V16" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/>`,
    "refresh": `<rect x="2" y="2" width="28" height="28" rx="5" fill="url(#g-green)" stroke="#145a17"/><path d="M22 12 a7 7 0 1 0 1 6" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/><path d="M23 6 V12 H17" fill="none" stroke="#fff" stroke-width="2.6" stroke-linejoin="round"/>`,
    "palette": `<path d="M16 3 C8 3 3 9 3 15 c0 6 5 9 9 8 c3 -1 1 -4 3 -5 c2 -1 5 2 9 0 c4 -2 5 -6 3 -10 C25 5 21 3 16 3 Z" fill="url(#g-paper)" stroke="#6b5a35"/>
      <circle cx="10" cy="12" r="2.4" fill="#e2402b"/><circle cx="16" cy="8" r="2.4" fill="#f7c81b"/><circle cx="22" cy="11" r="2.4" fill="#3cae3c"/><circle cx="9" cy="18" r="2.4" fill="#2f6fde"/>`,
    "code": `<rect x="3" y="4" width="26" height="24" rx="2" fill="url(#g-paper)" stroke="#5a6e8c"/><path d="M12 11 L7 16 L12 21 M20 11 L25 16 L20 21" fill="none" stroke="#2f6fde" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>`,
  };

  const sprite = `<svg xmlns="http://www.w3.org/2000/svg" style="position:absolute;width:0;height:0;overflow:hidden" aria-hidden="true"><defs>${defs}</defs>` +
    Object.entries(symbols).map(([k, v]) => `<symbol id="i-${k}" viewBox="0 0 32 32">${v}</symbol>`).join("") + `</svg>`;

  function mount() {
    if (document.getElementById("i-info")) return;
    document.body.insertAdjacentHTML("afterbegin", sprite);
  }

  function icon(name, size = 16, cls = "") {
    return `<svg class="ico ${cls}" width="${size}" height="${size}" viewBox="0 0 32 32" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  }

  // Replace <i data-icon="name" data-size="16"> placeholders in static HTML
  function hydrate(root = document) {
    root.querySelectorAll("i[data-icon]").forEach((n) => {
      n.outerHTML = icon(n.dataset.icon, Number(n.dataset.size || 16), n.className || "");
    });
  }

  window.Icons = { mount, icon, hydrate, names: Object.keys(symbols) };
})();
