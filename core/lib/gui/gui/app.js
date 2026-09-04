/* emp3r0r operator GUI frontend.
 *
 * Layout is tabbed: the left rail switches the WHOLE content area between
 *   - Console : output/log pane + the emp3r0r reflective console terminal
 *   - Agents  : agent table or p2p mesh node view
 *   - OS Shell: local operator shell on its own pty
 *
 * Single websocket to the cc backend:
 *   client -> server: login / pty_* (console) / shell_* / select_agent / exit
 *   server -> client: state / login_result / log / pty_out / agents / shell_*
 */
"use strict";

const $ = (id) => document.getElementById(id);

// ── token from the URL (http://127.0.0.1:PORT/?token=...) ──────────────
const token = new URLSearchParams(location.search).get("token") || "";
if (!token) {
  document.body.innerHTML =
    '<div style="padding:40px;font-family:monospace">' +
    "Missing session token. Re-run <code>emp3r0r client --gui</code> and open the printed URL.</div>";
  throw new Error("no token");
}

// The terminal core (xterm.js) is downloaded at build time by
// `go generate ./internal/cc/operator` (or core/build.py). If a binary was
// compiled without it, fail loudly instead of showing a dead console pane.
if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
  $("login-command").disabled = true;
  $("login-btn").disabled = true;
  $("login-error").textContent =
    "Terminal assets are missing from this build. Rebuild the cc binary after running:\n" +
    "  go generate ./internal/cc/operator\n" +
    "(core/build.py fetches them automatically).";
  throw new Error("xterm assets not embedded");
}

const wsURL = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws?token=${encodeURIComponent(token)}`;
const SHELL_ID = "0";

// ── os icons ────────────────────────────────────────────────────────────
// Map an agent's GOOS / human OS string to a small glyph, used in the agent
// table's OS column and as the marker inside mesh nodes.
function osGlyph(a) {
  const o = String((((a && a.goos) || "") + " " + ((a && a.os) || "")).toLowerCase());
  if (o.includes("windows") || o.includes("win32") || o.includes("winnt")) return "🪟";
  if (o.includes("darwin") || o.includes("macos") || o.includes("mac os")) return "🍎";
  if (o.includes("android")) return "🤖";
  if (o.includes("ios") || o.includes("iphone")) return "📱";
  if (o.includes("linux") || o.includes("debian") || o.includes("ubuntu") || o.includes("kali") ||
      o.includes("centos") || o.includes("fedora") || o.includes("red hat") || o.includes("arch") ||
      o.includes("suse") || o.includes("alpine") || o.includes("gentoo") || o.includes("mint")) return "🐧";
  return "💻";
}

// ── websocket ───────────────────────────────────────────────────────────
let ws = null;
let connected = false; // C2 session up (console running)
let connecting = false;
let exiting = false;   // user clicked Exit; don't reconnect after the daemon dies

function send(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function connectWS() {
  if (connecting) return;
  connecting = true;
  ws = new WebSocket(wsURL);
  ws.onopen = () => {
    connecting = false;
    // re-attach to anything that is already running server-side
    if (term) send({ type: "term_ready" });
    if (shellTerm && !shellDead) send({ type: "shell_open", id: SHELL_ID });
  };
  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (_) { return; }
    handleMessage(msg);
  };
  ws.onclose = () => {
    connecting = false;
    if (exiting) {
      // the daemon is gone — stop the reconnect loop and tell the operator
      connected = false; // closing the tab now must not raise the exit warning
      appendLogRaw("\x1b[92m[gui] GUI daemon exited — you can close this tab\x1b[0m");
      return;
    }
    appendLogRaw("\x1b[93m[gui] connection to backend lost — reconnecting...\x1b[0m");
    setTimeout(connectWS, 1500);
  };
}

// ── message handlers ────────────────────────────────────────────────────
// consoleDownNotice keeps us from nagging on every state frame once we have
// already told the operator the console is not running.
let consoleDownNotice = false;

function handleMessage(msg) {
  switch (msg.type) {
    case "state":
      // The daemon is authoritative: if it still has a live session, a page
      // reload / reconnect must drop the operator straight back into the
      // console — no WireGuard login command is ever re-entered. `connected`
      // tracks the session so the Exit flow and the close-tab warning behave
      // after a reconnect too.
      if (msg.connected) {
        connected = true;
        if ($("app").classList.contains("hidden")) {
          enterMain(msg.server);
        } else {
          setConnTag(msg.server);
        }
        if (msg.console === false && !consoleDownNotice) {
          consoleDownNotice = true;
          appendLogRaw("\x1b[91m[gui] console session is not running — use Exit to stop the daemon\x1b[0m");
        }
      } else {
        connected = false;
        consoleDownNotice = false;
        setConnTag("");
      }
      break;
    case "login_result":
      handleLoginResult(msg);
      break;
    case "log":
      appendLogRaw(msg.msg || "");
      break;
    case "pty_out":
      if (term) term.write(b64ToBytes(msg.data || ""));
      break;
    case "agents":
      renderAgents(msg.agents || []);
      break;
    case "shell_opened":
      handleShellOpened(msg);
      break;
    case "shell_out":
      if (shellTerm && !shellDead) shellTerm.write(b64ToBytes(msg.data || ""));
      break;
    case "shell_closed":
      handleShellClosed(msg);
      break;
    case "console_closed":
      appendLogRaw("\x1b[91m[gui] console session closed — use Exit to shut the daemon down\x1b[0m");
      // console is gone: the Exit button is now the only in-page way to stop
      // the daemon, so it must be enabled (it was disabled during the session)
      $("disconnect-btn").disabled = false;
      break;
  }
}

// ── login box ───────────────────────────────────────────────────────────
function handleLoginResult(msg) {
  if (msg.ok) {
    $("login-error").textContent = "";
    $("login-btn").disabled = true;
    $("login-btn").textContent = "Connecting…";
    appendLogRaw("\x1b[92m[gui] login successful\x1b[0m");
    connected = true;
    enterMain("");
  } else {
    $("login-btn").disabled = false;
    $("login-error").textContent = msg.error || "login failed";
    appendLogRaw(`\x1b[91m[gui] login failed: ${msg.error || "unknown error"}\x1b[0m`);
  }
}

function enterMain(server) {
  if (!$("app").classList.contains("hidden")) {
    setConnTag(server);
    return;
  }
  connected = true;
  consoleDownNotice = false;
  $("login-overlay").classList.add("hidden");
  $("app").classList.remove("hidden");
  setConnTag(server);
  switchPage("console");
  initTerm();
  // flush connection-progress log lines into the main log pane
  history.forEach((raw) => appendLogLine(raw));
  history = [];
  appendLogRaw(
    "\x1b[92m═══════════════════════════════════════════════════════════\x1b[0m\n" +
    "\x1b[92m[gui] connected — type `help` for commands\x1b[0m"
  );
  $("disconnect-btn").disabled = false;
  term.focus();
}

function setConnTag(server) {
  const tag = $("conn-tag");
  if (server) {
    tag.textContent = `C2 ${server}`;
    tag.classList.remove("off");
  } else {
    tag.textContent = "not connected";
    tag.classList.add("off");
  }
}

$("login-btn").addEventListener("click", () => {
  const cmd = $("login-command").value.trim();
  if (!cmd) {
    $("login-error").textContent = "paste the connection command from your C2 server first";
    return;
  }
  $("login-error").textContent = "";
  $("login-btn").disabled = true;
  appendLogRaw(`\x1b[36m[gui] connecting with: ${cmd}\x1b[0m`);
  send({ type: "login", command: cmd });
});

$("login-command").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) {
    $("login-btn").click();
  }
});

$("disconnect-btn").addEventListener("click", () => {
  exiting = true;
  $("disconnect-btn").disabled = true;
  appendLogRaw("\x1b[93m[gui] exiting — shutting the GUI daemon down...\x1b[0m");
  send({ type: "exit" });
  // If the daemon is somehow still up after the backend's grace period,
  // surface a hint and let the operator retry instead of leaving a dead
  // button on screen.
  setTimeout(() => {
    if (exiting && ws && ws.readyState === WebSocket.OPEN) {
      appendLogRaw("\x1b[93m[gui] daemon is still running — click Exit again if needed\x1b[0m");
      $("disconnect-btn").disabled = false;
    }
  }, 8000);
});

// ── tabbed pages: console | agents | shell ─────────────────────────────
let page = "console";   // which full-page view is shown
let aview = "table";    // agents sub-view: table | mesh

function switchPage(next) {
  page = next;
  document.querySelectorAll("#nav-rail .nav-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.page === next)
  );
  ["console", "agents", "shell"].forEach((p) =>
    $("page-" + p).classList.toggle("hidden", p !== next)
  );
  if (next === "agents" && aview === "mesh") renderMesh();
  if (next === "console" && term) {
    fitTerm();
    // typing must land in the terminal, not on the (now hidden) login box
    term.focus();
  }
  if (next === "shell") ensureShell();
}

document.querySelectorAll("#nav-rail .nav-btn").forEach((b) =>
  b.addEventListener("click", () => switchPage(b.dataset.page))
);

document.querySelectorAll("#agent-view-toggle button").forEach((b) =>
  b.addEventListener("click", () => {
    aview = b.dataset.aview;
    document.querySelectorAll("#agent-view-toggle button").forEach((x) =>
      x.classList.toggle("active", x === b)
    );
    $("agent-table-wrap").classList.toggle("hidden", aview !== "table");
    $("mesh-wrap").classList.toggle("hidden", aview !== "mesh");
    if (aview === "mesh") renderMesh();
  })
);

// ── console terminal (command pane) ─────────────────────────────────────
let term = null;
let fitAddon = null;

const termTheme = {
  cursorBlink: true,
  fontSize: 13,
  fontFamily: '"JetBrains Mono","Fira Code",Menlo,Consolas,monospace',
  theme: {
    background: "#0b1017",
    foreground: "#d7e0e8",
    cursor: "#38bdf8",
    selectionBackground: "#2a4a66",
    black: "#3b4048", red: "#f85149", green: "#3fb950", yellow: "#d29922",
    blue: "#58a6ff", magenta: "#a371f7", cyan: "#39c5cf", white: "#d7e0e8",
    brightBlack: "#7d8a99", brightRed: "#ff7b72", brightGreen: "#7ee787",
    brightYellow: "#e3b341", brightBlue: "#79c0ff", brightMagenta: "#bc8cff",
    brightCyan: "#56d4dd", brightWhite: "#f0f6fc",
  },
  scrollback: 8000,
};

function initTerm() {
  if (term) return;
  term = new Terminal(termTheme);
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open($("term"));
  term.onData((d) => {
    const bytes = new TextEncoder().encode(d);
    send({ type: "pty_input", data: bytesToB64(bytes) });
  });
  term.onResize(({ cols, rows }) => send({ type: "pty_resize", cols, rows }));
  fitTerm();
  send({ type: "term_ready" });
}

function fitTerm() {
  if (!term) return;
  try { fitAddon.fit(); } catch (_) { /* container not laid out yet */ }
  send({ type: "pty_resize", cols: term.cols, rows: term.rows });
}

// ── OS shell terminal (own page, own pty on the operator machine) ──────
let shellTerm = null;
let shellFit = null;
let shellDead = true;

function ensureShell() {
  if (!connected) return;
  if (shellTerm && !shellDead) {
    fitShell();
    return;
  }
  if (shellTerm) {
    try { shellTerm.dispose(); } catch (_) { /* already gone */ }
    shellTerm = null;
    shellFit = null;
  }
  shellTerm = new Terminal(Object.assign({}, termTheme, { fontSize: 13 }));
  shellFit = new FitAddon.FitAddon();
  shellTerm.loadAddon(shellFit);
  shellTerm.open($("shell-term"));
  shellDead = false;
  shellTerm.onData((d) => {
    const bytes = new TextEncoder().encode(d);
    send({ type: "shell_input", id: SHELL_ID, data: bytesToB64(bytes) });
  });
  shellTerm.onResize(({ cols, rows }) =>
    send({ type: "shell_resize", id: SHELL_ID, cols, rows })
  );
  $("shell-status").textContent = "starting…";
  send({ type: "shell_open", id: SHELL_ID });
  fitShell();
}

function fitShell() {
  if (!shellTerm) return;
  try { shellFit.fit(); } catch (_) { /* hidden or not laid out */ }
  send({ type: "shell_resize", id: SHELL_ID, cols: shellTerm.cols, rows: shellTerm.rows });
}

function handleShellOpened(msg) {
  if (!msg.ok) {
    shellDead = true;
    $("shell-status").textContent = "failed";
    const err = msg.error || "unknown error";
    if (shellTerm) shellTerm.write(`\r\n\x1b[91m[shell] ${err}\x1b[0m\r\n`);
    appendLogRaw(`\x1b[91m[gui] OS shell failed to start: ${err}\x1b[0m`);
    return;
  }
  $("shell-status").textContent = "running";
}

function handleShellClosed(_msg) {
  shellDead = true;
  $("shell-status").textContent = "exited";
  if (shellTerm) {
    shellTerm.write("\r\n\x1b[93m[process exited — Restart to reopen]\x1b[0m\r\n");
  }
  appendLogRaw("\x1b[93m[gui] OS shell exited\x1b[0m");
}

$("shell-restart-btn").addEventListener("click", () => {
  send({ type: "shell_close", id: SHELL_ID });
  shellDead = true;
  if (shellTerm) {
    try { shellTerm.dispose(); } catch (_) { /* */ }
    shellTerm = null;
    shellFit = null;
  }
  ensureShell();
});

if ("ResizeObserver" in window) {
  new ResizeObserver(() => {
    if (page === "console" && term) fitTerm();
  }).observe($("term"));
  new ResizeObserver(() => {
    if (page === "shell" && shellTerm && !shellDead) fitShell();
  }).observe($("shell-term"));
}

// ── log view (output pane) ──────────────────────────────────────────────
let history = []; // raw lines produced before the main layout appeared
const MAX_LINES = 3000;

function appendLogRaw(raw) {
  raw.split("\n").forEach((line) => {
    if (line.length > 4096) line = line.slice(0, 4096);
    if ($("app").classList.contains("hidden")) {
      history.push(line);
      if (history.length > 500) history.shift();
      // login progress: mirror into the mini log
      const mini = $("login-log");
      const div = document.createElement("div");
      div.innerHTML = ansiToHtml(line) || "&nbsp;";
      mini.appendChild(div);
      while (mini.childElementCount > 250) mini.removeChild(mini.firstChild);
      mini.scrollTop = mini.scrollHeight;
    } else {
      appendLogLine(line);
    }
  });
}

function appendLogLine(raw) {
  const body = $("log-body");
  const div = document.createElement("div");
  div.innerHTML = ansiToHtml(raw) || "&nbsp;";
  body.appendChild(div);
  while (body.childElementCount > MAX_LINES) body.removeChild(body.firstChild);
  // autoscroll when the user is near the bottom
  const nearBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 60;
  if (nearBottom) body.scrollTop = body.scrollHeight;
}

$("clear-log-btn").addEventListener("click", () => {
  $("log-body").innerHTML = "";
  history = [];
  $("login-log").innerHTML = "";
});

// minimal ANSI (SGR) -> HTML so colored log lines keep their meaning
function ansiToHtml(s) {
  let out = "";
  let i = 0;
  const styles = { bold: false, fg: null, bg: null };
  const fg16 = {
    30: "#7d8a99", 31: "#f85149", 32: "#3fb950", 33: "#d29922", 34: "#58a6ff",
    35: "#a371f7", 36: "#39c5cf", 37: "#d7e0e8",
    90: "#b8c6d0", 91: "#ff7b72", 92: "#7ee787", 93: "#e3b341", 94: "#79c0ff",
    95: "#bc8cff", 96: "#56d4dd", 97: "#f0f6fc",
  };
  const bg16 = {
    40: "#1c2530", 41: "#5c1a1c", 42: "#1d3a24", 43: "#4d3a10", 44: "#1f3a5c",
    45: "#3d2a5c", 46: "#1f4a4a", 47: "#3b4048",
    100: "#57606a", 101: "#8b3a3a", 102: "#3d5a3d", 103: "#7a5c1c", 104: "#3a5a8b",
    105: "#6a3d8b", 106: "#3a7a7a", 107: "#6a7681",
  };
  const esc = (c) => (c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : c);
  const close = () => {
    if (styles.bold || styles.fg || styles.bg) {
      out += "</span>";
      styles.bold = false;
      styles.fg = null;
      styles.bg = null;
    }
  };
  const apply = (p) => {
    if (p.length === 0) p = [0];
    close();
    for (const code of p) {
      if (code === 1) styles.bold = true;
      else if (code >= 30 && code <= 37) styles.fg = fg16[code];
      else if (code >= 90 && code <= 97) styles.fg = fg16[code];
      else if (code >= 40 && code <= 47) styles.bg = bg16[code];
      else if (code >= 100 && code <= 107) styles.bg = bg16[code];
    }
    if (styles.bold || styles.fg || styles.bg) {
      out += '<span style="' +
        (styles.bold ? "font-weight:700;" : "") +
        (styles.fg ? `color:${styles.fg};` : "") +
        (styles.bg ? `background:${styles.bg};` : "") + '">';
    }
  };
  while (i < s.length) {
    const ch = s[i];
    if (ch === "\x1b" && s[i + 1] === "[") {
      const end = s.indexOf("m", i);
      if (end === -1) break;
      const params = s.slice(i + 2, end).split(";").map((x) => parseInt(x, 10));
      apply(params);
      i = end + 1;
      continue;
    }
    if (ch === "\x1b") { i++; continue; } // drop other escape sequences
    out += esc(ch);
    i++;
  }
  return out;
}

// ── agents: table + mesh ────────────────────────────────────────────────
let agentList = [];

function meshRoleOf(a) {
  const r = (a.meshRoute || "").toLowerCase().trim();
  if (r === "gateway") return "gateway";
  if (r === "direct" || r === "") return "direct";
  if (r.startsWith("via ")) return "silent";
  return "direct";
}

function renderAgents(agents) {
  agentList = agents;
  const count = agents.length;
  let direct = 0, silent = 0, gw = 0;
  agents.forEach((a) => {
    const role = meshRoleOf(a);
    if (role === "silent") silent++;
    else if (role === "gateway") gw++;
    else direct++;
  });
  const parts = [`${count} total`];
  if (direct) parts.push(`${direct} direct`);
  if (gw) parts.push(`${gw} gateway`);
  if (silent) parts.push(`${silent} mesh`);
  $("agents-summary").textContent = parts.join(" · ");
  $("agent-count").textContent = count ? `🛡 ${count}` : "";
  renderTable();
  if (page === "agents" && aview === "mesh") renderMesh();
}

function renderTable() {
  const tbody = $("agent-table").querySelector("tbody");
  tbody.innerHTML = "";
  if (agentList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="muted">No agents connected yet</td></tr>';
    return;
  }
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  agentList.forEach((a) => {
    const role = meshRoleOf(a);
    const tr = document.createElement("tr");
    if (a.active) tr.classList.add("active");
    tr.dataset.tag = a.tag;
    const meshClass = role === "gateway" ? "gateway-cell" : role === "silent" ? "silent-cell" : "direct-cell";
    tr.innerHTML =
      `<td>${esc(a.id)}</td>` +
      `<td class="tag-cell">${esc(a.name || a.tag)}</td>` +
      `<td title="${esc(a.os || "")}">${a.hasRoot ? "👑 " : ""}${osGlyph(a)}${a.os ? "&nbsp;" + esc(a.os.split(",")[0]) : ""}</td>` +
      `<td>${esc(a.user || "")}</td>` +
      `<td>${esc(a.from || "")}</td>` +
      `<td>${esc(a.transport || "")}</td>` +
      `<td class="${meshClass}" title="${esc(a.meshRoute || "")}">${esc((a.meshRoute || "direct").slice(0, 22))}</td>` +
      `<td>${esc(a.lastSeen || "--")}</td>` +
      `<td>${a.lastSeenRttMs > 0 ? a.lastSeenRttMs.toFixed(1) + "ms" : "--"}</td>`;
    tbody.appendChild(tr);
  });
  tbody.querySelectorAll("tr[data-tag]").forEach((tr) => {
    tr.addEventListener("click", () => {
      send({ type: "select_agent", id: tr.dataset.tag });
      tbody.querySelectorAll("tr.active").forEach((x) => x.classList.remove("active"));
      tr.classList.add("active");
    });
    // double-click opens the agent console and targets it (Cobalt Strike style)
    tr.addEventListener("dblclick", () => openAgentConsole(tr.dataset.tag));
  });
}

// osShortLabel maps the agent's human OS string to a short family name.
function osShortLabel(a) {
  const o = String(a.os || "");
  if (/windows/i.test(o)) return "Windows";
  if (/macos|darwin/i.test(o)) return "macOS";
  if (/kali/i.test(o)) return "Kali";
  if (/ubuntu/i.test(o)) return "Ubuntu";
  if (/debian/i.test(o)) return "Debian";
  if (/fedora/i.test(o)) return "Fedora";
  if (/centos/i.test(o)) return "CentOS";
  if (/alpine/i.test(o)) return "Alpine";
  if (/linux/i.test(o)) return "Linux";
  if (a.goos) return a.goos.charAt(0).toUpperCase() + a.goos.slice(1);
  return (o || "?").split(/[\s(]/)[0] || "?";
}

function renderMesh() {
  const svg = $("mesh-svg"), root = $("mesh-root");
  if (!svg || !root) return;
  const W = Math.max(svg.clientWidth || 900, 320);
  const H = Math.max(svg.clientHeight || 420, 240);
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg._W = W; svg._H = H;

  mesh.byTag = {};
  if (agentList.length === 0) {
    root.innerHTML = `<text x="${W / 2}" y="${H / 2}" text-anchor="middle" fill="var(--muted)" font-size="13" font-family="var(--mono)">No agents connected yet</text>`;
    mesh.hub = null; mesh.edges = [];
    applyMeshView();
    return;
  }

  const esc = (s) => String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  const byIP = {};
  agentList.forEach((a) => {
    (a.ips || []).forEach((ip) => { byIP[ip.split("/")[0]] = a; });
    if (a.from) byIP[a.from] = a;
  });
  const roleOf = (a) => {
    const r = meshRoleOf(a);
    return r === "gateway" ? "gateway" : r === "silent" ? "mesh" : "direct";
  };
  const nodes = agentList.map((a) => {
    // every IP we know about, deduped (from + reported ips)
    const ipSet = [];
    const addIP = (ip) => {
      ip = String(ip || "").split("/")[0].trim();
      if (ip && !ipSet.includes(ip)) ipSet.push(ip);
    };
    (a.ips || []).forEach(addIP);
    addIP(a.from);
    const ipLine = ipSet.slice(0, 2).join(" · ") + (ipSet.length > 2 ? " +" + (ipSet.length - 2) : "");
    const route = (a.meshRoute || "direct").slice(0, 26);
    return {
      tag: a.tag, kind: roleOf(a), active: !!a.active, root: !!a.hasRoot,
      os: a.os || "", goos: a.goos || "", arch: a.arch || "",
      user: a.user || "", from: a.from || "",
      name: (a.name || a.tag || "").slice(0, 24),
      ipLine: ipLine || "?",
      osLine: osShortLabel(a) + (a.arch ? " · " + a.arch : ""),
      metaLine: [a.transport, route].filter(Boolean).join(" · "),
      seenLine: [a.lastSeen || "", a.lastSeenRttMs > 0 ? a.lastSeenRttMs.toFixed(0) + "ms" : ""].filter(Boolean).join(" · "),
      mesh: a.meshRoute || "", p2p: a.p2pRelayPort || "", version: a.version || "",
      tip: `${a.tag}  v${a.version || "?"}\n` +
        `uuid: ${a.uuid || "?"}\n` +
        `os: ${a.os || "?"} (${a.goos || "?"}/${a.arch || "?"})\n` +
        `user: ${a.user || "?"}\n` +
        `process: ${a.process || "?"}\n` +
        `cwd: ${a.cwd || "?"}\n` +
        `ips: ${ipSet.join(", ") || "?"} (from: ${a.from || "?"})\n` +
        `transport: ${a.transport || "?"} · route: ${a.meshRoute || "direct"}\n` +
        `p2p: ${a.p2pRelayPort || "-"} · gossip: ${a.meshGossipPort || "-"}\n` +
        `lastSeen: ${a.lastSeen || "?"} · rtt: ${a.lastSeenRttMs > 0 ? a.lastSeenRttMs.toFixed(1) + "ms" : "-"}`,
    };
  });
  nodes.forEach((n) => { mesh.byTag[n.tag] = n; });

  // parent: mesh agents attach to the gateway they route "via", all else to the C2 hub
  const parentOf = {};
  nodes.forEach((n) => {
    if (n.kind === "mesh") {
      const via = (n.mesh || "").match(/via\s+(\S+)/i);
      const gw = via ? byIP[via[1]] : null;
      parentOf[n.tag] = gw && gw.tag !== n.tag ? gw.tag : "hub";
    } else parentOf[n.tag] = "hub";
  });

  // left-to-right tree layout, C2 hub on the left (Cobalt Strike style)
  const COL_W = 260, ROW_H = 152, HUB_X = 92, TOP = 64;
  const kidsOf = {};
  nodes.forEach((n) => { const p = parentOf[n.tag]; (kidsOf[p] = kidsOf[p] || []).push(n.tag); });
  const layout = {}; const placed = {}; let row = 0;
  const place = (tag, depth) => {
    if (placed[tag]) return layout[tag] ? layout[tag].y : TOP + row * ROW_H;
    placed[tag] = 1;
    const x = HUB_X + depth * COL_W;
    const kids = (kidsOf[tag] || []).filter((k) => !placed[k]);
    let y;
    if (!kids.length) { y = TOP + row * ROW_H; row++; }
    else { const ys = kids.map((k) => place(k, depth + 1)); y = (Math.min(...ys) + Math.max(...ys)) / 2; }
    layout[tag] = { x, y };
    return y;
  };
  nodes.forEach((n) => place(n.tag, 1));

  // centre the tree vertically, hub at the vertical middle of its children
  const ys = nodes.map((n) => layout[n.tag].y);
  const dy = H / 2 - (Math.min(...ys) + Math.max(...ys)) / 2;
  nodes.forEach((n) => { layout[n.tag].y += dy; });
  const hubKids = (kidsOf["hub"] || []).map((k) => (layout[k] ? layout[k].y : H / 2));
  mesh.hub = { x: HUB_X, y: hubKids.length ? (Math.min(...hubKids) + Math.max(...hubKids)) / 2 : H / 2 };
  svg._layout = layout;

  const posOf = (tag) => mesh.pos[tag] || layout[tag] || mesh.hub || { x: HUB_X, y: H / 2 };
  const radOf = (tag) => (tag === "hub" ? 26 : 28);

  mesh.edges = [];
  nodes.forEach((n) => mesh.edges.push({ from: parentOf[n.tag], to: n.tag, kind: n.kind, root: n.root }));

  let html = "<defs>" +
    '<marker id="ma-green" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="#3fb950"/></marker>' +
    '<marker id="ma-red"   viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="#f85149"/></marker>' +
    '<marker id="ma-blue"  viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="#4d9fe6"/></marker>' +
    "</defs>";

  // edges
  mesh.edges.forEach((ed) => {
    const a = posOf(ed.from), b = posOf(ed.to);
    if (!a || !b) return;
    const col = ed.kind === "mesh" ? "#4d9fe6" : ed.root ? "#f85149" : "#3fb950";
    const mk = col === "#f85149" ? "ma-red" : col === "#4d9fe6" ? "ma-blue" : "ma-green";
    html += `<path id="me-${esc(ed.from)}-${esc(ed.to)}" d="${edgePath(a, b, radOf(ed.from), radOf(ed.to))}" stroke="${col}" stroke-width="2.2" fill="none" marker-end="url(#${mk})"/>`;
  });

  // C2 hub node
  html += `<g transform="translate(${mesh.hub.x},${mesh.hub.y})">` +
    `<title>C2 server</title>` +
    `<circle r="26" fill="#241b38" stroke="#a371f7" stroke-width="2"/>` +
    `<text y="6" text-anchor="middle" fill="#a371f7" font-size="22">☸</text>` +
    `<text class="mesh-node-label" y="44" text-anchor="middle" fill="var(--fg)" font-size="10.5" font-weight="bold">C2</text>` +
    `<text class="mesh-node-label" y="55" text-anchor="middle" fill="var(--muted)" font-size="9">server</text>` +
    "</g>";

  // agent nodes: icon + as much info as fits (name, user, IPs, OS/arch,
  // transport·route, last-seen·rtt) — hover tooltip carries the full record
  const cut = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + "…" : s || "");
  nodes.forEach((n) => {
    const p = posOf(n.tag);
    const ring = n.active ? "#38bdf8" : n.root ? "#f85149" : "#39414d";
    const ringW = n.active ? 3 : 1.5;
    const nameCol = n.root ? "#f85149" : "#d7e0e8";
    html += `<g class="gnode" data-tag="${esc(n.tag)}" transform="translate(${p.x.toFixed(1)},${p.y.toFixed(1)})">` +
      `<title>${esc(n.tip)}</title>` +
      `<rect x="-92" y="-32" width="184" height="142" fill="transparent"/>` +
      `<circle class="mesh-icon" r="26" fill="#10161f" stroke="${ring}" stroke-width="${ringW}"/>` +
      `<text y="5" text-anchor="middle" font-size="20">${osGlyph(n)}</text>` +
      `<text y="40" text-anchor="middle" fill="${nameCol}" font-size="11" font-weight="bold" font-family="var(--mono)">${n.root ? "👑 " : ""}${esc(cut(n.name, 22))}</text>` +
      `<text y="52" text-anchor="middle" fill="#9aa4b2" font-size="9.5" font-family="var(--mono)">${esc(cut(n.user || n.tag, 26))}</text>` +
      `<text y="66" text-anchor="middle" fill="#79c0ff" font-size="9.5" font-family="var(--mono)">${esc(cut(n.ipLine, 28))}</text>` +
      `<text y="79" text-anchor="middle" fill="#8b949e" font-size="9" font-family="var(--mono)">${esc(cut(n.osLine, 28))}</text>` +
      `<text y="91" text-anchor="middle" fill="#8b949e" font-size="9" font-family="var(--mono)">${esc(cut(n.metaLine, 28))}</text>` +
      `<text y="103" text-anchor="middle" fill="#6e7681" font-size="8.5" font-family="var(--mono)">${esc(cut(n.seenLine, 28))}</text>` +
      "</g>";
  });
  root.innerHTML = html;
  applyMeshView();
}

// edgePath insets a straight line so arrowheads stop at the node edge.
function edgePath(a, b, ra, rb) {
  const dx = b.x - a.x, dy = b.y - a.y;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len, uy = dy / len;
  return `M${(a.x + ux * ra).toFixed(1)} ${(a.y + uy * ra).toFixed(1)} L${(b.x - ux * rb).toFixed(1)} ${(b.y - uy * rb).toFixed(1)}`;
}

function meshPosOf(tag) {
  const svg = $("mesh-svg");
  const layout = svg && svg._layout;
  return mesh.pos[tag] || (layout && layout[tag]) || mesh.hub || { x: 92, y: 100 };
}

function applyMeshView() {
  const g = $("mesh-root");
  if (g) g.setAttribute("transform", `translate(${mesh.view.tx},${mesh.view.ty}) scale(${mesh.view.scale})`);
}

function resetMeshView() {
  mesh.pos = {};
  mesh.view = { tx: 0, ty: 0, scale: 1 };
  renderMesh();
}

// ── agent graph canvas: pan, zoom, drag, double-click select, context menu ──
const mesh = {
  view: { tx: 0, ty: 0, scale: 1 },
  pos: {},      // tag -> {x,y}: dragged positions, kept across re-renders
  hub: null, byTag: {}, edges: [],
  mode: null, dragTag: null,
  startX: 0, startY: 0, origX: 0, origY: 0, moved: 0,
  suppressClick: false,
};
let meshWired = false;

function wireMeshView() {
  if (meshWired) return;
  const svg = $("mesh-svg");
  if (!svg) return;
  meshWired = true;

  // pan / node-drag
  svg.addEventListener("mousedown", (e) => {
    const nodeEl = e.target.closest(".gnode");
    mesh.startX = e.clientX; mesh.startY = e.clientY; mesh.moved = 0;
    if (nodeEl && nodeEl.dataset.tag) {
      mesh.mode = "node"; mesh.dragTag = nodeEl.dataset.tag;
      const p = meshPosOf(mesh.dragTag); mesh.origX = p.x; mesh.origY = p.y;
    } else {
      mesh.mode = "pan";
      mesh.origX = mesh.view.tx; mesh.origY = mesh.view.ty;
    }
    svg.classList.add("panning");
    e.preventDefault();
  });
  document.addEventListener("mousemove", (e) => {
    if (!mesh.mode) return;
    const dx = e.clientX - mesh.startX, dy = e.clientY - mesh.startY;
    mesh.moved = Math.max(mesh.moved, Math.abs(dx) + Math.abs(dy));
    if (mesh.mode === "pan") {
      mesh.view.tx = mesh.origX + dx;
      mesh.view.ty = mesh.origY + dy;
      applyMeshView();
      return;
    }
    const tag = mesh.dragTag;
    const nx = mesh.origX + dx / mesh.view.scale;
    const ny = mesh.origY + dy / mesh.view.scale;
    mesh.pos[tag] = { x: nx, y: ny };
    const g = svg.querySelector(`.gnode[data-tag="${CSS.escape(tag)}"]`);
    if (g) g.setAttribute("transform", `translate(${nx.toFixed(1)},${ny.toFixed(1)})`);
    (mesh.edges || []).forEach((ed) => {
      if (ed.from !== tag && ed.to !== tag) return;
      const el = svg.querySelector(`#me-${CSS.escape(ed.from)}-${CSS.escape(ed.to)}`);
      if (el) el.setAttribute("d", edgePath(meshPosOf(ed.from), meshPosOf(ed.to), ed.from === "hub" ? 26 : 28, 28));
    });
  });
  document.addEventListener("mouseup", () => {
    if (!mesh.mode) return;
    svg.classList.remove("panning");
    mesh.mode = null; mesh.dragTag = null;
    if (mesh.moved > 6) mesh.suppressClick = true; // it was a drag, not a click
  });

  // wheel zoom centred on the cursor
  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const rect = svg.getBoundingClientRect();
    const W = svg._W || rect.width, H = svg._H || rect.height;
    const mx = ((e.clientX - rect.left) / rect.width) * W;
    const my = ((e.clientY - rect.top) / rect.height) * H;
    const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
    const ns = Math.min(3.2, Math.max(0.3, mesh.view.scale * factor));
    mesh.view.tx = mx - (mx - mesh.view.tx) * (ns / mesh.view.scale);
    mesh.view.ty = my - (my - mesh.view.ty) * (ns / mesh.view.scale);
    mesh.view.scale = ns;
    applyMeshView();
  }, { passive: false });

  // single click does nothing on the graph: select by double-click or menu
  svg.addEventListener("click", () => { mesh.suppressClick = false; });
  svg.addEventListener("dblclick", (e) => {
    const nodeEl = e.target.closest(".gnode");
    if (nodeEl && nodeEl.dataset.tag) openAgentConsole(nodeEl.dataset.tag);
  });
  svg.addEventListener("contextmenu", (e) => {
    const nodeEl = e.target.closest(".gnode");
    if (!nodeEl || !nodeEl.dataset.tag) return; // plain right-click on canvas: browser menu
    e.preventDefault();
    showAgentCtx(e.clientX, e.clientY, mesh.byTag[nodeEl.dataset.tag] || { tag: nodeEl.dataset.tag });
  });

  $("mesh-reset-btn").addEventListener("click", resetMeshView);
}

// double-click (or the context menu) targets an agent — same effect as a table row click
function selectMeshAgent(tag) {
  send({ type: "select_agent", id: tag });
  document.querySelectorAll("#agent-table tbody tr[data-tag]").forEach((tr) => {
    tr.classList.toggle("active", tr.dataset.tag === tag);
  });
  renderMesh(); // re-render so the new active ring shows (node positions are kept)
}

// openAgentConsole targets the agent, then jumps to the Console tab — the
// Cobalt Strike double-click behaviour: interact with the agent you clicked.
// The emp3r0r console prompt follows the selected target (live.ActiveAgent).
function openAgentConsole(tag) {
  selectMeshAgent(tag);
  switchPage("console");
}

// ── agent context menu ────────────────────────────────────────────────
function showAgentCtx(x, y, a) {
  const m = $("agent-ctx");
  if (!m) return;
  m._agent = a;
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  m.innerHTML =
    `<div class="ctx-title">${esc(a.name || a.tag || "")}</div>` +
    `<button data-act="select">🎯 Select as target</button>` +
    `<div class="ctx-sep"></div>` +
    `<button data-act="copy-tag">Copy tag</button>` +
    (a.from ? `<button data-act="copy-ip">Copy IP (${esc(a.from)})</button>` : "");
  m.classList.remove("hidden");
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(4, Math.min(x, window.innerWidth - r.width - 8)) + "px";
  m.style.top = Math.max(4, Math.min(y, window.innerHeight - r.height - 8)) + "px";
}

document.addEventListener("click", (e) => {
  const m = $("agent-ctx");
  if (!m || m.classList.contains("hidden")) return;
  const btn = e.target.closest("#agent-ctx button");
  const a = m._agent || {};
  if (!btn) { m.classList.add("hidden"); return; }
  m.classList.add("hidden");
  const act = btn.dataset.act;
  if (act === "select") selectMeshAgent(a.tag);
  else if (act === "copy-tag") copyToClipboard(a.tag);
  else if (act === "copy-ip") copyToClipboard(a.from);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { const m = $("agent-ctx"); if (m) m.classList.add("hidden"); }
});
document.addEventListener("contextmenu", (e) => {
  // right-clicking anywhere else hides the agent menu; node right-clicks are
  // handled by the svg handler (which shows it), so never fight it here
  const m = $("agent-ctx");
  if (m && !m.classList.contains("hidden") && !e.target.closest("#agent-ctx") && !e.target.closest(".gnode")) {
    m.classList.add("hidden");
  }
});

function copyToClipboard(text) {
  const done = () => appendLogRaw(`\x1b[92m[gui] copied: ${text}\x1b[0m`);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text || "").then(done).catch(() => fallbackCopy(text, done));
  } else fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
  const ta = document.createElement("textarea");
  ta.value = text || "";
  ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } catch (_) { /* ignore */ }
  ta.remove();
}

// ── base64 helpers ──────────────────────────────────────────────────────
function bytesToB64(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ── boot ────────────────────────────────────────────────────────────────
$("login-command").focus();
connectWS();
wireMeshView();

// Warn before the tab is closed (Ctrl+W / close button) while a C2 session is
// live, so an accidental close never silently drops the operator console.
window.addEventListener("beforeunload", (e) => {
  if (!connected || exiting) return;
  e.preventDefault();
  e.returnValue = "";
});
