/* =============================================================
   rayengader.github.io — page behaviour
   No framework, no build step. Four things happen here:
     1. the hero terminal boots
     2. the status bar tracks which section you are reading
     3. the SOC topology replays a real attack scenario
     4. the ATT&CK matrix and the certification grid respond to input
   ============================================================= */
(function () {
  "use strict";

  var reduced = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  /* ---------------------------------------------------------------
     1. Boot the hero terminal
     Lines are in the HTML already, so the page reads correctly with
     no JS at all; this only staggers their arrival.
     --------------------------------------------------------------- */
  function bootTerminal() {
    var term = $("#boot .term-body");
    if (!term || reduced) return;
    var lines = $$(".ln", term);
    term.classList.add("is-typing");
    lines.forEach(function (ln, i) {
      setTimeout(function () { ln.classList.add("shown"); }, 70 + i * 85);
    });
  }

  /* ---------------------------------------------------------------
     2. Section tracking in the status bar
     --------------------------------------------------------------- */
  function trackSections() {
    var links = $$(".navlinks a");
    if (!links.length || !("IntersectionObserver" in window)) return;

    var byId = {};
    var targets = [];
    links.forEach(function (a) {
      var id = a.getAttribute("href").slice(1);
      var el = document.getElementById(id);
      if (el) { byId[id] = a; targets.push(el); }
    });

    var seen = {};
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { seen[e.target.id] = e.intersectionRatio; });
      var best = null, bestRatio = 0;
      Object.keys(seen).forEach(function (id) {
        if (seen[id] > bestRatio) { bestRatio = seen[id]; best = id; }
      });
      links.forEach(function (a) { a.classList.remove("is-active"); });
      if (best && byId[best] && bestRatio > 0.02) byId[best].classList.add("is-active");
    }, { rootMargin: "-56px 0px -55% 0px", threshold: [0, 0.02, 0.15, 0.4, 0.8] });

    targets.forEach(function (t) { io.observe(t); });
  }

  /* ---------------------------------------------------------------
     3. Attack replay over the SOC topology

     Each step carries the second it happens at, the edge the traffic
     travels, the component that changes state, and the log line the
     component would actually write. Timings are the ones measured on
     the build: both scenarios reach a contextualised alert well inside
     a minute, with no analyst touching anything.
     --------------------------------------------------------------- */

  var MS_PER_SEC = 165;   // scenario seconds are compressed for watching

  var SCENARIOS = {
    ftp: {
      label: "T1110.001 · FTP brute force",
      mttd: "MTTD 00:09",
      rule: "wazuh 100210 · level 12",
      kase: "TheHive #0142 · HIGH",
      out: "contextualised alert · no human action",
      end: 21,
      steps: [
        { t: 0,  path: "pA",  node: "n-atk",  state: "crit", src: "ngfw",     msg: "session 203.0.113.44 → 10.10.20.15:21 · ftp permitted to DMZ" },
        { t: 2,  path: "pB2", node: "n-ftp",  state: "crit", src: "ftp-srv",  msg: "12 failed logins in 8s · username rotation, single source" },
        { t: 4,  path: "pC2", node: "n-suri", state: "hot",  src: "suricata", msg: "ET SCAN Potential FTP Brute-Force attempt · sid 2002383" },
        { t: 7,  path: "pD1", node: "n-wazuh",state: "hot",  src: "wazuh",    msg: "rule 11402 matched ×12 · 2 agents reporting the same source" },
        { t: 9,  node: "n-wazuh", state: "hot", cls: "hi", detect: true, src: "wazuh", msg: "correlation 100210 fired · level 12 · T1110.001 — DETECTED" },
        { t: 11, path: "pE",  node: "n-hive",  state: "crit", cls: "crit", src: "thehive", msg: "case #0142 opened · severity HIGH · observable 203.0.113.44" },
        { t: 13, path: "pF",  node: "n-cortex",state: "hot",  src: "cortex",  msg: "AbuseIPDB 97% confidence · VirusTotal 14/94 · known scanner" },
        { t: 15, path: "pG",  node: "n-misp",  state: "hot",  src: "misp",    msg: "event 1183 published · tlp:amber · tag ftp-bruteforce" },
        { t: 17, path: "pH",  node: "n-n8n",   state: "hot",  src: "n8n",     msg: "contextualised alert dispatched to the SOC channel" },
        { t: 19, node: "n-ftp", state: "done", cls: "ok", src: "response",    msg: "source blocked at the NGFW · account lockout verified · case closed" }
      ]
    },

    web: {
      label: "T1190 → T1505.003 · SQL injection to web shell",
      mttd: "MTTD 00:16",
      rule: "wazuh 100315 · level 14",
      kase: "TheHive #0143 · CRITICAL",
      out: "host contained via Falcon · web shell quarantined",
      end: 28,
      steps: [
        { t: 0,  path: "pA",  node: "n-atk",  state: "crit", src: "ngfw",     msg: "session 203.0.113.44 → 10.10.20.10:443 · https permitted to DMZ" },
        { t: 2,  path: "pB1", node: "n-web",  state: "crit", src: "web-srv",  msg: "POST /login.php · payload ' UNION SELECT 1,2,version()--" },
        { t: 4,  path: "pC1", node: "n-suri", state: "hot",  src: "suricata", msg: "ET WEB_SERVER SQL Injection Select From · sid 2006446" },
        { t: 7,  path: "pB1", node: "n-web",  state: "crit", src: "web-srv",  msg: "POST /upload.php → uploads/cmd.php · 200 OK" },
        { t: 9,  path: "pC1", node: "n-suri", state: "hot",  src: "suricata", msg: "ET WEB_SERVER PHP tags in HTTP POST · possible web shell upload" },
        { t: 11, path: "pD1", node: "n-wazuh",state: "hot",  src: "wazuh",    msg: "syscheck: new file /var/www/html/uploads/cmd.php · 644 www-data" },
        { t: 14, path: "pC3", node: "n-cs",   state: "crit", cls: "crit", src: "crowdstrike", msg: "process tree apache2 → sh -c "id;uname -a" · detection: Web Shell" },
        { t: 16, path: "pD2", node: "n-wazuh",state: "hot",  cls: "hi", detect: true, src: "wazuh", msg: "correlation 100315 fired · level 14 · T1190 → T1505.003 — DETECTED" },
        { t: 18, path: "pE",  node: "n-hive",  state: "crit", cls: "crit", src: "thehive", msg: "case #0143 opened · severity CRITICAL · 3 observables" },
        { t: 20, path: "pF",  node: "n-cortex",state: "hot",  src: "cortex",  msg: "VirusTotal 31/94 on cmd.php · AbuseIPDB 97% on the source" },
        { t: 22, path: "pG",  node: "n-misp",  state: "hot",  src: "misp",    msg: "IoC set published · file hash, source IP, URI pattern" },
        { t: 24, path: "pH",  node: "n-n8n",   state: "hot",  src: "n8n",     msg: "contextualised alert dispatched to the SOC channel" },
        { t: 26, node: "n-web", state: "done", cls: "ok", src: "response",    msg: "host network-contained via Falcon · web shell quarantined · case closed" }
      ]
    }
  };

  var NODE_IDS = ["n-atk", "n-ngfw", "n-web", "n-ftp", "n-ad", "n-ws", "n-suri",
                  "n-cs", "n-wazuh", "n-hive", "n-cortex", "n-misp", "n-n8n", "n-noc"];

  var timers = [];
  var rafId = null;
  var current = "ftp";

  function mmss(sec) {
    var s = Math.max(0, Math.floor(sec));
    var m = Math.floor(s / 60);
    return (m < 10 ? "0" : "") + m + ":" + ((s % 60) < 10 ? "0" : "") + (s % 60);
  }

  function clearRun() {
    timers.forEach(clearTimeout);
    timers = [];
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    var packet = $("#packet");
    if (packet) packet.setAttribute("opacity", "0");
  }

  function resetNodes() {
    NODE_IDS.forEach(function (id) {
      var n = document.getElementById(id);
      if (n) n.setAttribute("class", "node");
    });
  }

  function logRow(step) {
    var row = document.createElement("div");
    row.className = "row" + (step.cls ? " " + step.cls : "");
    row.innerHTML =
      '<span class="t">t+' + mmss(step.t) + '</span>' +
      '<span class="src">' + step.src + '</span>' +
      '<span class="msg"></span>';
    row.lastChild.textContent = step.msg;
    return row;
  }

  function movePacket(pathId, dur) {
    var p = document.getElementById(pathId);
    var c = $("#packet");
    if (!p || !c || reduced || typeof p.getTotalLength !== "function") return;
    var len = p.getTotalLength();
    var t0 = performance.now();
    c.setAttribute("opacity", "1");
    (function frame(now) {
      var k = Math.min(1, (now - t0) / dur);
      var pt = p.getPointAtLength(len * k);
      c.setAttribute("cx", pt.x);
      c.setAttribute("cy", pt.y);
      if (k < 1) requestAnimationFrame(frame);
      else c.setAttribute("opacity", "0");
    })(t0);
  }

  function applyStep(step, log) {
    if (step.node && step.state) {
      var n = document.getElementById(step.node);
      if (n) n.setAttribute("class", "node " + step.state);
    }
    if (step.path) movePacket(step.path, 520);
    if (log) {
      log.appendChild(logRow(step));
      log.scrollTop = log.scrollHeight;
    }
  }

  function setVerdict(sc) {
    $("#v-mttd").textContent = sc.mttd;
    $("#v-rule").textContent = sc.rule;
    $("#v-case").textContent = sc.kase;
    $("#v-out").textContent = sc.out;
  }

  /* Draw the scenario in its finished state, with no animation. This is
     what the page shows at rest, and what a reader with reduced motion
     gets when they press replay. */
  function renderStatic(key) {
    var sc = SCENARIOS[key];
    var log = $("#log");
    clearRun();
    resetNodes();
    if (!log) return;
    log.innerHTML = "";
    sc.steps.forEach(function (step) {
      if (step.node && step.state) {
        var n = document.getElementById(step.node);
        if (n) n.setAttribute("class", "node " + step.state);
      }
      log.appendChild(logRow(step));
    });
    log.scrollTop = 0;
    setVerdict(sc);
    var clock = $("#clock");
    if (clock) clock.innerHTML = "t+<b>" + mmss(sc.end) + "</b> · " + sc.mttd.toLowerCase();
  }

  function run(key) {
    var sc = SCENARIOS[key];
    var log = $("#log");
    var clock = $("#clock");
    var btn = $("#replay");

    if (reduced) { renderStatic(key); return; }

    clearRun();
    resetNodes();
    if (log) log.innerHTML = '<div class="idle">// replaying ' + sc.label + " …</div>";
    setVerdict(sc);
    if (btn) { btn.disabled = true; btn.textContent = "▶ running…"; }

    var t0 = performance.now();
    var detected = false;

    (function tick(now) {
      var sec = Math.min(sc.end, (now - t0) / MS_PER_SEC);
      if (clock) {
        clock.innerHTML = "t+<b>" + mmss(sec) + "</b>" +
          (detected ? " · " + sc.mttd.toLowerCase() : " · watching");
      }
      if (sec < sc.end) rafId = requestAnimationFrame(tick);
    })(t0);

    sc.steps.forEach(function (step, i) {
      timers.push(setTimeout(function () {
        if (i === 0 && log) log.innerHTML = "";
        if (step.detect) detected = true;
        applyStep(step, log);
      }, step.t * MS_PER_SEC + 120));
    });

    timers.push(setTimeout(function () {
      if (clock) clock.innerHTML = "t+<b>" + mmss(sc.end) + "</b> · " + sc.mttd.toLowerCase();
      if (btn) { btn.disabled = false; btn.textContent = "▶ Replay attack"; }
    }, sc.end * MS_PER_SEC + 240));
  }

  function wireConsole() {
    var picks = $$(".scenario-pick .chip");
    var btn = $("#replay");
    if (!btn) return;

    picks.forEach(function (chip) {
      chip.addEventListener("click", function () {
        current = chip.getAttribute("data-scenario");
        picks.forEach(function (c) {
          c.setAttribute("aria-pressed", String(c === chip));
        });
        run(current);
      });
    });

    btn.addEventListener("click", function () { run(current); });

    renderStatic(current);
  }

  /* ---------------------------------------------------------------
     4a. ATT&CK matrix — one technique open at a time
     --------------------------------------------------------------- */
  function wireMatrix() {
    var detail = $("#tq-detail");
    var buttons = $$(".tq");
    if (!detail || !buttons.length) return;

    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        buttons.forEach(function (o) { o.setAttribute("aria-expanded", "false"); });
        b.setAttribute("aria-expanded", "true");

        var id = $(".tid", b).textContent;
        var name = $(".tnm", b).textContent;
        detail.innerHTML =
          "<b></b><br><span class=\"body\"></span>" +
          '<span class="d3">D3FEND countermeasures mapped: <em>DNS traffic analysis</em> · ' +
          "<em>network traffic filtering</em> · <em>executable allowlisting</em> · " +
          "<em>credential hardening</em>.</span>";
        $("b", detail).textContent = id + " · " + name;
        $(".body", detail).textContent = b.getAttribute("data-d");
      });
    });
  }

  /* ---------------------------------------------------------------
     4b. Certification grid filter
     --------------------------------------------------------------- */
  function wireCerts() {
    var chips = $$(".cert-filter .chip");
    var cards = $$("#cert-grid .cert");
    var count = $("#cert-count");
    if (!chips.length || !cards.length) return;

    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        var f = chip.getAttribute("data-filter");
        chips.forEach(function (c) {
          c.setAttribute("aria-pressed", String(c === chip));
        });
        var shown = 0;
        cards.forEach(function (card) {
          var match = f === "all" || card.getAttribute("data-domain") === f;
          card.hidden = !match;
          if (match) shown++;
        });
        if (count) count.textContent = String(shown);
      });
    });
  }

  /* --------------------------------------------------------------- */
  bootTerminal();
  trackSections();
  wireConsole();
  wireMatrix();
  wireCerts();
})();
