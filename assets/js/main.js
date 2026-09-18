/* =============================================================
   rayengader.github.io — page behaviour

   No framework, no build step. Three things happen here:
     1. the navigation tracks which section you are reading
     2. the attack simulation replays a scenario over the topology
     3. the ATT&CK matrix and the credential filter respond to input
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
     1. Section tracking
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
    }, { rootMargin: "-64px 0px -55% 0px", threshold: [0, 0.02, 0.15, 0.4, 0.8] });

    targets.forEach(function (t) { io.observe(t); });
  }

  /* ---------------------------------------------------------------
     2. Attack simulation

     Each step carries the second it happens at, the link the traffic
     travels, the component that changes state, and the event that
     component would actually record. Timings are the ones measured on
     the build: both scenarios reach a contextualised alert well inside
     a minute, with no analyst touching anything.
     --------------------------------------------------------------- */

  var MS_PER_SEC = 165;   // scenario seconds are compressed for watching

  var SCENARIOS = {
    ftp: {
      label: "FTP brute force",
      mttd: "00:09",
      rule: "Wazuh 100210 · level 12",
      kase: "TheHive #0142 · High",
      out: "Contextualised alert, no human action",
      end: 21,
      steps: [
        { t: 0,  path: "pA",  node: "n-atk",   state: "crit", src: "Firewall",    msg: "Session 203.0.113.44 → 10.10.20.15:21 · FTP permitted to DMZ" },
        { t: 2,  path: "pB2", node: "n-ftp",   state: "crit", sev: "critical", src: "FTP server", msg: "12 failed logins in 8 seconds · username rotation from a single source" },
        { t: 4,  path: "pC2", node: "n-suri",  state: "hot",  src: "Suricata",    msg: "ET SCAN Potential FTP Brute-Force attempt · sid 2002383" },
        { t: 7,  path: "pD1", node: "n-wazuh", state: "hot",  src: "Wazuh",       msg: "Rule 11402 matched 12 times · two agents reporting the same source" },
        { t: 9,  node: "n-wazuh", state: "hot", sev: "high", detect: true, src: "Wazuh", msg: "Correlation rule 100210 fired · level 12 · T1110.001 — detected" },
        { t: 11, path: "pE",  node: "n-hive",  state: "crit", sev: "critical", src: "TheHive", msg: "Case #0142 opened · severity High · observable 203.0.113.44" },
        { t: 13, path: "pF",  node: "n-cortex",state: "hot",  src: "Cortex",      msg: "AbuseIPDB 97% confidence · VirusTotal 14/94 · known scanner" },
        { t: 15, path: "pG",  node: "n-misp",  state: "hot",  src: "MISP",        msg: "Event 1183 published · tlp:amber · tagged ftp-bruteforce" },
        { t: 17, path: "pH",  node: "n-n8n",   state: "hot",  src: "n8n",         msg: "Contextualised alert dispatched to the SOC channel" },
        { t: 19, node: "n-ftp", state: "done", sev: "resolved", src: "Response",  msg: "Source blocked at the firewall · account lockout verified · case closed" }
      ]
    },

    web: {
      label: "SQL injection to web shell",
      mttd: "00:16",
      rule: "Wazuh 100315 · level 14",
      kase: "TheHive #0143 · Critical",
      out: "Host contained via Falcon, web shell quarantined",
      end: 28,
      steps: [
        { t: 0,  path: "pA",  node: "n-atk",   state: "crit", src: "Firewall",   msg: "Session 203.0.113.44 → 10.10.20.10:443 · HTTPS permitted to DMZ" },
        { t: 2,  path: "pB1", node: "n-web",   state: "crit", sev: "critical", src: "Web server", msg: "POST /login.php · payload ' UNION SELECT 1,2,version()--" },
        { t: 4,  path: "pC1", node: "n-suri",  state: "hot",  src: "Suricata",   msg: "ET WEB_SERVER SQL Injection Select From · sid 2006446" },
        { t: 7,  path: "pB1", node: "n-web",   state: "crit", sev: "critical", src: "Web server", msg: "POST /upload.php → uploads/cmd.php · 200 OK" },
        { t: 9,  path: "pC1", node: "n-suri",  state: "hot",  src: "Suricata",   msg: "ET WEB_SERVER PHP tags in HTTP POST · possible web shell upload" },
        { t: 11, path: "pD1", node: "n-wazuh", state: "hot",  src: "Wazuh",      msg: "File integrity: new file /var/www/html/uploads/cmd.php · 644 www-data" },
        { t: 14, path: "pC3", node: "n-cs",    state: "crit", sev: "critical", src: "CrowdStrike", msg: "Process tree apache2 → sh -c \"id;uname -a\" · detection: Web Shell" },
        { t: 16, path: "pD2", node: "n-wazuh", state: "hot",  sev: "high", detect: true, src: "Wazuh", msg: "Correlation rule 100315 fired · level 14 · T1190 → T1505.003 — detected" },
        { t: 18, path: "pE",  node: "n-hive",  state: "crit", sev: "critical", src: "TheHive", msg: "Case #0143 opened · severity Critical · three observables" },
        { t: 20, path: "pF",  node: "n-cortex",state: "hot",  src: "Cortex",     msg: "VirusTotal 31/94 on cmd.php · AbuseIPDB 97% on the source" },
        { t: 22, path: "pG",  node: "n-misp",  state: "hot",  src: "MISP",       msg: "Indicator set published · file hash, source address, URI pattern" },
        { t: 24, path: "pH",  node: "n-n8n",   state: "hot",  src: "n8n",        msg: "Contextualised alert dispatched to the SOC channel" },
        { t: 26, node: "n-web", state: "done", sev: "resolved", src: "Response", msg: "Host network-contained via Falcon · web shell quarantined · case closed" }
      ]
    }
  };

  var NODE_IDS = ["n-atk", "n-ngfw", "n-web", "n-ftp", "n-ad", "n-ws", "n-suri",
                  "n-cs", "n-wazuh", "n-hive", "n-cortex", "n-misp", "n-n8n", "n-noc"];

  var timers = [];
  var rafId = null;
  var packetRaf = null;
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
    if (packetRaf) { cancelAnimationFrame(packetRaf); packetRaf = null; }
    var packet = $("#packet");
    if (packet) packet.setAttribute("opacity", "0");
  }

  function resetNodes() {
    NODE_IDS.forEach(function (id) {
      var n = document.getElementById(id);
      if (n) n.setAttribute("class", "node");
    });
  }

  function eventRow(step) {
    var li = document.createElement("li");
    li.className = "ev";
    li.setAttribute("data-sev", step.sev || "info");
    li.innerHTML =
      '<span class="ev-t">' + mmss(step.t) + '</span>' +
      '<span class="ev-mark" aria-hidden="true"></span>' +
      '<span class="ev-body"><span class="ev-src"></span><span class="ev-msg"></span></span>';
    $(".ev-src", li).textContent = step.src;
    $(".ev-msg", li).textContent = step.msg;
    return li;
  }

  function setClock(sec, sc, detected) {
    var el = $("#clock");
    if (!el) return;
    el.innerHTML = "Elapsed <b>" + mmss(sec) + "</b>" +
      (detected ? ' <span style="color:var(--blue)">· detected ' + sc.mttd + "</span>" : "");
  }

  function movePacket(pathId, dur) {
    var p = document.getElementById(pathId);
    var c = $("#packet");
    if (!p || !c || reduced || typeof p.getTotalLength !== "function") return;
    if (packetRaf) cancelAnimationFrame(packetRaf);
    var len = p.getTotalLength();
    var t0 = performance.now();
    c.setAttribute("opacity", "1");
    (function frame(now) {
      var k = Math.min(1, (now - t0) / dur);
      var pt = p.getPointAtLength(len * k);
      c.setAttribute("cx", pt.x);
      c.setAttribute("cy", pt.y);
      if (k < 1) packetRaf = requestAnimationFrame(frame);
      else { packetRaf = null; c.setAttribute("opacity", "0"); }
    })(t0);
  }

  function setResults(sc) {
    $("#v-mttd").textContent = sc.mttd;
    $("#v-rule").textContent = sc.rule;
    $("#v-case").textContent = sc.kase;
    $("#v-out").textContent = sc.out;
  }

  /* The finished state, drawn with no animation. This is what the page
     shows at rest, before anyone presses Run. */
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
      log.appendChild(eventRow(step));
    });
    log.parentNode.scrollTop = 0;
    setResults(sc);
    setClock(sc.end, sc, true);
  }

  function run(key) {
    var sc = SCENARIOS[key];
    var log = $("#log");
    var feed = log ? log.parentNode : null;
    var btn = $("#replay");

    /* Reduced motion still replays step by step, so pressing Run visibly
       does something; only the moving packet is skipped (movePacket). */
    clearRun();
    resetNodes();
    if (log) log.innerHTML = '<li class="ev-idle">Replaying ' + sc.label + "…</li>";
    setResults(sc);
    if (btn) { btn.disabled = true; btn.textContent = "Running…"; }

    var t0 = performance.now();
    var detected = false;

    (function tick(now) {
      var sec = Math.min(sc.end, (now - t0) / MS_PER_SEC);
      setClock(sec, sc, detected);
      if (sec < sc.end) rafId = requestAnimationFrame(tick);
    })(t0);

    sc.steps.forEach(function (step, i) {
      timers.push(setTimeout(function () {
        if (i === 0 && log) log.innerHTML = "";
        if (step.detect) detected = true;
        if (step.node && step.state) {
          var n = document.getElementById(step.node);
          if (n) n.setAttribute("class", "node " + step.state);
        }
        if (step.path) movePacket(step.path, 520);
        if (log) {
          log.appendChild(eventRow(step));
          if (feed) feed.scrollTop = feed.scrollHeight;
        }
      }, step.t * MS_PER_SEC + 120));
    });

    timers.push(setTimeout(function () {
      setClock(sc.end, sc, true);
      if (btn) { btn.disabled = false; btn.textContent = "Run simulation"; }
    }, sc.end * MS_PER_SEC + 240));
  }

  function wireSimulation() {
    var picks = $$(".segmented button[data-scenario]");
    var btn = $("#replay");
    if (!btn) return;

    picks.forEach(function (tab) {
      tab.addEventListener("click", function () {
        current = tab.getAttribute("data-scenario");
        picks.forEach(function (t) { t.setAttribute("aria-pressed", String(t === tab)); });
        run(current);
      });
    });

    btn.addEventListener("click", function () { run(current); });

    renderStatic(current);
  }

  /* ---------------------------------------------------------------
     3a. ATT&CK matrix — one technique open at a time
     --------------------------------------------------------------- */
  function wireMatrix() {
    var detail = $("#tq-detail");
    var buttons = $$(".tq");
    if (!detail || !buttons.length) return;

    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        buttons.forEach(function (o) { o.setAttribute("aria-expanded", "false"); });
        b.setAttribute("aria-expanded", "true");
        $("b", detail).textContent = $(".tid", b).textContent + " · " + $(".tnm", b).textContent;
        $(".body", detail).textContent = b.getAttribute("data-d");
      });
    });
  }

  /* ---------------------------------------------------------------
     3b. Credential filter
     --------------------------------------------------------------- */
  function wireCerts() {
    var chips = $$(".filter");
    var cards = $$("#cert-grid .cert");
    var count = $("#cert-count");
    if (!chips.length || !cards.length) return;

    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        var f = chip.getAttribute("data-filter");
        chips.forEach(function (c) { c.setAttribute("aria-pressed", String(c === chip)); });
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
  trackSections();
  wireSimulation();
  wireMatrix();
  wireCerts();
})();
