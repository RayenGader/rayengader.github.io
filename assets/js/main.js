/* =============================================================
   rayengader.github.io — page behaviour

   No framework, no build step. Three things happen here:
     1. the navigation tracks which section you are reading
     2. the attack simulation replays a scenario over the topology
     3. the ATT&CK matrix and the credential filter respond to input

   The two scenarios below are the ones actually run in the project:
   Kali (192.168.10.129) against the DMZ, with the real Suricata
   signatures, Wazuh rule IDs, CrowdStrike detections and Discord
   notifications observed on the build. Times shown on each event are
   the attack chronology; the headline metric is the measured MTTD,
   under a minute from the first action to the analyst-visible alert.
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

     Each step carries the attack-clock label it should display, the
     link the traffic travels, the component that changes state, the
     event that component actually recorded, and — where relevant —
     the ATT&CK technique and the rule identifier. All values are the
     real ones from the two validation scenarios.
     --------------------------------------------------------------- */

  var STEP_MS = 640;   // time between steps while replaying
  var PACKET_MS = 520; // how long the packet takes to cross an edge

  var SCENARIOS = {
    ftp: {
      label: "FTP brute force",
      steps: [
        { at: "00:00", path: "pA",  node: "n-atk",   state: "crit", tech: "T1595", src: "Kali",
          msg: "nmap -sV 192.168.10.0/24 — vsftpd 3.0.5 open on 192.168.10.150:21" },
        { at: "02:00", path: "pB2", node: "n-ftp",   state: "crit", sev: "critical", tech: "T1110", src: "vsftpd",
          msg: "530 Login incorrect ×100 — Hydra from 192.168.10.129 against account ftpuser" },
        { at: "02:04", path: "pC2", node: "n-suri",  state: "hot", src: "Suricata dmz0",
          msg: "sid 1000001 · LOCAL SOC – FTP Brute-Force · Priority 1 · Attempted Admin Privilege Gain" },
        { at: "02:06", path: "pD1", node: "n-wazuh", state: "hot", sev: "high", tech: "T1110", src: "Wazuh",
          msg: "rule 11452 · level 10 · multiple FTP connection attempts from a single source IP" },
        { at: "08:00", node: "n-ftp", state: "crit", sev: "critical", tech: "T1078", src: "vsftpd",
          msg: "230 Login successful · ftpuser · password recovered on attempt 101" },
        { at: "08:05", node: "n-wazuh", state: "hot", sev: "high", detect: true, tech: "T1078", src: "Wazuh",
          msg: "rule 40112 · level 12 · authentication failures followed by a success — brute force succeeded" },
        { at: "08:08", path: "pE",  node: "n-hive",  state: "crit", sev: "critical", src: "TheHive",
          msg: "case opened · vsftpd 11403 + Suricata 86601 + Palo Alto 100104 correlated in one incident" },
        { at: "08:11", path: "pF",  node: "n-cortex",state: "hot", src: "Cortex",
          msg: "AbuseIPDB 192.168.10.129 → 0% · Usage Type: Reserved (private lab range, as expected)" },
        { at: "08:14", path: "pG",  node: "n-misp",  state: "hot", src: "MISP",
          msg: "observables recorded · source address and file SHA-256 kept for correlation" },
        { at: "09:00", node: "n-ftp", state: "crit", sev: "critical", tech: "T1105", src: "Wazuh FIM",
          msg: "rule 554 · /home/ftpuser/eicar_1788471354.com created · md5 44d88612…" },
        { at: "09:02", path: "pC3", node: "n-cs",    state: "crit", sev: "critical", src: "CrowdStrike",
          msg: "Malicious file on ftpserver by ftpuser · Critical · file quarantined in 0.5 s · out-of-band console" },
        { at: "09:05", path: "pH",  node: "n-n8n",   state: "hot", src: "n8n → Discord",
          msg: "HIGH (L10) rule 11452 + CRITICAL (L12) rule 40112 delivered to the SOC channel in under 15 s" },
        { at: "09:20", node: "n-ftp", state: "done", sev: "resolved", src: "Response L2",
          msg: "host contained via CrowdStrike · 192.168.10.129 blocked at Palo Alto · ftpuser reset · case closed" }
      ],
      results: {
        mttd: "< 60 s",
        rule: "Wazuh 40112 · level 12",
        kase: "TheHive · vsftpd + Suricata + Palo Alto",
        out:  "One correlated incident, file quarantined"
      }
    },

    web: {
      label: "SQL injection to web shell",
      steps: [
        { at: "00:00", path: "pA",  node: "n-atk",   state: "crit", tech: "T1190", src: "Kali",
          msg: "GET /dvwa/vulnerabilities/sqli/?id=' UNION SELECT user,password FROM users# → 192.168.10.151" },
        { at: "00:02", path: "pB1", node: "n-web",   state: "crit", sev: "critical", tech: "T1190", src: "Web · DVWA",
          msg: "HTTP 200 · the users table and its password hashes are returned to the attacker" },
        { at: "00:04", path: "pC1", node: "n-suri",  state: "hot", src: "Suricata dmz0",
          msg: "sid 2000040 · access to the vulnerable DVWA app + sid 2221043 · double-encoded URI" },
        { at: "00:06", path: "pD1", node: "n-wazuh", state: "hot", sev: "high", detect: true, tech: "T1190", src: "Wazuh",
          msg: "rule 31106 · level 6 · a web attack returned code 200 (success) on 192.168.10.151" },
        { at: "00:09", path: "pE",  node: "n-hive",  state: "crit", sev: "critical", src: "TheHive",
          msg: "alert · 7 observables · domain 192.168.10.151, the injection URL, source 192.168.10.129" },
        { at: "00:12", path: "pF",  node: "n-cortex",state: "hot", src: "Cortex",
          msg: "VirusTotal 0/91 on the URL · AbuseIPDB on 192.168.10.129 — enrichment returned in seconds" },
        { at: "00:15", path: "pG",  node: "n-misp",  state: "hot", src: "MISP",
          msg: "injection URL and target host recorded as observables" },
        { at: "00:20", node: "n-web", state: "crit", sev: "critical", tech: "T1505.003", src: "CrowdStrike",
          msg: "a shell was spawned by www-data straight after the suspicious SQL query — web shell" },
        { at: "00:22", path: "pC3", node: "n-cs",    state: "crit", sev: "critical", src: "CrowdStrike",
          msg: "Malicious shell on httpserver by www-data · Critical · machine quarantined in 0.5 s · out-of-band console" },
        { at: "00:25", path: "pH",  node: "n-n8n",   state: "hot", src: "n8n → Discord",
          msg: "MEDIUM (L6) rule 31106 · T1190 delivered to the SOC channel in under 15 s" },
        { at: "00:40", node: "n-web", state: "done", sev: "resolved", src: "Response",
          msg: "machine auto-contained via CrowdStrike · web shell removed · case closed" }
      ],
      results: {
        mttd: "< 60 s",
        rule: "Wazuh 31106 · L6 + Suricata 2000040",
        kase: "TheHive · 7 observables · VT + AbuseIPDB",
        out:  "Web shell caught host-side, machine auto-contained"
      }
    }
  };

  var NODE_IDS = ["n-atk", "n-ngfw", "n-web", "n-ftp", "n-ad", "n-ws", "n-suri",
                  "n-cs", "n-wazuh", "n-hive", "n-cortex", "n-misp", "n-n8n", "n-noc"];

  var timers = [];
  var packetRaf = null;
  var current = "ftp";

  function clearRun() {
    timers.forEach(clearTimeout);
    timers = [];
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
      '<span class="ev-t"></span>' +
      '<span class="ev-mark" aria-hidden="true"></span>' +
      '<span class="ev-body"><span class="ev-src"></span><span class="ev-msg"></span></span>';
    $(".ev-t", li).textContent = step.at;
    $(".ev-src", li).textContent = step.src;
    $(".ev-msg", li).textContent = step.msg;
    if (step.tech) {
      var tag = document.createElement("span");
      tag.className = "ev-tech";
      tag.textContent = step.tech;
      $(".ev-body", li).appendChild(tag);
    }
    return li;
  }

  function setClock(label, detected) {
    var el = $("#clock");
    if (!el) return;
    el.innerHTML = "Attack timeline <b>" + label + "</b>" +
      (detected ? ' <span style="color:var(--blue)">· MTTD &lt; 60 s</span>' : "");
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
    $("#v-mttd").textContent = sc.results.mttd;
    $("#v-rule").textContent = sc.results.rule;
    $("#v-case").textContent = sc.results.kase;
    $("#v-out").textContent  = sc.results.out;
  }

  function applyState(step) {
    if (step.node && step.state) {
      var n = document.getElementById(step.node);
      if (n) n.setAttribute("class", "node " + step.state);
    }
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
    var last = sc.steps[sc.steps.length - 1];
    sc.steps.forEach(function (step) {
      applyState(step);
      log.appendChild(eventRow(step));
    });
    if (log.parentNode) log.parentNode.scrollTop = 0;
    setResults(sc);
    setClock(last.at, true);
  }

  function run(key) {
    var sc = SCENARIOS[key];
    var log = $("#log");
    var feed = log ? log.parentNode : null;
    var btn = $("#replay");

    clearRun();
    resetNodes();
    if (log) log.innerHTML = '<li class="ev-idle">Replaying ' + sc.label + "…</li>";
    setResults(sc);
    setClock(sc.steps[0].at, false);
    if (btn) { btn.disabled = true; btn.textContent = "Running…"; }

    var detected = false;

    sc.steps.forEach(function (step, i) {
      timers.push(setTimeout(function () {
        if (i === 0 && log) log.innerHTML = "";
        if (step.detect) detected = true;
        applyState(step);
        if (step.path) movePacket(step.path, PACKET_MS);
        setClock(step.at, detected);
        if (log) {
          log.appendChild(eventRow(step));
          if (feed) feed.scrollTop = feed.scrollHeight;
        }
      }, i * STEP_MS + 120));
    });

    timers.push(setTimeout(function () {
      setClock(sc.steps[sc.steps.length - 1].at, true);
      if (btn) { btn.disabled = false; btn.textContent = "Run simulation"; }
    }, sc.steps.length * STEP_MS + 240));
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
