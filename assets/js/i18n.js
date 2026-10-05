/* =============================================================
   rayengader.github.io - French translation

   English lives in index.html and is the source of truth. This file
   holds the French for the same content, and main.js swaps between
   the two when the EN / FR control in the navigation is used.

     dom    CSS selector -> French HTML. An array maps onto the
            elements the selector matches, in page order; null keeps
            the English for that element. If the count ever differs
            from the page, that selector is skipped and stays English.
     attrs  [selector, attribute, French value or array]
     ui     strings written by main.js
     sim    the attack simulation, per scenario; null keeps the English

   Certification names, ATT&CK technique names and product names are
   left in English on purpose - they are the official names.
   ============================================================= */
window.I18N_FR = {
  title: "Rayen Gader - Ingénieur cybersécurité",

  dom: {
    /* navigation */
    ".navlinks a": ["Expertise", "Réalisations", "Expérience", "Certifications", "Contact"],
    "#nav-cv": "CV",

    /* hero */
    ".availability": "<span class='led' aria-hidden='true'></span>Ouvert aux opportunités - relocalisation ou télétravail",
    ".hero h1": "Je construis la détection, puis je réponds de ce qu'elle remonte.",
    ".hero-sub": "Ingénieur cybersécurité et analyste SOC N2. Deux ans à déployer et affiner <strong>Darktrace</strong>, <strong>LogRhythm</strong> et <strong>CrowdStrike Falcon</strong> au sein d'un SOC managé - et un projet où j'ai construit moi-même toute la chaîne de détection, chronomètre en main.",
    ".hero .hero-actions a": ["Voir les réalisations", "Me contacter"],

    /* metrics */
    ".metric .v": ["2+ ans", null, null, "Top 1 %"],
    ".metric .l": [
      "en SOC managé, comme analyste N2 sur les alertes escaladées",
      "certifications - INE, EC-Council, CrowdStrike, Red Hat",
      "de MTTD mesuré sur le SOC que j'ai construit et instrumenté de bout en bout",
      "mondial sur TryHackMe, entre CTF et labs pratiques"
    ],

    /* expertise */
    "#expertise h2": "Les deux moitiés du métier, pas une seule.",
    "#expertise .section-lead": "Dans un centre d'opérations de sécurité, la plupart des profils administrent les outils ou traitent la file d'alertes. Je fais les deux - je mets en service et j'affine les plateformes de détection sur le parc client, et je suis l'analyste qui investigue ce que ces mêmes règles escaladent. <strong>Construire la détection et en répondre ferme une boucle que la plupart des équipes laissent ouverte.</strong>",
    ".cap h3": ["Ingénierie de détection", "Réponse à incident et forensique", "Threat hunting et renseignement"],
    ".cap p": [
      "Mise en service, réglage et optimisation des plateformes de détection des clients : conception de cas d'usage face au risque réel, écriture de règles de corrélation, intégration des sources de logs, et la moitié ingrate - faire baisser les faux positifs jusqu'à ce que la file d'alertes veuille à nouveau dire quelque chose.",
      "Qualification et investigation approfondie des alertes escaladées selon le NIST SP 800-61 : reconstitution du scénario d'attaque, cause racine, confinement, et une remédiation priorisée rédigée pour que les décideurs du client puissent agir.",
      "Chasse proactive entre les incidents, profilage des adversaires selon MITRE ATT&amp;CK, et transformation du renseignement en quelque chose d'opérationnel - des règles de détection et des contre-mesures D3FEND plutôt qu'un rapport que personne n'exploite."
    ],
    ".cap-meta": [
      "LogRhythm AI Engine · règles Wazuh · Suricata · politiques Falcon",
      null,
      "MITRE ATT&amp;CK · D3FEND · OpenCTI · analyse d'IoC"
    ],

    /* platforms */
    "#platforms .eyebrow": "Plateformes",
    "#platforms h2": "L'environnement dans lequel je travaille.",
    "#platforms .section-lead": "Les trois premières tournent en production chez les clients, et je détiens la certification éditeur sur chacune. Les autres, je les ai déployées et configurées moi-même en construisant le SOC ci-dessous.",
    ".stack-item .sn": [null, null, null, null, null, null, "TheHive et Cortex", null, null,
                        "Zabbix, Prometheus et Grafana", "Python et Bash", "Linux et Windows Server"],
    ".stack-item .sc": ["NDR - certifié", null, null, null, null, null, null, "Threat intelligence",
                        "Identité", "Observabilité", "Automatisation", null],
    ".stack-note": "Référentiels : NIST SP 800-61 · NIST CSF · ISO/IEC 27001 · CIS Controls · OWASP · PCI-DSS",

    /* selected work */
    "#work .section-head .eyebrow": "Réalisations",
    "#work .section-head h2": "Trois réalisations à montrer.",
    ".work-head h3": ["Un SOC conçu et construit de bout en bout", "Profilage d'APT34 (OilRig)", "Autres travaux"],
    ".work-kicker": [
      "Projet de fin d'études d'ingénieur · Global IT Vision · 2026",
      null,
      "Missions offensives, automatisation et cryptographie appliquée"
    ],
    ".work-body p": [
      "Dix composants, <strong>dont huit open source</strong>, segmentés derrière un NGFW Palo Alto et alignés sur le cycle de réponse à incident du <strong>NIST SP 800-61</strong>. Détection, enrichissement, gestion de cas et notification reliés en une seule chaîne - puis validés par deux scénarios MITRE ATT&amp;CK de bout en bout plutôt que par une capture de tableau de bord.",
      "La mesure qui comptait : <strong>le délai jusqu'à une alerte contextualisée, sans intervention humaine</strong>. Lancez l'un des deux scénarios ci-dessous et observez.",
      "Un profil complet du groupe d'espionnage iranien : modes opératoires cartographiés sur toute la kill chain, trois familles de malwares décortiquées, et l'infrastructure de commande et de contrôle caractérisée.",
      "Le renseignement ne vaut que par la détection qu'il produit ; le livrable n'était donc pas le rapport, mais un ensemble de <strong>règles de détection exploitables</strong> et les contre-mesures <strong>MITRE D3FEND</strong> correspondantes. Sélectionnez une technique pour voir ce qu'elle donnait entre les mains de ce groupe."
    ],

    /* simulation panel */
    ".sim-title": "Simulation d'attaque",
    ".segmented button": ["T1110 → T1078 · Brute force FTP", null],
    ".res .rk": [null, "Règle de corrélation", "Cas ouvert", "Résultat"],
    ".sim-legend .lg": [
      "<span class='dot d-crit'></span>Attaqué / compromis",
      "<span class='dot d-hot'></span>Détection et télémétrie",
      "<span class='dot d-done'></span>Confiné / résolu",
      "CrowdStrike fonctionne hors bande, dans sa propre console cloud"
    ],
    ".sim-note": "Les deux scénarios ont été rejoués sur l'environnement réel - Kali 192.168.10.129 contre la DMZ. Les adresses IP et les identifiants de règles sont ceux du projet.",
    "#topo-title": "Architecture du SOC à dix composants",
    "#topo-desc": "Kali (192.168.10.129) attaque deux serveurs de la DMZ à travers un pare-feu nouvelle génération Palo Alto. Suricata écoute la DMZ et les agents des hôtes alimentent un SIEM Wazuh, qui corrèle les événements, ouvre des cas dans TheHive, les enrichit via Cortex auprès de VirusTotal et AbuseIPDB, publie les indicateurs dans MISP et notifie Discord via n8n. CrowdStrike Falcon fonctionne hors bande dans sa propre console cloud. Zabbix, Prometheus et Grafana surveillent la santé de la plateforme.",
    ".zone-label": [null, "SOC · IDENTITÉ · 192.168.80.0/24", null],
    "#n-atk .n-label": "ATTAQUANT",
    "#n-ftp .n-label": "SERVEUR FTP",
    "#n-ad .n-label": "CONTRÔLEUR DE DOMAINE",
    "#n-ws .n-label": "POSTES",
    "#n-ws .n-sub": "win10 · 8 agents wazuh",
    "#n-cs .n-sub": "XDR · console cloud",
    "#n-wazuh .n-sub": [null, "décode · corrèle · ATT&amp;CK"],
    "#n-hive .n-sub": "cas · tâches · observables",
    "#n-misp .n-sub": "partage d'IOC · flux",
    ".comp .ck": ["Détecter", "Enrichir et répondre", "Superviser", "Segmenter et notifier"],

    /* APT34 */
    ".tactic > h4": ["Accès initial", "Exécution", "Persistance", "Accès aux identifiants",
                     "Découverte", "Mouvement latéral", "Commande et contrôle", "Exfiltration"],
    ".mal p": [
      "Backdoor qui reçoit ses ordres et renvoie ses résultats via des requêtes DNS vers des domaines contrôlés par l'attaquant.",
      "Backdoor PowerShell utilisant un canal de tunnel DNS, avec bascule entre types de requêtes pour survivre au filtrage.",
      "Backdoor de génération suivante qui dissimulait son trafic dans des e-mails et dans des fichiers image - la stéganographie comme canal caché."
    ],
    ".tq-detail .d3": "Contre-mesures D3FEND associées : <em>analyse du trafic DNS</em> · <em>filtrage du trafic réseau</em> · <em>liste blanche d'exécutables</em> · <em>durcissement des identifiants</em>.",

    /* further work */
    ".minor-row .mt": [
      "Simulation de phishing, de bout en bout",
      "Plateforme de formation en cybersécurité",
      "Blocage piloté par la threat intelligence",
      "Cryptographie d'après les spécifications"
    ],
    ".minor-row .md": [
      "Reconnaissance OSINT, scénarios et modèles sur mesure, campagnes déclenchées et suivies via une API - livrée entièrement fonctionnelle et intégralement documentée, avec une procédure reproductible et un débrief de sensibilisation. <span class='dim'>Pwn &amp; Patch Tunisia, 2024.</span>",
      "Un LMS basé sur Odoo pour les cursus internes : catalogue de modules, parcours apprenants, suivi de progression, et des labs pratiques rattachés à chaque module. Mené du recueil des besoins jusqu'à la mise en production. <span class='dim'>DEFENSYLAB, 2023.</span>",
      "Blocage DNS et IP automatisé, alimenté par des flux de threat intelligence, en Python sur PostgreSQL.",
      "AES, RSA et ECC implémentés à partir des standards plutôt qu'appelés depuis une bibliothèque, ainsi que des applications web sécurisées en MERN et PHP/MySQL."
    ],

    /* experience */
    "#experience .eyebrow": "Expérience",
    "#experience h2": "Là où le travail s'est fait.",
    ".role .period": [
      "Novembre 2023 - aujourd'hui<br><span class='now'><span class='led' aria-hidden='true'></span>Poste actuel</span>",
      "Mai - juin 2024<br><span>Stage</span>",
      "Février - juillet 2023<br><span>Stage de fin d'études, licence</span>"
    ],
    ".role h3": ["Ingénieur cybersécurité", "Stagiaire en cybersécurité", "Stagiaire de fin d'études"],
    ".role .org": [
      "Global IT Vision <span class='loc'>- Tunis, Tunisie</span>",
      "Pwn &amp; Patch Tunisia <span class='loc'>- Tunis, Tunisie</span>",
      "DEFENSYLAB <span class='loc'>- Tunis, Tunisie</span>"
    ],
    ".role li": [
      "Mise en service, réglage et optimisation de <strong>l'outillage de détection sur le parc client</strong> - conception de cas d'usage, écriture de règles de corrélation, réduction des faux positifs.",
      "Qualification et investigation des alertes escaladées en <strong>N2</strong> : reconstitution du scénario d'attaque, cause racine, confinement, remédiation priorisée, et un reporting rédigé pour les décideurs.",
      "<strong>Threat hunting</strong> proactif, conseil sur la posture de sécurité et montée en compétences des équipes clientes.",
      "<strong>Simulation de phishing</strong> menée de la sélection des cibles au rapport final : reconnaissance OSINT, scénarios et modèles sur mesure, campagnes déclenchées et suivies via une API.",
      "Livrée entièrement fonctionnelle et <strong>intégralement documentée</strong> - une procédure reproductible et le débrief de sensibilisation qui donne son intérêt à l'exercice.",
      "Construction d'une <strong>plateforme de formation en cybersécurité</strong> - un LMS basé sur Odoo pour les cursus internes : catalogue de modules, parcours apprenants, suivi de progression.",
      "<strong>Labs pratiques</strong> rattachés à chaque module, du recueil des besoins jusqu'à la mise en production."
    ],

    /* credentials */
    "#credentials .eyebrow": "Certifications",
    "#credentials h2": "<span id='cert-count'>18</span> certifications, de 2023 à 2026.",
    "#credentials .section-lead": "Orientées blue team, et vers les plateformes que j'exploite réellement. Filtrez selon le profil que vous recrutez.",
    ".filter": ["Toutes (18)", "DFIR et réponse à incident", "Défense et plateformes", "Offensif", "Systèmes"],

    /* education */
    "#education .eyebrow": "Formation",
    "#education h2": "Formations et diplômes.",
    ".deg .d": [
      "Diplôme d'ingénieur - Sécurité des réseaux et des systèmes d'information",
      "Parcours de certification Analyste SOC",
      "Licence - Télécommunications et sécurité des réseaux"
    ],

    /* contact */
    ".contact h2": "Vous recrutez pour un SOC ?",
    ".contact .section-lead": "Je suis ouvert aux postes d'ingénieur SOC, ingénieur cybersécurité, réponse à incident, threat hunting, ingénierie de détection et analyste SOC. Écrivez-moi ici, ou contactez-moi directement.",
    ".channels .ch-k": ["E-mail", null, null, "CV"],
    "label[for='cf-name']": "Nom",
    "label[for='cf-email']": "E-mail",
    "label[for='cf-company']": "Entreprise <span class='opt'>facultatif</span>",
    ".topics legend": "Objet",
    ".chips label": ["Opportunité d'emploi", "Projet ou mission", "Autre sujet"],
    ".cform-note": "Acheminé par FormSubmit. Vos coordonnées servent uniquement à vous répondre.",
    "#cf-done-title": "Message envoyé",
    "#cf-again": "Envoyer un autre message",
    ".detail dt": ["Localisation", "Mobilité", "Langues"],
    ".detail dd": [
      "Ariana, Tunisie <span class='sub'>· GMT+1</span>",
      "Europe, Canada, EMEA <span class='sub'>ou 100 % télétravail</span>",
      "Arabe <span class='sub'>natif</span> · Français <span class='sub'>courant</span> · Anglais <span class='sub'>courant</span>"
    ],
    "footer span:first-child": "Rayen Gader - Ingénieur cybersécurité"
  },

  attrs: [
    ["meta[name='description']", "content", "Ingénieur cybersécurité et analyste SOC N2. Je déploie et j'affine Darktrace, LogRhythm et CrowdStrike au sein d'un SOC managé, et j'ai construit une chaîne de détection et de réponse à dix composants, mesurée à moins d'une minute jusqu'à l'alerte."],
    [".lang", "aria-label", "Langue"],
    [".segmented", "aria-label", "Scénario"],
    ["#log", "aria-label", "Chronologie de détection"],
    [".filters", "aria-label", "Filtrer les certifications par domaine"],
    ["#cf-name", "placeholder", "Votre nom complet"],
    ["#cf-email", "placeholder", "vous@entreprise.com"],
    ["#cf-company", "placeholder", "Entreprise ou organisation"],
    ["#cf-message", "placeholder", "Le poste, l'équipe, le calendrier - tout ce qui m'aide à vous répondre utilement."],
    [".tq", "data-d", [
      "Documents Office piégés envoyés à des collaborateurs ciblés - le point d'entrée le plus constant du groupe, et la raison pour laquelle la détonation des pièces jointes et la politique de macros pèsent autant face à lui.",
      "Liens de collecte d'identifiants, souvent hébergés sur une infrastructure qui imite un service déjà utilisé par la cible.",
      "Identifiants volés réutilisés pour se connecter comme un utilisateur légitime - aucun malware sur le réseau, d'où l'importance de la télémétrie d'identité autant que de celle des postes.",
      "L'exécution dépend du destinataire, qui doit ouvrir le document et activer le contenu - la charnière sur laquelle repose toute l'intrusion.",
      "PowerShell est la langue de travail du groupe : BONDUPDATER est écrit en PowerShell, ce qui fait de la journalisation des blocs de script l'une des sources de logs les plus rentables contre lui.",
      "Interpréteur de commandes natif utilisé pour la découverte et pour exécuter les ordres transmis par la backdoor.",
      "Des tâches planifiées relancent la backdoor à intervalle régulier - durables, d'apparence banale, et visibles dans l'événement Windows 4698 si vous le collectez.",
      "Clés Run pour persister après un redémarrage : peu coûteuses pour l'attaquant, et peu coûteuses à détecter une fois l'audit du registre activé.",
      "Des web shells déposés sur des serveurs exposés à Internet maintiennent l'accès même après le nettoyage côté postes - la technique sur laquelle se termine le scénario d'injection SQL ci-dessus.",
      "Extraction d'identifiants depuis LSASS pour récupérer ce qui permet de passer d'un hôte à plusieurs.",
      "Enregistrement de frappe pour capturer ce que l'extraction n'atteint pas - les identifiants saisis dans les applications plutôt que mis en cache.",
      "Énumération des comptes pour repérer les identités à compromettre ensuite.",
      "Cartographie des hôtes joignables avant de se déplacer - une rafale de ce type depuis un seul poste est un excellent signal de hunting.",
      "Énumération des connexions actives pour comprendre le segment et ce que l'hôte peut atteindre.",
      "RDP avec des identifiants volés - protocole légitime, compte légitime ; cela apparaît donc comme une anomalie d'identité bien avant d'apparaître comme un malware.",
      "SMB et partages administratifs utilisés pour déplacer l'outillage d'un hôte à l'autre.",
      "La signature de ce groupe. POWRUNER et BONDUPDATER transportent tous deux les ordres et leurs résultats dans des requêtes DNS, parce que le DNS sort de presque tous les réseaux sans filtrage. La détection tient à la forme du trafic plutôt qu'à la charge utile : volume de requêtes par domaine, entropie des sous-domaines, et types d'enregistrement qu'un client normal ne demande jamais.",
      "Canaux HTTP et HTTPS utilisés lorsque le DNS est contraint.",
      "Outillage complémentaire téléchargé une fois la tête de pont établie.",
      "Les données collectées repartent par le canal d'arrivée des ordres ; c'est ce qui fait du canal C2 la cible de détection la plus précieuse."
    ]]
  ],

  ui: {
    timeline: "Chronologie de l'attaque",
    run: "Lancer la simulation",
    running: "En cours…",
    replaying: "Rejeu du scénario - ",
    send: "Envoyer le message",
    sending: "Envoi…",
    errName: "Veuillez indiquer votre nom.",
    errEmail: "Veuillez saisir une adresse e-mail valide.",
    errMessage: "Écrivez quelques mots - au moins 20 caractères.",
    failed: "Le message n'a pas pu être envoyé. Votre texte est conservé - réessayez, ou envoyez-le par e-mail.",
    mailto: "Ouvrir dans la messagerie",
    doneText: "Merci, {name}. Je vous répondrai à {email}."
  },

  sim: {
    ftp: {
      label: "brute force FTP",
      msgs: [
        "nmap -sV 192.168.10.0/24 - vsftpd 3.0.5 ouvert sur 192.168.10.150:21",
        "530 Login incorrect ×100 - Hydra depuis 192.168.10.129 contre le compte ftpuser",
        null,
        "règle 11452 · niveau 10 · tentatives de connexion FTP multiples depuis une même adresse IP source",
        "230 Login successful · ftpuser · mot de passe trouvé à la tentative 101",
        "règle 40112 · niveau 12 · échecs d'authentification suivis d'un succès - le brute force a abouti",
        "cas ouvert · vsftpd 11403 + Suricata 86601 + Palo Alto 100104 corrélés en un seul incident",
        "AbuseIPDB 192.168.10.129 → 0% · Usage Type: Reserved (plage privée du lab, comme attendu)",
        "observables enregistrés · adresse source et SHA-256 du fichier conservés pour corrélation",
        "règle 554 · /home/ftpuser/eicar_1788471354.com créé · md5 44d88612…",
        "Fichier malveillant sur ftpserver par ftpuser · Critique · fichier mis en quarantaine en 0,5 s · console hors bande",
        "HIGH (L10) règle 11452 + CRITICAL (L12) règle 40112 remontées au canal SOC en moins de 15 s",
        "hôte confiné via CrowdStrike · 192.168.10.129 bloquée sur le Palo Alto · ftpuser réinitialisé · cas clôturé"
      ],
      srcs: { 12: "Réponse N2" },
      results: {
        rule: "Wazuh 40112 · niveau 12",
        out: "Un seul incident corrélé, fichier en quarantaine"
      }
    },
    web: {
      label: "injection SQL vers web shell",
      msgs: [
        null,
        "HTTP 200 · la table users et ses hashs de mots de passe sont renvoyés à l'attaquant",
        "sid 2000040 · accès à l'application vulnérable DVWA + sid 2221043 · URI doublement encodée",
        "règle 31106 · niveau 6 · une attaque web a renvoyé le code 200 (succès) sur 192.168.10.151",
        "alerte · 7 observables · domaine 192.168.10.151, l'URL d'injection, source 192.168.10.129",
        "VirusTotal 0/91 sur l'URL · AbuseIPDB sur 192.168.10.129 - enrichissement renvoyé en quelques secondes",
        "URL d'injection et hôte cible enregistrés comme observables",
        "un shell a été lancé par www-data juste après la requête SQL suspecte - web shell",
        "Shell malveillant sur httpserver par www-data · Critique · machine mise en quarantaine en 0,5 s · console hors bande",
        "MEDIUM (L6) règle 31106 · T1190 remontée au canal SOC en moins de 15 s",
        "machine confinée automatiquement via CrowdStrike · web shell supprimé · cas clôturé"
      ],
      srcs: { 10: "Réponse" },
      results: {
        out: "Web shell détecté côté hôte, machine confinée automatiquement"
      }
    }
  }
};
