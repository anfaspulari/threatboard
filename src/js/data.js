/* =========================================================
   ThreatBoard — Intelligence Data
   In production, replace TB_DATA with live API responses
   from MISP, OpenCTI, VirusTotal, Recorded Future, etc.
   ========================================================= */

const TB_DATA = {

  kpis: {
    activeThreats:  47,
    iocsTracked:    1284,
    criticalAlerts: 9,
    threatActors:   23
  },

  severityBreakdown: [
    { level: 'Critical', count: 9,  pct: 19 },
    { level: 'High',     count: 18, pct: 38 },
    { level: 'Medium',   count: 14, pct: 30 },
    { level: 'Low',      count: 6,  pct: 13 }
  ],

  /* 7-day activity: [critical, high, medium] per day */
  activitySeries: {
    labels:   ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    critical: [3, 5, 2, 7, 4, 6, 9],
    high:     [8, 11, 6, 14, 9, 12, 18],
    medium:   [12, 9, 15, 10, 13, 8, 14]
  },

  alerts: [
    { id: 'ALT-0091', title: 'Cobalt Strike beacon detected on CORP-WS-042',       severity: 'Critical', source: 'EDR',   time: '14 min ago', category: 'Malware'          },
    { id: 'ALT-0090', title: 'Credential stuffing against auth.internal.corp',      severity: 'High',     source: 'WAF',   time: '31 min ago', category: 'Brute Force'      },
    { id: 'ALT-0089', title: 'Suspicious outbound DNS to known C2 domain',          severity: 'Critical', source: 'DNS',   time: '1 hr ago',   category: 'C2'               },
    { id: 'ALT-0088', title: 'Log4Shell exploit attempt blocked',                   severity: 'High',     source: 'IPS',   time: '2 hr ago',   category: 'Exploit'          },
    { id: 'ALT-0087', title: 'Lateral movement via PsExec from HR subnet',          severity: 'Critical', source: 'SIEM',  time: '3 hr ago',   category: 'Lateral Movement' },
    { id: 'ALT-0086', title: 'Anomalous data exfiltration: 4.2 GB to external IP', severity: 'High',     source: 'DLP',   time: '4 hr ago',   category: 'Exfiltration'     },
    { id: 'ALT-0085', title: 'Phishing email campaign targeting finance team',      severity: 'Medium',   source: 'Email', time: '5 hr ago',   category: 'Phishing'         },
    { id: 'ALT-0084', title: 'Brute force on RDP exposed on port 3389',             severity: 'Medium',   source: 'FW',    time: '6 hr ago',   category: 'Brute Force'      }
  ],

  /*
   * IOC status lifecycle:  open → investigating → escalated → closed
   * Reopening a closed IOC returns it to 'open'.
   * All timestamps are ISO-8601 date strings (UTC).
   */
  iocs: [
    {
      id: 'IOC-001', value: '185.220.101.47',
      type: 'IP', severity: 'Critical', confidence: 95,
      firstSeen: '2026-03-28', lastSeen: '2026-04-02',
      campaign: 'SILVERTHREAD', source: 'Internal EDR',
      tags: ['Tor exit', 'C2'], status: 'investigating'
    },
    {
      id: 'IOC-002', value: '6c9d12a1b3f8e4702cda5f91e0b7638942c1d5e8a2f0b3c4d6e7f8a9b0c1d2e',
      type: 'Hash', severity: 'Critical', confidence: 99,
      firstSeen: '2026-03-30', lastSeen: '2026-04-02',
      campaign: 'SILVERTHREAD', source: 'Internal EDR',
      tags: ['Cobalt Strike', 'Beacon'], status: 'escalated'
    },
    {
      id: 'IOC-003', value: 'update-cdn.cloudflare-secure[.]net',
      type: 'Domain', severity: 'High', confidence: 87,
      firstSeen: '2026-03-25', lastSeen: '2026-04-01',
      campaign: 'GHOSTPULSE', source: 'Recorded Future',
      tags: ['Phishing', 'Lookalike'], status: 'open'
    },
    {
      id: 'IOC-004', value: '45.142.212.100',
      type: 'IP', severity: 'High', confidence: 82,
      firstSeen: '2026-03-22', lastSeen: '2026-03-31',
      campaign: 'IRONVEIL', source: 'Partner ISAC',
      tags: ['Ransomware', 'LockBit'], status: 'closed'
    },
    {
      id: 'IOC-005', value: 'https://cdn-media[.]ru/payload.ps1',
      type: 'URL', severity: 'Critical', confidence: 97,
      firstSeen: '2026-03-31', lastSeen: '2026-04-02',
      campaign: 'SILVERTHREAD', source: 'Internal IPS',
      tags: ['Dropper', 'PowerShell'], status: 'investigating'
    },
    {
      id: 'IOC-006', value: 'a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2',
      type: 'Hash', severity: 'High', confidence: 90,
      firstSeen: '2026-03-29', lastSeen: '2026-04-01',
      campaign: 'BLUESHIFT', source: 'Threat Intel Platform',
      tags: ['Emotet', 'Loader'], status: 'open'
    },
    {
      id: 'IOC-007', value: '194.165.16.22',
      type: 'IP', severity: 'Medium', confidence: 70,
      firstSeen: '2026-03-20', lastSeen: '2026-03-28',
      campaign: null, source: 'Shodan',
      tags: ['Scanner'], status: 'closed'
    },
    {
      id: 'IOC-008', value: 'secure-login.microsoft-365[.]xyz',
      type: 'Domain', severity: 'High', confidence: 85,
      firstSeen: '2026-03-27', lastSeen: '2026-04-01',
      campaign: 'GHOSTPULSE', source: 'Mandiant',
      tags: ['Phishing', 'O365'], status: 'open'
    },
    {
      id: 'IOC-009', value: '91.92.136.9',
      type: 'IP', severity: 'High', confidence: 78,
      firstSeen: '2026-03-18', lastSeen: '2026-03-30',
      campaign: 'BLUESHIFT', source: 'Threat Intel Platform',
      tags: ['C2', 'Qakbot'], status: 'open'
    },
    {
      id: 'IOC-010', value: 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
      type: 'Hash', severity: 'Medium', confidence: 65,
      firstSeen: '2026-03-15', lastSeen: '2026-03-22',
      campaign: null, source: 'VirusTotal',
      tags: ['Miner', 'XMRig'], status: 'closed'
    },
    {
      id: 'IOC-011', value: 'http://45.33.32.156/gate.php',
      type: 'URL', severity: 'Critical', confidence: 96,
      firstSeen: '2026-04-01', lastSeen: '2026-04-02',
      campaign: 'CHROMEDUST', source: 'Internal EDR',
      tags: ['C2', 'Dridex'], status: 'open'
    },
    {
      id: 'IOC-012', value: 'malware-analysis[.]io',
      type: 'Domain', severity: 'Low', confidence: 45,
      firstSeen: '2026-03-10', lastSeen: '2026-03-15',
      campaign: null, source: 'VirusTotal',
      tags: ['Suspicious'], status: 'closed'
    }
  ],

  /*
   * Threat actors enriched with MITRE ATT&CK technique IDs
   * and a recent activity summary string.
   */
  actors: [
    {
      name: 'APT29 (Cozy Bear)',
      origin: 'Russia — Nation-State',
      severity: 'Critical',
      description: 'Sophisticated espionage group attributed to the Russian SVR. Known for supply chain attacks, spear-phishing, and long-term persistence in government and energy networks.',
      tags: ['Espionage', 'Supply Chain', 'Spear-phishing', 'OPSEC'],
      techniques: ['T1566.001', 'T1195.002', 'T1078', 'T1021.001', 'T1071.001'],
      lastActivity: '2026-03-29 — Spear-phishing campaign targeting EU defence contractors via compromised vendor email accounts; credential harvesting via AiTM proxy observed.'
    },
    {
      name: 'Lazarus Group',
      origin: 'North Korea — Nation-State',
      severity: 'Critical',
      description: 'Prolific threat actor attributed to the DPRK RGB. Conducts financially motivated attacks on cryptocurrency exchanges alongside destructive campaigns and cyber espionage.',
      tags: ['Financial', 'Crypto', 'Destructive', 'Backdoor'],
      techniques: ['T1059.001', 'T1566.001', 'T1486', 'T1020', 'T1190'],
      lastActivity: '2026-04-01 — New in-memory RAT variant with encrypted HTTPS C2 deployed against cryptocurrency exchanges in Southeast Asia; EDR evasion via process hollowing confirmed.'
    },
    {
      name: 'LockBit 3.0',
      origin: 'Russia — Cybercrime (RaaS)',
      severity: 'High',
      description: 'Ransomware-as-a-Service operation targeting critical infrastructure and healthcare. Known for its affiliate programme, bug bounty for the ransomware binary, and aggressive data leak site.',
      tags: ['Ransomware', 'RaaS', 'Double Extortion', 'Affiliate'],
      techniques: ['T1486', 'T1490', 'T1083', 'T1070.004', 'T1489'],
      lastActivity: '2026-03-30 — Claimed responsibility for attack on Hartwell Logistics Group; 46 GB of stolen data published after ransom negotiations broke down at $4.2M.'
    },
    {
      name: 'FIN7',
      origin: 'Eastern Europe — Cybercrime',
      severity: 'High',
      description: 'Financially motivated group targeting POS systems in retail, hospitality, and restaurant sectors. Has pivoted to ransomware partnerships and continues to evolve its POWERTRASH toolset.',
      tags: ['Financial', 'POS', 'Spear-phishing', 'Carbanak'],
      techniques: ['T1566.001', 'T1056.001', 'T1041', 'T1021.002', 'T1204.002'],
      lastActivity: '2026-03-25 — POWERTRASH loader delivered via malicious OneNote attachment to hospitality sector HR teams; lateral movement to POS systems within 72 h of initial access.'
    },
    {
      name: 'Volt Typhoon',
      origin: 'China — Nation-State',
      severity: 'Critical',
      description: 'State-sponsored actor pre-positioning on US critical infrastructure. Relies entirely on living-off-the-land binaries and compromised SOHO routers to blend with legitimate traffic.',
      tags: ['Critical Infra', 'LotL', 'Pre-positioning', 'Stealth'],
      techniques: ['T1078', 'T1036', 'T1070.003', 'T1090.003', 'T1016'],
      lastActivity: '2026-03-28 — LotL activity detected in US energy-sector OT network; SOHO router compromise used as relay; no destructive payload deployed — pre-positioning assessed.'
    },
    {
      name: 'Scattered Spider',
      origin: 'English-speaking — Cybercrime',
      severity: 'High',
      description: 'Social engineering specialists known for SIM swapping, MFA fatigue, and help-desk impersonation. Has breached major cloud tenants and subsequently deployed ransomware.',
      tags: ['Social Engineering', 'SIM Swap', 'MFA Bypass', 'Cloud'],
      techniques: ['T1598.004', 'T1621', 'T1556.006', 'T1078.004', 'T1657'],
      lastActivity: '2026-04-02 — Vishing campaign impersonating IT helpdesk of a US insurer; MFA fatigue attacks resulted in cloud tenant compromise; data staged for exfiltration.'
    }
  ],

  feed: [
    {
      time: '10:42', severity: 'Critical',
      title: 'New Cobalt Strike campaign targeting financial sector (SILVERTHREAD)',
      body: 'Threat intel partners report a fresh wave of spear-phishing emails delivering macro-laced Office documents that drop a Cobalt Strike beacon. C2 servers hosted on bulletproof infrastructure in Eastern Europe. 3 IOCs now tracked under campaign SILVERTHREAD.',
      source: 'Internal / Partner ISAC'
    },
    {
      time: '09:15', severity: 'Critical',
      title: 'CVE-2026-1234 (CVSS 9.8) actively exploited in the wild',
      body: 'A zero-day in a popular VPN appliance is being actively exploited by APT actors to achieve pre-auth RCE. Vendor patch released at 08:00 UTC. Apply immediately to all internet-facing instances — PoC is publicly available.',
      source: 'Vendor Advisory / NVD'
    },
    {
      time: '08:30', severity: 'High',
      title: 'LockBit 3.0 claims attack on Hartwell Logistics Group',
      body: 'LockBit operators published 46 GB of allegedly stolen data on their dark-web leak site after ransom negotiations broke down. Affected data includes customer PII, invoices, and internal contracts. IRONVEIL campaign IOCs updated.',
      source: 'Dark Web Monitor'
    },
    {
      time: '07:55', severity: 'High',
      title: 'AiTM phishing kit mimicking Microsoft 365 login — campaign GHOSTPULSE',
      body: 'A new phishing kit (GHOSTPULSE) targets enterprise M365 users with a pixel-perfect sign-in clone. The kit proxies credentials and session cookies in real time, bypassing MFA entirely. Two lookalike domains now tracked as IOC-003 and IOC-008.',
      source: 'Mandiant / Recorded Future'
    },
    {
      time: 'Yesterday', severity: 'Medium',
      title: 'Elevated DNS tunnelling activity — possible C2 egress',
      body: 'Multiple SOC teams report elevated DNS tunnelling attempts using dnscat2 and Iodine. Likely used for C2 and data exfiltration through organisations with permissive outbound DNS. Review resolver logs for high-entropy subdomain queries.',
      source: 'Internal SOC'
    },
    {
      time: 'Yesterday', severity: 'High',
      title: 'Lazarus Group — new in-memory implant analysis published',
      body: 'Researchers published full technical analysis of a new Lazarus custom implant (BLINDINGCAN v3). Features encrypted HTTPS C2, process hollowing for EDR evasion, and fileless persistence via WMI event subscriptions.',
      source: 'CISA / KISA Advisory'
    },
    {
      time: '2 days ago', severity: 'Medium',
      title: 'Tor exit node scanning targeting OT/SCADA systems',
      body: 'Elevated scan activity targeting Modbus (502), DNP3 (20000), and BACnet (47808) from Tor exit nodes. Sectors: energy, water treatment, transportation. Cross-reference IOC-001 (185.220.101.47) — confirmed Tor exit and active C2.',
      source: 'CISA ICS-CERT'
    },
    {
      time: '2 days ago', severity: 'Medium',
      title: 'Emotet botnet resurgence — precursor to Qakbot / ransomware',
      body: 'Emotet has resumed after a 6-week hiatus, spreading via macro-enabled Excel spreadsheets with geofenced payload delivery. Historic patterns: Emotet → Qakbot → Cobalt Strike → ransomware within 5–14 days. BLUESHIFT campaign updated.',
      source: 'Threat Intel Platform'
    }
  ]
};
