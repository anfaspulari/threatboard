/* =========================================================
   ThreatBoard — Mock Intelligence Data
   In a production build this would be fetched from a
   threat-intel API (e.g. MISP, OpenCTI, VirusTotal, etc.)
   ========================================================= */

const TB_DATA = {

  kpis: {
    activeThreats: 47,
    iocsTracked:   1284,
    criticalAlerts: 9,
    threatActors:  23
  },

  severityBreakdown: [
    { level: 'Critical', count: 9,   pct: 19 },
    { level: 'High',     count: 18,  pct: 38 },
    { level: 'Medium',   count: 14,  pct: 30 },
    { level: 'Low',      count: 6,   pct: 13 }
  ],

  /* 7-day activity: [critical, high, medium] per day */
  activitySeries: {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    critical: [3, 5, 2, 7, 4, 6, 9],
    high:     [8, 11, 6, 14, 9, 12, 18],
    medium:   [12, 9, 15, 10, 13, 8, 14]
  },

  alerts: [
    { id: 'ALT-0091', title: 'Cobalt Strike beacon detected on CORP-WS-042', severity: 'Critical', source: 'EDR',    time: '14 min ago', category: 'Malware' },
    { id: 'ALT-0090', title: 'Credential stuffing against auth.internal.corp', severity: 'High',     source: 'WAF',    time: '31 min ago', category: 'Brute Force' },
    { id: 'ALT-0089', title: 'Suspicious outbound DNS to known C2 domain',     severity: 'Critical', source: 'DNS',    time: '1 hr ago',   category: 'C2' },
    { id: 'ALT-0088', title: 'Log4Shell exploit attempt blocked',              severity: 'High',     source: 'IPS',    time: '2 hr ago',   category: 'Exploit' },
    { id: 'ALT-0087', title: 'Lateral movement via PsExec from HR subnet',     severity: 'Critical', source: 'SIEM',   time: '3 hr ago',   category: 'Lateral Movement' },
    { id: 'ALT-0086', title: 'Anomalous data exfil: 4.2 GB to external IP',   severity: 'High',     source: 'DLP',    time: '4 hr ago',   category: 'Exfiltration' },
    { id: 'ALT-0085', title: 'Phishing email campaign targeting finance team', severity: 'Medium',   source: 'Email',  time: '5 hr ago',   category: 'Phishing' },
    { id: 'ALT-0084', title: 'Brute force on RDP exposed on port 3389',        severity: 'Medium',   source: 'FW',     time: '6 hr ago',   category: 'Brute Force' }
  ],

  iocs: [
    { value: '185.220.101.47',                           type: 'IP',     severity: 'Critical', confidence: 95, firstSeen: '2026-03-28', tags: ['Tor exit', 'C2'] },
    { value: '6c9d12a1b3f8e4702cda5f91e0b7638942c1d5e8a2f0b3c4d6e7f8a9b0c1d2e', type: 'Hash',   severity: 'Critical', confidence: 99, firstSeen: '2026-03-30', tags: ['Cobalt Strike', 'Beacon'] },
    { value: 'update-cdn.cloudflare-secure[.]net',       type: 'Domain', severity: 'High',     confidence: 87, firstSeen: '2026-03-25', tags: ['Phishing', 'Lookalike'] },
    { value: '45.142.212.100',                           type: 'IP',     severity: 'High',     confidence: 82, firstSeen: '2026-03-22', tags: ['Ransomware', 'LockBit'] },
    { value: 'https://cdn-media[.]ru/payload.ps1',       type: 'URL',    severity: 'Critical', confidence: 97, firstSeen: '2026-03-31', tags: ['Dropper', 'PowerShell'] },
    { value: 'a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2', type: 'Hash',   severity: 'High',     confidence: 90, firstSeen: '2026-03-29', tags: ['Emotet', 'Loader'] },
    { value: '194.165.16.22',                            type: 'IP',     severity: 'Medium',   confidence: 70, firstSeen: '2026-03-20', tags: ['Scanner', 'Shodan'] },
    { value: 'secure-login.microsoft-365[.]xyz',         type: 'Domain', severity: 'High',     confidence: 85, firstSeen: '2026-03-27', tags: ['Phishing', 'O365'] },
    { value: '91.92.136.9',                              type: 'IP',     severity: 'High',     confidence: 78, firstSeen: '2026-03-18', tags: ['C2', 'Qakbot'] },
    { value: 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3', type: 'Hash',   severity: 'Medium',   confidence: 65, firstSeen: '2026-03-15', tags: ['Miner', 'XMRig'] },
    { value: 'http://45.33.32.156/gate.php',             type: 'URL',    severity: 'Critical', confidence: 96, firstSeen: '2026-04-01', tags: ['C2', 'Dridex'] },
    { value: 'malware-analysis[.]io',                    type: 'Domain', severity: 'Low',      confidence: 45, firstSeen: '2026-03-10', tags: ['Suspicious'] }
  ],

  actors: [
    {
      name: 'APT29 (Cozy Bear)',
      origin: 'Russia — Nation-State',
      severity: 'Critical',
      description: 'Sophisticated espionage group attributed to the Russian SVR. Known for supply chain attacks, spear-phishing, and long-term persistence. Targets government, energy, and defence sectors.',
      tags: ['Espionage', 'Supply Chain', 'Spear-phishing', 'OPSEC']
    },
    {
      name: 'Lazarus Group',
      origin: 'North Korea — Nation-State',
      severity: 'Critical',
      description: 'Prolific threat actor attributed to the DPRK. Conducts financially motivated attacks on banks and cryptocurrency exchanges alongside destructive campaigns and cyber espionage.',
      tags: ['Financial', 'Crypto', 'Destructive', 'Backdoor']
    },
    {
      name: 'LockBit 3.0',
      origin: 'Russia — Cybercrime',
      severity: 'High',
      description: 'Ransomware-as-a-Service (RaaS) operation. Among the most active ransomware groups, targeting critical infrastructure and healthcare. Known for its affiliate programme and data leak site.',
      tags: ['Ransomware', 'RaaS', 'Double Extortion', 'Affiliate']
    },
    {
      name: 'FIN7',
      origin: 'Eastern Europe — Cybercrime',
      severity: 'High',
      description: 'Financially motivated group primarily targeting retail, restaurant, and hospitality industries for payment card data. Has evolved to conduct ransomware operations via partnerships.',
      tags: ['Financial', 'POS', 'Spear-phishing', 'Carbanak']
    },
    {
      name: 'Volt Typhoon',
      origin: 'China — Nation-State',
      severity: 'Critical',
      description: 'State-sponsored actor pre-positioning on US critical infrastructure networks. Relies on living-off-the-land (LotL) techniques and compromised SOHO routers to blend in with normal traffic.',
      tags: ['Critical Infra', 'LotL', 'Pre-positioning', 'Stealth']
    },
    {
      name: 'Scattered Spider',
      origin: 'English-speaking — Cybercrime',
      severity: 'High',
      description: 'Social engineering specialist group known for SIM swapping, MFA fatigue attacks, and help-desk impersonation. Has compromised major cloud environments and deployed ransomware.',
      tags: ['Social Engineering', 'SIM Swap', 'MFA Bypass', 'Cloud']
    }
  ],

  feed: [
    { time: '10:42',  title: 'New Cobalt Strike campaign targeting financial sector', body: 'Threat intel partners report a fresh wave of spear-phishing emails delivering macro-laced Office documents that drop a Cobalt Strike beacon. C2 servers hosted on bulletproof hosting in Eastern Europe.', severity: 'Critical' },
    { time: '09:15',  title: 'CVE-2026-1234 actively exploited in the wild',          body: 'A zero-day in a popular VPN appliance is being actively exploited by APT actors. Patch available as of this morning. Apply immediately to internet-facing devices.', severity: 'Critical' },
    { time: '08:30',  title: 'LockBit 3.0 claims attack on logistics company',        body: 'LockBit ransomware operators published 46 GB of allegedly stolen data from a major logistics firm on their dark-web leak site after ransom negotiations broke down.', severity: 'High' },
    { time: '07:55',  title: 'Phishing kit mimicking Microsoft 365 login detected',   body: 'A new phishing kit has been observed targeting enterprise users with a near-pixel-perfect clone of the M365 sign-in page. The kit bypasses MFA via adversary-in-the-middle proxy.', severity: 'High' },
    { time: 'Yesterday', title: 'Increase in DNS tunnelling activity observed',       body: 'Multiple SOC teams report elevated DNS tunnelling attempts using dnscat2 and Iodine. Likely used for C2 and data exfiltration through organisations with permissive DNS egress policies.', severity: 'Medium' },
    { time: 'Yesterday', title: 'Open-source intelligence: new Lazarus tooling',      body: 'Researchers published technical analysis of a new custom implant attributed to Lazarus Group, featuring encrypted C2 communications over HTTPS and in-memory execution to evade EDR.', severity: 'High' },
    { time: '2 days ago', title: 'Critical infrastructure scans from Tor exit nodes', body: 'Elevated scanning activity targeting OT/SCADA systems originating from Tor exit nodes. Sectors affected include energy, water treatment, and transportation.', severity: 'Medium' },
    { time: '2 days ago', title: 'Emotet botnet activity resurging',                  body: 'A new Emotet campaign has resumed after a brief hiatus, spreading via macro-enabled Excel spreadsheets. Emotet is often a precursor to Qakbot and ransomware deployment.', severity: 'Medium' }
  ]
};
