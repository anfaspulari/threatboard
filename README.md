# ThreatBoard

A lightweight, client-side **Cyber Threat Intelligence (CTI) dashboard** built with vanilla HTML, CSS, and JavaScript — no build tools, no dependencies.

**[Live Demo →](https://anfaspulari.github.io/threatboard)**

---

## Overview

ThreatBoard aggregates and visualises cyber threat intelligence data in a single, fast-loading dashboard. It's designed as a clean reference implementation for a CTI portal — easy to extend with real threat-feed APIs (MISP, OpenCTI, VirusTotal, Shodan, etc.).

---

## Features

| Feature | Description |
|---|---|
| **Overview Dashboard** | KPI strip, 7-day activity chart, severity breakdown, and recent alerts |
| **IOC Tracker** | Searchable and filterable list of Indicators of Compromise (IPs, hashes, domains, URLs) |
| **Threat Actor Profiles** | Cards for known APT groups and cybercrime actors with TTPs and tags |
| **Intel Feed** | Chronological feed of threat intelligence items with severity filtering |
| **Zero dependencies** | Pure vanilla JS — no React, no bundler, no npm required |
| **Responsive** | Works on desktop, tablet, and mobile |

---

## Project Structure

```
threatboard/
├── index.html          # Entry point
└── src/
    ├── css/
    │   └── style.css   # Design system & component styles
    ├── js/
    │   ├── data.js     # Mock CTI data (replace with live API calls)
    │   ├── chart.js    # Lightweight canvas bar chart (no Chart.js)
    │   └── app.js      # Application logic & DOM rendering
    └── assets/
        └── favicon.svg
```

---

## Getting Started

No installation needed. Open `index.html` directly in a browser:

```bash
git clone https://github.com/anfaspulari/threatboard.git
cd threatboard
open index.html        # macOS
# or: xdg-open index.html  (Linux)
# or: start index.html     (Windows)
```

Or serve it locally:

```bash
python3 -m http.server 8080
# → http://localhost:8080
```

---

## Connecting to Real Threat Feeds

The mock data lives in `src/js/data.js`. To plug in live data, replace the `TB_DATA` object with API calls in `app.js`:

**Example integrations:**
- **MISP** — `GET /attributes/restSearch` for IOCs
- **OpenCTI** — GraphQL API for actors and indicators
- **VirusTotal** — `/api/v3/indicators` for enrichment
- **Shodan** — `/shodan/host/search` for IP intelligence
- **AbuseIPDB** — `/api/v2/check` for IP reputation

---

## Roadmap

- [ ] Live API integration (MISP / OpenCTI)
- [ ] MITRE ATT&CK technique mapping on actor profiles
- [ ] Alert triage workflow (acknowledge / escalate / close)
- [ ] Export to PDF / CSV
- [ ] Dark / light theme toggle
- [ ] WebSocket support for real-time alerts

---

## Tech Stack

- **HTML5** — semantic markup
- **CSS3** — custom properties, grid, flexbox, canvas animations
- **Vanilla JavaScript** — ES2020, no frameworks
- **Canvas 2D API** — custom chart renderer

---

## License

MIT — see [LICENSE](LICENSE) for details.
