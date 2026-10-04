# Homunculus Threat Stream & Triage Lab

An automated, low-latency Cyber Threat Intelligence (CTI) ingestion engine, multi-source correlator, and local reverse-engineering lab.

Homunculus continuously monitors 32 international threat sources spanning global CERT government advisories, dark web ransomware victim streams, active zero-day exploit drops, malware distribution infrastructure, and live phishing campaigns. Indicators are enriched with autonomous network telemetry, brand heuristics, and automated foreign-language translation before being dispatched to Discord with one-click hooks into **Ghidra** and cloud sandboxes.

---

## Intelligence Feeds & Alert Specifications

Homunculus normalizes multi-source intelligence into standardized alert formats mapped to the MITRE ATT&CK framework:

### 1. Government Advisories & CERT Bulletins
Aggregates official cyber defense alerts and critical infrastructure warnings from global national CERTs:
- **Sources:** NCSC (UK), CISA & CISA ICS (US), CERT-FR (France), CERT-EU, CERT-Bund / BSI (Germany), CERT NZ (New Zealand), ACSC (Australia), Canadian Centre for Cyber Security (CCCS).
- **Automated Selective Translation:** Feeds published in French, German, or other languages (CERT-FR, CERT-Bund) are automatically translated to English with `[Translated]` indicators.
- **Alert Information:** Advisory title, issuing government agency, summary breakdown, direct link to official bulletin, and MITRE ATT&CK taxonomy (`T1592`, `T1595`).

### 2. Dark Web & Ransomware Leak Stream
Monitors underground leak sites and extortion portals for newly confirmed corporate victims:
- **Sources:** ThreatCluster Dark Web Stream and automated ransomware group tracking.
- **Alert Information:** Victim organization name, threat group / ransomware strain attribution, compromised sector, source leak link, and MITRE ATT&CK classification (`T1486 Data Encrypted for Impact`, `T1567 Exfiltration`).

### 3. Malware Droppers & Botnet Staging (`URLhaus`)
Tracks active binary delivery hosts, staging servers, and IoT botnet distribution endpoints (e.g. Mozi, Mirai, shell script downloaders, loaders):
- **Payload & Botnet Classification:** Identifies specific malware strains or unclassified loaders.
- **Host Status (Live Probe):** Asynchronous HTTP/socket probe detects if the payload is `🟢 Live (<size> KB)` or `🔴 Dead / Offline` before analysis.
- **Routing & ASN Telemetry:** Resolves hosting provider, BGP ASN, and origin country.
- **Defanged Payload Link:** Safe text-defanged link (`hxxp://...`) to prevent accidental clicks.
- **Integrated Triage Suite:**
  - `Scan on VirusTotal`: Immediate multi-engine reputation analysis.
  - `Search on URLScan.io`: Historical scan lookup and infrastructure profiling.
  - `Detonate on Triage`: One-click sandbox execution link.
  - `⚡ Open in Ghidra Lab`: Downloads the binary directly into `samples/` and launches Ghidra with your project and file manager.
- **MITRE ATT&CK Mapping:** Tagged with `T1204.001 (Malicious Link)` and `T1105 (Ingress Tool Transfer)`.

### 4. Malicious Infrastructure: Phishing Sites (`OpenPhish`)
Detects credential harvesting pages, login lures, and cloud provider abuse (Cloudflare Pages, Vercel, Netlify, Firebase):
- **Campaign & Brand Attribution:** Regex heuristics and HTML title scraping identify targeted brands across:
  - *Corporate Identity & SSO:* Microsoft 365, Entra ID, Google Workspace, Adobe, DocuSign.
  - *Web3 & Crypto Wallets:* MetaMask, Ledger, Trezor, Coinbase, Binance, Phantom.
  - *Financial & Banking:* PayPal, JPMorgan Chase, Bank of America, Wells Fargo, UK/EU banks.
  - *Logistics & Delivery:* DHL, USPS, FedEx, UPS.
  - *Cloud Staging:* Identifies free cloud developer platforms abused to evade email gateways.
- **DNS Resolution Status:** Flags `🟢 Live DNS` vs. `⚠️ Host currently unresolved` (for pre-staged or taken-down domains).
- **Domain-Level Deduplication:** Filters out redundant alerts for multiple paths on the same root domain.
- **Interactive Sandbox Investigation:**
  - `Scan on VirusTotal`: Vendor reputation and certificate inspection.
  - `Scan on URLScan.io`: Pre-populates the target URL into URLScan's scanner for on-demand cloud analysis.
- **MITRE ATT&CK Mapping:** Tagged with `T1566.002 (Spearphishing Link)` and `T1056.003 (Web Portal Capture)`.

### 5. Exploit Drops & PoC Disclosures
Monitors public exploit releases and severe CVE weaponization:
- **Sources:** Exploit-DB, Packet Storm, and AssureStart CVE (CVSS 9.0+ critical feeds).
- **Alert Information:** Vulnerability title, CVE identifier, CVSS severity score, proof-of-concept availability, technical advisory links, and MITRE ATT&CK mapping (`T1588.005`, `T1588.006`).

### 6. Threat Research, Forensics & PCAP Feeds
Tracks published forensic investigations, network packet captures, and academic reverse-engineering papers:
- **Sources:** Malware Traffic Analysis, vx-underground Papers Library, Palo Alto Unit 42, Malpedia, SANS ISC, Krebs on Security, BleepingComputer, The Hacker News, BornCity, nao_sec.
- **PCAP & Artifact Linking:** Provides direct links to downloadable network packet captures (`.pcap`), infection binary archives, and IoC lists for lab analysis.

---

## Architecture Overview

┌──────────────────────────────────────────────┐
│ 32 Global Intelligence Data Feeds │
│ - National CERTs (CISA, NCSC, CERT-FR/Bund) │
│ - Dark Web Streams & Ransomware Trackers │
│ - Live Malware & Phishing (URLhaus/OpenPhish)│
│ - Exploit Databases & Security Research Feeds│
└──────────────────────┬───────────────────────┘
│
▼
┌──────────────────────────────────────────────┐
│ threat_feed.py │
│ - Domain-Level Deduplication Cache │
│ - Asynchronous DNS & Liveness Probers │
│ - Brand Attribution & Title Scraper │
│ - Selective Translation Engine (FR/DE -> EN)│
└──────────────┬────────────────┬──────────────┘
│ │
┌────────────────┘ └────────────────┐
▼ ▼
┌─────────────────────┐ ┌─────────────────────┐
│ Discord Webhook │ │ ghidra_bridge.py │
│ Categorized Embeds │ │ (Local Port 9999) │
└─────────────────────┘ └──────────┬──────────┘
│
┌────────────┴────────────┐
▼ ▼
┌─────────────────┐ ┌─────────────────┐
│ samples/ │ │ Ghidra │
│ Payload Storage │ │ Decompiler │
└─────────────────┘ └─────────────────┘

text

---

## Quickstart & Implementation

### 1. Prerequisites

- **Linux** (Arch Linux, Debian, Ubuntu, Fedora)
- **Python 3.10+**
- **Ghidra** (Optional; required for local binary analysis)
- A **Discord Webhook URL**

### 2. Installation

Clone the repository and set up a virtual environment:

```bash
git clone [https://github.com/homunculus-git/homunculus-threat-feed.git](https://github.com/homunculus-git/homunculus-threat-feed.git)
cd homunculus-threat-feed

python3 -m venv .venv
source .venv/bin/activate
pip install aiohttp requests feedparser
```

### 3. Configuration

Initialize your configuration from the template:

```bash
cp .env.example .env
```

Open `.env` and set your Discord Webhook URL:

```ini
DISCORD_WEBHOOK_URL="[https://discord.com/api/webhooks/your_webhook_id/your_webhook_token](https://discord.com/api/webhooks/your_webhook_id/your_webhook_token)"
```

### 4. Running the Threat Feed

Start the feed service:

```bash
python3 threat_feed.py
```

---

## (Optional) Local Ghidra Lab Triage Bridge

To enable one-click binary acquisition and automated Ghidra launching:

1. Create a project named `Threat Lab` inside the repository directory.
2. Launch the local triage bridge:
   ```bash
   python3 ghidra_bridge.py
   ```
3. When a **Malware Dropper** alert arrives in Discord, click `⚡ Open in Ghidra Lab`. The bridge downloads the live payload directly into `samples/`, displays a desktop notification, launches Ghidra with your project, and opens your file browser for drag-and-drop decompilation.

---

## Production Deployment (Systemd User Service)

To run the threat feed continuously in the background:

```ini
# ~/.config/systemd/user/homunculus-threat-feed.service
[Unit]
Description=Homunculus Automated CTI Threat Feed
After=network.target

[Service]
Type=simple
WorkingDirectory=%h/homunculus/homunculus-threat-feed
ExecStart=%h/homunculus/homunculus-threat-feed/.venv/bin/python3 threat_feed.py
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
```

Enable and start the service:

```bash
systemctl --user daemon-reload
systemctl --user enable --now homunculus-threat-feed.service
```

---

## Security Guidelines

- Raw malware binaries obtained via the triage bridge are saved to `samples/` for static reverse engineering.
- Never execute downloaded binaries directly on your host operating system. Perform deep analysis within an isolated virtual machine or analysis container.
- `samples/` and `.env` are excluded from version control by default via `.gitignore`.
