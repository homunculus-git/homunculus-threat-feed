# Homunculus Threat Feed

**Homunculus** is a real-time cyber threat intelligence aggregator that streams 30+ curated feeds into Discord (with WhatsApp and Telegram support). Built for SOC analysts, threat hunters, and security teams who need immediate visibility into emerging threats without noise or duplication.

## Features

- **32 Threat Intelligence Sources**: Ransomware leaks, malware droppers, phishing URLs, C2 infrastructure, CVEs, and government advisories from trusted publishers including CISA, NCSC UK, CERT-Bund, CERT-FR, abuse.ch, and independent researchers
- **Auto-Translation Engine**: German, French, and other foreign-language advisories automatically translated to English using Google Translate API with language detection and rate-limit protection
- **Infrastructure Enrichment**: Every phishing URL and malware dropper is resolved to IP, ASN, hosting provider, and country; subnet-level threat history queried from ThreatFox to identify flagged C2 neighborhoods
- **SQLite Deduplication**: Persistent event cache prevents duplicate alerts across restarts; each event ID is tracked with source and timestamp
- **MITRE ATT&CK Mapping**: Known ransomware groups mapped to MITRE Group IDs (e.g., LockBit → G0092); dynamic links to MITRE and Malpedia dossiers
- **Multi-Platform Alerts**: Discord webhooks (rich embeds), WhatsApp (Twilio), or Telegram bot API
- **Defanged URLs**: All malicious links automatically defanged (`hxxp://`, `[.]`) to prevent accidental clicks
- **Sandbox Integration**: One-click links to VirusTotal, URLScan.io, Triage, and Ghidra Lab for deeper investigation
- **RSS Stream Processor**: 20+ government and research RSS feeds polled asynchronously with per-feed timeouts and error isolation

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

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/homunculus-git/homunculus-threat-feed.git
cd homunculus-threat-feed
```

### 2. Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate  # Windows
pip install aiohttp requests feedparser python-dotenv
```

### 3. Configure Your Alert Destination

Create a `.env` file in the project root with **one** of the following configurations:

#### Discord (Default)

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN
```

**How to get a Discord webhook:**
1. Go to your Discord server → Server Settings → Integrations → Webhooks
2. Click "New Webhook" and copy the URL

---

#### WhatsApp (via Twilio)

```env
ALERT_METHOD=whatsapp
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
TWILIO_WHATSAPP_TO=whatsapp:+YOUR_NUMBER
```

**How to set up WhatsApp alerts:**
1. Sign up at [Twilio](https://www.twilio.com/try-twilio)
2. Enable the WhatsApp sandbox in your Twilio console
3. Follow the sandbox instructions to link your phone number
4. Copy your Account SID and Auth Token from the Twilio dashboard
5. Add your WhatsApp number in international format (e.g., `whatsapp:+447123456789`)

---

#### Telegram

```env
ALERT_METHOD=telegram
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=-1001234567890
```

**How to set up Telegram alerts:**
1. Message [@BotFather](https://t.me/botfather) on Telegram and create a new bot
2. Copy the bot token provided by BotFather
3. Add your bot to a group or channel (or use your personal chat)
4. Get your chat ID:
   - For a group/channel: Add the bot, send a message, then visit `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - Look for `"chat":{"id":-1001234567890,...}"` in the response
   - For personal chat: Use your numeric Telegram user ID (find via [@userinfobot](https://t.me/userinfobot))
5. Ensure the bot has permission to send messages in the target chat

---

### 4. Run the Threat Feed

```bash
python threat_feed.py
```

You should see:

```
Homunculus 32-Source Threat Intelligence Stream Running. Selective Auto-Translation Active.
```

---

### 5. Run in Background (Optional)

```bash
nohup python threat_feed.py > threat_feed.log 2>&1 &
```

Check it's running:

```bash
pgrep -f threat_feed.py
```

View logs:

```bash
tail -f threat_feed.log
```

---

## Alert Examples

### Discord
Rich embeds with color-coded alerts, inline fields, and clickable investigation links (VirusTotal, URLScan, Triage, Ghidra Lab).

### WhatsApp
Plain-text alerts formatted with emojis and short URLs:

```
🎣 Phishing Site Detected

Campaign: Microsoft 365 Harvest
Hosting: Cloudflare, Inc. (US)
IP: 104.21.45.67
Link: hxxps://login[.]microsft-verify[.]com

🔍 Scan: virustotal.com/gui/url/...
```

### Telegram
Markdown-formatted alerts with inline buttons for quick actions (if implemented):

```
**🎣 Malicious Infrastructure: Phishing Site**

Credential harvest target identified in live circulation.

**Suspected Campaign:** Microsoft 365 Harvest
**Hosting / ASN:** `Cloudflare, Inc. (US)`
**Server IP:** `104.21.45.67`
**Defanged Link:** `hxxps://login[.]microsft-verify[.]com`

🔍 [Scan on VirusTotal](https://virustotal.com/...)
```

---

## Intelligence Sources

| Category | Sources |
|----------|---------||
| **Ransomware Leaks** | Ransomware.live, RansomLook, Ransomwatch |
| **Malware URLs** | URLhaus, MalwareBazaar |
| **Phishing** | OpenPhish |
| **C2 Infrastructure** | Feodo Tracker, SSLBL, ThreatMon |
| **IOC Attribution** | ThreatFox |
| **Vulnerabilities** | CISA Known Exploited Vulnerabilities |
| **Advisories** | CISA, NCSC UK, CERT-Bund, CERT-FR, CERT-EU, ACSC, Canadian Cyber Centre, CERT NZ |
| **Research** | Malware Traffic Analysis, vx-underground, naosec, BornCity, Krebs, Unit 42, Malpedia, SANS ISC, Exploit-DB, Packet Storm, AssureStart CVE, BleepingComputer, The Hacker News, ThreatCluster |

---

## Troubleshooting

### No alerts appearing

1. Check the script is running: `pgrep -f threat_feed.py`
2. Verify your webhook/token in `.env` is correct and not expired
3. Check logs: `tail -f threat_feed.log`
4. Ensure outbound HTTPS (port 443) is not blocked by your firewall

### Syntax errors

```bash
python3 -m py_compile threat_feed.py
```

### Duplicate alerts

The SQLite database (`threat_cache.db`) deduplicates by event ID. To reset:

```bash
rm threat_cache.db
```

## Optional local Ghidra acquisition bridge

This repository includes an optional bridge script (`ghidra_bridge.py`) that forwards malware samples from your local Ghidra instance into the Homunculus threat-feed pipeline for enrichment and Discord alerting.

- Bridge script: [`ghidra_bridge.py`](ghidra_bridge.py)
- Systemd unit (optional): [`systemd/ghidra-bridge.service`](systemd/ghidra-bridge.service)
- Detailed setup & usage: [`docs/GHIDRA_BRIDGE.md`](docs/GHIDRA_BRIDGE.md)

Typical workflow:

1. Configure Ghidra to call `ghidra_bridge.py` when a new sample is identified.
2. The bridge writes samples into the configured `samples/` directory and updates `Threat Lab.gpr`.
3. `threat_feed.py` detects these as local filesystem events and processes them like any other source.

No changes to `threat_feed.py` are required; the bridge is entirely optional and local.
