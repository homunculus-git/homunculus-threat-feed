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

---

## License

**Open Source (MIT License)**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
