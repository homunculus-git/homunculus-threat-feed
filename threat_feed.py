import os
import re
import csv
import io
import html
import sqlite3
import asyncio
import aiohttp
import requests
import feedparser
from dotenv import load_dotenv

load_dotenv()

DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")

# --- DATABASE PERSISTENCE (DEDUPLICATION) ---
conn = sqlite3.connect("threat_cache.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS seen_events (
        event_id TEXT PRIMARY KEY,
        source TEXT,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
conn.commit()

def is_duplicate(event_id: str) -> bool:
    cursor.execute("SELECT 1 FROM seen_events WHERE event_id = ?", (event_id,))
    return cursor.fetchone() is not None

def record_event(event_id: str, source: str):
    cursor.execute("INSERT OR IGNORE INTO seen_events (event_id, source) VALUES (?, ?)", (event_id, source))
    conn.commit()

def defang_url(url: str) -> str:
    """Sanitises malicious links to prevent accidental clicks."""
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

def clean_html_to_markdown(raw_html: str) -> str:
    """Converts HTML links into Discord Markdown and strips raw HTML tags."""
    if not raw_html:
        return ""
    text = html.unescape(raw_html)
    text = re.sub(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"[^>]*>(.*?)</a>', r'[\2](\1)', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def dispatch_discord_embed(title: str, description: str, fields: list, color: int):
    """Formats and dispatches styled embeds to Discord."""
    if not DISCORD_WEBHOOK or "discord.com" not in DISCORD_WEBHOOK:
        return
    payload = {
        "embeds": [{
            "title": title[:256],
            "description": description[:2000],
            "color": color,
            "fields": fields,
            "footer": {"text": "Homunculus CTI Core • Automated Threat Stream"}
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
    except Exception as err:
        print(f"[Discord Dispatch Error] {err}")

# --- COLLECTOR TASKS ---

# 1. Dark Web Ransomware Leak Trackers (Red - 0xE74C3C)
async def poll_leak_trackers(session):
    # Ransomware.live v2
    try:
        async with session.get("https://api.ransomware.live/v2/recentvictims", timeout=15) as resp:
            if resp.status == 200:
                for v in (await resp.json())[:6]:
                    victim = v.get("victim") or "Confidential Victim"
                    group = v.get("group") or "Unknown"
                    event_id = f"rwlive_{group}_{victim}".lower().strip()
                    if not is_duplicate(event_id):
                        record_event(event_id, "Ransomware.live")
                        dispatch_discord_embed(
                            title=f"🚨 Ransomware Alert: {victim}",
                            description=f"Group **{group}** has published an extortion notice.",
                            fields=[
                                {"name": "Threat Actor", "value": f"`{group}`", "inline": True},
                                {"name": "Target Country", "value": v.get("country", "Global"), "inline": True},
                                {"name": "Source", "value": "Ransomware.live v2", "inline": True}
                            ],
                            color=0xE74C3C
                        )
    except Exception as e:
        print(f"[Collector Error] Ransomware.live: {e}")

    # RansomLook API
    try:
        async with session.get("https://www.ransomlook.io/api/posts?days=1", timeout=15) as resp:
            if resp.status == 200:
                for post in (await resp.json())[:6]:
                    victim = post.get("post_title", "Unknown")
                    group = post.get("group_name", "Unknown")
                    event_id = f"rlook_{group}_{victim}".lower().strip()
                    if not is_duplicate(event_id):
                        record_event(event_id, "RansomLook")
                        dispatch_discord_embed(
                            title=f"🚨 Ransomware Alert: {victim}",
                            description="Identified on double-extortion dark web directory.",
                            fields=[
                                {"name": "Threat Actor", "value": f"`{group}`", "inline": True},
                                {"name": "Source", "value": "RansomLook API", "inline": True}
                            ],
                            color=0xE74C3C
                        )
    except Exception as e:
        print(f"[Collector Error] RansomLook: {e}")

    # Ransomwatch Raw Git Feed
    try:
        async with session.get("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json", timeout=20) as resp:
            if resp.status == 200:
                for post in (await resp.json())[-6:]:
                    victim = post.get("post_title", "Unknown")
                    group = post.get("group_name", "Unknown")
                    event_id = f"rwatch_{group}_{victim}".lower().strip()
                    if not is_duplicate(event_id):
                        record_event(event_id, "Ransomwatch")
                        dispatch_discord_embed(
                            title=f"🚨 Ransomware Alert: {victim}",
                            description=f"Automated crawler detected leak post under **{group}**.",
                            fields=[
                                {"name": "Threat Actor", "value": f"`{group}`", "inline": True},
                                {"name": "Source", "value": "Ransomwatch Git Data", "inline": True}
                            ],
                            color=0xE74C3C
                        )
    except Exception as e:
        print(f"[Collector Error] Ransomwatch: {e}")

# 2. C2 & Malicious Infrastructure (Yellow / Orange / Purple)
async def poll_infrastructure(session):
    # Feodo Tracker (Botnet C2s)
    try:
        async with session.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recent.json", timeout=15) as resp:
            if resp.status == 200:
                for s in (await resp.json())[:4]:
                    ip, port, malware = s.get("ip_address"), s.get("port"), s.get("malware", "Botnet")
                    event_id = f"feodo_{ip}_{port}"
                    if not is_duplicate(event_id):
                        record_event(event_id, "Feodo")
                        dispatch_discord_embed(
                            title=f"🤖 Active C2 Infrastructure: {malware}",
                            description="Active command-and-control server verified by abuse.ch.",
                            fields=[
                                {"name": "Host", "value": f"`{ip}:{port}`", "inline": True},
                                {"name": "Family", "value": f"`{malware}`", "inline": True}
                            ],
                            color=0xF1C40F  # Yellow
                        )
    except Exception as e:
        print(f"[Collector Error] Feodo: {e}")

    # ThreatMon Daily C2 Feed
    try:
        async with session.get("https://raw.githubusercontent.com/ThreatMon/ThreatMon-Daily-C2-Feeds/main/daily-c2.csv", timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                reader = csv.reader(io.StringIO(text))
                for row in list(reader)[:4]:
                    if row and len(row) >= 2 and not row[0].startswith("#"):
                        c2_ip = row[0].strip()
                        c2_type = row[1].strip() if len(row) > 1 else "Malicious C2"
                        event_id = f"tmon_{c2_ip}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "ThreatMon")
                            dispatch_discord_embed(
                                title="🤖 Active C2 Infrastructure: ThreatMon Feed",
                                description="Fresh Command & Control endpoint detected by ThreatMon.",
                                fields=[
                                    {"name": "Host", "value": f"`{c2_ip}`", "inline": True},
                                    {"name": "Type", "value": f"`{c2_type}`", "inline": True}
                                ],
                                color=0xF1C40F  # Yellow
                            )
    except Exception as e:
        print(f"[Collector Error] ThreatMon C2: {e}")

    # URLhaus Droppers
    try:
        async with session.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                reader = csv.reader([line for line in text.splitlines() if not line.startswith("#")])
                for row in list(reader)[:3]:
                    if len(row) > 6:
                        raw_url, threat, tags = row[2], row[5], row[6]
                        event_id = f"urlhaus_{row[0]}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "URLhaus")
                            dispatch_discord_embed(
                                title=f"☣️ Malware Dropper: {threat}",
                                description="Payload distribution URL detected in live attacks.",
                                fields=[
                                    {"name": "Defanged Link", "value": f"`{defang_url(raw_url)[:120]}`", "inline": False},
                                    {"name": "Tags", "value": f"`{tags}`", "inline": True}
                                ],
                                color=0xE67E22  # Orange
                            )
    except Exception as e:
        print(f"[Collector Error] URLhaus: {e}")

    # OpenPhish
    try:
        async with session.get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", timeout=15) as resp:
            if resp.status == 200:
                for raw_link in (await resp.text()).splitlines()[:3]:
                    if raw_link.strip():
                        event_id = f"phish_{hash(raw_link.strip())}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "OpenPhish")
                            dispatch_discord_embed(
                                title="🎣 Malicious Infrastructure: Phishing Site",
                                description="Credential harvest target identified in live circulation.",
                                fields=[
                                    {"name": "Defanged Link", "value": f"`{defang_url(raw_link.strip())[:150]}`", "inline": False}
                                ],
                                color=0x9B59B6  # Purple
                            )
    except Exception as e:
        print(f"[Collector Error] OpenPhish: {e}")

# 3. Live Malware Binaries (abuse.ch MalwareBazaar - Grey 0x95A5A6)
async def poll_malware_bazaar(session):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_recent", "selector": "10"}
    try:
        async with session.post(url, data=data, timeout=15) as resp:
            if resp.status == 200:
                body = await resp.json()
                if body.get("query_status") == "ok":
                    for sample in body.get("data", [])[:3]:
                        sha256 = sample.get("sha256_hash")
                        malware = sample.get("signature") or "Unclassified Malware"
                        file_type = sample.get("file_type", "Executable")
                        event_id = f"bazaar_{sha256}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "MalwareBazaar")
                            dispatch_discord_embed(
                                title=f"🔬 New Malware Sample: {malware}",
                                description=f"A fresh `{file_type}` payload was staged and identified.",
                                fields=[
                                    {"name": "Signature", "value": f"`{malware}`", "inline": True},
                                    {"name": "File Type", "value": f"`{file_type}`", "inline": True},
                                    {"name": "SHA256", "value": f"`{sha256[:20]}...`", "inline": False}
                                ],
                                color=0x95A5A6  # Grey
                            )
    except Exception as e:
        print(f"[Collector Error] MalwareBazaar: {e}")

# 4. Actively Exploited CVEs (Orange - 0xE67E22)
async def poll_vulnerabilities(session):
    try:
        async with session.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=15) as resp:
            if resp.status == 200:
                for vuln in (await resp.json()).get("vulnerabilities", [])[-5:]:
                    cve_id = vuln.get("cveID")
                    event_id = f"cisa_{cve_id}".lower()
                    if not is_duplicate(event_id):
                        record_event(event_id, "CISA-KEV")
                        is_ransom = vuln.get("knownRansomwareCampaignUse", "Unknown")
                        dispatch_discord_embed(
                            title=f"🦠 Vulnerability Alert: {cve_id}",
                            description=clean_html_to_markdown(vuln.get("shortDescription", "Actively exploited vulnerability.")),
                            fields=[
                                {"name": "Product", "value": f"{vuln.get('vendorProject')} {vuln.get('product')}", "inline": True},
                                {"name": "Ransomware Link", "value": f"**{is_ransom}**", "inline": True},
                                {"name": "Required Action", "value": vuln.get("requiredAction", "Patch immediately"), "inline": False}
                            ],
                            color=0xE67E22
                        )
    except Exception as e:
        print(f"[Collector Error] CISA KEV: {e}")

# 5. RSS Advisories, Research & Breaking Disclosures
async def poll_rss_streams():
    rss_catalog = [
        # National CERT Advisories (Blue - 0x2980B9)
        ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "🛡️ Government Advisory", 0x2980B9),
        ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "🛡️ Government Advisory", 0x2980B9),
        ("CERT-FR", "https://www.cert.ssi.gouv.fr/feed/", "🛡️ Government Advisory", 0x2980B9),
        ("CERT-EU", "https://cert.europa.eu/publications/security-advisories/rss.xml", "🛡️ Government Advisory", 0x2980B9),
        ("CERT-Bund (BSI)", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "🛡️ Government Advisory", 0x2980B9),
        # Industrial Control Systems / SCADA (Rust - 0xD35400)
        ("CISA ICS", "https://www.cisa.gov/rss/ics-advisories.xml", "🏭 Industrial Control Systems Alert", 0xD35400),
        # Critical CVE Stream (Orange - 0xE67E22)
        ("AssureStart CVE", "https://cve.assurestart.co/api/feed.xml?cvss_min=9", "🦠 Vulnerability Alert", 0xE67E22),
        # Threat Research, Taxonomy & Operations (Teal / Purple)
        ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "🔬 Threat Research & APTs", 0x1ABC9C),
        ("Malpedia", "https://malpedia.caad.fkie.fraunhofer.de/rss", "🧬 Threat Actor Taxonomy Update", 0x8E44AD),
        ("SANS ISC", "https://isc.sans.edu/rssfeed.xml", "⚡ Global Threat Storm Briefing", 0x3498DB),
        # Incident Reports & Breaking News (Green - 0x2ECC71)
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "📰 Cyber Incident Report", 0x2ECC71),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "📰 Cyber Incident Report", 0x2ECC71)
    ]
    for publisher, feed_url, alert_type, color in rss_catalog:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:3]:
                event_id = f"rss_{entry.get('id', entry.link)}"
                if not is_duplicate(event_id):
                    record_event(event_id, publisher)
                    raw_content = entry.summary if hasattr(entry, 'summary') else (entry.description if hasattr(entry, 'description') else "")
                    clean_text = clean_html_to_markdown(raw_content)[:350]
                    dispatch_discord_embed(
                        title=f"{alert_type}: {entry.title}",
                        description=clean_text + ("..." if len(clean_text) >= 350 else ""),
                        fields=[
                            {"name": "Publisher", "value": publisher, "inline": True},
                            {"name": "Details", "value": f"[Open Document / Article]({entry.link})", "inline": False}
                        ],
                        color=color
                    )
        except Exception as e:
            print(f"[RSS Error] {publisher}: {e}")

# --- ORCHESTRATION ---

async def main():
    print("[*] Homunculus 21-Source Threat Intelligence Engine Active.")
    while True:
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(
                poll_leak_trackers(session),
                poll_infrastructure(session),
                poll_malware_bazaar(session),
                poll_vulnerabilities(session),
                poll_rss_streams(),
                return_exceptions=True
            )
        await asyncio.sleep(300)

if __name__ == "__main__":
    asyncio.run(main())
