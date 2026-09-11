import os
import re
import csv
import io
import html
import base64
import sqlite3
import asyncio
import aiohttp
import requests
import feedparser
import urllib.parse
from dotenv import load_dotenv
from deep_translator import GoogleTranslator

load_dotenv()

DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")

# --- TRANSLATOR ENGINE ---
translator = GoogleTranslator(source='auto', target='en')

def translate_to_english(text: str) -> str:
    if not text:
        return ""
    try:
        return translator.translate(text)
    except Exception:
        return text

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
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

def get_virustotal_url_link(raw_url: str) -> str:
    vt_id = base64.urlsafe_b64encode(raw_url.encode()).decode().strip("=")
    return f"https://www.virustotal.com/gui/url/{vt_id}"

def clean_html_to_markdown(raw_html: str) -> str:
    if not raw_html:
        return ""
    text = html.unescape(raw_html)
    text = re.sub(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"[^>]*>(.*?)</a>', r'[\2](\1)', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_malware_family(raw_tags: str) -> str:
    """Extracts high-fidelity malware family or botnet name from URLhaus campaign tags."""
    if not raw_tags or raw_tags.strip() == "None":
        return "Unclassified Dropper"
    
    tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
    
    # Check for direct 'dropped-by-<family>' attribution
    for tag in tags:
        if tag.lower().startswith("dropped-by-"):
            return tag.split("-")[-1].capitalize()
    
    # Generic operational terms to filter out
    generic_noise = {"exe", "elf", "dll", "sh", "bin", "zip", "32-bit", "64-bit", "plugin", "arm", "mips", "x86"}
    
    # Look for well-known malware families
    known_families = {
        "amadey", "mirai", "gafgyt", "redline", "stealc", "lumma", "vidar", 
        "asyncrat", "agenttesla", "remcos", "qakbot", "icedid", "cobaltstrike",
        "njrat", "guploader", "smoke loader", "danabot", "meduzastealer"
    }
    
    for tag in tags:
        if tag.lower() in known_families:
            return tag.capitalize()
            
    # Fallback to the first non-generic tag if available
    for tag in tags:
        if tag.lower() not in generic_noise and not tag.endswith(".dll") and not tag.endswith(".exe"):
            return tag.capitalize()
            
    return "Malware Payload"

def dispatch_discord_embed(title: str, description: str, fields: list, color: int, image_url: str = None):
    if not DISCORD_WEBHOOK or "discord.com" not in DISCORD_WEBHOOK:
        return
    embed = {
        "title": title[:256],
        "description": description[:2000],
        "color": color,
        "fields": fields,
        "footer": {"text": "Homunculus CTI Core • Automated Threat Stream"}
    }
    if image_url and image_url.startswith("http"):
        embed["image"] = {"url": image_url}

    payload = {"embeds": [embed]}
    try:
        requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
    except Exception as err:
        print(f"[Discord Error] {err}")

# --- COLLECTOR TASKS ---

# 1. Dark Web Ransomware Leak Trackers
async def poll_leak_trackers(session):
    try:
        async with session.get("https://api.ransomware.live/v2/recentvictims", timeout=15) as resp:
            if resp.status == 200:
                for v in (await resp.json())[:6]:
                    victim = v.get("victim") or "Confidential Victim"
                    group = v.get("group") or "Unknown"
                    event_id = f"rwlive_{group}_{victim}".lower().strip()
                    if not is_duplicate(event_id):
                        record_event(event_id, "Ransomware.live")
                        note_text = v.get("description") or "No detailed extortion note disclosed."
                        clean_note = clean_html_to_markdown(note_text)[:450]
                        fields = [
                            {"name": "Threat Actor", "value": f"`{group}`", "inline": True},
                            {"name": "Target Country", "value": v.get("country", "Global"), "inline": True},
                            {"name": "Data Claimed", "value": v.get("data_size") or "Unspecified", "inline": True}
                        ]
                        permalink = v.get("permalink") or v.get("post_url")
                        if permalink:
                            fields.append({"name": "Full Extortion Dossier", "value": f"[Inspect Leak Page]({permalink})", "inline": False})
                        dispatch_discord_embed(
                            title=f"🚨 Ransomware Alert: {victim}",
                            description=f"**Extortion Notice / Group Claim:**\n>>> {clean_note}",
                            fields=fields,
                            color=0xE74C3C,
                            image_url=v.get("screenshot")
                        )
    except Exception as e:
        print(f"[Collector Error] Ransomware.live: {e}")

    try:
        async with session.get("https://www.ransomlook.io/api/posts?days=1", timeout=15) as resp:
            if resp.status == 200:
                for post in (await resp.json())[:6]:
                    victim = post.get("post_title", "Unknown")
                    group = post.get("group_name", "Unknown")
                    event_id = f"rlook_{group}_{victim}".lower().strip()
                    if not is_duplicate(event_id):
                        record_event(event_id, "RansomLook")
                        desc = post.get("description") or "Target listed on double-extortion leak directory."
                        dispatch_discord_embed(
                            title=f"🚨 Ransomware Alert: {victim}",
                            description=f"**Extortion Claim:**\n>>> {clean_html_to_markdown(desc)[:350]}",
                            fields=[
                                {"name": "Threat Actor", "value": f"`{group}`", "inline": True},
                                {"name": "Source", "value": "RansomLook API", "inline": True}
                            ],
                            color=0xE74C3C
                        )
    except Exception as e:
        print(f"[Collector Error] RansomLook: {e}")

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
                            description=f"Automated crawler detected fresh victim published on **{group}**'s leak site.",
                            fields=[
                                {"name": "Threat Actor", "value": f"`{group}`", "inline": True},
                                {"name": "Source", "value": "Ransomwatch Git Data", "inline": True}
                            ],
                            color=0xE74C3C
                        )
    except Exception as e:
        print(f"[Collector Error] Ransomwatch: {e}")

# 2. C2, Botnets, Malicious SSL & Infrastructure
async def poll_infrastructure(session):
    # Feodo Tracker
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
                            color=0xF1C40F
                        )
    except Exception as e:
        print(f"[Collector Error] Feodo: {e}")

    # abuse.ch SSLBL
    try:
        async with session.get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                reader = csv.reader([line for line in text.splitlines() if not line.startswith("#")])
                for row in list(reader)[:4]:
                    if len(row) >= 3:
                        seen_time, bad_ip, bad_port = row[0].strip(), row[1].strip(), row[2].strip()
                        event_id = f"sslbl_{bad_ip}_{bad_port}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "abuse.ch SSLBL")
                            vt_ip_url = f"https://www.virustotal.com/gui/ip-address/{bad_ip}"
                            dispatch_discord_embed(
                                title="🔒 Malicious SSL Infrastructure: Botnet Node",
                                description="Host operating a blacklisted SSL/TLS certificate associated with malware C2.",
                                fields=[
                                    {"name": "Server Endpoint", "value": f"`{bad_ip}:{bad_port}`", "inline": True},
                                    {"name": "First Seen (UTC)", "value": seen_time, "inline": True},
                                    {"name": "Infrastructure Profile", "value": f"[Investigate IP on VirusTotal]({vt_ip_url})", "inline": False}
                                ],
                                color=0xD35400
                            )
    except Exception as e:
        print(f"[Collector Error] SSLBL: {e}")

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
                                color=0xF1C40F
                            )
    except Exception as e:
        print(f"[Collector Error] ThreatMon: {e}")

    # URLhaus Droppers (With Intelligent Family Extraction)
    try:
        async with session.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                reader = csv.reader([line for line in text.splitlines() if not line.startswith("#")])
                for row in list(reader)[:3]:
                    if len(row) > 6:
                        url_id, raw_url, threat, tags = row[0].strip(), row[2].strip(), row[5].strip(), row[6].strip()
                        event_id = f"urlhaus_{url_id}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "URLhaus")
                            
                            # Identify specific botnet/malware family from tags
                            detected_family = extract_malware_family(tags)
                            
                            vt_url = get_virustotal_url_link(raw_url)
                            urlscan_search = f"https://urlscan.io/search/#page.url:%22{urllib.parse.quote(raw_url, safe='')}%22"
                            urlhaus_dossier = f"https://urlhaus.abuse.ch/url/{url_id}/"
                            
                            dispatch_discord_embed(
                                title=f"☣️ Malware Dropper: {detected_family}",
                                description="Payload distribution URL detected in live malware campaigns.",
                                fields=[
                                    {"name": "Malware / Botnet Family", "value": f"**{detected_family}**", "inline": True},
                                    {"name": "Threat Database", "value": f"[View URLhaus Dossier]({urlhaus_dossier})", "inline": True},
                                    {"name": "Campaign Tags", "value": f"`{tags or 'None'}`", "inline": False},
                                    {"name": "Defanged Payload Link", "value": f"`{defang_url(raw_url)[:120]}`", "inline": False},
                                    {"name": "Safe Investigation Sandboxes", "value": f"[Scan on VirusTotal]({vt_url}) • [Search on URLScan.io]({urlscan_search})", "inline": False}
                                ],
                                color=0xE67E22
                            )
    except Exception as e:
        print(f"[Collector Error] URLhaus: {e}")

    # OpenPhish
    try:
        async with session.get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", timeout=15) as resp:
            if resp.status == 200:
                for raw_link in (await resp.text()).splitlines()[:3]:
                    link = raw_link.strip()
                    if link:
                        event_id = f"phish_{hash(link)}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "OpenPhish")
                            vt_url = get_virustotal_url_link(link)
                            urlscan_search = f"https://urlscan.io/search/#page.url:%22{urllib.parse.quote(link, safe='')}%22"
                            dispatch_discord_embed(
                                title="🎣 Malicious Infrastructure: Phishing Site",
                                description="Credential harvest target identified in live circulation.",
                                fields=[
                                    {"name": "Defanged Link", "value": f"`{defang_url(link)[:120]}`", "inline": False},
                                    {"name": "Safe Investigation Sandboxes", "value": f"[Scan on VirusTotal]({vt_url}) • [Search on URLScan.io]({urlscan_search})", "inline": False}
                                ],
                                color=0x9B59B6
                            )
    except Exception as e:
        print(f"[Collector Error] OpenPhish: {e}")

# 3. Live Malware Binaries (MalwareBazaar)
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
                            vt_hash_url = f"https://www.virustotal.com/gui/file/{sha256}"
                            dispatch_discord_embed(
                                title=f"🔬 New Malware Sample: {malware}",
                                description=f"A fresh `{file_type}` payload was staged and identified.",
                                fields=[
                                    {"name": "Signature", "value": f"`{malware}`", "inline": True},
                                    {"name": "File Type", "value": f"`{file_type}`", "inline": True},
                                    {"name": "SHA256", "value": f"`{sha256[:20]}...`", "inline": False},
                                    {"name": "Hash Analysis", "value": f"[Inspect Binary on VirusTotal]({vt_hash_url})", "inline": False}
                                ],
                                color=0x95A5A6
                            )
    except Exception as e:
        print(f"[Collector Error] MalwareBazaar: {e}")

# 4. Actively Exploited CVEs (CISA KEV)
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

# 5. RSS Feeds
async def poll_rss_streams():
    rss_catalog = [
        ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "🛡️ Government Advisory", 0x2980B9, False),
        ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "🛡️ Government Advisory", 0x2980B9, False),
        ("CERT-FR", "https://www.cert.ssi.gouv.fr/feed/", "🛡️ Government Advisory", 0x2980B9, True),
        ("CERT-EU", "https://cert.europa.eu/publications/security-advisories/rss.xml", "🛡️ Government Advisory", 0x2980B9, False),
        ("CERT-Bund (BSI)", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "🛡️ Government Advisory", 0x2980B9, True),
        ("CERT NZ", "https://www.cert.govt.nz/it-specialists/advisories/rss", "🛡️ Government Advisory", 0x2980B9, False),
        ("CISA ICS", "https://www.cisa.gov/rss/ics-advisories.xml", "🏭 Industrial Control Systems Alert", 0xD35400, False),
        ("Exploit-DB", "https://www.exploit-db.com/rss.xml", "💥 Exploit PoC Alert", 0xE91E63, False),
        ("Packet Storm", "https://packetstorm.news/rss/files", "💥 Exploit PoC Alert", 0xE91E63, False),
        ("AssureStart CVE", "https://cve.assurestart.co/api/feed.xml?cvss_min=9", "🦠 Vulnerability Alert", 0xE67E22, False),
        ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "🔬 Threat Research & APTs", 0x1ABC9C, False),
        ("Malpedia", "https://malpedia.caad.fkie.fraunhofer.de/rss", "🧬 Threat Actor Taxonomy Update", 0x8E44AD, False),
        ("SANS ISC", "https://isc.sans.edu/rssfeed.xml", "⚡ Global Threat Storm Briefing", 0x3498DB, False),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "📰 Cyber Incident Report", 0x2ECC71, False),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "📰 Cyber Incident Report", 0x2ECC71, False)
    ]
    for publisher, feed_url, alert_type, color, needs_translation in rss_catalog:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:3]:
                event_id = f"rss_{entry.get('id', entry.link)}"
                if not is_duplicate(event_id):
                    record_event(event_id, publisher)
                    raw_title = entry.title
                    raw_content = entry.summary if hasattr(entry, 'summary') else (entry.description if hasattr(entry, 'description') else "")
                    clean_text = clean_html_to_markdown(raw_content)[:350]

                    if needs_translation:
                        final_title = f"{alert_type} [Translated]: {translate_to_english(raw_title)}"
                        final_desc = translate_to_english(clean_text)
                    else:
                        final_title = f"{alert_type}: {raw_title}"
                        final_desc = clean_text

                    dispatch_discord_embed(
                        title=final_title,
                        description=final_desc + ("..." if len(final_desc) >= 350 else ""),
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
    print("[*] Homunculus 25-Source Threat Intelligence Stream Running.")
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
