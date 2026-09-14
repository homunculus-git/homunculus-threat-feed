import os
import re
import csv
import io
import html
import base64
import socket
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

def normalize_leak_event_id(group: str, victim: str) -> str:
    clean_group = re.sub(r'[^a-z0-9]', '', (group or "").lower())
    clean_victim = re.sub(r'[^a-z0-9]', '', (victim or "").lower())
    return f"victim_{clean_group}_{clean_victim}"

# --- UNIVERSAL AUTO-TRANSLATOR ENGINE ---
def _sync_translate_if_foreign(text: str) -> tuple[str, bool]:
    """Translates text to English if foreign. Returns (translated_text, was_translated)."""
    if not text or not text.strip():
        return "", False
    
    # Strip bracketed metadata tags like [NEU] [mittel] that confuse translation models
    cleaned = re.sub(r'\[.*?\]', '', text).strip()
    sample = cleaned if len(cleaned) > 5 else text

    try:
        t = GoogleTranslator(source='auto', target='en')
        translated = t.translate(sample)
        # If the translation differs meaningfully from the original, it was foreign
        if translated and translated.strip().lower() != sample.strip().lower():
            return translated, True
        return text, False
    except Exception:
        return text, False

async def auto_translate_to_english(text: str) -> tuple[str, bool]:
    """Asynchronously translates foreign content without blocking the event loop."""
    if not text:
        return "", False
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_translate_if_foreign, text)

# --- MITRE ATT&CK & THREAT ACTOR ENRICHMENT ENGINES ---

KNOWN_MITRE_GROUPS = {
    "lockbit": ("G0092", "LockBit"),
    "clop": ("G0096", "CL0P"),
    "cl0p": ("G0096", "CL0P"),
    "blackcat": ("G1017", "BlackCat"),
    "alphv": ("G1017", "BlackCat (ALPHV)"),
    "play": ("G1019", "Play"),
    "akira": ("G1024", "Akira"),
    "blackbasta": ("G1011", "Black Basta"),
    "qilin": ("G1036", "Qilin"),
    "rhysida": ("G1035", "Rhysida"),
    "bianlian": ("G1005", "BianLian"),
    "medusa": ("G1028", "Medusa"),
    "8base": ("G1030", "8Base"),
    "incransom": ("G1037", "Inc Ransom"),
    "ransomhub": ("G1040", "RansomHub"),
    "lazarus": ("G0032", "Lazarus Group"),
    "apt29": ("G0016", "APT29 (Cozy Bear)"),
    "apt28": ("G0007", "APT28 (Fancy Bear)"),
    "scatteredspider": ("G1015", "Scattered Spider")
}

def get_threat_actor_dossier_links(actor_name: str) -> str:
    if not actor_name or actor_name.lower() in ("unknown", "unspecified", "anonymous"):
        return f"`{actor_name or 'Unattributed'}`"
    
    slug = re.sub(r'[^a-z0-9]', '', actor_name.lower())
    links = []
    
    if slug in KNOWN_MITRE_GROUPS:
        gid, _ = KNOWN_MITRE_GROUPS[slug]
        links.append(f"[MITRE {gid}](https://attack.mitre.org/groups/{gid}/)")
    else:
        search_query = urllib.parse.quote(actor_name)
        links.append(f"[Search MITRE](https://attack.mitre.org/?q={search_query})")
    
    links.append(f"[Malpedia Dossier](https://malpedia.caad.fkie.fraunhofer.de/details/actor.{slug})")
    return f"**{actor_name}** • " + " | ".join(links)

def classify_research_post(title: str, default_desc: str) -> tuple:
    low = title.lower()
    
    if any(k in low for k in ["macos", "mac os", "osx", "amos", "shub"]):
        platform = "Apple macOS"
    elif any(k in low for k in ["linux", "elf", "mips", "arm"]):
        platform = "Linux / Unix"
    elif any(k in low for k in ["android", "apk", "ios"]):
        platform = "Mobile Device"
    else:
        platform = "Microsoft Windows"
        
    if any(k in low for k in ["stealer", "infostealer", "amos", "vidar", "lumma", "stealc", "essential"]):
        threat_type = "Credential & Infostealer"
    elif any(k in low for k in ["rat", "xworm", "remcos", "njrat", "asyncrat", "agenttesla"]):
        threat_type = "Remote Access Trojan (RAT)"
    elif any(k in low for k in ["botnet", "mirai", "gafgyt"]):
        threat_type = "Botnet DDoS Node"
    elif any(k in low for k in ["exercise", "traffic analysis"]):
        threat_type = "Traffic Analysis & PCAP Exercise"
    else:
        threat_type = "Malware Infection Chain"
        
    desc = default_desc
    if not desc or len(desc.strip()) < 15 or desc.strip() == title.strip():
        desc = (
            "Verified live malware infection exercise published by Brad Duncan. "
            "Features full network traffic captures (PCAPs), staged payload execution, and IoC extractions."
        )
        
    return platform, threat_type, desc

async def resolve_host_metadata(session, raw_url: str) -> dict:
    try:
        domain = urllib.parse.urlparse(raw_url).netloc.split(":")[0]
        if not domain:
            return {"ip": "Unresolved", "org": "Unknown Host", "country": "N/A"}
        
        loop = asyncio.get_running_loop()
        addr_info = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
        ip = addr_info[0][4][0]
        
        async with session.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as", timeout=5) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("status") == "success":
                    host_org = data.get("org") or data.get("isp") or "Unknown"
                    return {"ip": ip, "org": host_org, "country": data.get("country", "N/A")}
        return {"ip": ip, "org": "Unknown Host", "country": "N/A"}
    except Exception:
        return {"ip": "Unresolved", "org": "Unknown Host", "country": "N/A"}

def detect_target_campaign(url: str) -> str:
    brand_signatures = {
        "Trezor Wallet Phishing": r"trezor",
        "Ledger Wallet Phishing": r"ledger",
        "MetaMask Phishing": r"metamask",
        "Coinbase Phishing": r"coinbase",
        "Binance Phishing": r"binance",
        "Phantom Wallet Phishing": r"phantom",
        "PayPal Credential Harvest": r"paypal",
        "Microsoft 365 / Outlook Harvest": r"office365|microsoft|outlook|sharepoint|onedrive",
        "Google Account Harvest": r"google|gmail|accounts-google",
        "Apple ID Harvest": r"appleid|icloud",
        "Netflix Billing Scam": r"netflix",
        "DHL / Parcel Delivery Scam": r"dhl|parcel|delivery-track",
        "Banking Portal Impersonation": r"chase|hsbc|barclays|natwest|lloyds|santander",
    }
    low = url.lower()
    for label, pattern in brand_signatures.items():
        if re.search(pattern, low):
            return label
    return "Unattributed / Generic Credential Phish"

def extract_malware_family(raw_tags: str) -> str:
    if not raw_tags or raw_tags.strip() == "None":
        return "Unclassified Dropper"
    
    tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
    for tag in tags:
        if tag.lower().startswith("dropped-by-"):
            return tag.split("-")[-1].capitalize()
    
    generic_noise = {"exe", "elf", "dll", "sh", "bin", "zip", "32-bit", "64-bit", "plugin", "arm", "mips", "x86"}
    known_families = {
        "amadey", "mirai", "gafgyt", "redline", "stealc", "lumma", "vidar",  
        "asyncrat", "agenttesla", "remcos", "qakbot", "icedid", "cobaltstrike",
        "njrat", "guploader", "smoke loader", "danabot", "meduzastealer"
    }
    
    for tag in tags:
        if tag.lower() in known_families:
            return tag.capitalize()
            
    for tag in tags:
        if tag.lower() not in generic_noise and not tag.endswith(".dll") and not tag.endswith(".exe"):
            return tag.capitalize()
            
    return "Malware Payload"

def dispatch_discord_embed(title: str, description: str, fields: list, color: int, image_url: str = None, mitre_tactics: str = None):
    if not DISCORD_WEBHOOK or "discord.com" not in DISCORD_WEBHOOK:
        return
    
    footer_text = "Homunculus CTI Core • Automated Threat Stream"
    if mitre_tactics:
        footer_text = f"ATT&CK: {mitre_tactics} • {footer_text}"
        
    embed = {
        "title": title[:256],
        "description": description[:2000],
        "color": color,
        "fields": fields,
        "footer": {"text": footer_text}
    }
    if image_url and image_url.startswith("http"):
        embed["image"] = {"url": image_url}

    payload = {"embeds": [embed]}
    try:
        requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
    except Exception as err:
        print(f"[Discord Error] {err}")

# --- COLLECTOR TASKS ---

async def poll_leak_trackers(session):
    try:
        async with session.get("https://api.ransomware.live/v2/recentvictims", timeout=12) as resp:
            if resp.status == 200:
                for v in (await resp.json())[:6]:
                    victim = v.get("victim") or "Confidential Victim"
                    group = v.get("group") or "Unknown"
                    event_id = normalize_leak_event_id(group, victim)
                    if not is_duplicate(event_id):
                        record_event(event_id, "Ransomware.live")
                        note_text = v.get("description") or "No detailed extortion note disclosed."
                        clean_note = clean_html_to_markdown(note_text)[:450]
                        # Auto-translate extortion note if foreign
                        translated_note, was_trans = await auto_translate_to_english(clean_note)
                        actor_dossier = get_threat_actor_dossier_links(group)
                        
                        fields = [
                            {"name": "Threat Actor Dossier", "value": actor_dossier, "inline": False},
                            {"name": "Target Country", "value": v.get("country", "Global"), "inline": True},
                            {"name": "Data Claimed", "value": v.get("data_size") or "Unspecified", "inline": True}
                        ]
                        permalink = v.get("permalink") or v.get("post_url")
                        if permalink:
                            fields.append({"name": "Full Extortion Dossier", "value": f"[Inspect Leak Page]({permalink})", "inline": False})
                        
                        prefix = "🚨 Ransomware Alert [Translated]:" if was_trans else "🚨 Ransomware Alert:"
                        dispatch_discord_embed(
                            title=f"{prefix} {victim}",
                            description=f"**Extortion Notice / Group Claim:**\n>>> {translated_note}",
                            fields=fields,
                            color=0xE74C3C,
                            image_url=v.get("screenshot"),
                            mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service"
                        )
    except Exception as e:
        print(f"[Collector Error] Ransomware.live: {e}")

    try:
        async with session.get("https://www.ransomlook.io/api/posts?days=1", timeout=12) as resp:
            if resp.status == 200:
                for post in (await resp.json())[:6]:
                    victim = post.get("post_title", "Unknown")
                    group = post.get("group_name", "Unknown")
                    event_id = normalize_leak_event_id(group, victim)
                    if not is_duplicate(event_id):
                        record_event(event_id, "RansomLook")
                        desc = post.get("description") or "Target listed on double-extortion leak directory."
                        clean_desc = clean_html_to_markdown(desc)[:350]
                        translated_desc, was_trans = await auto_translate_to_english(clean_desc)
                        actor_dossier = get_threat_actor_dossier_links(group)
                        prefix = "🚨 Ransomware Alert [Translated]:" if was_trans else "🚨 Ransomware Alert:"
                        dispatch_discord_embed(
                            title=f"{prefix} {victim}",
                            description=f"**Extortion Claim:**\n>>> {translated_desc}",
                            fields=[
                                {"name": "Threat Actor Dossier", "value": actor_dossier, "inline": False},
                                {"name": "Source", "value": "RansomLook API", "inline": True}
                            ],
                            color=0xE74C3C,
                            mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service"
                        )
    except Exception as e:
        print(f"[Collector Error] RansomLook: {e}")

    try:
        async with session.get("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json", timeout=15) as resp:
            if resp.status == 200:
                for post in (await resp.json())[-6:]:
                    victim = post.get("post_title", "Unknown")
                    group = post.get("group_name", "Unknown")
                    event_id = normalize_leak_event_id(group, victim)
                    if not is_duplicate(event_id):
                        record_event(event_id, "Ransomwatch")
                        actor_dossier = get_threat_actor_dossier_links(group)
                        dispatch_discord_embed(
                            title=f"🚨 Ransomware Alert: {victim}",
                            description=f"Automated crawler detected fresh victim published on **{group}**'s leak site.",
                            fields=[
                                {"name": "Threat Actor Dossier", "value": actor_dossier, "inline": False},
                                {"name": "Source", "value": "Ransomwatch Git Data", "inline": True}
                            ],
                            color=0xE74C3C,
                            mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service"
                        )
    except Exception as e:
        print(f"[Collector Error] Ransomwatch: {e}")

async def poll_infrastructure(session):
    try:
        async with session.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recent.json", timeout=12) as resp:
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
                            color=0xF1C40F,
                            mitre_tactics="T1071 Application Layer Protocol • T1573 Encrypted Channel"
                        )
    except Exception as e:
        print(f"[Collector Error] Feodo: {e}")

    try:
        async with session.get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", timeout=12) as resp:
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
                                color=0xD35400,
                                mitre_tactics="T1573.002 Asymmetric Cryptography • T1071.001 Web Protocols"
                            )
    except Exception as e:
        print(f"[Collector Error] SSLBL: {e}")

    try:
        async with session.get("https://raw.githubusercontent.com/ThreatMon/ThreatMon-Daily-C2-Feeds/main/daily-c2.csv", timeout=12) as resp:
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
                                color=0xF1C40F,
                                mitre_tactics="T1071 Application Layer Protocol"
                            )
    except Exception as e:
        print(f"[Collector Error] ThreatMon: {e}")

    try:
        async with session.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=12) as resp:
            if resp.status == 200:
                text = await resp.text()
                reader = csv.reader([line for line in text.splitlines() if not line.startswith("#")])
                for row in list(reader)[:3]:
                    if len(row) > 6:
                        url_id, raw_url, threat, tags = row[0].strip(), row[2].strip(), row[5].strip(), row[6].strip()
                        event_id = f"urlhaus_{url_id}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "URLhaus")
                            detected_family = extract_malware_family(tags)
                            vt_url = get_virustotal_url_link(raw_url)
                            urlscan_search = f"https://urlscan.io/search/#page.url:%22{urllib.parse.quote(raw_url, safe='')}%22"
                            urlhaus_dossier = f"https://urlhaus.abuse.ch/url/{url_id}/"
                            
                            dispatch_discord_embed(
                                title=f"☣ Malware Dropper: {detected_family}",
                                description="Payload distribution URL detected in live malware campaigns.",
                                fields=[
                                    {"name": "Malware / Botnet Family", "value": f"**{detected_family}**", "inline": True},
                                    {"name": "Threat Database", "value": f"[View URLhaus Dossier]({urlhaus_dossier})", "inline": True},
                                    {"name": "Campaign Tags", "value": f"`{tags or 'None'}`", "inline": False},
                                    {"name": "Defanged Payload Link", "value": f"`{defang_url(raw_url)[:120]}`", "inline": False},
                                    {"name": "Safe Investigation Sandboxes", "value": f"[Scan on VirusTotal]({vt_url}) • [Search on URLScan.io]({urlscan_search})", "inline": False}
                                ],
                                color=0xE67E22,
                                mitre_tactics="T1204.001 Malicious Link • T1105 Ingress Tool Transfer"
                            )
    except Exception as e:
        print(f"[Collector Error] URLhaus: {e}")

    try:
        async with session.get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", timeout=12) as resp:
            if resp.status == 200:
                for raw_link in (await resp.text()).splitlines()[:3]:
                    link = raw_link.strip()
                    if link:
                        event_id = f"phish_{hash(link)}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "OpenPhish")
                            vt_url = get_virustotal_url_link(link)
                            urlscan_search = f"https://urlscan.io/search/#page.url:%22{urllib.parse.quote(link, safe='')}%22"
                            campaign = detect_target_campaign(link)
                            net_meta = await resolve_host_metadata(session, link)
                            
                            dispatch_discord_embed(
                                title=f"🎣 Malicious Infrastructure: Phishing Site",
                                description="Credential harvest target identified in live circulation.",
                                fields=[
                                    {"name": "Suspected Campaign", "value": f"**{campaign}**", "inline": True},
                                    {"name": "Hosting Provider / ASN", "value": f"`{net_meta['org']}`", "inline": True},
                                    {"name": "Origin Country", "value": f"`{net_meta['country']}`", "inline": True},
                                    {"name": "Server IP", "value": f"`{net_meta['ip']}`", "inline": True},
                                    {"name": "Defanged Link", "value": f"`{defang_url(link)[:120]}`", "inline": False},
                                    {"name": "Safe Investigation Sandboxes", "value": f"[Scan on VirusTotal]({vt_url}) • [Search on URLScan.io]({urlscan_search})", "inline": False}
                                ],
                                color=0x9B59B6,
                                mitre_tactics="T1566.002 Spearphishing Link • T1056.003 Web Portal Capture"
                            )
    except Exception as e:
        print(f"[Collector Error] OpenPhish: {e}")

async def poll_threatfox(session):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 1}
    try:
        async with session.post(url, json=payload, timeout=12) as resp:
            if resp.status == 200:
                body = await resp.json()
                if body.get("query_status") == "ok":
                    for item in body.get("data", [])[:4]:
                        ioc_id = item.get("id")
                        ioc_val = item.get("ioc")
                        malware = item.get("malware_printable") or "Unclassified"
                        threat_type = item.get("threat_type_desc") or item.get("threat_type") or "C2 Infrastructure"
                        confidence = item.get("confidence_level", 0)
                        tags = item.get("tags") or []
                        tags_str = ", ".join(tags) if isinstance(tags, list) else str(tags)
                        
                        event_id = f"tfox_{ioc_id}"
                        if not is_duplicate(event_id):
                            record_event(event_id, "ThreatFox")
                            defanged = defang_url(ioc_val)[:120]
                            tf_url = f"https://threatfox.abuse.ch/ioc/{ioc_id}/"
                            
                            fields = [
                                {"name": "Malware / Campaign", "value": f"**{malware}**", "inline": True},
                                {"name": "Activity Type", "value": f"`{threat_type}`", "inline": True},
                                {"name": "Confidence Score", "value": f"`{confidence}%`", "inline": True},
                                {"name": "Campaign Tags", "value": f"`{tags_str or 'None'}`", "inline": False},
                                {"name": "Defanged Indicator", "value": f"`{defanged}`", "inline": False},
                                {"name": "Threat Database", "value": f"[View ThreatFox Dossier]({tf_url})", "inline": False}
                            ]
                            
                            dispatch_discord_embed(
                                title=f"🎯 Threat Attribution: {malware}",
                                description="Community intelligence indicator linked to active adversary campaign.",
                                fields=fields,
                                color=0x8E44AD,
                                mitre_tactics="T1071 C2 Protocols • T1584 Compromise Infrastructure"
                            )
    except Exception as e:
        print(f"[Collector Error] ThreatFox: {e}")

async def poll_malware_bazaar(session):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_recent", "selector": "10"}
    try:
        async with session.post(url, data=data, timeout=12) as resp:
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
                                color=0x95A5A6,
                                mitre_tactics="T1204 User Execution • T1027 Obfuscated Files"
                            )
    except Exception as e:
        print(f"[Collector Error] MalwareBazaar: {e}")

async def poll_vulnerabilities(session):
    try:
        async with session.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=12) as resp:
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
                            color=0xE67E22,
                            mitre_tactics="T1190 Exploit Public-Facing Application"
                        )
    except Exception as e:
        print(f"[Collector Error] CISA KEV: {e}")

async def fetch_and_process_rss(session, publisher, feed_url, alert_type, color):
    try:
        headers = {"User-Agent": "HomunculusCTI/2.0 (+https://github.com/homunculus-git)"}
        async with session.get(feed_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return
            xml_data = await resp.text()

        feed = feedparser.parse(xml_data)
        for entry in feed.entries[:3]:
            if publisher == "ThreatCluster":
                event_id = f"tc_{entry.get('id', entry.link)}"
            else:
                event_id = f"rss_{entry.get('id', entry.link)}"

            if not is_duplicate(event_id):
                record_event(event_id, publisher)
                raw_title = entry.title
                raw_content = entry.summary if hasattr(entry, 'summary') else (entry.description if hasattr(entry, 'description') else "")
                clean_text = clean_html_to_markdown(raw_content)

                # Universal Auto-Translation: checks any language, translates only if foreign
                final_title, title_was_foreign = await auto_translate_to_english(raw_title)
                final_desc, desc_was_foreign = await auto_translate_to_english(clean_text)

                # Add [Translated] tag if either title or description was translated
                if title_was_foreign or desc_was_foreign:
                    display_title = f"{alert_type} [Translated]: {final_title}"
                else:
                    display_title = f"{alert_type}: {raw_title}"

                if publisher == "Malware Traffic Analysis":
                    platform, threat_cat, final_desc = classify_research_post(display_title, final_desc)
                    fields = [
                        {"name": "Target Platform", "value": f"`{platform}`", "inline": True},
                        {"name": "Threat Category", "value": f"`{threat_cat}`", "inline": True},
                        {"name": "Investigation Artifacts", "value": "• `Wireshark PCAP (.zip)`\n• `Infection Binaries`\n• `Host/DNS IoC List`", "inline": False},
                        {"name": "Forensic Dossier", "value": f"[Open Full Analysis & PCAP Download]({entry.link})", "inline": False}
                    ]
                    alert_mitre = "T1204 User Execution • T1071 C2 Traffic • T1056 Input Capture"
                elif publisher == "vx-underground":
                    fields = [
                        {"name": "Source", "value": "`vx-underground Papers Library`", "inline": True},
                        {"name": "Category", "value": "`Reverse Engineering Whitepaper`", "inline": True},
                        {"name": "Document Link", "value": f"[Download Paper]({entry.link})", "inline": False}
                    ]
                    alert_mitre = "T1588 Obtain Capabilities"
                else:
                    fields = [
                        {"name": "Publisher", "value": publisher, "inline": True},
                        {"name": "Details", "value": f"[Open Document / Article]({entry.link})", "inline": False}
                    ]
                    alert_mitre = "T1592 Gather Victim Host Info • T1595 Active Scanning" if "Advisory" in alert_type else "T1588 Obtain Capabilities"

                dispatch_discord_embed(
                    title=display_title,
                    description=final_desc + ("..." if len(final_desc) >= 350 else ""),
                    fields=fields,
                    color=color,
                    mitre_tactics=alert_mitre
                )
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[RSS Error] {publisher}: {e}")

async def poll_rss_streams(session):
    # Notice: No more manual True/False translation flags! Everything is auto-detected.
    rss_catalog = [
        ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "🛡 Government Advisory", 0x2980B9),
        ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "🛡 Government Advisory", 0x2980B9),
        ("CISA ICS", "https://www.cisa.gov/rss/ics-advisories.xml", "🏭 Industrial Control Systems Alert", 0xD35400),
        ("CERT-FR", "https://www.cert.ssi.gouv.fr/feed/", "🛡 Government Advisory", 0x2980B9),
        ("CERT-EU", "https://cert.europa.eu/publications/security-advisories/rss.xml", "🛡 Government Advisory", 0x2980B9),
        ("CERT-Bund (BSI)", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "🛡 Government Advisory", 0x2980B9),
        ("CERT NZ", "https://www.cert.govt.nz/it-specialists/advisories/rss", "🛡 Government Advisory", 0x2980B9),
        ("ACSC Australia", "https://www.cyber.gov.au/rss/alerts.xml", "🛡 Government Advisory", 0x2980B9),
        ("Canadian Cyber Centre", "https://cyber.gc.ca/api/v1/feed/cyber-advisories/en", "🛡 Government Advisory", 0x2980B9),
        ("Malware Traffic Analysis", "https://www.malware-traffic-analysis.net/blog-entries.rss", "🔬 PCAP & Infection Chain", 0x1ABC9C),
        ("vx-underground", "https://vx-underground.org/rss/papers.xml", "🧬 Malware Research & Analysis", 0x8E44AD),
        ("nao_sec", "https://nao-sec.org/feed", "🔬 Independent Threat Hunting", 0x1ABC9C),
        ("BornCity Security", "https://borncity.com/win/feed/", "⚡ Breaking IT & Zero-Day Report", 0x3498DB),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/", "📰 Cybercrime Investigation", 0x2ECC71),
        ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "🔬 Threat Research & APTs", 0x1ABC9C),
        ("Malpedia", "https://malpedia.caad.fkie.fraunhofer.de/rss", "🧬 Threat Actor Taxonomy Update", 0x8E44AD),
        ("SANS ISC", "https://isc.sans.edu/rssfeed.xml", "⚡ Global Threat Storm Briefing", 0x3498DB),
        ("Exploit-DB", "https://www.exploit-db.com/rss.xml", "💥 Exploit PoC Alert", 0xE91E63),
        ("Packet Storm", "https://packetstorm.news/rss/files", "💥 Exploit PoC Alert", 0xE91E63),
        ("AssureStart CVE", "https://cve.assurestart.co/api/feed.xml?cvss_min=9", "🦠 Vulnerability Alert", 0xE67E22),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "📰 Cyber Incident Report", 0x2ECC71),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "📰 Cyber Incident Report", 0x2ECC71),
        ("ThreatCluster", "https://threatcluster.io/dark-web/feed.xml", "🚨 Dark Web Victim Stream", 0xE74C3C)
    ]
    
    rss_tasks = [
        fetch_and_process_rss(session, pub, url, a_type, color)
        for pub, url, a_type, color in rss_catalog
    ]
    await asyncio.gather(*rss_tasks, return_exceptions=True)

# --- ORCHESTRATION ---

async def main():
    print("[*] Homunculus 32-Source Threat Intelligence Stream Running (Universal Auto-Translation Active).")
    while True:
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(
                poll_leak_trackers(session),
                poll_infrastructure(session),
                poll_threatfox(session),
                poll_malware_bazaar(session),
                poll_vulnerabilities(session),
                poll_rss_streams(session),
                return_exceptions=True
            )
        await asyncio.sleep(300)

if __name__ == "__main__":
    asyncio.run(main())
