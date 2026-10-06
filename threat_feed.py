import os
import re
import csv
import io
import html
import time
import base64
import socket
import hashlib
import ipaddress
import asyncio
import aiohttp
import aiosqlite
import feedparser
import urllib.parse
from dotenv import load_dotenv

load_dotenv()

# --- WEBHOOK ROUTING MAP ---
WEBHOOK_CHANNELS = {
    "ransomware": os.getenv("DISCORD_WEBHOOK_RANSOMWARE"),
    "malware": os.getenv("DISCORD_WEBHOOK_MALWARE"),
    "infrastructure": os.getenv("DISCORD_WEBHOOK_INFRASTRUCTURE"),
    "phishing": os.getenv("DISCORD_WEBHOOK_PHISHING"),
    "vulnerabilities": os.getenv("DISCORD_WEBHOOK_VULNERABILITIES"),
    "gov_advisory": os.getenv("DISCORD_WEBHOOK_GOV_ADVISORY"),
    "incidents": os.getenv("DISCORD_WEBHOOK_INCIDENTS"),
}

TRIAGE_LAB_HOST = os.getenv("TRIAGE_LAB_HOST", "http://127.0.0.1:9999")
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")
CONCURRENCY_SEMAPHORE = asyncio.Semaphore(5)

# --- DATABASE PERSISTENCE (NON-BLOCKING ASYNC) ---
DB_PATH = "threat_cache.db"

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS seen_events (
                event_id TEXT PRIMARY KEY,
                source TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()

async def is_duplicate(event_id: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM seen_events WHERE event_id = ?", (event_id,)) as cursor:
            row = await cursor.fetchone()
            return row is not None

async def record_event(event_id: str, source: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO seen_events (event_id, source) VALUES (?, ?)", (event_id, source))
        await db.commit()

# --- UTILITIES & SANITIZATION ---

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
    return re.sub(r'\s+', ' ', text).strip()

def normalize_leak_event_id(group: str, victim: str) -> str:
    clean_group = re.sub(r'[^a-z0-9]', '', (group or "").lower())
    clean_victim = re.sub(r'[^a-z0-9]', '', (victim or "").lower())
    return f"victim_{clean_group}_{clean_victim}"

def get_stable_id(prefix: str, content: str) -> str:
    digest = hashlib.sha256(content.encode()).hexdigest()[:16]
    return f"{prefix}_{digest}"

def is_safe_target(host: str) -> bool:
    try:
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except Exception:
        return False

# Standard browser headers to avoid Cloudflare/WAF 403 blocks
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# --- UNIVERSAL ASYNCHRONOUS AUTO-TRANSLATOR ENGINE ---
TRANSLATION_LOCK = asyncio.Lock()
TRANSLATION_CACHE = {}

async def auto_translate_to_english(session: aiohttp.ClientSession, text: str) -> tuple[str, bool]:
    if not text or not text.strip():
        return "", False

    cleaned = re.sub(r'\[.*?\]', '', text).strip()
    sample = cleaned if len(cleaned) > 5 else text

    if sample in TRANSLATION_CACHE:
        return TRANSLATION_CACHE[sample]

    async with TRANSLATION_LOCK:
        if sample in TRANSLATION_CACHE:
            return TRANSLATION_CACHE[sample]

        try:
            url = f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=en&dt=t&q={urllib.parse.quote(sample[:3000])}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    detected_lang = data[2] if len(data) > 2 and isinstance(data[2], str) else "auto"

                    if detected_lang.lower().startswith("en"):
                        TRANSLATION_CACHE[sample] = (text, False)
                        return text, False

                    if data and data[0]:
                        res = "".join([segment[0] for segment in data[0] if segment and segment[0]])
                        if res and res.strip().lower() != sample.strip().lower():
                            prefix_match = re.match(r'^(\[.*?\]\s*)+', text)
                            prefix = prefix_match.group(0) if prefix_match else ""
                            final_res = f"{prefix}{res}".strip()
                            TRANSLATION_CACHE[sample] = (final_res, True)
                            await asyncio.sleep(0.2)
                            return final_res, True
        except Exception as e:
            print(f"[Translation Warning] {e}")

    TRANSLATION_CACHE[sample] = (text, False)
    return text, False

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
    title = title or ""
    default_desc = default_desc or ""
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

async def resolve_host_metadata(session: aiohttp.ClientSession, raw_url: str) -> dict:
    try:
        domain = urllib.parse.urlparse(raw_url).netloc.split(":")[0]
        if not domain or not is_safe_target(domain):
            return {"ip": "Unresolved", "org": "Unknown Host", "country": "N/A"}
        
        loop = asyncio.get_running_loop()
        addr_info = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
        ip = addr_info[0][4][0]
        
        async with session.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as", timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("status") == "success":
                    host_org = data.get("org") or data.get("isp") or "Unknown"
                    return {"ip": ip, "org": host_org, "country": data.get("country", "N/A")}
        return {"ip": ip, "org": "Unknown Host", "country": "N/A"}
    except Exception:
        return {"ip": "Unresolved", "org": "Unknown Host", "country": "N/A"}

async def enrich_dropper_infrastructure(session: aiohttp.ClientSession, raw_url: str) -> dict:
    info = {
        "ip": None,
        "routing": "Unknown ASN",
        "subnet_note": "Clean / Unflagged",
        "strains": []
    }
    try:
        host = urllib.parse.urlparse(raw_url).netloc.split(":")[0]
        if not host or not is_safe_target(host):
            return info
            
        loop = asyncio.get_running_loop()
        addr_info = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
        ip = addr_info[0][4][0]
        info["ip"] = ip
        
        async with session.get(f"http://ip-api.com/json/{ip}?fields=status,country,as,org", timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("status") == "success":
                    as_num = data.get("as", "").split(" ")[0]
                    org = data.get("org") or data.get("as", "")
                    country = data.get("country", "")
                    info["routing"] = f"`{as_num}` {org} ({country})"
                    
        octets = ip.split(".")
        if len(octets) == 4 and ABUSECH_AUTH_KEY:
            subnet = f"{octets[0]}.{octets[1]}.{octets[2]}."
            headers = {"Auth-Key": ABUSECH_AUTH_KEY}
            async with session.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": subnet}, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as tf:
                if tf.status == 200:
                    tdata = await tf.json()
                    if tdata.get("query_status") == "ok":
                        items = tdata.get("data", [])
                        strains = {it.get("malware_printable") for it in items if it.get("malware_printable")}
                        info["strains"] = sorted(list(strains))[:4]
                        if len(items) > 0:
                            info["subnet_note"] = f"⚠ **Flagged C2 Subnet**: `{len(items)}` neighbor hit(s) in `/24`"
    except Exception:
        pass
    return info

def detect_target_campaign(url: str) -> str:
    brand_signatures = {
        "Microsoft 365 / Entra ID Harvest": r"office365|microsoft|outlook|sharepoint|onedrive|o365|msft|login\.live|owa|adfs|bpos|mdm|intune",
        "Google Workspace / Accounts": r"google|gmail|accounts-google|gsuite|gdrive|docs-google|drive-google",
        "Apple ID / iCloud Phishing": r"appleid|icloud|apple-id|findmy",
        "Adobe / Document Cloud": r"adobe|acrobat|adobesign",
        "DocuSign Lure Phish": r"docusign|esign|docusg",
        "Trezor Hardware Wallet Phish": r"trezor",
        "Ledger Hardware Wallet Phish": r"ledger",
        "MetaMask Web3 Phish": r"metamask",
        "Coinbase Exchange Phish": r"coinbase",
        "Binance Exchange Phish": r"binance|bnance",
        "Phantom Solana Wallet Phish": r"phantom|solflare",
        "PayPal Credential Harvest": r"paypal|pypl",
        "JPMorgan Chase Impersonation": r"chase|jpmorgan",
        "Bank of America Impersonation": r"bankofamerica|bofa",
        "Wells Fargo Impersonation": r"wellsfargo",
        "UK / EU Banking Impersonation": r"hsbc|barclays|natwest|lloyds|santander|halifax|revolut",
        "Stripe / Merchant Harvest": r"stripe|merchant-portal",
        "Postal / Parcel Delivery Scam": r"dhl|parcel|delivery-track|usps|fedex|ups-tracking|post-office|evri",
        "Netflix / Streaming Scam": r"netflix|spotify",
        "Meta / Facebook / WhatsApp": r"facebook|fb-login|instagram|meta-security|whatsapp",
        "Telecom / Carrier Phishing": r"att-login|verizon|t-mobile|vodafone",
        "Cloudflare Pages Staged Phish": r"pages\.dev",
        "Vercel / Netlify Staged Phish": r"vercel\.app|netlify\.app",
        "Firebase Staged Phish": r"web\.app|firebaseapp\.com",
    }
    low = url.lower()
    for label, pattern in brand_signatures.items():
        if re.search(pattern, low):
            return label
    return "Unattributed / Generic Credential Phish"

async def check_payload_liveness(session: aiohttp.ClientSession, url: str) -> str:
    try:
        domain = urllib.parse.urlparse(url).netloc.split(":")[0]
        if not is_safe_target(domain):
            return "🔴 Untrusted Target Host"
        real_url = url.replace("hxxp", "http").replace("[.]", ".")
        headers = {"User-Agent": "Wget/1.21"}
        async with session.head(real_url, timeout=aiohttp.ClientTimeout(total=3), headers=headers, allow_redirects=True) as resp:
            if resp.status == 200:
                length = resp.headers.get("Content-Length")
                if length and length.isdigit():
                    kb = int(length) // 1024
                    return f"🟢 Live ({kb} KB)"
                return "🟢 Live (Online)"
            elif resp.status == 404:
                return "🔴 Offline (404 Removed)"
            else:
                return f"🟡 Responding (HTTP {resp.status})"
    except Exception:
        return "🔴 Dead / Offline"

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

# --- STRICT DISCORD EMBED ROUTER ---

async def dispatch_discord_embed(
    session: aiohttp.ClientSession,
    channel_key: str,
    title: str,
    description: str,
    fields: list,
    color: int,
    image_url: str = None,
    mitre_tactics: str = None
):
    target_webhook = WEBHOOK_CHANNELS.get(channel_key)
    if not target_webhook or "discord.com" not in target_webhook:
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
    for attempt in range(3):
        try:
            async with session.post(target_webhook, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 429:
                    retry_data = await resp.json()
                    wait_time = float(retry_data.get("retry_after", 1.5))
                    await asyncio.sleep(wait_time)
                    continue
                elif resp.status in (200, 204):
                    break
        except Exception:
            await asyncio.sleep(1)

# --- COLLECTOR TASKS ---

async def poll_leak_trackers(session: aiohttp.ClientSession):
    # 1. Ransomware.live Real-Time XML Stream
    try:
        async with session.get("https://ransomware.live/rss.xml", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                feed = feedparser.parse(await resp.text())
                for entry in feed.entries[:25]:
                    link = entry.get("link", "")
                    title = entry.get("title", "")
                    raw_id = entry.get("id") or link or title
                    event_id = get_stable_id("rwlive", raw_id)

                    if not await is_duplicate(event_id):
                        await record_event(event_id, "Ransomware.live")
                        clean_desc = clean_html_to_markdown(entry.get("summary", "") or entry.get("description", ""))
                        trans_desc, was_trans = await auto_translate_to_english(session, clean_desc[:450])
                        
                        group_name = "Ransomware Group"
                        if " - " in title:
                            group_name = title.split(" - ")[0].strip()
                        elif " claimed by " in title.lower():
                            parts = re.split(r" claimed by ", title, flags=re.IGNORECASE)
                            group_name = parts[-1].strip()

                        actor_dossier = get_threat_actor_dossier_links(group_name)
                        fields = [
                            {"name": "Threat Actor Dossier", "value": actor_dossier, "inline": False},
                            {"name": "Discovery Link", "value": f"[Inspect Leak Page]({link})", "inline": False}
                        ]

                        prefix = "🚨 Ransomware Alert [Translated]:" if was_trans else "🚨 Ransomware Alert:"
                        await dispatch_discord_embed(
                            session=session,
                            channel_key="ransomware",
                            title=f"{prefix} {title[:100]}",
                            description=f"**Extortion Notice / Group Claim:**\n>>> {trans_desc or clean_desc or 'New victim published on extortion leak site.'}",
                            fields=fields,
                            color=0xE74C3C,
                            mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service"
                        )
    except Exception as e:
        print(f"[Collector Error] Ransomware.live RSS: {e}")

    # 2. RansomLook API
    try:
        async with session.get("https://www.ransomlook.io/api/posts?days=1", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                for post in (await resp.json())[:20]:
                    victim = post.get("post_title", "Unknown")
                    group = post.get("group_name", "Unknown")
                    raw_id = f"{group}_{victim}_{post.get('discovered', '')}"
                    event_id = get_stable_id("rlook", raw_id)

                    if not await is_duplicate(event_id):
                        await record_event(event_id, "RansomLook")
                        desc = post.get("description") or "Target listed on double-extortion leak directory."
                        clean_desc = clean_html_to_markdown(desc)[:350]
                        trans_desc, was_trans = await auto_translate_to_english(session, clean_desc)
                        actor_dossier = get_threat_actor_dossier_links(group)
                        prefix = "🚨 Ransomware Alert [Translated]:" if was_trans else "🚨 Ransomware Alert:"
                        await dispatch_discord_embed(
                            session=session,
                            channel_key="ransomware",
                            title=f"{prefix} {victim}",
                            description=f"**Extortion Claim:**\n>>> {trans_desc}",
                            fields=[
                                {"name": "Threat Actor Dossier", "value": actor_dossier, "inline": False},
                                {"name": "Source", "value": "RansomLook API", "inline": True}
                            ],
                            color=0xE74C3C,
                            mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service"
                        )
    except Exception as e:
        print(f"[Collector Error] RansomLook: {e}")

    # 3. Ransomwatch Git Data
    try:
        async with session.get("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json", timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                for post in (await resp.json())[-20:]:
                    victim = post.get("post_title", "Unknown")
                    group = post.get("group_name", "Unknown")
                    raw_id = f"{group}_{victim}_{post.get('discovered', '')}"
                    event_id = get_stable_id("rwatch", raw_id)

                    if not await is_duplicate(event_id):
                        await record_event(event_id, "Ransomwatch")
                        actor_dossier = get_threat_actor_dossier_links(group)
                        await dispatch_discord_embed(
                            session=session,
                            channel_key="ransomware",
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

async def poll_infrastructure(session: aiohttp.ClientSession):
    # Patched Feodo Tracker endpoint
    try:
        async with session.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                for s in (await resp.json())[:4]:
                    ip, port, malware = s.get("ip_address"), s.get("port"), s.get("malware", "Botnet")
                    event_id = f"feodo_{ip}_{port}"
                    if not await is_duplicate(event_id):
                        await record_event(event_id, "Feodo")
                        await dispatch_discord_embed(
                            session=session,
                            channel_key="infrastructure",
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
        async with session.get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                text = await resp.text()
                reader = csv.reader([line for line in text.splitlines() if not line.startswith("#")])
                for row in list(reader)[:4]:
                    if len(row) >= 3:
                        seen_time, bad_ip, bad_port = row[0].strip(), row[1].strip(), row[2].strip()
                        event_id = f"sslbl_{bad_ip}_{bad_port}"
                        if not await is_duplicate(event_id):
                            await record_event(event_id, "abuse.ch SSLBL")
                            vt_ip_url = f"https://www.virustotal.com/gui/ip-address/{bad_ip}"
                            await dispatch_discord_embed(
                                session=session,
                                channel_key="infrastructure",
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
        async with session.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                text = await resp.text()
                reader = csv.reader([line for line in text.splitlines() if not line.startswith("#")])
                for row in list(reader)[:3]:
                    if len(row) > 6:
                        url_id, raw_url, threat, tags = row[0].strip(), row[2].strip(), row[5].strip(), row[6].strip()
                        event_id = f"urlhaus_{url_id}"
                        if not await is_duplicate(event_id):
                            await record_event(event_id, "URLhaus")
                            detected_family = extract_malware_family(tags)
                            vt_url = get_virustotal_url_link(raw_url)
                            urlscan_link = f"https://urlscan.io/#{urllib.parse.quote(raw_url, safe='')}"
                            urlhaus_dossier = f"https://urlhaus.abuse.ch/url/{url_id}/"
                            
                            infra = await enrich_dropper_infrastructure(session, raw_url)
                            
                            fields = [
                                {"name": "Malware / Botnet Family", "value": f"**{detected_family}**", "inline": True},
                                {"name": "Threat Database", "value": f"[View URLhaus Dossier]({urlhaus_dossier})", "inline": True},
                                {"name": "Routing & ASN", "value": infra["routing"], "inline": False}
                            ]
                            
                            if "Flagged" in infra["subnet_note"]:
                                strains_str = ", ".join(infra["strains"]) if infra["strains"] else "Unclassified Botnet"
                                fields.append({
                                    "name": "Subnet Threat History (/24)",
                                    "value": f"{infra['subnet_note']}\nAssociated Strains: `{strains_str}`",
                                    "inline": False
                                })
                                
                            liveness = await check_payload_liveness(session, raw_url)
                            fields.extend([
                                {"name": "Host Status", "value": f"**{liveness}**", "inline": True},
                                {"name": "Campaign Tags", "value": f"`{tags or 'None'}`", "inline": True},
                                {"name": "Defanged Payload Link", "value": f"`{defang_url(raw_url)[:120]}`", "inline": False},
                                {
                                    "name": "Safe Investigation Sandboxes",
                                    "value": (
                                        f"[Scan on VirusTotal]({vt_url}) • "
                                        f"[Scan on URLScan.io]({urlscan_link}) • "
                                        f"[Detonate on Triage](https://tria.ge/reports?q=\" + urllib.parse.urlparse(raw_url).netloc.split(\":\")[0] + \""
                                        f"[⚡ Open in Ghidra Lab]({TRIAGE_LAB_HOST}/triage?target={urllib.parse.quote(raw_url, safe='')})"
                                    ),
                                    "inline": False
                                }
                            ])
                            
                            await dispatch_discord_embed(
                                session=session,
                                channel_key="malware",
                                title=f"☣ Malware Dropper: {detected_family}",
                                description="Payload distribution URL detected in live malware campaigns.",
                                fields=fields,
                                color=0xE67E22,
                                mitre_tactics="T1204.001 Malicious Link • T1105 Ingress Tool Transfer"
                            )
    except Exception as e:
        print(f"[Collector Error] URLhaus: {e}")

    try:
        async with session.get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                for raw_link in (await resp.text()).splitlines()[:5]:
                    link = raw_link.strip()
                    if link:
                        domain = urllib.parse.urlparse(link).netloc.lower()
                        event_id = f"phish_{domain}" if domain else get_stable_id("phish", link)
                        if not await is_duplicate(event_id):
                            await record_event(event_id, "OpenPhish")
                            vt_url = get_virustotal_url_link(link)
                            urlscan_link = f"https://urlscan.io/#{urllib.parse.quote(link, safe='')}"
                            campaign = detect_target_campaign(link)
                            
                            net_meta = await resolve_host_metadata(session, link)
                            is_resolved = net_meta.get("ip") != "Unresolved"
                            dns_badge = "🟢 Live DNS" if is_resolved else "⚠ Host currently unresolved"
                            host_type = "Cloud Stager" if any(h in link for h in ["pages.dev", "vercel.app", "netlify.app", "firebaseapp.com"]) else "Self-Hosted / VPS"

                            await dispatch_discord_embed(
                                session=session,
                                channel_key="phishing",
                                title="🎣 Malicious Infrastructure: Phishing Site",
                                description="Credential harvest target identified in live circulation.",
                                fields=[
                                    {"name": "Suspected Campaign", "value": f"**{campaign}**", "inline": True},
                                    {"name": "Hosting / ASN", "value": f"`{net_meta['org'][:22]}`", "inline": True},
                                    {"name": "Origin Country", "value": f"`{net_meta['country']}`", "inline": True},
                                    {"name": "DNS Status", "value": f"**{dns_badge}**", "inline": True},
                                    {"name": "Server IP", "value": f"`{net_meta['ip']}`", "inline": True},
                                    {"name": "Staging Platform", "value": f"`{host_type}`", "inline": True},
                                    {"name": "Defanged Link", "value": f"`{defang_url(link)[:120]}`", "inline": False},
                                    {"name": "Safe Investigation Sandboxes", "value": f"[Scan on VirusTotal]({vt_url}) • [Scan on URLScan.io]({urlscan_link})", "inline": False}
                                ],
                                color=0x9B59B6 if is_resolved else 0x7F8C8D,
                                mitre_tactics="T1566.002 Spearphishing Link • T1056.003 Web Portal Capture"
                            )
    except Exception as e:
        print(f"[Collector Error] OpenPhish: {e}")

async def poll_threatfox(session: aiohttp.ClientSession):
    if not ABUSECH_AUTH_KEY:
        return
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    payload = {"query": "get_iocs", "days": 1}
    try:
        async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
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
                        if not await is_duplicate(event_id):
                            await record_event(event_id, "ThreatFox")
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
                            
                            await dispatch_discord_embed(
                                session=session,
                                channel_key="infrastructure",
                                title=f"🎯 Threat Attribution: {malware}",
                                description="Community intelligence indicator linked to active adversary campaign.",
                                fields=fields,
                                color=0x8E44AD,
                                mitre_tactics="T1071 C2 Protocols • T1584 Compromise Infrastructure"
                            )
    except Exception as e:
        print(f"[Collector Error] ThreatFox: {e}")

async def poll_malware_bazaar(session: aiohttp.ClientSession):
    if not ABUSECH_AUTH_KEY:
        return
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    data = {"query": "get_recent", "selector": "10"}
    try:
        async with session.post(url, data=data, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                body = await resp.json()
                if body.get("query_status") == "ok":
                    for sample in body.get("data", [])[:3]:
                        sha256 = sample.get("sha256_hash")
                        malware = sample.get("signature") or "Unclassified Malware"
                        file_type = sample.get("file_type", "Executable")
                        event_id = f"bazaar_{sha256}"
                        if not await is_duplicate(event_id):
                            await record_event(event_id, "MalwareBazaar")
                            vt_hash_url = f"https://www.virustotal.com/gui/file/{sha256}"
                            await dispatch_discord_embed(
                                session=session,
                                channel_key="malware",
                                title=f"🔬 New Malware Sample: {malware}",
                                description=f"A fresh `{file_type}` payload was staged and identified.",
                                fields=[
                                    {"name": "Signature", "value": f"`{malware}`", "inline": True},
                                    {"name": "File Type", "value": f"`{file_type}`", "inline": True},
                                    {"name": "SHA256", "value": f"`{sha256[:20]}...`", "inline": False},
                                    {"name": "Hash Analysis", "value": f"[Inspect on VirusTotal]({vt_hash_url}) • [Detonate on Triage](https://tria.ge/reports?q={sha256}) • [⚡ Open in Ghidra Lab]({TRIAGE_LAB_HOST}/triage?hash={sha256})", "inline": False}
                                ],
                                color=0x95A5A6,
                                mitre_tactics="T1204 User Execution • T1027 Obfuscated Files"
                            )
    except Exception as e:
        print(f"[Collector Error] MalwareBazaar: {e}")

async def poll_vulnerabilities(session: aiohttp.ClientSession):
    try:
        async with session.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                for vuln in (await resp.json()).get("vulnerabilities", [])[-5:]:
                    cve_id = vuln.get("cveID")
                    event_id = f"cisa_{cve_id}".lower()
                    if not await is_duplicate(event_id):
                        await record_event(event_id, "CISA-KEV")
                        is_ransom = vuln.get("knownRansomwareCampaignUse", "Unknown")
                        await dispatch_discord_embed(
                            session=session,
                            channel_key="vulnerabilities",
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

async def fetch_and_process_rss(session: aiohttp.ClientSession, publisher: str, feed_url: str, alert_type: str, color: int, channel_key: str, may_need_translation: bool = False):
    async with CONCURRENCY_SEMAPHORE:
        try:
            async with session.get(feed_url, headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status != 200:
                    return
                xml_data = await resp.text()

            feed = feedparser.parse(xml_data)
            for entry in feed.entries[:3]:
                entry_link = entry.get("link", "")
                raw_id = entry.get("id") or entry_link
                event_id = f"tc_{raw_id}" if publisher == "ThreatCluster" else get_stable_id("rss", raw_id)

                if not await is_duplicate(event_id):
                    await record_event(event_id, publisher)
                    raw_title = entry.get("title", "Untitled feed entry")
                    raw_content = entry.summary if hasattr(entry, 'summary') else (entry.description if hasattr(entry, 'description') else "")
                    clean_text = clean_html_to_markdown(raw_content)

                    if may_need_translation:
                        final_title, title_was_foreign = await auto_translate_to_english(session, raw_title)
                        final_desc, desc_was_foreign = await auto_translate_to_english(session, clean_text)
                        display_title = f"{alert_type} [Translated]: {final_title}" if (title_was_foreign or desc_was_foreign) else f"{alert_type}: {raw_title}"
                    else:
                        final_desc = clean_text
                        display_title = f"{alert_type}: {raw_title}"

                    if publisher == "Malware Traffic Analysis":
                        platform, threat_cat, final_desc = classify_research_post(display_title, final_desc)
                        fields = [
                            {"name": "Target Platform", "value": f"`{platform}`", "inline": True},
                            {"name": "Threat Category", "value": f"`{threat_cat}`", "inline": True},
                            {"name": "Investigation Artifacts", "value": "• `Wireshark PCAP (.zip)`\n• `Infection Binaries`\n• `Host/DNS IoC List`", "inline": False},
                            {"name": "Forensic Dossier", "value": f"[Open Full Analysis & PCAP Download]({entry_link})", "inline": False}
                        ]
                        alert_mitre = "T1204 User Execution • T1071 C2 Traffic • T1056 Input Capture"
                    elif publisher == "vx-underground":
                        fields = [
                            {"name": "Source", "value": "`vx-underground Papers Library`", "inline": True},
                            {"name": "Category", "value": "`Reverse Engineering Whitepaper`", "inline": True},
                            {"name": "Document Link", "value": f"[Download Paper]({entry_link})", "inline": False}
                        ]
                        alert_mitre = "T1588 Obtain Capabilities"
                    else:
                        fields = [
                            {"name": "Publisher", "value": publisher, "inline": True},
                            {"name": "Details", "value": f"[Open Document / Article]({entry_link})", "inline": False}
                        ]

                    await dispatch_discord_embed(
                        session=session,
                        channel_key=channel_key,
                        title=display_title,
                        description=final_desc[:1900] + ("..." if len(final_desc) >= 1900 else ""),
                        fields=fields,
                        color=color,
                        mitre_tactics="T1592 Gather Victim Host Info"
                    )
        except Exception:
            pass

async def poll_rss_streams(session: aiohttp.ClientSession):
    # Patched and updated RSS catalog
    rss_catalog = [
        ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "🛡 Government Advisory", 0x2980B9, "gov_advisory", False),
        ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "🛡 Government Advisory", 0x2980B9, "gov_advisory", False),
        ("CISA ICS", "https://www.securityweek.com/feed/", "🏭 Industrial Control Systems Alert", 0xD35400, "gov_advisory", False),
        ("CERT-FR", "https://www.cert.ssi.gouv.fr/feed/", "🛡 Government Advisory", 0x2980B9, "gov_advisory", True),
        ("CERT-Bund (BSI)", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "🛡 Government Advisory", 0x2980B9, "gov_advisory", True),
        ("Canadian Cyber", "https://www.cyber.gc.ca/api/v1/feed/cyber-advisories/en", "🛡 Government Advisory", 0x2980B9, "gov_advisory", False),
        ("Malware Traffic Analysis", "https://www.malware-traffic-analysis.net/blog-entries.rss", "🔬 PCAP & Infection Chain", 0x1ABC9C, "malware", False),
        ("vx-underground", "https://vx-underground.org/rss/papers.xml", "🧬 Malware Research & Analysis", 0x8E44AD, "malware", False),
        ("nao_sec", "https://nao-sec.org/feed", "🔬 Independent Threat Hunting", 0x1ABC9C, "malware", True),
        ("BornCity Security", "https://borncity.com/win/feed/", "⚡ Breaking IT & Zero-Day Report", 0x3498DB, "incidents", True),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/", "📰 Cybercrime Investigation", 0x2ECC71, "incidents", False),
        ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "🔬 Threat Research & APTs", 0x1ABC9C, "malware", False),
        ("SANS ISC", "https://isc.sans.edu/rssfeed.xml", "⚡ Global Threat Storm Briefing", 0x3498DB, "incidents", False),
        ("Exploit-DB", "https://www.exploit-db.com/rss.xml", "💥 Exploit PoC Alert", 0xE91E63, "vulnerabilities", False),
        ("Packet Storm", "https://packetstorm.news/rss/files", "💥 Exploit PoC Alert", 0xE91E63, "vulnerabilities", False),
        ("ThreatCluster Vulns", "https://threatcluster.io/vulnerabilities/feed.xml", "🦠 Vulnerability Alert", 0xE67E22, "vulnerabilities", False),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "📰 Cyber Incident Report", 0x2ECC71, "incidents", False),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "📰 Cyber Incident Report", 0x2ECC71, "incidents", False),
        ("ThreatCluster", "https://threatcluster.io/dark-web/feed.xml", "🚨 Dark Web Victim Stream", 0xE74C3C, "ransomware", True)
    ]
    
    rss_tasks = [
        fetch_and_process_rss(session, pub, url, a_type, color, ch_key, trans_flag)
        for pub, url, a_type, color, ch_key, trans_flag in rss_catalog
    ]
    await asyncio.gather(*rss_tasks, return_exceptions=True)

# --- ENGINE ORCHESTRATION ---

async def main():
    await init_db()
    print("[*] Threat Feed Engine Active with Corrected Endpoints, Triage Sandbox Links, and Multi-Channel Routing.")
    
    connector = aiohttp.TCPConnector(limit=15, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
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
