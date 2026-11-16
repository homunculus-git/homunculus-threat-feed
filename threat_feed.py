from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from actor_ttps import format_threat_actor_info, format_actor_ttp_field
from collections import Counter
from contextlib import asynccontextmanager
import calendar
import random
import os
import re
import csv
import io
import html
import json
import time
import base64
import socket
import hashlib
import weakref
import ipaddress
import asyncio
import aiohttp
import aiosqlite
import feedparser
import urllib.parse
from dotenv import load_dotenv

_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(_ENV_PATH)

# --- WEBHOOK ROUTING MAP ---
WEBHOOK_CHANNELS = {
    "ransomware": os.getenv("DISCORD_WEBHOOK_RANSOMWARE"),
    "malware": os.getenv("DISCORD_WEBHOOK_MALWARE"),
    "infrastructure": os.getenv("DISCORD_WEBHOOK_INFRASTRUCTURE"),
    "phishing": os.getenv("DISCORD_WEBHOOK_PHISHING"),
    "vulnerabilities": os.getenv("DISCORD_WEBHOOK_VULNERABILITIES"),
    "gov_advisory": os.getenv("DISCORD_WEBHOOK_GOV_ADVISORY"),
    "incidents": os.getenv("DISCORD_WEBHOOK_INCIDENTS"),
    "podcasts": os.getenv("DISCORD_WEBHOOK_PODCASTS"),
    "research": os.getenv("DISCORD_WEBHOOK_RESEARCH"),
    "metrics_bounty": os.getenv("DISCORD_WEBHOOK_METRICS_BOUNTY"),
    "metrics_cve": os.getenv("DISCORD_WEBHOOK_METRICS_CVE"),
    "metrics_adversary": os.getenv("DISCORD_WEBHOOK_METRICS_ADVERSARY"),
    "metrics_infra": os.getenv("DISCORD_WEBHOOK_METRICS_INFRA"),
}

TRIAGE_LAB_HOST = os.getenv("TRIAGE_LAB_HOST", "http://127.0.0.1:9999")
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")
CONCURRENCY_SEMAPHORE = asyncio.Semaphore(5)

# --- DATABASE PERSISTENCE (NON-BLOCKING ASYNC) ---
DB_PATH = "threat_cache.db"


def _cache_set(cache_dict: dict, key, value, max_size: int = 500) -> None:
    """Insert into an in-memory dict cache while bounding maximum size (FIFO eviction)."""
    if key in cache_dict:
        cache_dict.pop(key, None)
    elif len(cache_dict) >= max_size:
        oldest_key = next(iter(cache_dict), None)
        if oldest_key is not None:
            cache_dict.pop(oldest_key, None)
    cache_dict[key] = value


@asynccontextmanager
async def open_db():
    """Open an aiosqlite connection configured with WAL mode and a 10-second busy timeout."""
    async with aiosqlite.connect(DB_PATH, timeout=10.0) as db:
        await db.execute("PRAGMA busy_timeout = 10000;")
        yield db


_DEDUP_LOCKS: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()


@asynccontextmanager
async def dedup_guard(*keys: str):
    """Serialize concurrent duplicate checks and dispatches for overlapping event/IOC/victim keys.
    Prevents concurrent collectors from double-firing on the same event while never dropping
    an alert if the first dispatch attempt fails."""
    norm_keys = sorted({str(k).strip().lower() for k in keys if k and str(k).strip()})
    locks: list[asyncio.Lock] = []
    for k in norm_keys:
        lock = _DEDUP_LOCKS.get(k)
        if lock is None:
            lock = asyncio.Lock()
            _DEDUP_LOCKS[k] = lock
        locks.append(lock)
    acquired: list[asyncio.Lock] = []
    try:
        for lock in locks:
            await lock.acquire()
            acquired.append(lock)
        yield
    finally:
        for lock in reversed(acquired):
            lock.release()


async def init_db():
    async with open_db() as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS seen_events (
                event_id TEXT PRIMARY KEY,
                source TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                threat_actor TEXT,
                target_industry TEXT,
                affected_product TEXT,
                country_code TEXT,
                ioc TEXT,
                title TEXT,
                tags TEXT,
                cvss_score REAL,
                severity TEXT,
                cwe TEXT,
                malware_family TEXT,
                asn TEXT
            )
        """)
        async with db.execute("PRAGMA table_info(seen_events)") as cur:
            existing = {row[1] for row in await cur.fetchall()}
        for col, col_type in (
            ("threat_actor", "TEXT"),
            ("target_industry", "TEXT"),
            ("affected_product", "TEXT"),
            ("country_code", "TEXT"),
            ("ioc", "TEXT"),
            ("title", "TEXT"),
            ("tags", "TEXT"),
            ("cvss_score", "REAL"),
            ("severity", "TEXT"),
            ("cwe", "TEXT"),
            ("malware_family", "TEXT"),
            ("asn", "TEXT"),
        ):
            if col not in existing:
                await db.execute(f"ALTER TABLE seen_events ADD COLUMN {col} {col_type}")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_seen_events_ioc ON seen_events(LOWER(ioc));")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_seen_events_title ON seen_events(LOWER(title));")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_seen_events_discovered_at ON seen_events(discovered_at);")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_seen_events_source_discovered ON seen_events(source, discovered_at);")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_seen_events_actor ON seen_events(LOWER(threat_actor));")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS dispatched_metrics (
                metric_id TEXT PRIMARY KEY,
                channel_key TEXT,
                trigger_type TEXT,
                subject TEXT,
                metric_value TEXT,
                dispatched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_dispatched_metrics_channel ON dispatched_metrics(channel_key);")
        await db.commit()


MAX_HTTP_RESPONSE_BYTES = 50 * 1024 * 1024  # 50 MiB limit for RSS/HTML responses (e.g. CyberWire Daily ~22 MiB)


async def _safe_text(resp: aiohttp.ClientResponse, max_bytes: int = MAX_HTTP_RESPONSE_BYTES) -> str:
    """Read full response body up to max_bytes until EOF to prevent memory exhaustion without truncating streams."""
    chunks = []
    total = 0
    while True:
        chunk = await resp.content.readany()
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"HTTP response exceeded {max_bytes} bytes")
        chunks.append(chunk)
    raw = b"".join(chunks)
    resp._body = raw
    try:
        charset = resp.get_encoding()
    except Exception:
        charset = resp.charset or "utf-8"
    return raw.decode(charset, errors="replace")


def _safe_md_url(url: str) -> str:
    """Sanitize parentheses and whitespace in URLs before embedding in Discord Markdown links."""
    return (
        str(url or "")
        .strip()
        .replace("(", "%28")
        .replace(")", "%29")
        .replace(" ", "%20")
    )

def normalize_ioc(raw_ioc: str) -> str:
    if not raw_ioc:
        return ""
    s = str(raw_ioc).strip().lower()
    s = re.sub(r"^https?://", "", s)
    if s.startswith("www."):
        s = s[4:]
    return s.rstrip("/")

async def is_duplicate(event_id: str, *, ioc: str = None, alt_event_ids: list[str] = None) -> bool:
    candidate_ids = [event_id]
    if alt_event_ids:
        candidate_ids.extend(eid for eid in alt_event_ids if eid)

    norm_ioc = normalize_ioc(ioc)[:300] if ioc else ""
    raw_ioc = str(ioc).strip().lower()[:300] if ioc else ""

    if norm_ioc:
        ip_port_slug = norm_ioc.replace(":", "_")
        candidate_ids.extend([
            f"feodo_{ip_port_slug}",
            f"sslbl_{ip_port_slug}",
            f"bazaar_{norm_ioc}",
            f"cisa_{norm_ioc}",
            f"cve_{norm_ioc}",
            f"phish_{norm_ioc}",
            get_stable_id("tfox_ioc", norm_ioc),
            get_stable_id("urlhaus_url", norm_ioc),
            get_stable_id("phish", raw_ioc),
        ])

    unique_ids = list(dict.fromkeys(candidate_ids))
    placeholders = ",".join("?" for _ in unique_ids)

    async with open_db() as db:
        async with db.execute(
            f"SELECT 1 FROM seen_events WHERE event_id IN ({placeholders}) LIMIT 1",
            tuple(unique_ids),
        ) as cursor:
            if await cursor.fetchone() is not None:
                return True

        if norm_ioc:
            ioc_variants = list(dict.fromkeys([
                raw_ioc,
                norm_ioc,
                f"http://{norm_ioc}",
                f"https://{norm_ioc}",
                f"http://{norm_ioc}/",
                f"https://{norm_ioc}/",
                f"http://www.{norm_ioc}",
                f"https://www.{norm_ioc}",
                f"http://www.{norm_ioc}/",
                f"https://www.{norm_ioc}/",
            ]))
            ioc_placeholders = ",".join("?" for _ in ioc_variants)
            async with db.execute(
                f"SELECT 1 FROM seen_events WHERE LOWER(ioc) IN ({ioc_placeholders}) LIMIT 1",
                tuple(ioc_variants),
            ) as cursor:
                if await cursor.fetchone() is not None:
                    return True

            if re.match(r"^cve-\d{4}-\d{4,}$", norm_ioc):
                async with db.execute(
                    "SELECT 1 FROM seen_events WHERE LOWER(TRIM(title)) = ? LIMIT 1",
                    (norm_ioc,),
                ) as cursor:
                    if await cursor.fetchone() is not None:
                        return True

    return False

async def record_event(event_id: str, source: str, *, threat_actor=None, target_industry=None,
                       affected_product=None, country_code=None, ioc=None, title=None, tags=None,
                       cvss_score=None, severity=None, cwe=None, malware_family=None, asn=None):
    async with open_db() as db:
        await db.execute(
            "INSERT OR IGNORE INTO seen_events "
            "(event_id, source, threat_actor, target_industry, affected_product, country_code, ioc, title, tags, "
            "cvss_score, severity, cwe, malware_family, asn) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, source, threat_actor, target_industry, affected_product, country_code, ioc, title, tags,
             cvss_score, severity, cwe, malware_family, asn),
        )
        await db.commit()

INDUSTRY_PATTERNS = {
    "Healthcare & Pharma": r"\b(health|hospital|clinic|pharma|medical|dental|care)\b",
    "Education & Research": r"\b(school|university|college|academy|district|education)\b",
    "Government & Municipal": r"\b(council|city|county|municip|ministry|gov|state|police|tribe)\b",
    "Financial Services": r"\b(bank|financial|insurance|credit union|capital|invest|fund|cu\b)\b",
    "Manufacturing & Industrial": r"\b(mfg|manufactur|industr|steel|packaging|metal|plastics|supply|specialty)\b",
    "Transportation & Logistics": r"\b(transport|logistics|freight|lines|shipping|bus|rail|aviation)\b",
    "Technology & IT Services": r"\b(tech|software|systems|digital|networks|cyber|solutions|telecom)\b",
    "Construction & Engineering": r"\b(construct|build|engineer|architect|contractor)\b",
    "Food & Agriculture": r"\b(foods?|meat|farms?|brew|beverage|bakery|dairy)\b",
}

async def get_actor_randomized_stat(threat_actor: str) -> str:
    cleaned = (threat_actor or "").strip()
    if not cleaned or cleaned.lower() in ("unattributed", "unknown", "unspecified", "anonymous", "none"):
        return "Activity Stat  : No specific syndicate attributed to this claim"

    stats = {
        "past_7": 0,
        "past_30": 0,
        "top_industry": None,
        "top_industry_count": 0,
    }

    try:
        async with open_db() as db:
            async with db.execute("""
                SELECT 
                    SUM(CASE WHEN discovered_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END),
                    SUM(CASE WHEN discovered_at >= datetime('now', '-30 days') THEN 1 ELSE 0 END)
                FROM seen_events 
                WHERE LOWER(threat_actor) = LOWER(?)
            """, (cleaned,)) as cur:
                row = await cur.fetchone()
                if row:
                    stats["past_7"] = int(row[0] or 0)
                    stats["past_30"] = int(row[1] or 0)

            async with db.execute("""
                SELECT target_industry, COUNT(*) as cnt
                FROM seen_events 
                WHERE LOWER(threat_actor) = LOWER(?)
                  AND target_industry IS NOT NULL
                  AND TRIM(target_industry) != ''
                  AND discovered_at >= datetime('now', '-30 days')
                GROUP BY target_industry
                ORDER BY cnt DESC
                LIMIT 1
            """, (cleaned,)) as cur:
                ind_row = await cur.fetchone()
                if ind_row and int(ind_row[1] or 0) >= 2:
                    stats["top_industry"] = str(ind_row[0]).strip()
                    stats["top_industry_count"] = int(ind_row[1])
    except Exception:
        pass

    # Include the current claim being dispatched (+1) in the 7-day and 30-day windows
    past_7 = stats["past_7"] + 1
    past_30 = max(stats["past_30"] + 1, past_7)
    top_ind = stats["top_industry"]
    top_cnt = stats["top_industry_count"]

    stat_line = (
        f"Tracked Tempo  : {past_7} claim{'s' if past_7 != 1 else ''} (7d) • "
        f"{past_30} claim{'s' if past_30 != 1 else ''} (30d) • ~{past_30 / 30:.1f}/day"
    )
    if top_ind and top_cnt >= 2:
        stat_line += f"\nVerified Sector: {top_ind} ({top_cnt} confirmed in 30d)"
    return stat_line

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
    # Strip anchor tags down to their visible text to prevent untrusted Markdown link injection / spoofing
    text = re.sub(r'<a\s+[^>]*>(.*?)</a>', r'\1', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<[^>]+>', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()

_PLACEHOLDER_VICTIM_SLUGS = {
    "unknown",
    "unknownvictim",
    "unidentifiedbreachclaim",
    "untitledfeedentry",
    "na",
    "none",
}

def normalize_victim_slug(victim: str) -> str:
    v = html.unescape(html.unescape(victim or "")).strip().lower()
    v = re.sub(r"^\([a-z0-9]{1,3}\)\s*", "", v)
    v = re.sub(r"^https?://", "", v)
    if v.startswith("www."):
        v = v[4:]
    v = re.sub(r"^(?:first\s+and\s+)?final\s+warning\s*[-—–:]\s*", "", v)
    v = re.sub(
        r"\s*[-—–]\s*(?:(?:first\s+and\s+)?final\s+warning(?:\s*(?:&|and)\s*sample)?|new\s+dl)\s*$",
        "",
        v,
    )
    paren_match = re.match(r"^(?P<base>.+?)\s*\((?P<paren>[^)]+)\)\s*$", v)
    if paren_match:
        base_slug = re.sub(r"[^a-z0-9]", "", paren_match.group("base"))
        paren_slug = re.sub(r"[^a-z0-9]", "", paren_match.group("paren"))
        if base_slug and paren_slug and (base_slug in paren_slug or paren_slug in base_slug):
            v = paren_match.group("base")
    slug = re.sub(r"[^a-z0-9]", "", v)
    return "" if slug in _PLACEHOLDER_VICTIM_SLUGS else slug

def normalize_leak_event_id(group: str, victim: str, fallback_id: str = "") -> str:
    clean_group = re.sub(r'[^a-z0-9]', '', html.unescape(group or "").lower())
    clean_victim = normalize_victim_slug(victim)
    if not clean_victim:
        return get_stable_id(f"victim_{clean_group}", fallback_id or (victim or "unknown"))
    return f"victim_{clean_group}_{clean_victim}"

async def is_ransomware_duplicate(event_id: str, group: str, victim: str) -> bool:
    unescaped_victim = html.unescape(html.unescape(victim or "")).strip()
    raw_clean_group = re.sub(r'[^a-z0-9]', '', html.unescape(group or "").lower())
    raw_clean_victim = re.sub(r'[^a-z0-9]', '', unescaped_victim.lower())
    raw_amp_victim = re.sub(r'[^a-z0-9]', '', (victim or "").lower())
    clean_victim = normalize_victim_slug(unescaped_victim)
    amp_clean_victim = (
        normalize_victim_slug(unescaped_victim.replace("&", "amp"))
        if "&" in unescaped_victim
        else ""
    )

    alt_ids = []
    for v_slug in (raw_clean_victim, raw_amp_victim, clean_victim, amp_clean_victim):
        if v_slug and v_slug not in _PLACEHOLDER_VICTIM_SLUGS:
            alt_ids.append(f"victim_{raw_clean_group}_{v_slug}")

    if await is_duplicate(event_id, alt_event_ids=alt_ids):
        return True

    slug_candidates = list(dict.fromkeys(
        s for s in (clean_victim, raw_clean_victim, amp_clean_victim, raw_amp_victim)
        if s and len(s) >= 3 and s not in _PLACEHOLDER_VICTIM_SLUGS
    ))

    async with open_db() as db:
        if slug_candidates:
            like_clauses = " OR ".join("event_id LIKE ? ESCAPE '\\'" for _ in slug_candidates)
            like_params = tuple(f"victim\\_%\\_{s}" for s in slug_candidates)
            async with db.execute(
                f"""
                SELECT 1 FROM seen_events
                WHERE event_id LIKE 'victim\\_%' ESCAPE '\\'
                  AND ({like_clauses})
                  AND discovered_at >= datetime('now', '-14 days')
                LIMIT 1
                """,
                like_params,
            ) as cur:
                if await cur.fetchone() is not None:
                    return True

        if (
            unescaped_victim
            and clean_victim
            and unescaped_victim.lower() not in ("unknown victim", "unknown", "unidentified breach claim")
        ):
            title_variants = list(dict.fromkeys([
                unescaped_victim,
                html.escape(unescaped_victim),
                (victim or "").strip(),
            ]))
            title_variants = [t for t in title_variants if t]
            t_placeholders = ",".join("LOWER(?)" for _ in title_variants)
            async with db.execute(
                f"""
                SELECT 1 FROM seen_events
                WHERE event_id LIKE 'victim\\_%' ESCAPE '\\'
                  AND LOWER(TRIM(title)) IN ({t_placeholders})
                  AND discovered_at >= datetime('now', '-14 days')
                LIMIT 1
                """,
                tuple(title_variants),
            ) as cur:
                if await cur.fetchone() is not None:
                    return True

    return False

def get_stable_id(prefix: str, content: str) -> str:
    digest = hashlib.sha256(content.encode()).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.split("%")[0])
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


async def resolve_safe_public_ip(host: str) -> str | None:
    """Resolve host asynchronously with a 4s timeout and verify ALL returned A/AAAA records are public IPs."""
    cleaned = (host or "").strip().strip("[]")
    if not cleaned:
        return None
    try:
        ipaddress.ip_address(cleaned)
        return cleaned if _is_public_ip(cleaned) else None
    except ValueError:
        pass

    try:
        addr_info = await asyncio.wait_for(
            asyncio.to_thread(socket.getaddrinfo, cleaned, None),
            timeout=4.0,
        )
        resolved_ips = [r[4][0] for r in addr_info if r and len(r) > 4 and r[4]]
        if not resolved_ips:
            return None
        # Reject host if ANY resolved record points to private/internal/loopback space (anti-rebinding)
        if not all(_is_public_ip(ip) for ip in resolved_ips):
            return None
        for ip in resolved_ips:
            if ":" not in ip:
                return ip
        return resolved_ips[0]
    except Exception:
        return None


# Standard browser headers to avoid Cloudflare/WAF 403 blocks
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# --- UNIVERSAL ASYNCHRONOUS AUTO-TRANSLATOR ENGINE ---
TRANSLATION_LOCK = asyncio.Lock()
TRANSLATION_CACHE = {}
TRANSLATION_ENDPOINT_COOLDOWN: dict[str, float] = {}

async def auto_translate_to_english(session: aiohttp.ClientSession, text: str) -> tuple[str, bool]:
    if not text or not text.strip():
        return "", False

    prefix_match = re.match(r"^(\[[^\]]*\]\s*)+", text)
    prefix = prefix_match.group(0) if prefix_match else ""
    cleaned = text[len(prefix):].strip()
    sample = cleaned if len(cleaned) > 3 else text.strip()

    if sample in TRANSLATION_CACHE:
        cached_text, cached_flag = TRANSLATION_CACHE[sample]
        return (f"{prefix}{cached_text}".strip() if cached_flag else text), cached_flag

    encoded = urllib.parse.quote(sample[:1500])
    endpoints = [
        ("gtx", f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=en&dt=t&dj=1&q={encoded}"),
        ("clients5", f"https://clients5.google.com/translate_a/t?client=dict-chrome-ex&sl=auto&tl=en&q={encoded}"),
        ("at", f"https://translate.googleapis.com/translate_a/single?client=at&sl=auto&tl=en&dt=t&dj=1&q={encoded}"),
        ("gtx_raw", f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=en&dt=t&q={encoded}"),
    ]

    async with TRANSLATION_LOCK:
        if sample in TRANSLATION_CACHE:
            cached_text, cached_flag = TRANSLATION_CACHE[sample]
            return (f"{prefix}{cached_text}".strip() if cached_flag else text), cached_flag

        now = time.time()
        for ep_key, url in endpoints:
            if now < TRANSLATION_ENDPOINT_COOLDOWN.get(ep_key, 0.0):
                continue
            try:
                async with session.get(url, headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=7)) as resp:
                    if resp.status in (429, 403, 503):
                        TRANSLATION_ENDPOINT_COOLDOWN[ep_key] = time.time() + (300 if resp.status == 429 else 600)
                        continue
                    if resp.status != 200:
                        continue
                    data = await resp.json(content_type=None)

                res, src = "", ""
                if isinstance(data, dict):
                    if "sentences" in data:
                        res = "".join(s.get("trans", "") for s in data.get("sentences", []) if isinstance(s, dict))
                        src = data.get("src", "")
                    elif "translation" in data:
                        res = data.get("translation", "")
                        src = data.get("info", {}).get("detectedSource", "")
                elif isinstance(data, list) and data:
                    if isinstance(data[0], list) and data[0] and isinstance(data[0][0], str):
                        res = "".join(item[0] for item in data if isinstance(item, list) and item and isinstance(item[0], str))
                        if len(data[0]) > 1 and isinstance(data[0][1], str):
                            src = data[0][1]
                    elif isinstance(data[0], list):
                        res = "".join(seg[0] for seg in data[0] if isinstance(seg, list) and seg and isinstance(seg[0], str))
                        if len(data) > 2 and isinstance(data[2], str):
                            src = data[2]
                    elif isinstance(data[0], str):
                        res = " ".join(s for s in data if isinstance(s, str))

                if src and src.lower().startswith("en"):
                    _cache_set(TRANSLATION_CACHE, sample, (sample, False), max_size=500)
                    return text, False

                if res and res.strip().lower() != sample.strip().lower():
                    clean_res = res.replace("\u200b", "").strip()
                    _cache_set(TRANSLATION_CACHE, sample, (clean_res, True), max_size=500)
                    await asyncio.sleep(0.25)
                    return f"{prefix}{clean_res}".strip(), True
            except Exception:
                await asyncio.sleep(0.3)

    return text, False

# --- MITRE ATT&CK & THREAT ACTOR ENRICHMENT ENGINES ---

KNOWN_MITRE_GROUPS = {
    "akira": ("G1024", "Akira", "groups"),
    "qilin": ("G1050", "Water Galura (Qilin operators)", "groups"),
    "play": ("G1040", "Play", "groups"),
    "incransom": ("G1032", "INC Ransom", "groups"),
    "lazarus": ("G0032", "Lazarus Group", "groups"),
    "apt29": ("G0016", "APT29 (Cozy Bear)", "groups"),
    "apt28": ("G0007", "APT28 (Fancy Bear)", "groups"),
    "scatteredspider": ("G1015", "Scattered Spider", "groups"),
    "lockbit": ("S1202", "LockBit", "software"),
    "blackbasta": ("G1046", "Black Basta", "groups"),
    "cl0p": ("G0092", "CL0P", "groups"),
    "rhysida": ("G1025", "Rhysida", "groups"),
}

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
            "Technical malware infection analysis with staged payload execution, "
            "network observables, and IoC artifact extractions."
        )
        
    return platform, threat_type, desc

_IP_META_CACHE: dict[str, tuple[float, dict]] = {}


async def lookup_ip_metadata(session: aiohttp.ClientSession, ip: str) -> dict:
    """Resolve IP ASN/organization/country over HTTPS with bounded in-memory caching and fallback."""
    now = time.time()
    cached = _IP_META_CACHE.get(ip)
    if cached and (now - cached[0]) < 3600:
        return cached[1]

    meta = {"org": "Unknown Host", "country": "N/A", "country_code": None, "as_num": ""}
    # Primary HTTPS lookup via ipwho.is (encrypted TLS, no cleartext IP leakage)
    try:
        async with session.get(f"https://ipwho.is/{ip}", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, dict) and data.get("success") is True:
                    conn_info = data.get("connection") or {}
                    asn_val = conn_info.get("asn")
                    as_num = f"AS{asn_val}" if asn_val else ""
                    org = (conn_info.get("org") or conn_info.get("isp") or "").strip() or "Unknown Host"
                    country = (data.get("country") or "").strip() or "N/A"
                    cc = (data.get("country_code") or "").strip().upper() or None
                    meta = {"org": org, "country": country, "country_code": cc, "as_num": as_num}
                    _cache_set(_IP_META_CACHE, ip, (now, meta), max_size=500)
                    return meta
    except Exception:
        pass

    # Secondary encrypted HTTPS fallback via ipinfo.io (avoids cleartext HTTP leakage)
    try:
        async with session.get(f"https://ipinfo.io/{ip}/json", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, dict) and data.get("ip"):
                    raw_org = (data.get("org") or "").strip()
                    as_num = ""
                    org = raw_org or "Unknown Host"
                    if raw_org.upper().startswith("AS") and " " in raw_org:
                        first_tok, rest_org = raw_org.split(" ", 1)
                        if first_tok[2:].isdigit():
                            as_num = first_tok.upper()
                            org = rest_org.strip() or raw_org
                    cc = (data.get("country") or "").strip().upper() or None
                    country = cc or "N/A"
                    meta = {"org": org, "country": country, "country_code": cc, "as_num": as_num}
                    _cache_set(_IP_META_CACHE, ip, (now, meta), max_size=500)
                    return meta
    except Exception:
        pass

    # Tertiary fallback to ip-api.com if both HTTPS providers are unavailable or rate-limited
    try:
        async with session.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as", timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, dict) and data.get("status") == "success":
                    as_raw = (data.get("as") or "").strip()
                    as_num = as_raw.split(" ")[0] if as_raw else ""
                    org = (data.get("org") or data.get("isp") or as_raw or "").strip() or "Unknown Host"
                    country = (data.get("country") or "").strip() or "N/A"
                    cc = (data.get("countryCode") or "").strip().upper() or None
                    meta = {"org": org, "country": country, "country_code": cc, "as_num": as_num}
                    _cache_set(_IP_META_CACHE, ip, (now, meta), max_size=500)
                    return meta
    except Exception:
        pass

    return meta


async def resolve_host_metadata(session: aiohttp.ClientSession, raw_url: str) -> dict:
    try:
        domain = urllib.parse.urlparse(raw_url).hostname or ""
        ip = await resolve_safe_public_ip(domain)
        if not ip:
            return {"ip": "Unresolved", "org": "Unknown Host", "country": "N/A", "country_code": None}

        meta = await lookup_ip_metadata(session, ip)
        return {"ip": ip, "org": meta["org"], "country": meta["country"], "country_code": meta.get("country_code")}
    except Exception:
        return {"ip": "Unresolved", "org": "Unknown Host", "country": "N/A", "country_code": None}


async def enrich_dropper_infrastructure(session: aiohttp.ClientSession, raw_url: str) -> dict:
    info = {
        "ip": None,
        "routing": "Unknown ASN",
        "country_code": None,
        "subnet_note": "Clean / Unflagged",
        "strains": []
    }
    try:
        host = urllib.parse.urlparse(raw_url).hostname or ""
        ip = await resolve_safe_public_ip(host)
        if not ip:
            return info

        info["ip"] = ip
        meta = await lookup_ip_metadata(session, ip)
        info["country_code"] = meta.get("country_code")
        if meta["org"] != "Unknown Host" or meta["as_num"]:
            as_prefix = f"`{meta['as_num']}` " if meta["as_num"] else ""
            cc_suffix = f" ({meta['country']})" if meta["country"] and meta["country"] != "N/A" else ""
            info["routing"] = f"{as_prefix}{meta['org']}{cc_suffix}".strip()

        if ip and ABUSECH_AUTH_KEY:
            headers = {"Auth-Key": ABUSECH_AUTH_KEY}
            async with session.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ip}, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as tf:
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
        "Microsoft 365 / Entra ID Harvest": r"(office365|microsoft|outlook|sharepoint|onedrive|o365|msft|login\.live|owa|adfs|bpos|intune)",
        "Google Workspace / Accounts": r"(google|gmail|accounts-google|gsuite|gdrive|docs-google|drive-google)",
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

def extract_malware_family(raw_tags: str) -> str:
    if not raw_tags or raw_tags.strip() in ("None", ""):
        return "Unclassified Dropper"
    
    ignore_tokens = {
        "exe", "elf", "dll", "sh", "bin", "zip", "rar", "32-bit", "64-bit", "ps1", "powershell",
        "script", "github", "gitlab", "discord", "telegram", "pastebin", "stego", "ascii",
        "drop", "dropper", "downloader", "payload", "malware", "trojan", "stealer",
        "arm", "mips", "x86", "x64", "i386", "sparc", "powerpc", "intel", "amd64",
        "upx", "windows", "linux", "doc", "docx", "xls", "xlsx", "pdf", "iso", "vbs",
        "lnk", "hta", "apk", "32bit", "64bit", "compromised", "packed", "office"
    }
    
    known_families = {
        "mozi": "Mozi", "mirai": "Mirai", "gafgyt": "Gafgyt", "xworm": "XWorm",
        "darkcloud": "DarkCloud", "asyncrat": "AsyncRAT", "remcos": "Remcos",
        "agenttesla": "AgentTesla", "lumma": "Lumma Stealer", "stealc": "Stealc",
        "redline": "RedLine", "vidar": "Vidar", "amadey": "Amadey",
        "salatstealer": "SalatStealer", "zapret": "Zapret", "cobaltstrike": "Cobalt Strike"
    }
    
    tags = [t.strip() for t in raw_tags.replace(",", " ").split() if t.strip()]
    for t in tags:
        low = t.lower()
        if low in known_families:
            return known_families[low]
            
    for t in tags:
        if t.lower() not in ignore_tokens:
            return t.capitalize()
            
    return "Malware Payload"

# --- STRICT DISCORD EMBED ROUTER ---

async def is_first_run() -> bool:
    async with open_db() as db:
        async with db.execute("SELECT COUNT(*) FROM seen_events") as cursor:
            row = await cursor.fetchone()
            return not row or row[0] == 0


def parse_datetime_utc(raw_dt) -> datetime | None:
    if not raw_dt:
        return None
    if isinstance(raw_dt, datetime):
        return raw_dt if raw_dt.tzinfo else raw_dt.replace(tzinfo=timezone.utc)
    if isinstance(raw_dt, time.struct_time):
        try:
            return datetime.fromtimestamp(calendar.timegm(raw_dt), tz=timezone.utc)
        except Exception:
            pass

    s = str(raw_dt).strip()
    if not s or s.lower() in ("none", "not provided", "unknown", "-"):
        return None

    # 1. Try RFC 2822 / 822 (standard RSS date format)
    try:
        dt = parsedate_to_datetime(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    # 2. Try ISO 8601 with timezone
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    # 3. Fallback to naive string patterns
    s_clean = s.replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s_clean[:len(fmt)], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    return None


def is_older_than(raw_dt, days: int = 7) -> bool:
    """Returns True if the parsed timestamp is older than `days` ago."""
    dt = parse_datetime_utc(raw_dt)
    if dt is None:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return dt < cutoff


def format_clean_date(raw_dt) -> str:
    """Converts ISO or RFC timestamps to UTC format; returns fallback if missing."""
    if not raw_dt:
        return "Not provided"
    dt = parse_datetime_utc(raw_dt)
    if dt:
        return dt.strftime("%d %b %Y • %H:%M:%S UTC")
    return str(raw_dt).strip()


def clamp_discord_embed(embed: dict) -> dict:
    if len(embed.get("description", "")) > 1400:
        embed["description"] = embed["description"][:1400] + "..."

    fields = embed.get("fields") or []

    embed.pop("timestamp", None)

    embed["title"] = (embed.get("title") or "")[:256]
    embed["description"] = (embed.get("description") or "")[:2000]

    limited_fields = []
    total_length = len(embed["title"]) + len(embed["description"])
    footer_text = embed.get("footer", {}).get("text", "") if embed.get("footer") else ""
    total_length += len(footer_text)

    for field in fields[:25]:
        name = (field.get("name") or "Field")[:256]
        value = (field.get("value") or "Not provided")[:1024]
        remaining = 6000 - total_length - len(name) - len(value)
        if remaining < 0:
            break
        limited_fields.append({"name": name, "value": value, "inline": bool(field.get("inline"))})
        total_length += len(name) + len(value)

    embed["fields"] = limited_fields
    return embed


async def dispatch_discord_embed(
    session: aiohttp.ClientSession,
    channel_key: str,
    title: str,
    description: str,
    fields: list,
    color: int,
    image_url: str = None,
    mitre_tactics: str = None
) -> bool:
    target_webhook = WEBHOOK_CHANNELS.get(channel_key)

    if not target_webhook:
        print(f"[Discord Error] {channel_key}: no webhook configured")
        return False

    if not target_webhook.startswith(("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/")):
        print(f"[Discord Error] {channel_key}: invalid webhook URL")
        return False

    now_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    footer_text = f"ATT&CK: {mitre_tactics} • Alert Dispatched: {now_stamp}" if mitre_tactics else f"Alert Dispatched: {now_stamp}"

    embed = {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {"text": footer_text}
    }

    if image_url and image_url.startswith("http"):
        embed["image"] = {"url": image_url}

    embed = clamp_discord_embed(embed)
    payload = {"embeds": [embed]}

    for attempt in range(4):
        try:
            async with session.post(
                target_webhook,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as response:
                if response.status in (200, 204):
                    return True

                if response.status == 429:
                    retry_after = 1.5
                    try:
                        retry_data = await response.json()
                        retry_after = float(retry_data.get("retry_after", 1.5))
                    except Exception:
                        pass
                    await asyncio.sleep(retry_after + 0.25)
                    continue

                response_body = await response.text()
                print(f"[Discord Error] {channel_key}: HTTP {response.status}: {response_body[:500]}")

                if response.status in (500, 502, 503, 504):
                    await asyncio.sleep(2 ** attempt)
                    continue

                return False

        except (aiohttp.ClientError, asyncio.TimeoutError) as error:
            print(f"[Discord Error] {channel_key}: {error}")
            await asyncio.sleep(2 ** attempt)

    return False



# --- COLLECTOR TASKS ---

def ransomlook_source_links(post: dict, group: str) -> str:
    raw = ""
    for key in ("link", "url", "post_url"):
        value = post.get(key)
        if isinstance(value, str) and value.strip().lower().startswith(("http://", "https://")):
            raw = value.strip()
            break

    parts = ["RansomLook API"]
    if raw:
        host = urllib.parse.urlparse(raw).netloc.lower()
        if host.split(":")[0].endswith(".onion"):
            parts.append("Leak site (defanged): `" + defang_url(raw)[:150] + "`")
        else:
            parts.append(f"[Inspect leak page]({_safe_md_url(raw)})")

    clean_group = (group or "").strip().lower()
    if clean_group and clean_group not in ("unknown", "unattributed", "unspecified", "anonymous"):
        slug = urllib.parse.quote(clean_group, safe="")
        parts.append(f"[RansomLook group page](https://www.ransomlook.io/group/{slug})")
    return "\n".join(parts)[:1000]


# --- DARK WEB INFORMER ENRICHMENT & STREAM ENGINE ---
DARKWEBINFORMER_RSS_URL = "https://darkwebinformer.com/rss/"
DARKWEBINFORMER_API_KEY = os.getenv("DARKWEBINFORMER_API_KEY", "")
_DWI_CACHE = {"ts": 0.0, "items": []}

def parse_darkwebinformer_entry(entry: dict) -> dict:
    raw_title = html.unescape(html.unescape(str(entry.get("title") or ""))).strip()
    raw_summary = clean_html_to_markdown(entry.get("summary") or entry.get("description") or "")
    entry_link = (entry.get("link") or "").strip()
    raw_id = (entry.get("id") or entry_link).strip()
    raw_pub = str(entry.get("published") or entry.get("updated") or "").strip()
    categories = [
        str(t.get("term")).strip()
        for t in (entry.get("tags") or [])
        if isinstance(t, dict) and t.get("term")
    ]

    image_url = None
    media_list = entry.get("media_content") or []
    if isinstance(media_list, list) and media_list:
        first_media = media_list[0]
        if isinstance(first_media, dict) and str(first_media.get("url") or "").startswith("http"):
            image_url = first_media["url"]

    content_blocks = entry.get("content") or []
    raw_html = ""
    if isinstance(content_blocks, list) and content_blocks and isinstance(content_blocks[0], dict):
        raw_html = content_blocks[0].get("value") or ""

    report_type = None
    key_match = re.search(
        r'<span\s+class="pill\s+key[^"]*"[^>]*>(?:<span[^>]*>.*?</span>)?(.*?)</span>',
        raw_html,
        flags=re.I | re.S,
    )
    if key_match:
        report_type = clean_html_to_markdown(key_match.group(1)) or None

    country = None
    country_code = None
    country_match = re.search(r'<span\s+class="pill\s+country-badge[^"]*"[^>]*>(.*?)</span>', raw_html, flags=re.I | re.S)
    if country_match:
        country_inner = country_match.group(1)
        flag_match = re.search(r'flagcdn\.com/w\d+/([a-z]{2})\.png', country_inner, flags=re.I)
        if flag_match:
            country_code = flag_match.group(1).upper()
        country = clean_html_to_markdown(country_inner) or None

    warn_pills = []
    for wm in re.finditer(r'<span\s+class="pill\s+warn[^"]*"[^>]*>(.*?)</span>', raw_html, flags=re.I | re.S):
        cleaned_pill = clean_html_to_markdown(wm.group(1))
        if cleaned_pill:
            warn_pills.append(cleaned_pill)

    sector = warn_pills[0] if warn_pills else None
    exposed_data = ", ".join(warn_pills[1:]) if len(warn_pills) > 1 else None

    actor = None
    actor_patterns = [
        r'\bhandle\s+["\u201c]([^"\u201d]{2,40})["\u201d]',
        r'\bthreat\s+actor\s+["\u201c]([^"\u201d]{2,40})["\u201d]',
        r'\bclaimed\s+by\s+([A-Za-z0-9_.\-]{2,40})',
        r'\b([A-Za-z0-9_.\-]{2,30})\s+ransomware\s+(?:group|gang|syndicate|claim)',
    ]
    combined_source_text = f"{raw_title} {raw_summary}"
    for pat in actor_patterns:
        am = re.search(pat, combined_source_text, flags=re.I)
        if am:
            candidate = am.group(1).strip()
            if candidate.lower() not in ("a", "an", "the", "unknown", "unattributed", "new"):
                actor = candidate
                break

    victim = None
    victim_match = re.match(
        r"^(?P<v>.+?)\s+(?:Breach\s+Claim|Ransomware\s+Claim|Data\s+Breach|Allegedly\s+Breached|Claim\s+Says|Hit\s+by|Targeted\s+by)\b",
        raw_title,
        flags=re.I,
    )
    if victim_match:
        victim = victim_match.group("v").strip(" -—–:")

    return {
        "title": raw_title,
        "victim": victim,
        "victim_slug": normalize_victim_slug(victim) if victim else "",
        "actor": actor,
        "summary": raw_summary,
        "link": entry_link,
        "guid": raw_id,
        "published": raw_pub,
        "published_parsed": entry.get("published_parsed"),
        "categories": categories,
        "report_type": report_type,
        "country": country,
        "country_code": country_code,
        "sector": sector,
        "exposed_data": exposed_data,
        "image_url": image_url,
    }

async def fetch_darkwebinformer_items(session: aiohttp.ClientSession) -> list[dict]:
    now = time.time()
    if _DWI_CACHE["items"] and (now - _DWI_CACHE["ts"] < 240):
        return _DWI_CACHE["items"]
    try:
        async with session.get(
            DARKWEBINFORMER_RSS_URL,
            headers=BROWSER_HEADERS,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 200:
                feed = feedparser.parse(await _safe_text(resp))
                parsed = [
                    parse_darkwebinformer_entry(e)
                    for e in (feed.entries or [])
                    if (e.get("title") or "").strip()
                    and (e.get("link") or "").strip()
                    and (e.get("published") or e.get("updated") or e.get("published_parsed"))
                ]
                _DWI_CACHE["ts"] = now
                _DWI_CACHE["items"] = parsed
                return parsed
    except Exception as err:
        print(f"[Collector Error] Dark Web Informer cache fetch: {err}")
    return _DWI_CACHE["items"]

def lookup_dwi_enrichment(dwi_items: list[dict], victim: str) -> dict | None:
    slug = normalize_victim_slug(victim)
    if not slug or len(slug) < 3:
        return None
    for item in dwi_items:
        item_slug = item.get("victim_slug") or ""
        if item_slug and (item_slug == slug or (len(slug) >= 5 and slug in item_slug)):
            return item
        title_slug = re.sub(r"[^a-z0-9]", "", (item.get("title") or "").lower())
        if len(slug) >= 5 and title_slug.startswith(slug):
            return item
    return None

_ACTOR_VALUE_LINK_CACHE: dict[str, tuple[float, str | None]] = {}
_CISA_STOPRANSOMWARE_CACHE: dict[str, object] = {"ts": 0.0, "items": []}


async def fetch_cisa_stopransomware_advisories(session: aiohttp.ClientSession) -> list[tuple[str, str]]:
    """Fetch and cache official CISA #StopRansomware advisory links and titles."""
    now = time.time()
    if _CISA_STOPRANSOMWARE_CACHE["items"] and (now - float(_CISA_STOPRANSOMWARE_CACHE["ts"])) < 3600:
        return _CISA_STOPRANSOMWARE_CACHE["items"]  # type: ignore[return-value]

    url = "https://www.cisa.gov/stopransomware/official-alerts-statements-cisa"
    items: list[tuple[str, str]] = []
    try:
        async with session.get(url, headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status == 200:
                raw_html = await _safe_text(resp)
                for m in re.finditer(
                    r'<a[^>]+href="((?:https?://www\.cisa\.gov)?/news-events/cybersecurity-advisories/[^"]+)"[^>]*>(.*?)</a>',
                    raw_html,
                    flags=re.IGNORECASE | re.DOTALL,
                ):
                    href = m.group(1).strip()
                    if href.startswith("/"):
                        href = f"https://www.cisa.gov{href}"
                    anchor_text = html.unescape(re.sub(r"<[^>]+>", " ", m.group(2))).strip()
                    anchor_text = re.sub(r"\s+", " ", anchor_text)
                    if anchor_text:
                        items.append((anchor_text, href))
                if items:
                    _CISA_STOPRANSOMWARE_CACHE["ts"] = now
                    _CISA_STOPRANSOMWARE_CACHE["items"] = items
    except Exception:
        pass
    return items


async def resolve_actor_value_add_link(session: aiohttp.ClientSession, threat_actor: str) -> str | None:
    """
    Resolve the non-duplicating value-add dossier link for a ransomware actor:
      1. AlienVault OTX pulses (if matching pulses exist on OTX)
      2. Official CISA #StopRansomware advisory (Option 3, if matching advisory exists on CISA)
      3. None -> caller falls back to RansomLook (or Ransomware.live if publisher is RansomLook)
    """
    cleaned = (threat_actor or "").strip()
    slug = re.sub(r"[^a-z0-9]", "", cleaned.lower())
    if not slug or len(slug) < 2 or slug in ("unattributed", "unknown", "unspecified", "anonymous", "none", "na"):
        return None

    now = time.time()
    cached = _ACTOR_VALUE_LINK_CACHE.get(slug)
    if cached and (now - cached[0]) < 3600:
        return cached[1]

    # 1. AlienVault OTX lookup
    q_str = f"{cleaned} ransomware"
    otx_api_url = f"https://otx.alienvault.com/otxapi/pulses/?q={urllib.parse.quote(q_str)}&limit=5"
    try:
        async with session.get(
            otx_api_url,
            headers={**BROWSER_HEADERS, "Accept": "application/json"},
            timeout=aiohttp.ClientTimeout(total=6),
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                results = (data.get("results") or []) if isinstance(data, dict) else []
                matching = []
                for p in results:
                    if not isinstance(p, dict):
                        continue
                    p_name = (p.get("name") or "").lower()
                    p_desc = (p.get("description") or "").lower()
                    p_adv = str(p.get("adversary") or "").lower()
                    p_tags = [str(t).lower() for t in (p.get("tags") or [])]
                    if (
                        cleaned.lower() in p_name
                        or slug in re.sub(r"[^a-z0-9]", "", p_name)
                        or cleaned.lower() in p_desc
                        or cleaned.lower() in p_adv
                        or any(cleaned.lower() in t or slug in re.sub(r"[^a-z0-9]", "", t) for t in p_tags)
                    ):
                        matching.append(p)
                if matching:
                    total_pulses = (data.get("count") if isinstance(data, dict) else None) or len(matching)
                    browse_url = f"https://otx.alienvault.com/browse/global/pulses?q={urllib.parse.quote(q_str)}"
                    label = f"AlienVault OTX ({total_pulses} Pulse{'s' if total_pulses != 1 else ''})"
                    link_md = f"[{label}]({browse_url})"
                    _cache_set(_ACTOR_VALUE_LINK_CACHE, slug, (now, link_md), max_size=500)
                    return link_md
    except Exception:
        pass

    # 2. Option 3: Official CISA #StopRansomware Advisory lookup
    cisa_items = await fetch_cisa_stopransomware_advisories(session)
    for adv_title, adv_url in cisa_items:
        title_low = adv_title.lower()
        title_slug = re.sub(r"[^a-z0-9]", "", title_low)
        url_low = adv_url.lower()
        if (
            re.search(r"\b" + re.escape(cleaned.lower()) + r"\b", title_low)
            or (len(slug) >= 4 and slug in title_slug)
            or (len(slug) >= 4 and slug in url_low)
        ):
            code_match = re.search(r"/(aa\d{2}-\d{3}[a-z]?)\b", url_low, flags=re.IGNORECASE)
            label = f"CISA #StopRansomware ({code_match.group(1).upper()})" if code_match else "CISA #StopRansomware"
            link_md = f"[{label}]({adv_url})"
            _cache_set(_ACTOR_VALUE_LINK_CACHE, slug, (now, link_md), max_size=500)
            return link_md

    # 3. Fallback to None (handled by format_threat_actor_info: RansomLook unless publisher is RansomLook)
    _cache_set(_ACTOR_VALUE_LINK_CACHE, slug, (now, None), max_size=500)
    return None


def build_ransomware_fields(
    *,
    publisher: str,
    group: str,
    date_str: str,
    claim_text: str,
    source_link_name: str,
    source_link_value: str,
    actor_stat: str,
    dwi_match: dict | None = None,
    extra_dossier_link: str | None = None,
) -> list[dict]:
    actor_display = (group or "").strip() or "Unattributed"
    fields = [
        {"name": "Publisher", "value": publisher, "inline": True},
        {"name": "Threat Actor", "value": f"**{actor_display}**", "inline": True},
        {"name": "Date Discovered", "value": f"`{date_str}`", "inline": True},
    ]

    if dwi_match:
        if dwi_match.get("country"):
            cc_suffix = f" (`{dwi_match['country_code']}`)" if dwi_match.get("country_code") else ""
            fields.append({"name": "Victim Country", "value": f"{dwi_match['country']}{cc_suffix}", "inline": True})
        if dwi_match.get("sector"):
            fields.append({"name": "Target Sector", "value": f"`{dwi_match['sector']}`", "inline": True})
        if dwi_match.get("exposed_data"):
            fields.append({"name": "Exposed Assets", "value": f"`{dwi_match['exposed_data']}`", "inline": True})

    effective_claim = (claim_text or "").strip()
    if not effective_claim and dwi_match and dwi_match.get("summary"):
        effective_claim = dwi_match["summary"]

    if effective_claim:
        claim_val = f">>> {effective_claim[:950]}"
    else:
        claim_val = "Listed on a ransomware extortion portal. The source published no claim text."

    fields.append({
        "name": "Extortion Notice / Group Claim",
        "value": claim_val,
        "inline": False,
    })

    link_val = source_link_value
    if dwi_match and dwi_match.get("link") and dwi_match["link"] not in link_val:
        link_val = f"{link_val} • [Dark Web Informer Report]({dwi_match['link']})"

    fields.append({
        "name": source_link_name,
        "value": link_val,
        "inline": False,
    })
    fields.append(
        format_threat_actor_info(
            actor_display,
            actor_stat,
            publisher=publisher,
            extra_dossier_link=extra_dossier_link,
        )
    )
    return fields


async def poll_leak_trackers(session: aiohttp.ClientSession):
    bootstrap_limit = 2 if await is_first_run() else None
    dwi_items = await fetch_darkwebinformer_items(session)

    # 1. Ransomware.live victim RSS feed
    try:
        async with session.get(
            "https://ransomware.live/rss.xml",
            headers=BROWSER_HEADERS,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as response:
            if response.status == 200:
                feed = feedparser.parse(await _safe_text(response))
                entries = feed.entries[:bootstrap_limit] if bootstrap_limit else feed.entries

                for entry in (reversed(entries) if not bootstrap_limit else entries):
                    try:
                        entry_link = (entry.get("link") or "").strip()
                        title = html.unescape(html.unescape(str(entry.get("title") or ""))).strip()
                        raw_pub_check = str(entry.get("published") or entry.get("updated") or "").strip()
                        if not title or not entry_link or not (raw_pub_check or entry.get("published_parsed")):
                            continue

                        _m = re.match(r"^\W*(?P<g>.+?)\s+has just published a new victim\s*:\s*(?P<v>.+)$", title, flags=re.IGNORECASE | re.DOTALL)
                        if _m:
                            group = _m.group("g").strip()
                            victim = _m.group("v").strip()
                        elif "claimed by" in title.lower():
                            parts = re.split(r"\s+[—–-]?\s*claimed by\s+", title, flags=re.IGNORECASE, maxsplit=1)
                            victim = parts[0].strip(" -—–") or title
                            group = parts[1].strip() if len(parts) > 1 else "Unattributed"
                        else:
                            victim = title
                            group = "Unattributed"

                        event_id = normalize_leak_event_id(group, victim, fallback_id=entry_link or title)

                        if await is_ransomware_duplicate(event_id, group, victim):
                            continue

                        raw_pub = str(entry.get("published") or entry.get("updated") or "").strip()
                        if is_older_than(raw_pub or entry.get("published_parsed"), days=7):
                            continue

                        clean_v_slug = normalize_victim_slug(victim)
                        guard_keys = (event_id, f"victim:{clean_v_slug}" if len(clean_v_slug) >= 3 else "")
                        dispatched = False
                        async with dedup_guard(*guard_keys):
                            if await is_ransomware_duplicate(event_id, group, victim):
                                continue

                            raw_note = entry.get("summary", "") or entry.get("description", "")
                            clean_note = clean_html_to_markdown(raw_note)[:450]
                            if clean_note.strip().lower() in ("n/a", "na", "none", "-", "unknown"):
                                clean_note = ""
                            translated_note, was_translated = await auto_translate_to_english(session, clean_note)

                            raw_pub = str(entry.get("published") or entry.get("updated") or "").strip()
                            clean_pub_fmt = format_clean_date(raw_pub) if raw_pub else "Not provided"
                            actor_stat = await get_actor_randomized_stat(group)
                            dwi_match = lookup_dwi_enrichment(dwi_items, victim)
                            actor_dossier_link = await resolve_actor_value_add_link(session, group)

                            fields = build_ransomware_fields(
                                publisher="Ransomware.live",
                                group=group,
                                date_str=clean_pub_fmt,
                                claim_text=(translated_note or clean_note),
                                source_link_name="Discovery Link",
                                source_link_value=(f"[Inspect Leak Page]({entry_link})" if entry_link else "Not provided"),
                                actor_stat=actor_stat,
                                dwi_match=dwi_match,
                                extra_dossier_link=actor_dossier_link,
                            )
                            prefix = "🚨 Ransomware Alert [Translated]:" if was_translated else "🚨 Ransomware Alert:"

                            dispatched = await dispatch_discord_embed(
                                session=session,
                                channel_key="ransomware",
                                title=f"{prefix} {victim[:180]}",
                                description="",
                                fields=fields,
                                color=0xE74C3C,
                                image_url=(dwi_match.get("image_url") if dwi_match else None),
                                mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service",
                            )

                            if dispatched:
                                rss_cc = None
                                for _t in (entry.get("tags") or []):
                                    _term = str(_t.get("term") or "").strip().upper() if isinstance(_t, dict) else ""
                                    if len(_term) == 2 and _term.isalpha() and _term not in ("NA", "XX", "UN"):
                                        rss_cc = "GB" if _term == "UK" else _term
                                        break
                                await record_event(
                                    event_id,
                                    "Ransomware.live",
                                    threat_actor=(group if group != "Unattributed" else None),
                                    target_industry=(dwi_match.get("sector") if dwi_match else None),
                                    country_code=((dwi_match.get("country_code") if dwi_match else None) or rss_cc),
                                    title=str(victim)[:200],
                                )
                        if dispatched:
                            await asyncio.sleep(0.5)
                    except Exception as item_err:
                        print(f"[Collector Error] Ransomware.live item: {item_err}")
            else:
                print(f"[Collector Error] Ransomware.live RSS: HTTP {response.status}")

    except Exception as error:
        print(f"[Collector Error] Ransomware.live RSS: {error}")

    # 2. RansomLook victim API
    try:
        async with session.get(
            "https://www.ransomlook.io/api/posts?days=7",
            headers=BROWSER_HEADERS,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as response:
            if response.status == 200:
                payload = await response.json(content_type=None)

                if isinstance(payload, list):
                    posts = payload
                elif isinstance(payload, dict):
                    posts = payload.get("data") or payload.get("posts") or payload.get("results") or []
                else:
                    posts = []

                if bootstrap_limit:
                    posts = posts[:bootstrap_limit]

                for post in (reversed(posts) if not bootstrap_limit else posts):
                    try:
                        if not isinstance(post, dict):
                            continue

                        victim = html.unescape(html.unescape(str(post.get("post_title") or post.get("victim") or "Unknown victim"))).strip()
                        group = html.unescape(html.unescape(str(post.get("group_name") or post.get("group") or "Unattributed"))).strip()
                        post_fallback = str(post.get("link") or post.get("url") or post.get("discovered") or victim)
                        event_id = normalize_leak_event_id(group, victim, fallback_id=post_fallback)

                        if await is_ransomware_duplicate(event_id, group, victim):
                            continue

                        raw_discovered = post.get("discovered") or ""
                        if is_older_than(raw_discovered, days=7):
                            continue

                        clean_v_slug = normalize_victim_slug(victim)
                        guard_keys = (event_id, f"victim:{clean_v_slug}" if len(clean_v_slug) >= 3 else "")
                        dispatched = False
                        async with dedup_guard(*guard_keys):
                            if await is_ransomware_duplicate(event_id, group, victim):
                                continue

                            raw_note = post.get("description") or ""
                            clean_note = clean_html_to_markdown(raw_note)[:450]
                            translated_note, was_translated = await auto_translate_to_english(session, clean_note)

                            prefix = "🚨 Ransomware Alert [Translated]:" if was_translated else "🚨 Ransomware Alert:"

                            clean_obs = format_clean_date(post.get("discovered") or "")
                            actor_stat = await get_actor_randomized_stat(group)
                            dwi_match = lookup_dwi_enrichment(dwi_items, victim)
                            actor_dossier_link = await resolve_actor_value_add_link(session, group)

                            rl_fields = build_ransomware_fields(
                                publisher="RansomLook",
                                group=group,
                                date_str=clean_obs,
                                claim_text=(translated_note or clean_note),
                                source_link_name="Source / Investigation",
                                source_link_value=ransomlook_source_links(post, group),
                                actor_stat=actor_stat,
                                dwi_match=dwi_match,
                                extra_dossier_link=actor_dossier_link,
                            )

                            dispatched = await dispatch_discord_embed(
                                session=session,
                                channel_key="ransomware",
                                title=f"{prefix} {victim}",
                                description="",
                                fields=rl_fields,
                                color=0xE74C3C,
                                image_url=(dwi_match.get("image_url") if dwi_match else None),
                                mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service",
                            )

                            if dispatched:
                                await record_event(
                                    event_id,
                                    "RansomLook",
                                    threat_actor=(group if group != "Unattributed" else None),
                                    target_industry=(dwi_match.get("sector") if dwi_match else None),
                                    country_code=(dwi_match.get("country_code") if dwi_match else None),
                                    title=str(victim)[:200],
                                )
                        if dispatched:
                            await asyncio.sleep(0.5)
                    except Exception as item_err:
                        print(f"[Collector Error] RansomLook item: {item_err}")
            else:
                print(f"[Collector Error] RansomLook: HTTP {response.status}")

    except Exception as error:
        print(f"[Collector Error] RansomLook: {error}")

    # 3. Ransomwatch public JSON archive
    try:
        async with session.get(
            "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
            headers={
                **BROWSER_HEADERS,
                "Accept": "application/json",
            },
            timeout=aiohttp.ClientTimeout(total=20),
        ) as response:
            if response.status != 200:
                print(f"[Collector Error] Ransomwatch: HTTP {response.status}")
                posts = []
            else:
                content_type = response.headers.get("Content-Type", "")
                raw_body = await response.text()

                if "json" not in content_type.lower() and not raw_body.lstrip().startswith(("[", "{")):
                    print(f"[Collector Error] Ransomwatch: unexpected content type {content_type}")
                    posts = []
                else:
                    try:
                        payload = json.loads(raw_body)
                    except Exception as error:
                        print(f"[Collector Error] Ransomwatch JSON parsing: {error}")
                        payload = None

                    if isinstance(payload, list):
                        posts = payload
                    elif isinstance(payload, dict):
                        posts = payload.get("data") or payload.get("posts") or []
                    else:
                        posts = []

            if posts:
                if bootstrap_limit:
                    posts = posts[-bootstrap_limit:]
                else:
                    posts = posts[-1000:]

            for post in posts:
                try:
                    if not isinstance(post, dict):
                        continue

                    victim = html.unescape(html.unescape(str(post.get("post_title") or post.get("victim") or "Unknown victim"))).strip()
                    group = html.unescape(html.unescape(str(post.get("group_name") or post.get("group") or "Unattributed"))).strip()
                    rw_fallback = str(post.get("discovered") or victim)
                    event_id = normalize_leak_event_id(group, victim, fallback_id=rw_fallback)

                    if await is_ransomware_duplicate(event_id, group, victim):
                        continue

                    raw_discovered = post.get("discovered") or ""
                    if is_older_than(raw_discovered, days=7):
                        continue

                    clean_v_slug = normalize_victim_slug(victim)
                    guard_keys = (event_id, f"victim:{clean_v_slug}" if len(clean_v_slug) >= 3 else "")
                    dispatched = False
                    async with dedup_guard(*guard_keys):
                        if await is_ransomware_duplicate(event_id, group, victim):
                            continue

                        discovered_date = format_clean_date(raw_discovered)
                        actor_stat = await get_actor_randomized_stat(group)
                        raw_rw_desc = clean_html_to_markdown(post.get("description") or "")[:450]
                        dwi_match = lookup_dwi_enrichment(dwi_items, victim)
                        actor_dossier_link = await resolve_actor_value_add_link(session, group)

                        rw_fields = build_ransomware_fields(
                            publisher="Ransomwatch",
                            group=group,
                            date_str=discovered_date,
                            claim_text=raw_rw_desc,
                            source_link_name="Source",
                            source_link_value="Ransomwatch Public Archive",
                            actor_stat=actor_stat,
                            dwi_match=dwi_match,
                            extra_dossier_link=actor_dossier_link,
                        )

                        dispatched = await dispatch_discord_embed(
                            session=session,
                            channel_key="ransomware",
                            title=f"🚨 Ransomware Alert: {victim}",
                            description="",
                            fields=rw_fields,
                            color=0xE74C3C,
                            image_url=(dwi_match.get("image_url") if dwi_match else None),
                            mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service",
                        )

                        if dispatched:
                            await record_event(
                                event_id,
                                "Ransomwatch",
                                threat_actor=(group if group != "Unattributed" else None),
                                target_industry=(dwi_match.get("sector") if dwi_match else None),
                                country_code=(dwi_match.get("country_code") if dwi_match else None),
                                title=str(victim)[:200],
                            )
                    if dispatched:
                        await asyncio.sleep(0.5)
                except Exception as item_err:
                    print(f"[Collector Error] Ransomwatch item: {item_err}")

    except Exception as error:
        print(f"[Collector Error] Ransomwatch: {error}")

    # 4. Dark Web Informer breach & ransomware RSS stream
    try:
        if dwi_items:
            dwi_batch = dwi_items[:bootstrap_limit] if bootstrap_limit else dwi_items[:25]
            for dwi in (reversed(dwi_batch) if not bootstrap_limit else dwi_batch):
                try:
                    if is_older_than(dwi.get("published") or dwi.get("published_parsed"), days=7):
                        continue

                    dwi_victim = html.unescape(html.unescape(str(dwi.get("victim") or dwi.get("title") or "Unidentified breach claim"))).strip()
                    dwi_actor = html.unescape(html.unescape(str(dwi.get("actor") or "Unattributed"))).strip()
                    dwi_guid = dwi.get("guid") or dwi.get("link") or dwi_victim
                    alt_dwi = [get_stable_id("rss", dwi["link"])] if dwi.get("link") else []
                    if dwi.get("victim"):
                        event_id = normalize_leak_event_id(dwi_actor, dwi_victim, fallback_id=dwi_guid)
                        is_dup = await is_ransomware_duplicate(event_id, dwi_actor, dwi_victim)
                        dwi_slug = normalize_victim_slug(dwi_victim)
                        guard_keys = (event_id, f"victim:{dwi_slug}" if len(dwi_slug) >= 3 else "")
                    else:
                        event_id = get_stable_id("dwi", dwi_guid)
                        is_dup = await is_duplicate(event_id, alt_event_ids=alt_dwi)
                        guard_keys = (event_id, *alt_dwi)

                    if is_dup:
                        continue

                    dispatched = False
                    async with dedup_guard(*guard_keys):
                        if dwi.get("victim"):
                            if await is_ransomware_duplicate(event_id, dwi_actor, dwi_victim):
                                continue
                        else:
                            if await is_duplicate(event_id, alt_event_ids=alt_dwi):
                                continue

                        clean_pub = format_clean_date(dwi.get("published") or "")
                        actor_stat = await get_actor_randomized_stat(dwi_actor)
                        actor_dossier_link = await resolve_actor_value_add_link(session, dwi_actor)
                        dwi_link = dwi.get("link")
                        dwi_fields = build_ransomware_fields(
                            publisher="Dark Web Informer",
                            group=dwi_actor,
                            date_str=clean_pub,
                            claim_text=dwi.get("summary") or "",
                            source_link_name="Discovery Link",
                            source_link_value=(f"[Open Dark Web Informer Report]({dwi_link})" if dwi_link else "Not provided"),
                            actor_stat=actor_stat,
                            dwi_match=dwi,
                            extra_dossier_link=actor_dossier_link,
                        )

                        alert_label = dwi.get("report_type") or "Dark Web Breach Claim"
                        dispatched = await dispatch_discord_embed(
                            session=session,
                            channel_key="ransomware",
                            title=f"🚨 {alert_label}: {(dwi.get('title') or dwi_victim)[:180]}",
                            description="",
                            fields=dwi_fields,
                            color=0xE74C3C,
                            image_url=dwi.get("image_url"),
                            mitre_tactics="T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service",
                        )

                        if dispatched:
                            await record_event(
                                event_id,
                                "Dark Web Informer",
                                threat_actor=(dwi_actor if dwi_actor != "Unattributed" else None),
                                target_industry=dwi.get("sector"),
                                country_code=dwi.get("country_code"),
                                title=str(dwi.get("victim") or dwi.get("title") or "")[:200],
                            )
                    if dispatched:
                        await asyncio.sleep(0.5)
                except Exception as dwi_item_err:
                    print(f"[Collector Error] Dark Web Informer item: {dwi_item_err}")
    except Exception as dwi_err:
        print(f"[Collector Error] Dark Web Informer: {dwi_err}")



async def get_live_c2_for_family(session: aiohttp.ClientSession, family: str) -> str:
    if not family or family in ("Malware Payload", "Unclassified Dropper"):
        return ""
    if not ABUSECH_AUTH_KEY:
        return ""
    try:
        payload = {"query": "taginfo", "tag": family.lower().replace(" ", ""), "limit": 3}
        headers = {"Auth-Key": ABUSECH_AUTH_KEY}
        async with session.post("https://threatfox-api.abuse.ch/api/v1/", json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                data = await resp.json()
                for item in (data.get("data") or []):
                    threat = (item.get("threat_type_desc") or item.get("threat_type") or "").lower()
                    ioc = item.get("ioc")
                    if ioc and ("c2" in threat or "botnet" in threat):
                        return f"{ioc} (Active {family} C2)"
    except Exception:
        pass
    return ""

def build_c2_investigation_links(ioc_val: str, ioc_type: str = "") -> str:
    """Build direct OSINT pivot links (VirusTotal, URLScan.io, Shodan) for a C2 indicator."""
    val = (ioc_val or "").strip()
    if not val:
        return "Not provided"
    kind = (ioc_type or "").strip().lower()

    host = ""
    if kind == "url" or "://" in val:
        parsed = urllib.parse.urlparse(val if "://" in val else f"http://{val}")
        host = (parsed.hostname or "").strip("[]")
    elif kind == "ip:port" or (":" in val and "/" not in val):
        host = val.rsplit(":", 1)[0].strip("[]")
    else:
        host = val.split("/")[0].strip("[]")

    is_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

    pivots = []
    if kind == "url" or "://" in val:
        pivots.append(f"[VirusTotal URL]({get_virustotal_url_link(val)})")
        if host:
            if is_ip:
                pivots.append(f"[URLScan.io](https://urlscan.io/ip/{host})")
                pivots.append(f"[Shodan](https://www.shodan.io/host/{host})")
            else:
                q_host = urllib.parse.quote(host, safe="")
                pivots.append(f"[URLScan.io](https://urlscan.io/domain/{q_host})")
    elif is_ip:
        pivots.append(f"[VirusTotal](https://www.virustotal.com/gui/ip-address/{host})")
        pivots.append(f"[URLScan.io](https://urlscan.io/ip/{host})")
        pivots.append(f"[Shodan](https://www.shodan.io/host/{host})")
    elif host:
        q_host = urllib.parse.quote(host, safe="")
        pivots.append(f"[VirusTotal](https://www.virustotal.com/gui/domain/{q_host})")
        pivots.append(f"[URLScan.io](https://urlscan.io/domain/{q_host})")

    return " • ".join(pivots) if pivots else "Not provided"


async def poll_infrastructure(session: aiohttp.ClientSession):
    bootstrap_limit = 2 if await is_first_run() else None

    # Patched Feodo Tracker endpoint
    try:
        async with session.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                data = await resp.json()
                items = data[:bootstrap_limit] if bootstrap_limit else data[:25]
                for s in items:
                    try:
                        ip, port, malware = s.get("ip_address"), s.get("port"), s.get("malware", "Botnet")
                        seen_raw = s.get("first_seen") or s.get("last_online") or ""
                        if is_older_than(seen_raw, days=7):
                            continue
                        seen_date = format_clean_date(seen_raw)
                        event_id = f"feodo_{ip}_{port}"
                        feodo_ioc = f"{ip}:{port}"
                        if not await is_duplicate(event_id, ioc=feodo_ioc):
                            dispatched = False
                            async with dedup_guard(event_id, f"ioc:{normalize_ioc(feodo_ioc)}" if feodo_ioc else ""):
                                if await is_duplicate(event_id, ioc=feodo_ioc):
                                    continue
                                feodo_fields = [
                                    {"name": "Publisher", "value": "abuse.ch Feodo Tracker", "inline": True},
                                    {"name": "Host", "value": f"`{ip}:{port}`", "inline": True},
                                    {"name": "Family", "value": f"`{malware}`", "inline": True},
                                    {"name": "First Seen", "value": f"`{seen_date}`", "inline": True},
                                ]
                                as_num = s.get("as_number")
                                as_name = (s.get("as_name") or "").strip()
                                country = (s.get("country") or "").strip()
                                if as_num or as_name or country:
                                    asn_str = f"`AS{as_num}` " if as_num else ""
                                    cc_str = f" (`{country}`)" if country else ""
                                    feodo_fields.append({"name": "Routing / ASN", "value": f"{asn_str}{as_name}{cc_str}".strip(), "inline": True})
                                feodo_status = (s.get("status") or "").strip()
                                if feodo_status:
                                    feodo_fields.append({"name": "Host Status", "value": f"**{feodo_status}**", "inline": True})
                                feodo_pivots = (
                                    f"[Feodo Host Dossier](https://feodotracker.abuse.ch/browse/host/{ip}/) • "
                                    + build_c2_investigation_links(f"{ip}:{port}", "ip:port")
                                )
                                feodo_fields.append({"name": "Threat Database & Investigation", "value": feodo_pivots, "inline": False})

                                dispatched = await dispatch_discord_embed(
                                    session=session,
                                    channel_key="infrastructure",
                                    title=f"🤖 Active C2 Infrastructure: {malware}",
                                    description="Active command-and-control server verified by abuse.ch.",
                                    fields=feodo_fields,
                                    color=0xF1C40F,
                                    mitre_tactics="T1071 Application Layer Protocol • T1573 Encrypted Channel"
                                )
                                if dispatched:
                                    feodo_asn = f"AS{as_num} {as_name}".strip() if (as_num or as_name) else None
                                    await record_event(
                                        event_id,
                                        "Feodo",
                                        country_code=(country or None),
                                        ioc=feodo_ioc,
                                        title=f"Feodo {malware} C2",
                                        malware_family=(malware if malware and malware != "Botnet" else None),
                                        asn=feodo_asn,
                                    )
                            if dispatched:
                                await asyncio.sleep(0.5)
                    except Exception as item_err:
                        print(f"[Collector Error] Feodo item: {item_err}")
    except Exception as e:
        print(f"[Collector Error] Feodo: {e}")

    try:
        async with session.get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                text = await resp.text()
                reader = csv.reader([line for line in text.splitlines() if not line.startswith("#")])
                rows = list(reader)
                items = rows[:bootstrap_limit] if bootstrap_limit else rows[:25]
                for row in items:
                    try:
                        if len(row) >= 3:
                            seen_time = row[0].strip()
                            bad_ip = row[1].strip()
                            bad_port = row[2].strip()
                            if is_older_than(seen_time, days=7):
                                continue
                            event_id = f"sslbl_{bad_ip}_{bad_port}"
                            sslbl_ioc = f"{bad_ip}:{bad_port}"
                            if not await is_duplicate(event_id, ioc=sslbl_ioc):
                                dispatched = False
                                async with dedup_guard(event_id, f"ioc:{normalize_ioc(sslbl_ioc)}" if sslbl_ioc else ""):
                                    if await is_duplicate(event_id, ioc=sslbl_ioc):
                                        continue
                                    sslbl_pivots = build_c2_investigation_links(sslbl_ioc, "ip:port")
                                    dispatched = await dispatch_discord_embed(
                                        session=session,
                                        channel_key="infrastructure",
                                        title="🔒 Malicious SSL Infrastructure: Botnet Node",
                                        description="Host operating a blacklisted SSL/TLS certificate associated with malware C2.",
                                        fields=[
                                            {"name": "Publisher", "value": "abuse.ch SSLBL", "inline": True},
                                            {"name": "Server Endpoint", "value": f"`{bad_ip}:{bad_port}`", "inline": True},
                                            {"name": "Date Discovered", "value": f"`{format_clean_date(seen_time)}`", "inline": True},
                                            {"name": "Infrastructure Investigation", "value": sslbl_pivots, "inline": False}
                                        ],
                                        color=0xD35400,
                                        mitre_tactics="T1573.002 Asymmetric Cryptography • T1071.001 Web Protocols"
                                    )
                                    if dispatched:
                                        await record_event(event_id, "abuse.ch SSLBL", ioc=sslbl_ioc, title="SSL Blacklist Node")
                                if dispatched:
                                    await asyncio.sleep(0.5)
                    except Exception as item_err:
                        print(f"[Collector Error] SSLBL item: {item_err}")
    except Exception as e:
        print(f"[Collector Error] SSLBL: {e}")

    try:
        urlhaus_headers = {"Auth-Key": ABUSECH_AUTH_KEY} if ABUSECH_AUTH_KEY else {}
        async with session.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/", headers=urlhaus_headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                data = await resp.json()
                urls = data.get("urls", [])
                items = urls[:bootstrap_limit] if bootstrap_limit else urls[:25]
                for item in (reversed(items) if not bootstrap_limit else items):
                    try:
                        raw_date = item.get("date_added")
                        if is_older_than(raw_date, days=7):
                            continue
                        url_id = str(item.get("id"))
                        raw_url = item.get("url")
                        raw_tags = item.get("tags") or []
                        tags_str = ", ".join(raw_tags) if isinstance(raw_tags, list) else str(raw_tags)
                        
                        event_id = f"urlhaus_{url_id}"
                        if not await is_duplicate(event_id, ioc=str(raw_url)):
                            dispatched = False
                            async with dedup_guard(event_id, f"ioc:{normalize_ioc(str(raw_url))}" if raw_url else ""):
                                if await is_duplicate(event_id, ioc=str(raw_url)):
                                    continue
                                detected_family = extract_malware_family(tags_str)
                                vt_url = get_virustotal_url_link(raw_url)
                                urlscan_link = f"https://urlscan.io/#{urllib.parse.quote(raw_url, safe='')}"
                                urlhaus_dossier = f"https://urlhaus.abuse.ch/url/{url_id}/"
                                
                                infra = await enrich_dropper_infrastructure(session, raw_url)
                                
                                live_c2 = await get_live_c2_for_family(session, detected_family)
                                if live_c2:
                                    c2_display = f"{live_c2} (Global Family Reference)"
                                elif detected_family.lower() in ("mozi", "hns", "hajime"):
                                    c2_display = "P2P DHT Swarm (Decentralized Botnet)"
                                else:
                                    c2_display = "No Active ThreatFox C2 Record"
                                
                                delivery_val = str(infra.get("routing") or "Unknown Routing")
                                correlation_text = (
                                    "```ansi\n"
                                    f"\u001b[2;34mDropper Delivery  \u001b[0m : \u001b[2;32m{delivery_val}\u001b[0m\n"
                                    f"\u001b[2;34mKnown Family C2   \u001b[0m : \u001b[2;32m{c2_display}\u001b[0m\n"
                                    "```"
                                )
                                
                                raw_status = (item.get("url_status") or "online").strip().lower()
                                status_badge = "🟢 **URLhaus reports: online**" if raw_status == "online" else f"🔴 **URLhaus reports: {raw_status}**"
                                fields = [
                                    {"name": "Date Added", "value": f"`{format_clean_date(item.get('date_added'))}`", "inline": True},
                                    {"name": "Malware / Botnet Family", "value": f"**{detected_family}**", "inline": True},
                                    {"name": "Threat Database", "value": f"[View URLhaus Dossier]({urlhaus_dossier})", "inline": True},
                                    {"name": "Routing & ASN", "value": infra["routing"], "inline": False},
                                    {"name": "🎯 Cyber Kill Chain Reference", "value": correlation_text, "inline": False},
                                    {"name": "Host Status", "value": status_badge, "inline": True},
                                    {"name": "Campaign Tags", "value": f"`{tags_str or 'None'}`", "inline": True},
                                    {"name": "Defanged Payload Link", "value": f"`{defang_url(raw_url)[:120]}`", "inline": False},
                                    {
                                        "name": "Safe Investigation Sandboxes",
                                        "value": (
                                            f"[Scan on VirusTotal]({vt_url}) • "
                                            f"[Scan on URLScan.io]({urlscan_link}) • "
                                            f"[Search on Triage](https://tria.ge/reports?q={urllib.parse.urlparse(raw_url).netloc.split(':')[0]})"
                                        ),
                                        "inline": False
                                    }
                                ]
                                
                                dispatched = await dispatch_discord_embed(
                                    session=session,
                                    channel_key="malware",
                                    title=f"⚔️ Kill Chain Alert: {detected_family} (Dropper & C2)",
                                    description="Automated intelligence correlation linking initial delivery to active command server.",
                                    fields=fields,
                                    color=0xE67E22,
                                    mitre_tactics="T1204.001 Malicious Link • T1105 Ingress Tool Transfer • T1071 C2 Protocols"
                                )
                                if dispatched:
                                    clean_uh_fam = detected_family if detected_family not in ("Malware Payload", "Unclassified Dropper") else None
                                    clean_uh_asn = infra.get("routing") if infra.get("routing") not in ("Unknown ASN", "Unknown Host", None) else None
                                    await record_event(
                                        event_id,
                                        "URLhaus",
                                        country_code=infra.get("country_code"),
                                        ioc=str(raw_url)[:300],
                                        title=f"{detected_family} Payload"[:200],
                                        tags=tags_str[:300] or None,
                                        malware_family=clean_uh_fam,
                                        asn=clean_uh_asn,
                                    )
                            if dispatched:
                                await asyncio.sleep(0.5)
                    except Exception as item_err:
                        print(f"[Collector Error] URLhaus item: {item_err}")
    except Exception as e:
        print(f"[Collector Error] URLhaus: {e}")

    try:
        async with session.get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                raw_lines = [l.strip() for l in (await resp.text()).splitlines() if l.strip()]
                items = raw_lines[:bootstrap_limit] if bootstrap_limit else raw_lines[:25]
                for link in items:
                    try:
                        if link:
                            phish_host = (urllib.parse.urlparse(link).hostname or "").lower()
                            if phish_host.startswith("www."):
                                phish_host = phish_host[4:]
                            event_id = get_stable_id("phish", link.lower())
                            alt_phish_ids = [f"phish_{phish_host}"] if phish_host else []
                            if not await is_duplicate(event_id, ioc=link, alt_event_ids=alt_phish_ids):
                                dispatched = False
                                async with dedup_guard(event_id, *alt_phish_ids, f"ioc:{normalize_ioc(link)}" if link else ""):
                                    if await is_duplicate(event_id, ioc=link, alt_event_ids=alt_phish_ids):
                                        continue
                                    campaign = detect_target_campaign(link)
                                    vt_url = get_virustotal_url_link(link)
                                    urlscan_link = f"https://urlscan.io/#{urllib.parse.quote(link, safe='')}"
                                    
                                    net_meta = await resolve_host_metadata(session, link)
                                    is_resolved = net_meta.get("ip") != "Unresolved"
                                    dns_badge = "🟢 Live DNS" if is_resolved else "⚠ Host currently unresolved"
                                    host_type = "Cloud Stager" if any(h in link for h in ["pages.dev", "vercel.app", "netlify.app", "firebaseapp.com"]) else "Self-Hosted / VPS"

                                    dispatched = await dispatch_discord_embed(
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
                                    if dispatched:
                                        clean_phish_asn = net_meta.get("org") if net_meta.get("org") not in ("Unknown Host", None) else None
                                        await record_event(
                                            event_id,
                                            "OpenPhish",
                                            country_code=net_meta.get("country_code"),
                                            ioc=link[:300],
                                            title=f"{campaign}"[:200],
                                            asn=clean_phish_asn,
                                        )
                                if dispatched:
                                    await asyncio.sleep(0.5)
                    except Exception as item_err:
                        print(f"[Collector Error] OpenPhish item: {item_err}")
    except Exception as e:
        print(f"[Collector Error] OpenPhish: {e}")

async def check_c2_dns(ioc_value, ioc_type) -> str:
    try:
        value = (ioc_value or "").strip()
        kind = (ioc_type or "").lower()
        if kind == "url":
            url_to_parse = value if "://" in value else f"http://{value}"
            host = urllib.parse.urlparse(url_to_parse).hostname or ""
        elif kind == "ip:port":
            host = value.rsplit(":", 1)[0].strip("[]")
        elif kind == "domain":
            host = value
        else:
            return "⚪ Not applicable"
        if not host:
            return "⚪ Not applicable"
        try:
            ipaddress.ip_address(host)
            return "⚪ Direct IP (no DNS lookup)"
        except ValueError:
            pass
        info = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, None), timeout=5)
        ips = sorted({r[4][0] for r in info})
        if not ips:
            return "🔴 Does not resolve"
        public = []
        for ip in ips:
            obj = ipaddress.ip_address(ip.split("%")[0])
            if not (obj.is_private or obj.is_loopback or obj.is_unspecified or obj.is_reserved or obj.is_link_local):
                public.append(ip)
        if not public:
            return "🟠 Resolves to non-public IP only"
        return "🟢 Live DNS (" + ", ".join(public[:2]) + ")"
    except asyncio.TimeoutError:
        return "🟡 DNS check timed out"
    except socket.gaierror as err:
        missing = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}
        if err.errno in missing:
            return "🔴 Does not resolve"
        return "🟡 DNS check failed"
    except Exception:
        return "🟡 DNS check failed"

# ThreatFox tags that describe file type, platform, detection source or generic role
# rather than a campaign / tool / family, so they are useless as an identifier.
THREATFOX_GENERIC_TAGS = {
    "loader", "dropper", "payload", "malware", "rat", "stealer", "botnet", "c2", "cc", "c&c",
    "elf", "exe", "dll", "ps1", "macho", "mach-o", "jar", "sh", "bash", "js", "vbs", "bat", "hta",
    "msi", "lnk", "zip", "rar", "iso", "apk", "pdf", "doc", "xls", "python", "go", "golang",
    "linux", "windows", "macos", "android", "web", "http", "https", "telnet", "ssh", "ftp",
    "docker", "redis", "honeypot", "modat", "censys", "shodan", "fofa", "opendir", "open-dir",
    "github", "rmm", "ddos", "miner", "cryptojacking", "phishing", "scanner", "x86", "x64",
    "arm", "mips", "32-bit", "64-bit", "ip", "url", "domain", "hash", "signed", "unsigned",
    "dga", "tor", "vpn", "proxy", "abuse", "minecraft", "banker", "infostealer", "trojan", "backdoor",
    "dht", "triage", "any.run", "anyrun", "virustotal", "vt", "urlscan", "sandbox", "joesandbox",
    "powershell", "cmd", "whatsapp", "telegram", "discord", "unam",
    "residential", "residential-proxy", "vps", "bulletproof", "hosting", "cdn", "cloudflare",
}


# Commercial residential-proxy / proxyware networks frequently tagged on ThreatFox C2 entries.
# These are genuine identifiers but not malware families, so they are labelled as proxyware.
THREATFOX_PROXYWARE_TAGS = {
    "appsalt", "honeygain", "linesso", "ipipgo", "ipmoyu", "soax", "evomi", "hailiangip",
    "linkfog", "packetstream", "iproyal", "pawns", "peer2profit", "earnapp", "brightdata",
    "luminati", "oxylabs", "proxyrack", "bitping", "repocket", "traffmonetizer", "infatica",
}


def derive_threatfox_label(malware_printable: str, tags) -> str:
    """Return the family name, or for ThreatFox 'Unknown *' families a campaign/tool label
    built from the reporter's tags (e.g. 'ClickFix · Unknown Loader'). Falls back to the
    original value when no meaningful tag exists, so attribution is never invented."""
    fam = (malware_printable or "Unclassified").strip()
    if not fam.lower().startswith("unknown"):
        return fam
    tag_list = tags if isinstance(tags, list) else [t.strip() for t in str(tags or "").split(",")]
    meaningful = []
    for t in tag_list:
        t = str(t or "").strip()
        tl = t.lower()
        if not t or tl in THREATFOX_GENERIC_TAGS or tl == fam.lower():
            continue
        # Skip ASNs, port numbers, 2-letter country codes, filenames and very long free-text tags
        if re.fullmatch(r"(as\d+|\d+|[a-z]{2})", tl) or len(t) > 24:
            continue
        if re.search(r"\.(zip|rar|7z|exe|dll|msi|js|vbs|ps1|bat|lnk|iso|img|hta|apk|sh|jar|pdf|docx?|xlsx?)$", tl):
            continue
        meaningful.append(t)
    if not meaningful:
        return fam
    proxy = [t for t in meaningful if t.lower() in THREATFOX_PROXYWARE_TAGS]
    if proxy:
        return f"{proxy[0]} [proxyware] · {fam}"
    # Prefer proper-noun tags (ClickFix, GoPhish, DarkSword) over lowercase descriptors
    meaningful.sort(key=lambda s: 0 if any(ch.isupper() for ch in s) else 1)
    return f"{meaningful[0]} · {fam}"


async def threatfox_infra_overlap(session: aiohttp.ClientSession, ioc_val: str, ioc_id) -> str | None:
    """For an unattributed C2 indicator, search ThreatFox for *other* reports on the same host
    and return the most frequently attributed named family (infrastructure overlap), if any."""
    raw = str(ioc_val or "").strip()
    if not raw or not ABUSECH_AUTH_KEY:
        return None
    host = re.sub(r"^[a-z]+://", "", raw, flags=re.I).split("/")[0]
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d+", host):
        host = host.rsplit(":", 1)[0]
    try:
        async with session.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": host},
            headers={"Auth-Key": ABUSECH_AUTH_KEY},
            timeout=aiohttp.ClientTimeout(total=6),
        ) as resp:
            if resp.status != 200:
                return None
            body = await resp.json(content_type=None)
    except Exception:
        return None
    if body.get("query_status") != "ok" or not isinstance(body.get("data"), list):
        return None
    fams = Counter(
        (r.get("malware_printable") or "").strip()
        for r in body["data"]
        if str(r.get("id")) != str(ioc_id)
        and (r.get("malware_printable") or "").strip()
        and not (r.get("malware_printable") or "").lower().startswith(("unknown", "unclassified"))
    )
    return fams.most_common(1)[0][0] if fams else None


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
                    bootstrap_limit = 2 if await is_first_run() else None
                    data_items = [
                        it for it in (body.get("data") or [])
                        if isinstance(it, dict) and (
                            (it.get("threat_type") or "").lower() == "botnet_cc"
                            or any(k in f"{it.get('threat_type', '')} {it.get('threat_type_desc', '')}".lower() for k in ("c&c", "c2", "botnet"))
                        )
                    ]
                    items = data_items[:bootstrap_limit] if bootstrap_limit else data_items[:25]
                    for item in (reversed(items) if not bootstrap_limit else items):
                        try:
                            raw_seen = item.get("first_seen_utc") or item.get("first_seen")
                            if is_older_than(raw_seen, days=7):
                                continue
                            ioc_id = item.get("id")
                            ioc_val = item.get("ioc")
                            malware = item.get("malware_printable") or "Unclassified"
                            threat_type = item.get("threat_type_desc") or item.get("threat_type") or "C2 Infrastructure"
                            confidence = item.get("confidence_level", 0)
                            tags = item.get("tags") or []
                            tags_str = ", ".join(str(t) for t in tags) if isinstance(tags, list) else str(tags)
                            # Surface reporter campaign/tool tags when ThreatFox has no family attribution
                            malware = derive_threatfox_label(malware, tags)
                            
                            event_id = f"tfox_{ioc_id}"
                            if not await is_duplicate(event_id, ioc=str(ioc_val)):
                                dispatched = False
                                async with dedup_guard(event_id, f"ioc:{normalize_ioc(str(ioc_val))}" if ioc_val else ""):
                                    if await is_duplicate(event_id, ioc=str(ioc_val)):
                                        continue
                                    if malware.lower().startswith("unknown"):
                                        # No family or useful tag: check other ThreatFox reports on the same host
                                        overlap_fam = await threatfox_infra_overlap(session, ioc_val, ioc_id)
                                        if overlap_fam:
                                            malware = f"{overlap_fam} (infra overlap) · {malware}"
                                    defanged = defang_url(ioc_val)[:120]
                                    tf_url = f"https://threatfox.abuse.ch/ioc/{ioc_id}/"
                                    ioc_type_raw = item.get("ioc_type") or "unknown"
                                    reporter = (item.get("reporter") or "").strip()
                                    reference = (item.get("reference") or "").strip()
                                    malpedia_url = (item.get("malware_malpedia") or "").strip()

                                    db_links = [f"[ThreatFox Dossier]({tf_url})"]
                                    if reference.lower().startswith(("http://", "https://")):
                                        db_links.append(f"[Reporter Reference]({reference})")
                                    if malpedia_url.lower().startswith(("http://", "https://")):
                                        db_links.append(f"[Malpedia]({malpedia_url})")

                                    pivot_links = build_c2_investigation_links(str(ioc_val or ""), ioc_type_raw)
                                    dns_status = await check_c2_dns(ioc_val, ioc_type_raw)

                                    fields = [
                                        {"name": "Publisher", "value": "abuse.ch ThreatFox", "inline": True},
                                        {"name": "Date Identified", "value": f"`{format_clean_date(item.get('first_seen_utc') or item.get('first_seen'))}`", "inline": True},
                                        {"name": "Malware / Campaign", "value": f"**{malware}**", "inline": True},
                                        {"name": "Indicator Type", "value": f"`{ioc_type_raw}`", "inline": True},
                                        {"name": "Confidence Score", "value": f"`{confidence}%`", "inline": True},
                                        {"name": "DNS Status", "value": f"**{dns_status}**", "inline": True},
                                    ]
                                    if reporter:
                                        fields.append({"name": "Reporter", "value": f"`{reporter}`", "inline": True})
                                    fields.extend([
                                        {"name": "Campaign Tags", "value": f"`{tags_str or 'None'}`", "inline": True if reporter else False},
                                        {"name": "Defanged Indicator", "value": f"`{defanged}`", "inline": False},
                                        {"name": "Threat Database & References", "value": " • ".join(db_links), "inline": False},
                                        {"name": "Indicator Investigation", "value": pivot_links, "inline": False},
                                    ])
                                    
                                    is_proxyware = "[proxyware]" in malware.lower()
                                    if is_proxyware:
                                        proxy_net = malware.split("[proxyware]")[0].strip()
                                        embed_title = f"📡 Residential Proxyware / Exit Node: {proxy_net}"
                                        embed_desc = (
                                            "Commercial residential-proxyware / bandwidth monetization node or SDK callback detected. "
                                            "Frequently embedded in trojanized consumer apps, smart TV firmware, or hijacked IoT devices "
                                            "(e.g. XCPE botnet) to route adversary traffic and ad fraud."
                                        )
                                        embed_color = 0xF59E0B  # Amber/Orange
                                        embed_tactics = "T1090.003 External Proxy Service • T1584 Compromise Infrastructure"
                                        fields.insert(2, {"name": "Threat Category", "value": "📡 `Residential Proxyware / Monetization Node`", "inline": True})
                                    else:
                                        embed_title = f"🎯 Threat Attribution: {malware}"
                                        embed_desc = "Community intelligence indicator linked to active adversary campaign."
                                        embed_color = 0x8E44AD
                                        embed_tactics = "T1071 C2 Protocols • T1584 Compromise Infrastructure"

                                    dispatched = await dispatch_discord_embed(
                                        session=session,
                                        channel_key="infrastructure",
                                        title=embed_title,
                                        description=embed_desc,
                                        fields=fields,
                                        color=embed_color,
                                        mitre_tactics=embed_tactics,
                                    )
                                    if dispatched:
                                        raw_tf_fam = (item.get("malware_printable") or "").strip()
                                        clean_tf_fam = raw_tf_fam if (raw_tf_fam and not raw_tf_fam.lower().startswith(("unknown", "unclassified"))) else None
                                        await record_event(
                                            event_id,
                                            "ThreatFox",
                                            ioc=str(ioc_val)[:300],
                                            title=f"{malware} - {threat_type}"[:200],
                                            tags=tags_str[:300] or None,
                                            malware_family=clean_tf_fam,
                                        )
                                if dispatched:
                                    await asyncio.sleep(0.5)
                        except Exception as item_err:
                            print(f"[Collector Error] ThreatFox item: {item_err}")
    except Exception as e:
        print(f"[Collector Error] ThreatFox: {e}")

async def poll_malware_bazaar(session: aiohttp.ClientSession):
    if not ABUSECH_AUTH_KEY:
        return
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    data = {"query": "get_recent", "selector": "100"}
    try:
        async with session.post(url, data=data, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                body = await resp.json()
                if body.get("query_status") == "ok":
                    bootstrap_limit = 2 if await is_first_run() else None
                    data_items = body.get("data", [])
                    items = data_items[:bootstrap_limit] if bootstrap_limit else data_items[:25]
                    for sample in (reversed(items) if not bootstrap_limit else items):
                        try:
                            seen_raw = sample.get("first_seen")
                            if is_older_than(seen_raw, days=7):
                                continue
                            sha256 = sample.get("sha256_hash")
                            malware = sample.get("signature") or "Unclassified Malware"
                            file_type = sample.get("file_type", "Executable")
                            event_id = f"bazaar_{sha256}"
                            if not await is_duplicate(event_id, ioc=sha256):
                                dispatched = False
                                async with dedup_guard(event_id, f"ioc:{normalize_ioc(str(sha256))}" if sha256 else ""):
                                    if await is_duplicate(event_id, ioc=sha256):
                                        continue
                                    seen_date = format_clean_date(seen_raw or "")
                                    vt_hash_url = f"https://www.virustotal.com/gui/file/{sha256}"
                                    dispatched = await dispatch_discord_embed(
                                        session=session,
                                        channel_key="malware",
                                        title=f"🔬 New Malware Sample: {malware}",
                                        description=f"A fresh `{file_type}` payload was staged and identified.",
                                        fields=[
                                            {"name": "Signature", "value": f"`{malware}`", "inline": True},
                                            {"name": "File Type", "value": f"`{file_type}`", "inline": True},
                                            {"name": "First Seen", "value": f"`{seen_date}`", "inline": True},
                                            {"name": "SHA256", "value": f"`{sha256}`", "inline": False},
                                            {"name": "Hash Analysis", "value": f"[Inspect on VirusTotal]({vt_hash_url}) • [Detonate on Triage](https://tria.ge/reports?q={sha256}) • [⚡ Open in Ghidra Lab]({TRIAGE_LAB_HOST}/triage?hash={sha256})", "inline": False}
                                        ],
                                        color=0x95A5A6,
                                        mitre_tactics="T1204 User Execution • T1027 Obfuscated Files"
                                    )
                                    if dispatched:
                                        clean_mb_fam = malware if (malware and malware != "Unclassified Malware") else None
                                        await record_event(
                                            event_id,
                                            "MalwareBazaar",
                                            ioc=sha256,
                                            title=malware,
                                            tags=file_type,
                                            malware_family=clean_mb_fam,
                                        )
                                if dispatched:
                                    await asyncio.sleep(0.5)
                        except Exception as item_err:
                            print(f"[Collector Error] MalwareBazaar item: {item_err}")
    except Exception as e:
        print(f"[Collector Error] MalwareBazaar: {e}")

VULN_SEVERITY_STYLE = {
    "CRITICAL": {"dot": "🔴", "label": "Critical", "color": 0xE74C3C},
    "HIGH": {"dot": "🟠", "label": "High", "color": 0xE67E22},
    "MEDIUM": {"dot": "🟡", "label": "Medium", "color": 0xF1C40F},
    "LOW": {"dot": "🟢", "label": "Low", "color": 0x2ECC71},
}

_SEV_TEXT_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "IMPORTANT": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "MINOR": "LOW",
    "NOTE": "LOW",
    "INFORMATIONAL": "LOW",
}

_CVE_SEVERITY_CACHE: dict[str, tuple[str | None, float | None]] = {}
_CVE_ENRICHMENT_CACHE: dict[str, dict] = {}


def score_to_severity_level(score: float) -> str | None:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return None


def _normalize_severity_token(raw_token: str | None) -> str | None:
    if not raw_token:
        return None
    cleaned = str(raw_token).strip().upper()
    if cleaned in _SEV_TEXT_ALIASES:
        return _SEV_TEXT_ALIASES[cleaned]
    m = re.search(r"\b(CRITICAL|HIGH|IMPORTANT|MEDIUM|MODERATE|LOW|MINOR)\b", cleaned)
    if m:
        return _SEV_TEXT_ALIASES.get(m.group(1).upper())
    return None


def extract_inline_vuln_severity(title: str = "", description: str = "", tags: list | None = None) -> tuple[str | None, float | None, str]:
    """Extract source-provided severity level and/or CVSS score from vulnerability text/tags and colour-code inline prefixes."""
    sev_level = None
    cvss_score = None

    if tags:
        for t in tags:
            term = str(t.get("term", "") if isinstance(t, dict) else t)
            m_tag = re.search(r"\bseverity\s*:\s*(critical|high|important|medium|moderate|low)\b", term, flags=re.IGNORECASE)
            if m_tag:
                sev_level = _normalize_severity_token(m_tag.group(1))
                break

    combined = f"{title}\n{description}"
    if not sev_level:
        m_sev = re.search(r"\bseverity\s*:\s*(critical|high|important|medium|moderate|low)\b", combined, flags=re.IGNORECASE)
        if m_sev:
            sev_level = _normalize_severity_token(m_sev.group(1))

    m_cvss = re.search(
        r"\bCVSS(?:\s*v?[234](?:\.\d)?)?(?:\s+base)?(?:\s+(?:score|rating))?(?:\s+of)?[\s:]+(\d{1,2}\.\d)\b",
        combined,
        flags=re.IGNORECASE,
    )
    if m_cvss:
        try:
            val = float(m_cvss.group(1))
            if 0.0 < val <= 10.0:
                cvss_score = val
                if not sev_level:
                    sev_level = score_to_severity_level(val)
        except ValueError:
            pass

    updated_desc = description
    if sev_level in VULN_SEVERITY_STYLE and description:
        style = VULN_SEVERITY_STYLE[sev_level]
        updated_desc = re.sub(
            r"^\s*Severity\s*:\s*(?:CRITICAL|HIGH|IMPORTANT|MEDIUM|MODERATE|LOW)\s*\|\s*",
            f"**Severity:** {style['dot']} **{sev_level}** | ",
            description,
            count=1,
            flags=re.IGNORECASE,
        )

    return sev_level, cvss_score, updated_desc


def infer_vuln_severity_and_vector(title: str = "", description: str = "", cwe: str = "") -> tuple[str | None, str]:
    """Infer severity level (when official CVSS/CNA score is pending) and attack vector from vulnerability text."""
    combined = f"{title} {description} {cwe}".lower()

    # Attack vector & precondition inference
    vec_parts = []
    if any(k in combined for k in ("remote", "over the network", "network access", "http server", "web application", "rest endpoint", "unauthenticated attacker can")):
        vec_parts.append("Remote")
    elif any(k in combined for k in ("adjacent", "ble ", "bluetooth", "radio range", "local network")):
        vec_parts.append("Adjacent Network")
    elif any(k in combined for k in ("local attacker", "local user", "local access", "locally")):
        vec_parts.append("Local")

    if any(k in combined for k in ("unauthenticated", "without authentication", "without credentials", "without verifying credentials", "pre-auth")):
        vec_parts.append("Unauthenticated")
    elif any(k in combined for k in ("authenticated user", "authenticated attacker", "requires authentication", "low-privileged")):
        vec_parts.append("Authenticated")

    if any(k in combined for k in ("user interaction", "victim's browser", "must open", "must connect", "crafted page")):
        vec_parts.append("User Interaction")

    attack_vector = " • ".join(vec_parts) if vec_parts else "Network / Application"

    # Severity heuristic fallback when official score is not yet assigned
    is_unauth_remote = ("Remote" in vec_parts and "Unauthenticated" in vec_parts)
    if any(k in combined for k in ("remote code execution", " rce", "arbitrary code", "command injection", "code injection", "deserialization of untrusted")):
        inferred_sev = "CRITICAL" if is_unauth_remote else "HIGH"
    elif any(k in combined for k in (
        "authentication bypass", "bypass authentication", "missing authentication", "sql injection", "sqli",
        "gaining that user's privileges", "privilege escalation", "arbitrary files", "path traversal", "ssrf"
    )):
        inferred_sev = "HIGH" if is_unauth_remote else "MEDIUM"
    elif any(k in combined for k in (
        "session fixation", "denial of service", "infinite loop", "unbounded", "hostname verification",
        "cleartext", "credential disclosure", "information disclosure", "cross-site scripting", " xss"
    )):
        inferred_sev = "MEDIUM"
    else:
        inferred_sev = "MEDIUM"

    return inferred_sev, attack_vector


def classify_vulnerability_mitre(title: str = "", description: str = "", cwe: str = "", is_poc: bool = False) -> str:
    """Map vulnerability details and CWE to MITRE ATT&CK techniques."""
    combined = f"{title} {description} {cwe}".lower()
    tactics = []

    if is_poc:
        tactics.append("T1588.005 Obtain Capabilities: Exploits")

    if any(k in combined for k in ("remote code execution", " rce", "command injection", "code injection", "arbitrary code", "deserialization", "cwe-78", "cwe-94", "cwe-502")):
        tactics.extend(["T1190 Exploit Public-Facing Application", "T1059 Command and Scripting Interpreter"])
    elif any(k in combined for k in (
        "authentication bypass", "bypass authentication", "missing authentication", "improper authentication",
        "session fixation", "caller identity", "wrong session", "missing authorization", "incorrect authorization",
        "cwe-287", "cwe-306", "cwe-384", "cwe-488", "cwe-862", "cwe-863"
    )):
        tactics.extend(["T1190 Exploit Public-Facing Application", "T1078 Valid Accounts"])
    elif any(k in combined for k in (
        "path traversal", "directory traversal", "arbitrary files", "credential disclosure",
        "insufficiently protected credentials", "information disclosure", "cwe-22", "cwe-522", "cwe-200"
    )):
        tactics.extend(["T1190 Exploit Public-Facing Application", "T1005 Data from Local System"])
    elif any(k in combined for k in ("hostname verification", "certificate", "mitm", "cleartext transmission", "cwe-297", "cwe-295", "cwe-319")):
        tactics.extend(["T1557 Adversary-in-the-Middle", "T1040 Network Sniffing"])
    elif any(k in combined for k in ("sql injection", "sqli", "cwe-89")):
        tactics.extend(["T1190 Exploit Public-Facing Application", "T1213 Data from Information Repositories"])
    elif any(k in combined for k in ("privilege escalation", "elevation of privilege", "local privilege", "cwe-269")):
        tactics.append("T1068 Exploitation for Privilege Escalation")
    elif any(k in combined for k in ("buffer overflow", "heap-based", "use-after-free", "out-of-bounds", "memory corruption", "cwe-119", "cwe-122", "cwe-787")):
        tactics.extend(["T1203 Exploitation for Client Execution", "T1190 Exploit Public-Facing Application"])
    elif any(k in combined for k in ("denial of service", "infinite loop", "unbounded", "resource", "cwe-770", "cwe-835", "cwe-400")):
        tactics.append("T1499 Endpoint Denial of Service")
    else:
        tactics.append("T1190 Exploit Public-Facing Application")

    deduped = list(dict.fromkeys(tactics))[:3]
    return " • ".join(deduped)


def _extract_remediation_from_text(description: str) -> str | None:
    if not description:
        return None
    patterns = [
        r"((?:Users|Administrators|Customers|Operators|Deployments)\s+are\s+(?:recommended|advised|encouraged|urged)\s+to\s+[^.]+(?:\.(?!\s+[A-Z])[^.]+)*\.)",
        r"((?:Upgrade|Update|Migrate)\s+to\s+version\s+[^.]+\.)",
        r"(This\s+(?:issue|vulnerability|flaw)\s+(?:is|was)\s+(?:fixed|resolved|patched)\s+in\s+[^.]+\.)",
    ]
    for pat in patterns:
        m = re.search(pat, description, flags=re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


async def fetch_cve_enrichment(session: aiohttp.ClientSession, cve_id: str) -> dict:
    """Fetch comprehensive CVE intelligence (title, full description, affected products/versions, CWE, severity/CVSS, references) from MITRE CVE API with NVD fallback."""
    if not cve_id:
        return {}
    norm_cve = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", norm_cve):
        return {}
    if norm_cve in _CVE_ENRICHMENT_CACHE:
        return _CVE_ENRICHMENT_CACHE[norm_cve]

    info: dict = {
        "cve_id": norm_cve,
        "state": None,
        "date_published": None,
        "title": None,
        "description": None,
        "sev_level": None,
        "cvss_score": None,
        "cvss_vector": None,
        "raw_sev_text": None,
        "product": None,
        "short_product": None,
        "versions": None,
        "cwe": None,
        "attack_vector": None,
        "remediation": None,
        "references": [],
        "assigner": None,
    }

    url = f"https://cveawg.mitre.org/api/cve/{norm_cve}"
    try:
        async with session.get(url, headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=6)) as resp:
            if resp.status == 200:
                data = await resp.json()
                cve_meta = data.get("cveMetadata") or {}
                info["state"] = str(cve_meta.get("state") or "").strip().upper() or None
                info["date_published"] = str(cve_meta.get("datePublished") or "").strip() or None

                containers = data.get("containers") or {}
                cna = containers.get("cna") or {}
                adp_list = [a for a in (containers.get("adp") or []) if isinstance(a, dict)]

                info["assigner"] = (
                    (cna.get("providerMetadata") or {}).get("shortName")
                    or cve_meta.get("assignerShortName")
                )

                raw_cna_title = clean_html_to_markdown(cna.get("title") or "").strip()
                if raw_cna_title and raw_cna_title.upper() != norm_cve:
                    info["title"] = raw_cna_title

                # Full official description
                descs = cna.get("descriptions") or []
                chosen_desc = ""
                for d in descs:
                    if isinstance(d, dict) and str(d.get("lang") or "").lower().startswith("en") and d.get("value"):
                        chosen_desc = clean_html_to_markdown(d["value"])
                        break
                if not chosen_desc and descs and isinstance(descs[0], dict):
                    chosen_desc = clean_html_to_markdown(descs[0].get("value") or "")
                if chosen_desc:
                    info["description"] = chosen_desc

                # Affected vendors, products, packages, and version ranges
                prod_labels: list[str] = []
                short_prods: list[str] = []
                pkg_names: list[str] = []
                ver_ranges: list[str] = []
                _skip_tokens = {"", "n/a", "na", "unknown", "unspecified", "-"}

                for aff in (cna.get("affected") or []):
                    if not isinstance(aff, dict):
                        continue
                    vendor = str(aff.get("vendor") or "").strip()
                    prod = str(aff.get("product") or "").strip()
                    pkg = str(aff.get("packageName") or "").strip()
                    if vendor.lower() in _skip_tokens:
                        vendor = ""
                    if prod.lower() in _skip_tokens:
                        prod = ""
                    if pkg.lower() in _skip_tokens:
                        pkg = ""

                    if vendor and vendor.islower():
                        vendor = vendor.capitalize()

                    if vendor and prod:
                        label = prod if vendor.lower() in prod.lower() else f"{vendor} — {prod}"
                        short_p = prod if vendor.lower() in prod.lower() else f"{vendor} {prod}"
                    else:
                        label = prod or vendor or pkg
                        short_p = prod or vendor or pkg

                    if label and label not in prod_labels:
                        prod_labels.append(label)
                    if short_p and short_p not in short_prods:
                        short_prods.append(short_p)
                    if pkg and pkg not in pkg_names and all(pkg.lower() not in pl.lower() for pl in prod_labels):
                        pkg_names.append(pkg)

                    for v in (aff.get("versions") or []):
                        if not isinstance(v, dict):
                            continue
                        if str(v.get("status") or "affected").lower() != "affected":
                            continue
                        ver = str(v.get("version") or "").strip()
                        lt = str(v.get("lessThan") or "").strip()
                        lte = str(v.get("lessThanOrEqual") or "").strip()
                        if ver.lower() in _skip_tokens | {"*"}:
                            ver = ""
                        if lt.lower() in _skip_tokens | {"*"}:
                            lt = ""
                        if lte.lower() in _skip_tokens | {"*"}:
                            lte = ""

                        v_str = ""
                        if lt and ver and ver != "0":
                            v_str = f"{ver} to <{lt}"
                        elif lt:
                            v_str = f"<{lt}"
                        elif lte and ver and ver != "0":
                            v_str = f"{ver} to <={lte}"
                        elif lte:
                            v_str = f"<={lte}"
                        elif ver:
                            v_str = ver
                        if v_str and v_str not in ver_ranges:
                            ver_ranges.append(v_str)

                if prod_labels:
                    base_prod = " / ".join(prod_labels[:2])
                    if pkg_names:
                        base_prod += f" (`{pkg_names[0]}`)"
                    info["product"] = base_prod
                    info["short_product"] = short_prods[0] if short_prods else prod_labels[0]
                if ver_ranges:
                    info["versions"] = " • ".join(f"`{vr}`" for vr in ver_ranges[:4])
                elif info["description"]:
                    m_ver_desc = re.search(
                        r"\b(?:versions?\s+(\d[\w.\-]*\s+(?:to|through)\s+\d[\w.\-]*)|before\s+version\s+(\d[\w.\-]*(?:\s+SU\d+)?))\b",
                        info["description"],
                        flags=re.IGNORECASE,
                    )
                    if m_ver_desc:
                        v_extracted = m_ver_desc.group(1) or f"<{m_ver_desc.group(2)}"
                        info["versions"] = f"`{v_extracted.strip()}`"

                # Weakness / CWE
                cwe_items: list[str] = []
                all_problem_types = list(cna.get("problemTypes") or [])
                for adp_item in adp_list:
                    all_problem_types.extend(adp_item.get("problemTypes") or [])
                for pt in all_problem_types:
                    if not isinstance(pt, dict):
                        continue
                    for d in (pt.get("descriptions") or []):
                        if not isinstance(d, dict):
                            continue
                        cwe_id = str(d.get("cweId") or "").strip()
                        cwe_desc = clean_html_to_markdown(str(d.get("description") or "")).strip()
                        if cwe_id.lower() in _skip_tokens or "noinfo" in cwe_id.lower():
                            cwe_id = ""
                        if cwe_desc.lower() in _skip_tokens or "noinfo" in cwe_desc.lower():
                            cwe_desc = ""
                        m_inline_cwe = re.match(r"^(CWE-\d+)\s*[:\-]?\s*(.*)$", cwe_desc, flags=re.IGNORECASE)
                        if m_inline_cwe:
                            cid = m_inline_cwe.group(1).upper()
                            rest = m_inline_cwe.group(2).strip()
                            formatted_cwe = f"`{cid}` {rest}".strip()
                        elif cwe_id and cwe_desc:
                            formatted_cwe = f"`{cwe_id.upper()}` {cwe_desc}"
                        elif cwe_id:
                            formatted_cwe = f"`{cwe_id.upper()}`"
                        elif cwe_desc:
                            formatted_cwe = cwe_desc
                        else:
                            continue
                        if formatted_cwe not in cwe_items:
                            cwe_items.append(formatted_cwe)
                if cwe_items:
                    info["cwe"] = " • ".join(cwe_items[:2])

                # Severity, CVSS Score & Attack Vector
                metrics = list(cna.get("metrics") or [])
                for adp_item in adp_list:
                    metrics.extend(adp_item.get("metrics") or [])

                for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    if info["sev_level"]:
                        break
                    for m in metrics:
                        if isinstance(m, dict) and isinstance(m.get(key), dict):
                            cvss_obj = m[key]
                            raw_score = cvss_obj.get("baseScore")
                            raw_sev = _normalize_severity_token(cvss_obj.get("baseSeverity"))
                            score_val = float(raw_score) if raw_score is not None else None
                            if not raw_sev and score_val is not None:
                                raw_sev = score_to_severity_level(score_val)
                            if raw_sev in VULN_SEVERITY_STYLE:
                                info["sev_level"] = raw_sev
                                info["cvss_score"] = score_val
                                info["cvss_vector"] = cvss_obj.get("vectorString")
                                av = str(cvss_obj.get("attackVector") or cvss_obj.get("accessVector") or "").upper()
                                pr = str(cvss_obj.get("privilegesRequired") or "").upper()
                                ui = str(cvss_obj.get("userInteraction") or "").upper()
                                v_parts = []
                                if av in ("NETWORK", "REMOTE"):
                                    v_parts.append("Remote / Network")
                                elif "ADJACENT" in av:
                                    v_parts.append("Adjacent Network")
                                elif av == "LOCAL":
                                    v_parts.append("Local")
                                elif av == "PHYSICAL":
                                    v_parts.append("Physical")
                                if pr == "NONE":
                                    v_parts.append("Unauthenticated")
                                elif pr in ("LOW", "HIGH"):
                                    v_parts.append(f"{pr.capitalize()} Privs")
                                if ui == "REQUIRED":
                                    v_parts.append("User Interaction")
                                if v_parts:
                                    info["attack_vector"] = " • ".join(v_parts)
                                break

                # Fallback to textual CNA/ADP severity in metrics[].other
                if not info["sev_level"]:
                    for m in metrics:
                        if not isinstance(m, dict):
                            continue
                        other = m.get("other")
                        if isinstance(other, dict):
                            content = other.get("content")
                            raw_text = ""
                            if isinstance(content, dict):
                                raw_text = str(
                                    content.get("text")
                                    or content.get("value")
                                    or content.get("severity")
                                    or ""
                                ).strip()
                            elif isinstance(content, str):
                                raw_text = content.strip()
                            mapped = _normalize_severity_token(raw_text)
                            if mapped in VULN_SEVERITY_STYLE:
                                info["sev_level"] = mapped
                                info["raw_sev_text"] = raw_text.capitalize()
                                break

                # Solutions / Workarounds / Remediation
                sol_texts: list[str] = []
                for key in ("solutions", "workarounds"):
                    for s_item in (cna.get(key) or []):
                        if isinstance(s_item, dict) and s_item.get("value"):
                            cleaned_s = clean_html_to_markdown(s_item["value"]).strip()
                            if cleaned_s and cleaned_s not in sol_texts:
                                sol_texts.append(cleaned_s)
                if sol_texts:
                    info["remediation"] = " ".join(sol_texts)[:400]
                elif info["description"]:
                    info["remediation"] = _extract_remediation_from_text(info["description"])

                # Official Reference URLs
                seen_ref_urls: set[str] = set()
                ref_pairs: list[tuple[str, str]] = []
                for ref in (cna.get("references") or []):
                    if not isinstance(ref, dict):
                        continue
                    r_url = str(ref.get("url") or "").strip()
                    if not r_url.startswith(("http://", "https://")) or r_url in seen_ref_urls:
                        continue
                    seen_ref_urls.add(r_url)
                    tags_low = [str(t).lower() for t in (ref.get("tags") or [])]
                    url_low = r_url.lower()
                    if "vendor-advisory" in tags_low or any(d in url_low for d in ("lists.apache.org", "apache.org", "ivanti.com", "microsoft.com", "cisco.com", "fortiguard.com", "oracle.com", "eclipse.org")):
                        r_label = "Vendor Advisory"
                    elif "patch" in tags_low or "/commit/" in url_low or "/pull/" in url_low:
                        r_label = "Patch / Fix"
                    elif "exploit" in tags_low or "exploit-db.com" in url_low or "packetstorm" in url_low:
                        r_label = "Exploit / PoC"
                    elif "github.com" in url_low and "/advisories/" in url_low:
                        r_label = "GitHub Advisory"
                    else:
                        r_label = "Official Reference"
                    ref_pairs.append((r_label, r_url))
                info["references"] = ref_pairs[:3]
    except Exception:
        pass

    if info["sev_level"] in VULN_SEVERITY_STYLE:
        _cache_set(_CVE_SEVERITY_CACHE, norm_cve, (info["sev_level"], info["cvss_score"]), max_size=500)
    if any(info.get(k) for k in ("description", "sev_level", "product", "cwe", "title")):
        _cache_set(_CVE_ENRICHMENT_CACHE, norm_cve, info, max_size=500)

    return info


async def fetch_cve_official_severity(session: aiohttp.ClientSession, cve_id: str) -> tuple[str | None, float | None]:
    """Fetch official CVSS/CNA severity and base score from the authoritative MITRE CVE Services API."""
    if not cve_id:
        return None, None
    norm_cve = cve_id.strip().upper()
    if norm_cve in _CVE_SEVERITY_CACHE:
        return _CVE_SEVERITY_CACHE[norm_cve]
    info = await fetch_cve_enrichment(session, norm_cve)
    return info.get("sev_level"), info.get("cvss_score")


def format_vuln_severity_badge(
    sev_level: str | None,
    cvss_score: float | None = None,
    raw_sev_text: str | None = None,
) -> str | None:
    if not sev_level or sev_level not in VULN_SEVERITY_STYLE:
        return None
    style = VULN_SEVERITY_STYLE[sev_level]
    if cvss_score is not None:
        return f"{style['dot']} **{sev_level}** (`CVSS {cvss_score:.1f}`)"
    if raw_sev_text and raw_sev_text.upper() != sev_level:
        return f"{style['dot']} **{sev_level}** (`{raw_sev_text}`)"
    return f"{style['dot']} **{sev_level}**"


def build_vulnerability_fields(
    *,
    publisher: str,
    date_str: str,
    cve_id: str | None = None,
    cve_info: dict | None = None,
    sev_badge: str | None = None,
    attack_vector: str | None = None,
    entry_link: str | None = None,
    fallback_product: str | None = None,
    ransomware_use: str | None = None,
    required_action: str | None = None,
    date_label: str = "Date Published",
) -> list[dict]:
    """Build structured vulnerability intelligence fields for Discord embeds."""
    info = cve_info or {}
    fields: list[dict] = []

    product_val = info.get("product") or fallback_product
    if product_val:
        fields.append({"name": "Affected Product", "value": product_val[:250], "inline": True})

    if sev_badge:
        fields.append({"name": "Severity", "value": sev_badge, "inline": True})

    eff_vector = info.get("attack_vector") or attack_vector
    if eff_vector:
        fields.append({"name": "Attack Vector", "value": f"`{eff_vector}`", "inline": True})

    if info.get("versions"):
        fields.append({"name": "Affected Versions", "value": info["versions"][:300], "inline": True})

    if info.get("cwe"):
        fields.append({"name": "Weakness / CWE", "value": info["cwe"][:300], "inline": True})

    if ransomware_use:
        fields.append({"name": "Ransomware Campaign Use", "value": f"**{ransomware_use}**", "inline": True})

    if publisher:
        cna_short = info.get("assigner")
        pub_val = f"{publisher} (`CNA: {cna_short}`)" if (cna_short and cna_short.lower() not in publisher.lower()) else publisher
        fields.append({"name": "Source / CNA", "value": pub_val, "inline": True})

    fields.append({"name": date_label, "value": f"`{date_str}`", "inline": True})

    eff_remediation = required_action or info.get("remediation")
    if eff_remediation:
        fields.append({"name": "Remediation / Action", "value": eff_remediation[:500], "inline": False})

    # Build authoritative reference & dossier links
    ref_links: list[str] = []
    seen_urls: set[str] = set()
    for r_label, r_url in (info.get("references") or []):
        if r_url not in seen_urls:
            seen_urls.add(r_url)
            ref_links.append(f"[{r_label}]({r_url})")

    if entry_link and entry_link.startswith(("http://", "https://")) and entry_link not in seen_urls:
        if "threatcluster.io" not in entry_link.lower():
            seen_urls.add(entry_link)
            ref_links.insert(0, f"[{publisher} Advisory]({entry_link})")

    norm_cve = (cve_id or info.get("cve_id") or "").strip().upper()
    if re.match(r"^CVE-\d{4}-\d{4,}$", norm_cve):
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{norm_cve}"
        cve_org_url = f"https://www.cve.org/CVERecord?id={norm_cve}"
        if nvd_url not in seen_urls:
            ref_links.append(f"[NVD Dossier]({nvd_url})")
        if cve_org_url not in seen_urls:
            ref_links.append(f"[MITRE CVE Record]({cve_org_url})")

    if not ref_links and entry_link:
        ref_links.append(f"[Open Advisory]({entry_link})")

    if ref_links:
        fields.append({"name": "Advisory & Dossiers", "value": " • ".join(ref_links[:5]), "inline": False})

    return fields


async def poll_vulnerabilities(session: aiohttp.ClientSession):
    try:
        async with session.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                bootstrap_limit = 2 if await is_first_run() else None
                vulns = (await resp.json()).get("vulnerabilities", [])
                recent_vulns = [
                    v for v in vulns
                    if isinstance(v, dict) and not is_older_than(v.get("dateAdded") or "", days=7)
                ]
                recent_vulns.sort(key=lambda v: str(v.get("dateAdded") or ""))
                items = recent_vulns[-bootstrap_limit:] if bootstrap_limit else recent_vulns[-100:]
                for vuln in items:
                    try:
                        cve_id = vuln.get("cveID")
                        event_id = f"cisa_{cve_id}".lower()
                        if not await is_duplicate(event_id, ioc=cve_id):
                            dispatched = False
                            async with dedup_guard(event_id, f"ioc:{normalize_ioc(str(cve_id))}" if cve_id else ""):
                                if await is_duplicate(event_id, ioc=cve_id):
                                    continue
                                prod_name = f"{vuln.get('vendorProject')} {vuln.get('product')}".strip()
                                vuln_name = (vuln.get("vulnerabilityName") or "").strip()
                                is_ransom = vuln.get("knownRansomwareCampaignUse", "Unknown")
                                date_added = format_clean_date(vuln.get("dateAdded") or "")
                                short_desc = clean_html_to_markdown(vuln.get("shortDescription", "Actively exploited vulnerability."))

                                cve_info = await fetch_cve_enrichment(session, cve_id)
                                sev_level = cve_info.get("sev_level")
                                cvss_score = cve_info.get("cvss_score")
                                inferred_sev, inferred_vec = infer_vuln_severity_and_vector(
                                    vuln_name or prod_name,
                                    cve_info.get("description") or short_desc,
                                    cve_info.get("cwe") or ", ".join(vuln.get("cwes") or []),
                                )
                                if not sev_level:
                                    sev_level = inferred_sev or "HIGH"
                                sev_badge = format_vuln_severity_badge(sev_level, cvss_score, cve_info.get("raw_sev_text"))
                                alert_color = VULN_SEVERITY_STYLE[sev_level]["color"] if sev_level in VULN_SEVERITY_STYLE else 0xE67E22

                                title_suffix = f"{cve_id} — {vuln_name}" if vuln_name else f"{cve_id} ({prod_name})"
                                if sev_level in VULN_SEVERITY_STYLE:
                                    s_info = VULN_SEVERITY_STYLE[sev_level]
                                    alert_title = f"🦠 Vulnerability Alert · {s_info['dot']} {s_info['label']}: {title_suffix}"
                                else:
                                    alert_title = f"🦠 Vulnerability Alert: {title_suffix}"

                                if not cve_info.get("cwe") and vuln.get("cwes"):
                                    cve_info = {**cve_info, "cwe": " • ".join(f"`{c}`" for c in (vuln.get("cwes") or [])[:2])}

                                kev_notes = str(vuln.get("notes") or "")
                                note_urls = re.findall(r"https?://[^\s,;]+", kev_notes)
                                kev_entry_link = note_urls[0] if note_urls else None

                                kev_fields = build_vulnerability_fields(
                                    publisher="CISA KEV Catalog",
                                    date_str=date_added,
                                    cve_id=cve_id,
                                    cve_info=cve_info,
                                    sev_badge=sev_badge,
                                    attack_vector=inferred_vec,
                                    entry_link=kev_entry_link,
                                    fallback_product=prod_name,
                                    ransomware_use=is_ransom,
                                    required_action=vuln.get("requiredAction", "Patch immediately"),
                                    date_label="Date Added to KEV",
                                )

                                full_desc = cve_info.get("description") if (cve_info.get("description") and len(cve_info["description"]) > len(short_desc)) else short_desc
                                kev_mitre = classify_vulnerability_mitre(vuln_name, full_desc, cve_info.get("cwe") or "")

                                dispatched = await dispatch_discord_embed(
                                    session=session,
                                    channel_key="vulnerabilities",
                                    title=alert_title,
                                    description=full_desc,
                                    fields=kev_fields,
                                    color=alert_color,
                                    mitre_tactics=kev_mitre
                                )
                                if dispatched:
                                    await record_event(
                                        event_id,
                                        "CISA-KEV",
                                        affected_product=prod_name[:100],
                                        ioc=cve_id,
                                        title=cve_id,
                                        cvss_score=cvss_score,
                                        severity=cve_info.get("sev_level"),
                                        cwe=cve_info.get("cwe"),
                                    )
                            if dispatched:
                                await asyncio.sleep(0.5)
                    except Exception as item_err:
                        print(f"[Collector Error] CISA KEV item: {item_err}")
    except Exception as e:
        print(f"[Collector Error] CISA KEV: {e}")


def condense_podcast_summary(raw_html: str, max_points: int = 10) -> str:
    """Extract up to ten concise, sponsor-filtered takeaways from podcast notes."""
    if not raw_html:
        return "Episode published with no detailed show notes."

    text = clean_html_to_markdown(raw_html)

    ad_patterns = [
        r"(?i)thanks to our sponsor.*",
        r"(?i)sponsored by.*",
        r"(?i)check out our patreon.*",
        r"(?i)support us on patreon.*",
        r"(?i)use promo code.*",
        r"(?i)visit https?://[^\s]+ for \d+% off.*",
        r"(?i)music by.*",
        r"(?i)(allow what you need and block the rest|threatlocker|zero trust platform).*",
        r"(?i)(check out flare\.io|flare\.io|antisyphon training|sc academy).*",
        r"(?i)(get your cpes|cyberthreatbrief\.simplycyber\.io).*",
        r"(?i)(sign up for the simply cyber newsletter|follow sc:).*",
        r"(?i)(join sc discord|join our discord).*",
        r"(?i)(stop ransomware without the hassle).*",
        r"https?://[^\s]+",
    ]
    for pattern in ad_patterns:
        text = re.sub(pattern, "", text)

    candidates = []
    for line in text.splitlines():
        line = line.strip(" -•*\t")
        if len(line) >= 20:
            candidates.append(line)

    if len(candidates) < max_points:
        candidates = [
            sentence.strip(" -•*\t.")
            for sentence in re.split(r"(?<=[.!?])\s+", text)
            if len(sentence.strip()) >= 20
        ]

    points = candidates[:max_points]

    if not points:
        return text[:400] + ("..." if len(text) > 400 else "")

    return "\n".join(f"• {point}" for point in points)

from rss_topic import classify_rss_topic

from advisory_title import tidy_advisory_title

# --- Host Status indicator (red = offline, green = online) ---
import functools as _functools

def _status_dot(value):
    low = str(value).lower()
    if "offline" in low:
        return "🔴 "
    if "online" in low:
        return "🟢 "
    return ""

def _with_status_dots(fn):
    @_functools.wraps(fn)
    async def inner(*args, **kwargs):
        fields = kwargs.get("fields")
        if fields:
            new_fields = []
            for f in fields:
                if isinstance(f, dict) and "host status" in str(f.get("name", "")).lower():
                    val = str(f.get("value", ""))
                    if not val.startswith(("🔴", "🟢")):
                        f = {**f, "value": _status_dot(val) + val}
                new_fields.append(f)
            kwargs["fields"] = new_fields
        return await fn(*args, **kwargs)
    return inner

dispatch_discord_embed = _with_status_dots(dispatch_discord_embed)


async def fetch_simplycyber_stories(session: aiohttp.ClientSession, episode_title: str) -> list[str]:
    """Scrapes the published 'Stories covered' from the official episode website."""
    ep_match = re.search(r"Ep\s*(\d+)", episode_title, re.IGNORECASE)
    if not ep_match:
        return []
    ep_num = ep_match.group(1)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    try:
        # Search the episodes index for the target episode URL
        async with session.get("https://cyberthreatbrief.simplycyber.io/episodes/", headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status != 200:
                return []
            index_html = await resp.text()
            
        # Locate the link containing ep-{ep_num}
        link_match = re.search(r'href="([^"]*ep-' + ep_num + r'[^"]*)"', index_html, re.IGNORECASE)
        if not link_match:
            # Try alternate pattern with date-ep
            link_match = re.search(r'href="(/episodes/[^"]*' + ep_num + r'[^"]*)"', index_html, re.IGNORECASE)
        
        if not link_match:
            return []
            
        ep_path = link_match.group(1)
        target_url = ep_path if ep_path.startswith("http") else f"https://cyberthreatbrief.simplycyber.io{ep_path}"
        
        async with session.get(target_url, headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as ep_resp:
            if ep_resp.status != 200:
                return []
            page_html = await ep_resp.text()
            
        # Parse the 'Stories covered' block
        stories = []
        # Pattern 1: Heading questions
        headings = re.findall(r'<h3[^>]*>(.*?)</h3>', page_html, re.IGNORECASE)
        for h in headings:
            clean_h = re.sub(r'<[^>]+>', '', h).strip()
            if len(clean_h) > 15 and not any(k in clean_h.lower() for k in ["about", "sponsor", "support", "community", "cpe"]):
                stories.append(clean_h)
                
        # Pattern 2: 'At a glance' summary paragraph
        if not stories:
            glance_match = re.search(r'At a glance\s*</h2>\s*<p>(.*?)</p>', page_html, re.IGNORECASE | re.DOTALL)
            if glance_match:
                sentences = re.split(r';|\.\s+', re.sub(r'<[^>]+>', '', glance_match.group(1)))
                for s in sentences:
                    s_clean = s.strip()
                    if len(s_clean) > 20:
                        stories.append(s_clean)
                        
        return stories[:8]
    except Exception:
        return []

async def fetch_and_process_rss(session: aiohttp.ClientSession, publisher: str, feed_url: str, alert_type: str, color: int, channel_key: str, may_need_translation: bool = False):
    async with CONCURRENCY_SEMAPHORE:
        try:
            async with session.get(feed_url, headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status != 200:
                    print(f"[RSS Error] {publisher}: HTTP {resp.status}")
                    return
                xml_data = await _safe_text(resp)

            feed = feedparser.parse(xml_data)
            bootstrap_limit = 2 if await is_first_run() else None
            entries = feed.entries[:bootstrap_limit] if bootstrap_limit else feed.entries

            for entry in (reversed(entries) if not bootstrap_limit else entries):
                try:
                    raw_pub = str(entry.get("published") or entry.get("updated") or "").strip()
                    if is_older_than(raw_pub or entry.get("published_parsed"), days=7):
                        continue
                    raw_title = html.unescape(html.unescape(str(entry.get("title") or "Untitled feed entry"))).strip()
                    raw_content = entry.summary if hasattr(entry, 'summary') else (entry.description if hasattr(entry, 'description') else "")
                    raw_link = entry.get("link", "")
                    entry_link = _safe_md_url(raw_link)
                    raw_id = entry.get("id") or raw_link
                    rss_ioc = None
                    if publisher == "ThreatCluster":
                        parts = re.split(r"\s+[—–-]\s+claimed by\s+", raw_title, flags=re.IGNORECASE, maxsplit=1)
                        tc_victim = parts[0].replace("Dark Web Victim Stream:", "").strip()
                        tc_actor = parts[1].strip() if len(parts) > 1 else "Unattributed"
                        event_id = normalize_leak_event_id(tc_actor, tc_victim, fallback_id=raw_id or raw_title)
                        is_dup = await is_ransomware_duplicate(event_id, tc_actor, tc_victim)
                        tc_v_slug = normalize_victim_slug(tc_victim)
                        guard_keys = (event_id, f"victim:{tc_v_slug}" if len(tc_v_slug) >= 3 else "")
                    else:
                        event_id = get_stable_id("rss", raw_id)
                        alt_rss_ids = []
                        if raw_link and raw_link != raw_id:
                            alt_rss_ids.append(get_stable_id("rss", raw_link))
                        if entry_link and entry_link not in (raw_id, raw_link):
                            alt_rss_ids.append(get_stable_id("rss", entry_link))
                        wid_match = re.search(r"name=(WID-SEC-\d{4}-\d+)", entry_link or "", flags=re.IGNORECASE)
                        if wid_match:
                            alt_rss_ids.append(f"wid_{wid_match.group(1).lower()}")
                        if channel_key == "vulnerabilities":
                            title_cves = list(dict.fromkeys(
                                m.upper() for m in re.findall(r"\bCVE-\d{4}-\d{4,}\b", raw_title, flags=re.IGNORECASE)
                            ))
                            if len(title_cves) == 1:
                                rss_ioc = title_cves[0]
                            elif len(title_cves) == 0:
                                desc_cves = list(dict.fromkeys(
                                    m.upper() for m in re.findall(r"\bCVE-\d{4}-\d{4,}\b", clean_html_to_markdown(raw_content), flags=re.IGNORECASE)
                                ))
                                if len(desc_cves) == 1:
                                    rss_ioc = desc_cves[0]
                        is_dup = await is_duplicate(event_id, ioc=rss_ioc, alt_event_ids=alt_rss_ids)
                        guard_keys = (event_id, *alt_rss_ids, f"ioc:{normalize_ioc(rss_ioc)}" if rss_ioc else "")
                    if not is_dup:
                        dispatched = False
                        async with dedup_guard(*guard_keys):
                            if publisher == "ThreatCluster":
                                if await is_ransomware_duplicate(event_id, tc_actor, tc_victim):
                                    continue
                            else:
                                if await is_duplicate(event_id, ioc=rss_ioc, alt_event_ids=alt_rss_ids):
                                    continue

                            if channel_key == "podcasts" or "🎙" in alert_type or "🎧" in alert_type:
                                sc_stories = []
                                if "simply cyber" in publisher.lower() or "threat briefing" in alert_type.lower():
                                    sc_stories = await fetch_simplycyber_stories(session, raw_title)
                                    
                                if sc_stories:
                                    clean_text = "\n".join(f"• {st}" for st in sc_stories)
                                else:
                                    clean_text = condense_podcast_summary(raw_content, max_points=10)
                                audio_url = None
                                if hasattr(entry, "enclosures") and entry.enclosures:
                                    audio_url = entry.enclosures[0].get("href")
                            else:
                                clean_text = clean_html_to_markdown(raw_content)
                                audio_url = None

                            if may_need_translation:
                                final_title, title_was_foreign = await auto_translate_to_english(session, raw_title)
                                final_desc, desc_was_foreign = await auto_translate_to_english(session, clean_text)
                                display_title = f"{alert_type} [Translated]: {final_title}" if (title_was_foreign or desc_was_foreign) else f"{alert_type}: {raw_title}"
                            else:
                                final_title = raw_title
                                final_desc = clean_text
                                display_title = f"{alert_type}: {raw_title}"

                            entry_color = color
                            vuln_sev_badge = None
                            cve_info: dict = {}
                            inferred_vuln_vec: str | None = None
                            fallback_vuln_product: str | None = None
                            if channel_key == "vulnerabilities":
                                sev_level, cvss_score, final_desc = extract_inline_vuln_severity(
                                    raw_title, final_desc, entry.get("tags")
                                )
                                lookup_cve = rss_ioc
                                if not lookup_cve:
                                    cve_any = re.search(r"\b(CVE-\d{4}-\d{4,})\b", f"{raw_title}\n{final_desc}", flags=re.IGNORECASE)
                                    if cve_any:
                                        lookup_cve = cve_any.group(1).upper()

                                if lookup_cve:
                                    cve_info = await fetch_cve_enrichment(session, lookup_cve)
                                    if cve_info.get("description") and (
                                        len(cve_info["description"]) > len(final_desc)
                                        or publisher == "ThreatCluster Vulns"
                                        or not final_desc
                                        or final_desc.strip() == raw_title.strip()
                                    ):
                                        final_desc = cve_info["description"]
                                    if not sev_level and cve_info.get("sev_level"):
                                        sev_level = cve_info["sev_level"]
                                    if cvss_score is None and cve_info.get("cvss_score") is not None:
                                        cvss_score = cve_info["cvss_score"]

                                inferred_sev, inferred_vuln_vec = infer_vuln_severity_and_vector(
                                    cve_info.get("title") or final_title or raw_title,
                                    final_desc,
                                    cve_info.get("cwe") or "",
                                )
                                if not sev_level:
                                    sev_level = inferred_sev

                                # Enrich bare CVE titles (e.g. ThreatCluster Vulns) with official title or product/weakness
                                if re.fullmatch(r"CVE-\d{4}-\d{4,}", raw_title.strip(), flags=re.IGNORECASE) and cve_info:
                                    cve_norm = lookup_cve or raw_title.strip().upper()
                                    if cve_info.get("title"):
                                        final_title = f"{cve_norm} — {cve_info['title']}"
                                    elif cve_info.get("short_product"):
                                        first_cwe = str(cve_info.get("cwe") or "").split("•")[0]
                                        cwe_clean = re.sub(r"`?CWE-\d+`?", "", first_cwe, flags=re.IGNORECASE).strip(" :—-")
                                        if cwe_clean:
                                            final_title = f"{cve_norm} — {cve_info['short_product']}: {cwe_clean}"
                                        else:
                                            final_title = f"{cve_norm} — {cve_info['short_product']}"
                                    display_title = f"{alert_type}: {final_title}"

                                if not cve_info.get("product"):
                                    m_edb = re.match(r"^\s*\[[^\]]+\]\s*(.+?)\s+-\s+.+$", raw_title)
                                    m_zdi = re.match(r"^\s*ZDI-\d{2}-\d+\s*:\s*(.+?)\s+(?:Remote|Local|Privilege|Heap|Stack|Out-of-Bounds|Use-After-Free|Improper|SQL|Command|Deserialization|Authentication|Directory|Path)\b", raw_title, flags=re.IGNORECASE)
                                    if m_edb:
                                        fallback_vuln_product = re.sub(r"\s*\(CVE-\d{4}-\d{4,}\)\s*", " ", m_edb.group(1), flags=re.I).strip()
                                    elif m_zdi:
                                        fallback_vuln_product = m_zdi.group(1).strip()

                                if sev_level in VULN_SEVERITY_STYLE:
                                    s_info = VULN_SEVERITY_STYLE[sev_level]
                                    entry_color = s_info["color"]
                                    vuln_sev_badge = format_vuln_severity_badge(
                                        sev_level, cvss_score, cve_info.get("raw_sev_text")
                                    )
                                    _vhead, _vsep, _vrest = display_title.partition(": ")
                                    if _vsep:
                                        display_title = f"{_vhead} · {s_info['dot']} {s_info['label']}: {_vrest}"

                            if channel_key == "gov_advisory":
                                _head, _sep, _rest = display_title.partition(": ")
                                if _sep:
                                    _clean, _sev, _upd = tidy_advisory_title(_rest)
                                    if _sev:
                                        _head += f" · {_sev[0]} {_sev[1]}"
                                    if _upd:
                                        _head += " · 🔄 Updated"
                                    _wid = re.search(r"name=(WID-SEC-\d{4}-\d+)", entry_link or "")
                                    final_title = _clean + (f" ({_wid.group(1)})" if _wid else "")
                                    display_title = f"{_head}: {final_title}"
                            
                            if publisher == "Malware Traffic Analysis":
                                platform, threat_cat, final_desc = classify_research_post(display_title, final_desc)
                                fields = [
                                {"name": "📅 Published Date", "value": f"`{str(entry.get('published') or entry.get('updated') or 'Not provided')[:25]}`", "inline": True},
                                    {"name": "Target Platform", "value": f"`{platform}`", "inline": True},
                                    {"name": "Threat Category", "value": f"`{threat_cat}`", "inline": True},
                                    {"name": "Investigation Artifacts", "value": "• `Wireshark PCAP (.zip)`\n• `Infection Binaries`\n• `Host/DNS IoC List`", "inline": False},
                                    {"name": "Forensic Dossier", "value": f"[Open Full Analysis & PCAP Download]({entry_link})", "inline": False}
                                ]
                                alert_mitre = "T1204 User Execution • T1071 C2 Traffic • T1056 Input Capture"
                            elif publisher == "vx-underground":
                                clean_pub = format_clean_date(entry.get("published") or entry.get("updated") or "")
                                fields = [
                                    {"name": "Source", "value": "`vx-underground Papers Library`", "inline": True},
                                    {"name": "Date Published", "value": f"`{clean_pub}`", "inline": True},
                                    {"name": "Category", "value": "`Reverse Engineering Whitepaper`", "inline": True},
                                    {"name": "Document Link", "value": f"[Download Paper]({entry_link})", "inline": False}
                                ]
                                alert_mitre = "T1588 Obtain Capabilities"
                            elif channel_key == "vulnerabilities":
                                clean_pub = format_clean_date(entry.get("published") or entry.get("updated") or "")
                                fields = build_vulnerability_fields(
                                    publisher=publisher,
                                    date_str=clean_pub,
                                    cve_id=rss_ioc,
                                    cve_info=cve_info,
                                    sev_badge=vuln_sev_badge,
                                    attack_vector=inferred_vuln_vec,
                                    entry_link=entry_link,
                                    fallback_product=fallback_vuln_product,
                                )
                                alert_mitre = classify_vulnerability_mitre(
                                    final_title or raw_title,
                                    final_desc,
                                    cve_info.get("cwe") or "",
                                    is_poc=("poc" in alert_type.lower() or "exploit" in publisher.lower()),
                                )
                                tc_dwi_match = None
                            else:
                                clean_pub = format_clean_date(entry.get("published") or entry.get("updated") or "")
                                fields = [
                                    {"name": "Publisher", "value": publisher, "inline": True},
                                ]
                                if vuln_sev_badge:
                                    fields.append({"name": "Severity", "value": vuln_sev_badge, "inline": True})
                                fields.extend([
                                    {"name": "Date Published", "value": f"`{clean_pub}`", "inline": True},
                                    {"name": "Details", "value": f"[Open Document / Article]({entry_link})", "inline": False}
                                ])
                                if audio_url:
                                    fields.append({"name": "Audio Stream", "value": f"[▶ Listen to Episode (MP3)]({audio_url})", "inline": False})

                                tc_dwi_match = None
                                if publisher == "ThreatCluster":
                                    parts = re.split(r"\s+[—–-]\s+claimed by\s+", raw_title, flags=re.IGNORECASE, maxsplit=1)
                                    victim_text = parts[0].replace("Dark Web Victim Stream:", "").strip()
                                    actor_text = parts[1].strip() if len(parts) > 1 else "Unattributed"
                                    display_title = f"🚨 Ransomware Alert: {victim_text}"

                                    clean_date = format_clean_date(str(entry.get("published") or entry.get("updated") or ""))
                                    actor_stat = await get_actor_randomized_stat(actor_text)
                                    dwi_items = await fetch_darkwebinformer_items(session)
                                    tc_dwi_match = lookup_dwi_enrichment(dwi_items, victim_text)
                                    tc_dossier_link = await resolve_actor_value_add_link(session, actor_text)

                                    fields = build_ransomware_fields(
                                        publisher="ThreatCluster",
                                        group=actor_text,
                                        date_str=clean_date,
                                        claim_text=final_desc,
                                        source_link_name="Discovery Link",
                                        source_link_value=(f"[Inspect Leak Page]({entry_link})" if entry_link else "Not provided"),
                                        actor_stat=actor_stat,
                                        dwi_match=tc_dwi_match,
                                        extra_dossier_link=tc_dossier_link,
                                    )

                                if channel_key == "podcasts" or "🎙" in alert_type or "🎧" in alert_type:
                                    alert_mitre = None
                                elif channel_key == "research":
                                    _topic_label, alert_mitre = classify_rss_topic(final_title or raw_title, final_desc)
                                    display_title = display_title.replace(alert_type, _topic_label, 1)
                                elif publisher == "ThreatCluster":
                                    alert_mitre = "T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service"
                                else:
                                    _, classified_mitre = classify_rss_topic(final_title or raw_title, final_desc)
                                    alert_mitre = classified_mitre if classified_mitre != "Not mapped" else None

                            embed_desc = "" if publisher == "ThreatCluster" else (final_desc[:1900] + ("..." if len(final_desc) >= 1900 else ""))
                            embed_image = (tc_dwi_match.get("image_url") if (publisher == "ThreatCluster" and tc_dwi_match) else None)

                            dispatched = await dispatch_discord_embed(
                                session=session,
                                channel_key=channel_key,
                                title=display_title,
                                description=embed_desc,
                                fields=fields,
                                color=entry_color,
                                image_url=embed_image,
                                mitre_tactics=alert_mitre
                            )

                            if dispatched:
                                if publisher == "ThreatCluster":
                                    await record_event(
                                        event_id,
                                        publisher,
                                        threat_actor=(tc_actor if tc_actor != "Unattributed" else None),
                                        target_industry=(tc_dwi_match.get("sector") if tc_dwi_match else None),
                                        country_code=(tc_dwi_match.get("country_code") if tc_dwi_match else None),
                                        title=str(tc_victim)[:200],
                                    )
                                else:
                                    vuln_prod_rec = (cve_info.get("short_product") or fallback_vuln_product or "")[:100] or None
                                    await record_event(
                                        event_id,
                                        publisher,
                                        affected_product=vuln_prod_rec,
                                        ioc=rss_ioc,
                                        title=(final_title or raw_title)[:200],
                                        cvss_score=(cvss_score if channel_key == "vulnerabilities" else None),
                                        severity=(cve_info.get("sev_level") if channel_key == "vulnerabilities" else None),
                                        cwe=(cve_info.get("cwe") if channel_key == "vulnerabilities" else None),
                                    )
                        if dispatched:
                            await asyncio.sleep(0.5)
                except Exception as entry_error:
                    print(f"[RSS Entry Error] {publisher}: {entry_error}")

        except Exception as error:
            print(f"[RSS Error] {publisher}: {error}")



async def poll_rss_streams(session: aiohttp.ClientSession):
    # Patched and updated RSS catalog
    rss_catalog = [
        ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "🛡 Government Advisory", 0x2980B9, "gov_advisory", False),
        ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "🛡 Government Advisory", 0x2980B9, "gov_advisory", False),
        ("CISA ICS Advisories", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", "🏭 Industrial Control Systems Alert", 0xD35400, "gov_advisory", False),
        ("CERT-FR", "https://www.cert.ssi.gouv.fr/feed/", "🛡 Government Advisory", 0x2980B9, "gov_advisory", True),
        ("CERT-Bund (BSI)", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "🛡 Government Advisory", 0x2980B9, "gov_advisory", True),
        ("Canadian Cyber", "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en", "🛡 Government Advisory", 0x2980B9, "gov_advisory", False),
        ("Malware Traffic Analysis", "https://www.malware-traffic-analysis.net/blog-entries.rss", "🔬 PCAP & Infection Chain", 0x1ABC9C, "research", False),
          ("nao_sec", "https://nao-sec.org/feed", "🔬 Independent Threat Hunting", 0x1ABC9C, "research", True),
        ("BornCity Security", "https://borncity.com/win/feed/", "⚡ Breaking IT & Zero-Day Report", 0x3498DB, "incidents", True),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/", "📰 Cybercrime Investigation", 0x2ECC71, "incidents", False),
        ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "🔬 Threat Research & APTs", 0x1ABC9C, "research", False),
        ("SANS ISC", "https://isc.sans.edu/rssfeed.xml", "⚡ Global Threat Storm Briefing", 0x3498DB, "incidents", False),
        ("Exploit-DB", "https://www.exploit-db.com/rss.xml", "💥 Exploit PoC Alert", 0xE91E63, "vulnerabilities", False),
        ("Packet Storm", "https://packetstorm.news/rss/files", "💥 Exploit PoC Alert", 0xE91E63, "vulnerabilities", False),
        ("ThreatCluster Vulns", "https://threatcluster.io/vulnerabilities/feed.xml", "🦠 Vulnerability Alert", 0xE67E22, "vulnerabilities", False),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "📰 Cyber Incident Report", 0x2ECC71, "incidents", False),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "📰 Cyber Incident Report", 0x2ECC71, "incidents", False),
        ("ThreatCluster", "https://threatcluster.io/dark-web/feed.xml", "🚨 Dark Web Victim Stream", 0xE74C3C, "ransomware", True),
        ("Have I Been Pwned", "https://haveibeenpwned.com/feed/breaches/", "🚨 Data Breach Notification", 0xE74C3C, "ransomware", False),
        ("DataBreaches.net", "https://www.databreaches.net/feed/", "🚨 Leak Site Incident", 0xE74C3C, "ransomware", False),
        ("Google TAG", "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "🔬 Nation-State APT Report", 0x1ABC9C, "research", False),
        ("SentinelLabs", "https://www.sentinelone.com/labs/feed/", "🔬 Threat Research", 0x1ABC9C, "research", False),
        ("Red Canary Intel", "https://redcanary.com/blog/feed/", "🔬 Adversary Tradecraft", 0x1ABC9C, "research", False),
        ("Zero Day Initiative", "https://www.zerodayinitiative.com/blog?format=rss", "💥 Vulnerability & PoC Advisory", 0xE67E22, "vulnerabilities", False),
        ("Cybersecurity Headlines", "https://cisoseries.libsyn.com/rss", "🎙 Daily Audio Briefing", 0x3498DB, "podcasts", False),
        ("SANS Stormcast", "https://isc.sans.edu/podcast.rss", "🎙 Daily Audio Briefing", 0x3498DB, "podcasts", False),
        ("Risky Business", "https://risky.biz/feeds/risky-business", "🎙 Industry Podcast", 0x3498DB, "podcasts", False),
        ("Darknet Diaries", "https://feeds.megaphone.fm/darknetdiaries", "🎧 Darknet Stories", 0x9B59B6, "podcasts", False),
        ("Smashing Security", "https://www.smashingsecurity.com/rss", "🎙 Security & Tech Podcast", 0x3498DB, "podcasts", False),
        ("ShadowTalk", "https://rss.buzzsprout.com/2154459.rss", "🎙 Threat Intel Podcast", 0x3498DB, "podcasts", False),
        ("Hacker and the Fed", "https://feeds.megaphone.fm/CON9079456418", "🎙 Security Case Studies", 0x3498DB, "podcasts", False),
        ("Defensive Security", "https://defensivesecurity.org/feed/podcast", "🎙 Blue Team Analysis", 0x3498DB, "podcasts", False),
        ("CISO Series Podcast", "https://cisoseries.com/feed/podcast/", "🎙 Security Leadership", 0x3498DB, "podcasts", False),
        ("2.5 Admins", "https://2.5admins.com/feed/podcast", "🎙 Sysadmin & Ops Discussion", 0x3498DB, "podcasts", False),
        ("Cloud Security Podcast", "https://anchor.fm/s/10fb9928/podcast/rss", "🎙 Cloud Architecture & IAM", 0x3498DB, "podcasts", False),
        ("AI Security Podcast", "https://anchor.fm/s/eaa0671c/podcast/rss", "🎙 AI Safety & LLM Red Teaming", 0x3498DB, "podcasts", False),
        ("Cybersecurity Defenders", "https://feeds.transistor.fm/the-cybersecurity-defenders-podcast", "🎙 Detection & SOC Triage", 0x3498DB, "podcasts", False),
        ("Adversary Universe", "https://feeds.buzzsprout.com/1826048.rss", "🎙 Threat Actor Profiling", 0x3498DB, "podcasts", False),
        ("Cyber Threat Perspective", "https://rss.buzzsprout.com/1731753.rss", "🎙 Adversary Hunting", 0x3498DB, "podcasts", False),
        ("What the Hack", "https://rss.introcast.io/1571482669/feeds.megaphone.fm/TPG2245590306", "🎙 Scam & Fraud Breakdown", 0x3498DB, "podcasts", False),
        ("Hacked", "https://feeds.megaphone.fm/hackedpodcast", "🎙 Cybercrime Narrative", 0x3498DB, "podcasts", False),
        ("Error Code", "https://feed.podbean.com/errorcode/feed.xml", "🎙 IoT & Embedded Security", 0x3498DB, "podcasts", False),
        ("Dev Interrupted", "https://rss.buzzsprout.com/1422892.rss", "🎙 DevSecOps & Architecture", 0x3498DB, "podcasts", False),
        ("Cyber Uncut", "https://cybersecurityuncut.libsyn.com/rss", "🎙 National Cyber Policy", 0x3498DB, "podcasts", False),
        ("CyberWire Daily", "https://feeds.megaphone.fm/cyberwire-daily-podcast", "🎙 Daily Audio Briefing", 0x3498DB, "podcasts", False),
        ("Hacking Humans", "https://rss.pdrl.fm/7d51b0/feeds.megaphone.fm/hacking-humans", "🎙 Social Engineering & Scams", 0x9B59B6, "podcasts", False),
        ("Late Night Linux", "https://latenightlinux.com/feed/mp3", "🎙 Linux & Systems Ops", 0x2ECC71, "podcasts", False),
        ("Daily Cyber Threat Brief", "https://feeds.transistor.fm/simply-cyber", "🎙 Threat Briefing", 0x3498DB, "podcasts", False),
        ("Cybersecurity Today", "https://cybersecuritytoday.libsyn.com/rss", "🎙 Daily Infosec News", 0x3498DB, "podcasts", False),
        ("Microsoft Threat Intel", "https://feeds.megaphone.fm/microsoft-threat-intelligence", "🎙 Microsoft Research", 0x00A4EF, "podcasts", False),
        ("Secure AF", "https://feeds.buzzsprout.com/660007.rss", "🎙 Tactical Red/Blue Team", 0xE67E22, "podcasts", False),
        ("WIRED Security", "https://www.wired.com/feed/category/security/latest/rss", "📰 Investigative Journalism", 0xE91E63, "podcasts", False),
    ]
    
    rss_tasks = [
        fetch_and_process_rss(session, pub, url, a_type, color, ch_key, trans_flag)
        for pub, url, a_type, color, ch_key, trans_flag in rss_catalog
    ]
    _rss_results = await asyncio.gather(*rss_tasks, return_exceptions=True)
    for _r in _rss_results:
        if isinstance(_r, BaseException):
            import traceback
            print(f"[RSS Task Crash] {type(_r).__name__}: {_r}")
            traceback.print_exception(type(_r), _r, _r.__traceback__)

# --- ENGINE ORCHESTRATION ---

async def main():
    global ABUSECH_AUTH_KEY
    await init_db()
    print("[*] Threat Feed Engine Active with Corrected Endpoints, Triage Sandbox Links, and Multi-Channel Routing.", flush=True)
    import sys
    sys.modules.setdefault("threat_feed", sys.modules[__name__])
    from metrics_engine import evaluate_and_dispatch_metrics

    connector = aiohttp.TCPConnector(limit=15, ttl_dns_cache=300, family=socket.AF_INET)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            # Reload .env so newly added webhook URLs take effect dynamically without blanking active keys
            load_dotenv(_ENV_PATH, override=True)
            ABUSECH_AUTH_KEY = (os.getenv("ABUSECH_AUTH_KEY") or "").strip() or ABUSECH_AUTH_KEY
            for ch_k, env_k in (
                ("ransomware", "DISCORD_WEBHOOK_RANSOMWARE"),
                ("malware", "DISCORD_WEBHOOK_MALWARE"),
                ("infrastructure", "DISCORD_WEBHOOK_INFRASTRUCTURE"),
                ("phishing", "DISCORD_WEBHOOK_PHISHING"),
                ("vulnerabilities", "DISCORD_WEBHOOK_VULNERABILITIES"),
                ("gov_advisory", "DISCORD_WEBHOOK_GOV_ADVISORY"),
                ("incidents", "DISCORD_WEBHOOK_INCIDENTS"),
                ("podcasts", "DISCORD_WEBHOOK_PODCASTS"),
                ("research", "DISCORD_WEBHOOK_RESEARCH"),
                ("metrics_bounty", "DISCORD_WEBHOOK_METRICS_BOUNTY"),
                ("metrics_cve", "DISCORD_WEBHOOK_METRICS_CVE"),
                ("metrics_adversary", "DISCORD_WEBHOOK_METRICS_ADVERSARY"),
                ("metrics_infra", "DISCORD_WEBHOOK_METRICS_INFRA"),
            ):
                env_val = (os.getenv(env_k) or "").strip()
                if env_val:
                    WEBHOOK_CHANNELS[ch_k] = env_val

            results = await asyncio.gather(
                poll_leak_trackers(session),
                poll_infrastructure(session),
                poll_threatfox(session),
                poll_malware_bazaar(session),
                poll_vulnerabilities(session),
                poll_rss_streams(session),
                return_exceptions=True
            )

            for result in results:
                if isinstance(result, Exception):
                    print(f"[Collector Error] Unhandled collector failure: {result!r}")

            try:
                await evaluate_and_dispatch_metrics(session)
            except Exception as metrics_err:
                print(f"[Metrics Engine Error] {metrics_err!r}")

            await asyncio.sleep(300)



if __name__ == "__main__":
    asyncio.run(main())
