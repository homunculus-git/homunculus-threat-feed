import argparse
import asyncio
import ipaddress
import json
import os
import re
import socket
import sqlite3
import urllib.parse
from collections import Counter
from datetime import datetime, timedelta, timezone

import aiohttp

from actor_ttps import RANSOM_ACTOR_PROFILES, format_threat_actor_info
from threat_feed import (
    BROWSER_HEADERS,
    WEBHOOK_CHANNELS,
    defang_url,
    detect_target_campaign,
    dispatch_discord_embed,
    extract_malware_family,
    fetch_cve_enrichment,
    format_clean_date,
    format_vuln_severity_badge,
    init_db,
    lookup_ip_metadata,
    open_db,
    parse_datetime_utc,
)

POC_RADAR_DB_PATH = os.getenv(
    "POC_RADAR_DB_PATH",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "poc-radar", "seen_pocs.db")),
)

# Bootstrap cap per metrics channel on the very first run when a webhook is newly connected
FIRST_RUN_CHANNEL_CAP = 3

# Generic/placeholder family tokens that must never be treated as a specific malware family
GENERIC_MALWARE_TOKENS = {
    "",
    "none",
    "unknown",
    "unclassified",
    "unclassified malware",
    "unclassified dropper",
    "unclassified dropper payload",
    "malware payload",
    "malware payload payload",
    "botnet",
    "botnet node",
    "ssl blacklist node",
    "ua-wget",
    "ua-wget payload",
    "wget",
    "curl",
    "mozi",  # P2P DHT node without central C2 correlation unless multi-stage
}


def ensure_poc_radar_schema_and_load() -> list[dict]:
    """
    Ensure seen_pocs.db has structured columns (source_type, url, cve_ids, discovered_at),
    backfill any legacy rows deterministically, and return all PoC records.
    """
    if not os.path.exists(POC_RADAR_DB_PATH):
        return []

    records: list[dict] = []
    try:
        conn = sqlite3.connect(POC_RADAR_DB_PATH, timeout=10.0)
        cur = conn.cursor()
        cur.execute("PRAGMA busy_timeout = 10000;")
        existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(seen)").fetchall()}
        for col_name, col_def in (
            ("source_type", "TEXT"),
            ("url", "TEXT"),
            ("cve_ids", "TEXT"),
            ("discovered_at", "TIMESTAMP"),
        ):
            if col_name not in existing_cols:
                cur.execute(f"ALTER TABLE seen ADD COLUMN {col_name} {col_def}")

        missing_rows = cur.execute(
            "SELECT id, repo, created_at, source_type, url, cve_ids FROM seen "
            "WHERE source_type IS NULL OR cve_ids IS NULL"
        ).fetchall()
        for row_id, row_repo, row_created, row_src, row_url, row_cves in missing_rows:
            sid = str(row_id or "")
            srepo = str(row_repo or "")
            if sid.startswith("EXPLOITDB-"):
                b_src = "Exploit-DB"
                edb_num = sid.split("-", 1)[1]
                b_url = row_url or (f"https://www.exploit-db.com/exploits/{edb_num}" if edb_num.isdigit() else edb_num)
            elif sid.startswith("METASPLOIT-"):
                b_src = "Rapid7 Metasploit"
                b_url = row_url or "https://www.rapid7.com/db/modules/"
            elif sid.startswith("CISA-KEV-"):
                b_src = "CISA-KEV"
                kev_cve = sid.replace("CISA-KEV-", "").upper()
                b_url = row_url or f"https://nvd.nist.gov/vuln/detail/{kev_cve}"
            else:
                b_src = "GitHub"
                b_url = row_url or (f"https://github.com/{srepo}" if "/" in srepo else "")

            extracted_cves = list(
                dict.fromkeys(
                    m.upper().replace("_", "-")
                    for m in re.findall(r"CVE[-_]\d{4}[-_]\d{4,7}", f"{sid} {srepo}", re.IGNORECASE)
                )
            )
            cur.execute(
                "UPDATE seen SET source_type = ?, url = ?, cve_ids = ? WHERE id = ?",
                (b_src, b_url, ",".join(extracted_cves), sid),
            )
        if missing_rows:
            conn.commit()

        rows = cur.execute(
            "SELECT id, repo, created_at, source_type, url, cve_ids, discovered_at, rowid FROM seen ORDER BY rowid DESC"
        ).fetchall()
        for rid, repo, created_at, src_type, url, cve_ids, disc_at, rowid in rows:
            cves = [c.strip().upper() for c in str(cve_ids or "").split(",") if c.strip()]
            if not cves:
                cves = list(
                    dict.fromkeys(
                        m.upper().replace("_", "-")
                        for m in re.findall(r"CVE[-_]\d{4}[-_]\d{4,7}", f"{rid} {repo}", re.IGNORECASE)
                    )
                )
            records.append(
                {
                    "id": str(rid or ""),
                    "repo": str(repo or ""),
                    "created_at": str(created_at or "").strip(),
                    "discovered_at": str(disc_at or "").strip(),
                    "source_type": str(src_type or "GitHub"),
                    "url": str(url or ""),
                    "cves": cves,
                    "rowid": int(rowid or 0),
                }
            )
        conn.close()
    except Exception as err:
        print(f"[Metrics Engine] PoC Radar DB read error: {err}")

    return records


async def _get_dispatched_metric_ids(channel_key: str) -> set[str]:
    async with open_db() as db:
        async with db.execute(
            "SELECT metric_id FROM dispatched_metrics WHERE channel_key = ?",
            (channel_key,),
        ) as cur:
            return {row[0] for row in await cur.fetchall()}


async def _record_dispatched_metric(
    metric_id: str,
    channel_key: str,
    trigger_type: str,
    subject: str,
    metric_value: str,
) -> None:
    async with open_db() as db:
        await db.execute(
            "INSERT OR IGNORE INTO dispatched_metrics "
            "(metric_id, channel_key, trigger_type, subject, metric_value) "
            "VALUES (?, ?, ?, ?, ?)",
            (metric_id, channel_key, trigger_type, subject[:200], metric_value[:300]),
        )
        await db.commit()


async def dispatch_channel_triggers(
    session: aiohttp.ClientSession,
    channel_key: str,
    candidates: list[dict],
    *,
    dry_run: bool = False,
) -> int:
    """
    Dispatch real-time Mode A metric triggers for a specific metrics channel.
    - Deduplicates strictly against `dispatched_metrics`.
    - On the very first run for a newly configured channel, dispatches up to FIRST_RUN_CHANNEL_CAP
      newest alerts and records older historical triggers as baseline so Discord is never flooded.
    """
    already_sent = await _get_dispatched_metric_ids(channel_key)
    pending = [c for c in candidates if c["metric_id"] not in already_sent]
    if not pending:
        return 0

    webhook_url = WEBHOOK_CHANNELS.get(channel_key)
    if dry_run or not webhook_url:
        status_note = "DRY-RUN" if dry_run else "webhook not set in .env"
        print(f"[Metrics Engine] {channel_key}: {len(pending)} verified real-time trigger(s) ready ({status_note}).")
        for idx, item in enumerate(pending[:5], 1):
            print(f"  [{idx}] {item['metric_id']} -> {item['title']} | {item['metric_value']}")
        return 0

    is_channel_first_run = len(already_sent) == 0
    if is_channel_first_run and len(pending) > FIRST_RUN_CHANNEL_CAP:
        to_dispatch = pending[:FIRST_RUN_CHANNEL_CAP]
        to_seed = pending[FIRST_RUN_CHANNEL_CAP:]
        for seed_item in to_seed:
            await _record_dispatched_metric(
                seed_item["metric_id"],
                channel_key,
                f"{seed_item['trigger_type']}:baseline_seed",
                seed_item["subject"],
                seed_item["metric_value"],
            )
    else:
        to_dispatch = pending

    sent_count = 0
    for item in to_dispatch:
        ok = await dispatch_discord_embed(
            session=session,
            channel_key=channel_key,
            title=item["title"],
            description=item["description"],
            fields=item["fields"],
            color=item["color"],
            mitre_tactics=item.get("mitre_tactics"),
        )
        if ok:
            await _record_dispatched_metric(
                item["metric_id"],
                channel_key,
                item["trigger_type"],
                item["subject"],
                item["metric_value"],
            )
            sent_count += 1
            await asyncio.sleep(0.75)

    return sent_count


def _format_official_cvss(cve_info: dict) -> str:
    """Format strictly official CNA/ADP CVSS score and severity without guessing."""
    sev = cve_info.get("sev_level")
    score = cve_info.get("cvss_score")
    raw_sev = cve_info.get("raw_sev_text")
    badge = format_vuln_severity_badge(sev, score, raw_sev)
    if badge:
        return badge
    return "⚪ **Unrated by CNA** (`Official CVSS Pending`)"


def _format_official_vector(cve_info: dict) -> str:
    vec = cve_info.get("attack_vector")
    raw_vec = cve_info.get("cvss_vector")
    if vec and raw_vec:
        return f"`{vec}` (`{raw_vec}`)"
    if vec:
        return f"`{vec}`"
    if raw_vec:
        return f"`{raw_vec}`"
    return "`Not specified in CNA record`"


# ============================================================================
# CHANNEL 1 & 2 SHARED BUILDER: AUTHORITATIVE CVE + POC CORRELATION INDEX
# ============================================================================

_OFFICIAL_KEV_CACHE: dict[str, object] = {"ts": 0.0, "map": {}}


async def fetch_official_cisa_kev_map(session: aiohttp.ClientSession) -> dict[str, dict]:
    """Fetch and cache the authoritative CISA KEV catalog keyed by uppercase CVE ID."""
    import time

    now = time.time()
    cached_map = _OFFICIAL_KEV_CACHE.get("map")
    if isinstance(cached_map, dict) and cached_map and (now - float(_OFFICIAL_KEV_CACHE.get("ts", 0.0))) < 1800:
        return cached_map

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_map: dict[str, dict] = {}
    try:
        async with session.get(url, headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as resp:
            if resp.status == 200:
                payload = await resp.json(content_type=None)
                for v in (payload.get("vulnerabilities") or []):
                    if not isinstance(v, dict):
                        continue
                    cid = str(v.get("cveID") or "").strip().upper()
                    if not cid:
                        continue
                    d_added = str(v.get("dateAdded") or "").strip()
                    vendor = str(v.get("vendorProject") or "").strip()
                    prod = str(v.get("product") or "").strip()
                    kev_map[cid] = {
                        "source": "CISA-KEV",
                        "date_added": d_added,
                        "dt": parse_datetime_utc(d_added),
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                        "product": f"{vendor} {prod}".strip() or None,
                        "ransomware_use": str(v.get("knownRansomwareCampaignUse") or "Unknown").strip(),
                        "vuln_name": str(v.get("vulnerabilityName") or "").strip(),
                    }
                if kev_map:
                    _OFFICIAL_KEV_CACHE["ts"] = now
                    _OFFICIAL_KEV_CACHE["map"] = kev_map
    except Exception as err:
        print(f"[Metrics Engine] CISA KEV catalog fetch warning: {err}")

    return kev_map if kev_map else (cached_map if isinstance(cached_map, dict) else {})


async def build_verified_cve_index(session: aiohttp.ClientSession, poc_records: list[dict]) -> dict[str, dict]:
    """
    Correlate CVE records across seen_pocs.db, threat_cache.db (seen_events), and the official CISA KEV catalog.
    Only CVEs that have recent activity (last 14 days) or multi-source overlap are enriched via MITRE API.
    """
    cve_map: dict[str, dict] = {}
    now_utc = datetime.now(timezone.utc)
    cutoff_14d = now_utc - timedelta(days=14)
    official_kev_map = await fetch_official_cisa_kev_map(session)

    def _entry(cve_id: str) -> dict:
        if cve_id not in cve_map:
            cve_map[cve_id] = {
                "cve_id": cve_id,
                "pocs": [],          # list of dicts from seen_pocs.db or Exploit-DB/PacketStorm in threat_cache.db
                "advisories": [],    # list of dicts from threat_cache.db
                "kev": official_kev_map.get(cve_id),  # Authoritative CISA KEV entry if present
                "latest_activity": None,
            }
        return cve_map[cve_id]

    def _bump_ts(item_dict: dict, dt_val: datetime | None):
        if dt_val and (item_dict["latest_activity"] is None or dt_val > item_dict["latest_activity"]):
            item_dict["latest_activity"] = dt_val

    # 1. Ingest PoC Radar records (seen_pocs.db)
    for rec in poc_records:
        dt = parse_datetime_utc(rec["created_at"]) or parse_datetime_utc(rec["discovered_at"])
        for cve in rec["cves"]:
            if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve):
                continue
            item = _entry(cve)
            _bump_ts(item, dt)
            if rec["source_type"] == "CISA-KEV":
                if not item["kev"]:
                    item["kev"] = official_kev_map.get(cve) or {
                        "source": "CISA-KEV",
                        "date_added": rec["created_at"],
                        "dt": dt,
                        "url": rec["url"] or f"https://nvd.nist.gov/vuln/detail/{cve}",
                        "product": None,
                        "ransomware_use": "Unknown",
                    }
            else:
                item["pocs"].append(
                    {
                        "id": rec["id"],
                        "source": rec["source_type"],
                        "title": rec["repo"],
                        "url": rec["url"],
                        "timestamp_str": rec["created_at"] or rec["discovered_at"] or "Recorded in PoC Radar",
                        "dt": dt,
                        "rowid": rec["rowid"],
                    }
                )

    # 2. Ingest threat_cache.db CVE events
    async with open_db() as db:
        async with db.execute(
            """
            SELECT event_id, source, discovered_at, affected_product, ioc, title, cvss_score, severity, cwe
            FROM seen_events
            WHERE ioc LIKE 'CVE-%' OR title LIKE '%CVE-%'
            ORDER BY discovered_at DESC
            """
        ) as cur:
            tf_rows = await cur.fetchall()

    for eid, src, disc_at, prod, ioc, title, db_cvss, db_sev, db_cwe in tf_rows:
        found = list(
            dict.fromkeys(
                m.upper()
                for m in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", f"{ioc or ''} {title or ''}", re.IGNORECASE)
            )
        )
        dt = parse_datetime_utc(disc_at)
        for cve in found:
            item = _entry(cve)
            _bump_ts(item, dt)
            if src == "CISA-KEV":
                if cve in official_kev_map:
                    item["kev"] = official_kev_map[cve]
                item["advisories"].append(
                    {
                        "event_id": eid,
                        "source": src,
                        "discovered_at": str(disc_at or ""),
                        "dt": dt,
                        "product": prod,
                        "title": title,
                    }
                )
            elif src in ("Exploit-DB", "Packet Storm"):
                # Deduplicate against Exploit-DB items already in seen_pocs.db
                norm_title = re.sub(r"\s+", " ", str(title or "")).strip().lower()
                if not any(norm_title and norm_title in p["title"].lower() for p in item["pocs"]):
                    item["pocs"].append(
                        {
                            "id": eid,
                            "source": src,
                            "title": str(title or cve),
                            "url": "",
                            "timestamp_str": str(disc_at or ""),
                            "dt": dt,
                            "rowid": 0,
                        }
                    )
                item["advisories"].append(
                    {
                        "event_id": eid,
                        "source": src,
                        "discovered_at": str(disc_at or ""),
                        "dt": dt,
                        "product": prod,
                        "title": title,
                    }
                )
            else:
                item["advisories"].append(
                    {
                        "event_id": eid,
                        "source": src,
                        "discovered_at": str(disc_at or ""),
                        "dt": dt,
                        "product": prod,
                        "title": title,
                    }
                )

    # Deduplicate PoCs per CVE by normalized repository/title
    for cve, item in cve_map.items():
        deduped_pocs = []
        seen_keys = set()
        for p in item["pocs"]:
            k = re.sub(r"[^a-z0-9/_\-]", "", f"{p['source']}:{p['title']}".lower())
            if k not in seen_keys:
                seen_keys.add(k)
                deduped_pocs.append(p)
        item["pocs"] = deduped_pocs

    # Filter to candidate CVEs that qualify for real-time evaluation and enrich via MITRE API
    candidate_cves = [
        cve
        for cve, item in cve_map.items()
        if (
            len(item["pocs"]) >= 2
            or (item["pocs"] and item["advisories"])
            or (item["pocs"] and item["kev"])
            or any(p["source"] in ("Rapid7 Metasploit", "Exploit-DB") for p in item["pocs"])
            or len({a["source"] for a in item["advisories"]}) >= 2
            or (item["latest_activity"] and item["latest_activity"] >= cutoff_14d and (item["pocs"] or item["advisories"]))
        )
    ]

    sem = asyncio.Semaphore(8)

    async def _enrich_one(c_id: str):
        async with sem:
            cve_map[c_id]["mitre"] = await fetch_cve_enrichment(session, c_id)

    await asyncio.gather(*(_enrich_one(cve) for cve in candidate_cves[:60]), return_exceptions=True)

    return cve_map


# ============================================================================
# CHANNEL 1: BUG BOUNTY & OFFENSIVE RECON METRICS (`metrics_bounty`)
# ============================================================================

async def evaluate_bounty_metrics(session: aiohttp.ClientSession, cve_index: dict[str, dict]) -> list[dict]:
    """
    Evaluate deterministic Mode A triggers for `metrics_bounty`:
      1A. Multi-PoC Swarm (≥ 2 distinct verified public PoCs for a PUBLISHED MITRE CVE)
      1B. Rapid N-Day Time-to-PoC Velocity (PoC published within ≤ 72h of official MITRE CVE publication)
      1C. Active Product Vulnerability Cluster (≥ 3 distinct published CVEs for the same product in 7 days)
    """
    triggers: list[dict] = []
    now_utc = datetime.now(timezone.utc)
    cutoff_14d = now_utc - timedelta(days=14)
    cutoff_7d = now_utc - timedelta(days=7)

    # --- 1A. Verified Multi-PoC Swarm ---
    for cve, data in cve_index.items():
        pocs = data.get("pocs") or []
        if len(pocs) < 2:
            continue

        mitre = data.get("mitre") or {}
        # Strict accuracy check: must be a verified PUBLISHED CVE in MITRE
        if mitre.get("state") != "PUBLISHED":
            continue

        # Require either recent activity in the last 14d or high swarm count
        has_recent = any(
            (p["dt"] and p["dt"] >= cutoff_14d) or p["rowid"] >= 350
            for p in pocs
        )
        if not has_recent:
            continue

        poc_count = len(pocs)
        tier = 2 if poc_count >= 5 else 1
        metric_id = f"bounty_swarm_{cve}_tier{tier}"

        source_counts = Counter(p["source"] for p in pocs)
        breakdown_str = " • ".join(f"{cnt} {src}" for src, cnt in source_counts.most_common())

        poc_lines = []
        for p in pocs[:5]:
            date_lbl = format_clean_date(p["timestamp_str"]) if p["timestamp_str"] else "Tracked"
            if p["url"]:
                poc_lines.append(f"• [`{p['title'][:55]}`]({p['url']}) ({p['source']} · `{date_lbl}`)")
            else:
                poc_lines.append(f"• `{p['title'][:55]}` ({p['source']} · `{date_lbl}`)")

        product_val = mitre.get("product") or (data["kev"]["product"] if data.get("kev") else None) or "Specified in CNA Description"
        cwe_val = mitre.get("cwe") or "`Not specified by CNA`"
        versions_val = mitre.get("versions") or "`See CNA record`"
        mitre_pub_str = format_clean_date(mitre.get("date_published"))

        fields = [
            {"name": "📊 Metric Trigger", "value": f"**Multi-PoC Swarm (`{poc_count} Independent PoCs`)**", "inline": True},
            {"name": "🎯 Affected Product", "value": f"{product_val[:200]}", "inline": True},
            {"name": "🛡 Official CNA Severity", "value": _format_official_cvss(mitre), "inline": True},
            {"name": "🧭 Official Attack Vector", "value": _format_official_vector(mitre), "inline": True},
            {"name": "🧬 Weakness (CWE)", "value": cwe_val[:250], "inline": True},
            {"name": "📅 MITRE Published Date", "value": f"`{mitre_pub_str}`", "inline": True},
            {"name": "📦 Affected Versions", "value": versions_val[:300], "inline": False},
            {"name": f"🔬 Verified PoC Breakdown ({breakdown_str})", "value": "\n".join(poc_lines)[:1000], "inline": False},
            {
                "name": "🔗 Authoritative Dossiers",
                "value": (
                    f"[MITRE CVE API Record](https://www.cve.org/CVERecord?id={cve}) • "
                    f"[NVD Detail](https://nvd.nist.gov/vuln/detail/{cve})"
                ),
                "inline": False,
            },
        ]

        desc_text = (mitre.get("description") or "Verified multi-repository exploit PoC convergence.")[:500]
        triggers.append(
            {
                "metric_id": metric_id,
                "trigger_type": "bounty_poc_swarm",
                "subject": cve,
                "metric_value": f"{poc_count} public PoCs ({breakdown_str})",
                "sort_key": (tier, poc_count, data.get("latest_activity") or datetime.min.replace(tzinfo=timezone.utc)),
                "title": f"🎯 [Bounty Recon · PoC Swarm] {cve} ({poc_count} Public PoCs)",
                "description": desc_text,
                "fields": fields,
                "color": 0xE91E63 if poc_count >= 3 else 0xF39C12,
                "mitre_tactics": "T1190 Exploit Public-Facing Application • T1588.005 Exploit",
            }
        )

    # --- 1B. Rapid Time-to-PoC Velocity (TTPoC <= 72 hours) ---
    for cve, data in cve_index.items():
        pocs = data.get("pocs") or []
        if not pocs:
            continue

        mitre = data.get("mitre") or {}
        if mitre.get("state") != "PUBLISHED" or not mitre.get("date_published"):
            continue

        pub_dt = parse_datetime_utc(mitre["date_published"])
        dated_pocs = [p for p in pocs if p.get("dt") is not None]
        if not pub_dt or not dated_pocs:
            continue

        # Only evaluate CVEs published within the last 14 days
        if pub_dt < cutoff_14d:
            continue

        earliest_poc = min(dated_pocs, key=lambda p: p["dt"])
        delta_hours = (earliest_poc["dt"] - pub_dt).total_seconds() / 3600.0

        # Trigger if PoC dropped within 72 hours after CVE publication (or up to 72h before as pre-advisory 0-day PoC)
        if -72.0 <= delta_hours <= 72.0:
            metric_id = f"bounty_ttpoc_{cve}"
            if delta_hours >= 0:
                delta_str = f"+{delta_hours:.1f} hours after MITRE CVE publication"
            else:
                delta_str = f"{abs(delta_hours):.1f} hours BEFORE official MITRE CVE publication"

            product_val = mitre.get("product") or (data["kev"]["product"] if data.get("kev") else None) or "Specified in CNA Description"
            poc_link_md = (
                f"[`{earliest_poc['title']}`]({earliest_poc['url']}) ({earliest_poc['source']})"
                if earliest_poc.get("url")
                else f"`{earliest_poc['title']}` ({earliest_poc['source']})"
            )

            fields = [
                {"name": "⏱ Time-to-PoC (TTPoC)", "value": f"**`{delta_str}`**", "inline": False},
                {"name": "📅 Official MITRE Published", "value": f"`{format_clean_date(pub_dt)}`", "inline": True},
                {"name": "🚀 Earliest Public PoC", "value": f"`{format_clean_date(earliest_poc['dt'])}`", "inline": True},
                {"name": "🛡 Official CNA Severity", "value": _format_official_cvss(mitre), "inline": True},
                {"name": "🎯 Affected Product", "value": product_val[:200], "inline": True},
                {"name": "🧭 Official Attack Vector", "value": _format_official_vector(mitre), "inline": True},
                {"name": "🧬 Weakness (CWE)", "value": (mitre.get("cwe") or "`Not specified by CNA`")[:200], "inline": True},
                {"name": "📦 Affected Versions", "value": (mitre.get("versions") or "`See CNA record`")[:300], "inline": False},
                {"name": "🔬 First Observed PoC Artifact", "value": poc_link_md, "inline": False},
                {
                    "name": "🔗 Authoritative Dossiers",
                    "value": (
                        f"[MITRE CVE Record](https://www.cve.org/CVERecord?id={cve}) • "
                        f"[NVD Detail](https://nvd.nist.gov/vuln/detail/{cve})"
                    ),
                    "inline": False,
                },
            ]

            triggers.append(
                {
                    "metric_id": metric_id,
                    "trigger_type": "bounty_fast_ttpoc",
                    "subject": cve,
                    "metric_value": f"TTPoC: {delta_hours:+.1f}h",
                    "sort_key": (3, -abs(delta_hours), earliest_poc["dt"]),
                    "title": f"⚡ [Bounty Recon · Rapid Weaponization] {cve} (TTPoC: {delta_hours:+.1f}h)",
                    "description": (mitre.get("description") or "Public exploit PoC published within 72h of official CVE release.")[:500],
                    "fields": fields,
                    "color": 0xE74C3C if abs(delta_hours) <= 24 else 0xE67E22,
                    "mitre_tactics": "T1190 Exploit Public-Facing Application • T1588.005 Exploit",
                }
            )

    # --- 1C. Product Vulnerability Cluster (>= 3 distinct CVEs for same product in 7 days) ---
    async with open_db() as db:
        async with db.execute(
            """
            SELECT affected_product, ioc, title, source, discovered_at
            FROM seen_events
            WHERE affected_product IS NOT NULL
              AND TRIM(affected_product) != ''
              AND ioc LIKE 'CVE-%'
              AND discovered_at >= datetime('now', '-7 days')
            ORDER BY discovered_at DESC
            """
        ) as cur:
            prod_rows = await cur.fetchall()

    prod_clusters: dict[str, dict] = {}
    for prod, ioc, title, src, disc_at in prod_rows:
        clean_prod = str(prod).strip()
        if clean_prod.lower() in ("unknown", "n/a", "unspecified", "multiple products"):
            continue
        cve_upper = str(ioc).strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_upper):
            continue
        bucket = prod_clusters.setdefault(
            clean_prod,
            {"product": clean_prod, "cves": {}, "sources": set(), "latest_dt": None},
        )
        bucket["sources"].add(src)
        dt = parse_datetime_utc(disc_at)
        if dt and (bucket["latest_dt"] is None or dt > bucket["latest_dt"]):
            bucket["latest_dt"] = dt
        if cve_upper not in bucket["cves"]:
            bucket["cves"][cve_upper] = {"cve": cve_upper, "title": str(title or cve_upper), "discovered_at": str(disc_at)}

    for prod_name, cluster in prod_clusters.items():
        distinct_cves = list(cluster["cves"].values())
        if len(distinct_cves) < 3:
            continue

        # Check how many have PoCs or KEV or high official CVSS
        pocs_in_cluster = 0
        kev_in_cluster = 0
        for c_item in distinct_cves:
            cid = c_item["cve"]
            c_idx = cve_index.get(cid) or {}
            if c_idx.get("pocs"):
                pocs_in_cluster += 1
            if c_idx.get("kev"):
                kev_in_cluster += 1

        # Enrich top 3 CVEs in cluster to verify official state & severity
        verified_lines = []
        max_cvss = None
        for c_item in distinct_cves[:5]:
            cid = c_item["cve"]
            info = (cve_index.get(cid) or {}).get("mitre") or await fetch_cve_enrichment(session, cid)
            score = info.get("cvss_score")
            if score is not None and (max_cvss is None or score > max_cvss):
                max_cvss = score
            sev_txt = f"CVSS {score:.1f}" if score is not None else (info.get("sev_level") or "Unrated")
            poc_flag = " • **PoC Tracked**" if (cve_index.get(cid) or {}).get("pocs") else ""
            kev_flag = " • **CISA KEV**" if (cve_index.get(cid) or {}).get("kev") else ""
            clean_t = re.sub(rf"^{cid}\s*[—\-:]\s*", "", c_item["title"], flags=re.IGNORECASE).strip()
            verified_lines.append(
                f"• [`{cid}`](https://nvd.nist.gov/vuln/detail/{cid}) (`{sev_txt}`{poc_flag}{kev_flag}) — {clean_t[:85]}"
            )

        prod_slug = re.sub(r"[^a-z0-9]+", "_", prod_name.lower()).strip("_")[:40]
        tier = len(distinct_cves) // 3
        metric_id = f"bounty_prod_cluster_{prod_slug}_t{tier}"

        fields = [
            {"name": "🎯 Target Product / Stack", "value": f"**`{prod_name}`**", "inline": True},
            {"name": "📊 7-Day CVE Velocity", "value": f"**`{len(distinct_cves)} Distinct CVEs`**", "inline": True},
            {
                "name": "🔥 Exploitability Signals",
                "value": f"`{pocs_in_cluster} with Public PoC` • `{kev_in_cluster} on CISA KEV`",
                "inline": True,
            },
            {
                "name": "📡 Reporting Feeds",
                "value": ", ".join(f"`{s}`" for s in sorted(cluster["sources"])),
                "inline": True,
            },
            {
                "name": "📈 Highest Official CVSS",
                "value": f"`{max_cvss:.1f}`" if max_cvss is not None else "`Pending CNA Scoring`",
                "inline": True,
            },
            {
                "name": f"🗂 Verified CVEs in 7-Day Window (Showing {min(len(distinct_cves), 5)} of {len(distinct_cves)})",
                "value": "\n".join(verified_lines)[:1000],
                "inline": False,
            },
        ]

        triggers.append(
            {
                "metric_id": metric_id,
                "trigger_type": "bounty_product_cluster",
                "subject": prod_name,
                "metric_value": f"{len(distinct_cves)} CVEs in 7d ({pocs_in_cluster} PoCs, {kev_in_cluster} KEV)",
                "sort_key": (1 + pocs_in_cluster + kev_in_cluster, len(distinct_cves), cluster["latest_dt"] or now_utc),
                "title": f"📦 [Bounty Recon · Attack Surface Cluster] {prod_name} ({len(distinct_cves)} CVEs / 7d)",
                "description": (
                    f"Elevated vulnerability disclosure velocity detected for **{prod_name}**: "
                    f"`{len(distinct_cves)}` distinct CVEs recorded in the past 7 days."
                ),
                "fields": fields,
                "color": 0x9B59B6,
                "mitre_tactics": "T1595.002 Vulnerability Scanning • T1190 Exploit Public-Facing Application",
            }
        )

    triggers.sort(key=lambda x: x["sort_key"], reverse=True)
    return triggers


# ============================================================================
# CHANNEL 2: CVE LIFECYCLE & WEAPONIZATION METRICS (`metrics_cve`)
# ============================================================================

async def evaluate_cve_lifecycle_metrics(session: aiohttp.ClientSession, cve_index: dict[str, dict]) -> list[dict]:
    """
    Evaluate deterministic Mode A triggers for `metrics_cve`:
      2A. PoC-to-KEV Convergence (CVE confirmed in BOTH CISA KEV and public PoC feeds, with exact lead/lag days)
      2B. Curated Weaponization Milestone (Rapid7 Metasploit module or Exploit-DB verified exploit for a tracked CVE)
      2C. Multi-Agency / Multi-Feed Advisory Convergence (≥ 2 distinct vuln/advisory sources reporting same CVE)
    """
    triggers: list[dict] = []
    now_utc = datetime.now(timezone.utc)

    for cve, data in cve_index.items():
        pocs = data.get("pocs") or []
        kev = data.get("kev")
        advisories = data.get("advisories") or []
        mitre = data.get("mitre") or {}

        # --- 2A. PoC-to-KEV Active Exploitation Convergence ---
        if kev and pocs:
            if not mitre:
                mitre = await fetch_cve_enrichment(session, cve)
            if mitre.get("state") == "REJECTED":
                continue

            kev_dt = parse_datetime_utc(kev.get("date_added")) or kev.get("dt")
            # Only trigger for recent KEV additions (last 30 days)
            if not kev_dt or kev_dt < (now_utc - timedelta(days=30)):
                continue

            dated_pocs = [p for p in pocs if p.get("dt") is not None]
            earliest_poc = min(dated_pocs, key=lambda p: p["dt"]) if dated_pocs else pocs[0]
            poc_dt = earliest_poc.get("dt")

            if kev_dt and poc_dt:
                # CISA KEV dateAdded has calendar-day (YYYY-MM-DD) resolution
                cal_days = (kev_dt.date() - poc_dt.date()).days
                if cal_days == 0:
                    lead_str = f"Same-Day Convergence (PoC & CISA KEV both on {kev.get('date_added')})"
                elif cal_days > 0:
                    lead_str = f"PoC published {cal_days} calendar day{'s' if cal_days != 1 else ''} BEFORE CISA KEV addition"
                else:
                    abs_d = abs(cal_days)
                    lead_str = f"PoC published {abs_d} calendar day{'s' if abs_d != 1 else ''} AFTER CISA KEV addition"
            else:
                lead_str = "Confirmed in both CISA KEV and public PoC repositories"

            product_val = mitre.get("product") or kev.get("product") or "Specified in CNA Record"
            ransom_use = kev.get("ransomware_use") or "Unknown"
            poc_lines = []
            for p in pocs[:4]:
                d_str = format_clean_date(p["timestamp_str"])
                if p.get("url"):
                    poc_lines.append(f"• [`{p['title'][:55]}`]({p['url']}) ({p['source']} · `{d_str}`)")
                else:
                    poc_lines.append(f"• `{p['title'][:55]}` ({p['source']} · `{d_str}`)")

            metric_id = f"cve_poc_kev_{cve}"
            fields = [
                {"name": "🚨 Lifecycle Milestone", "value": "**Public PoC + CISA KEV Active Exploitation**", "inline": True},
                {"name": "🎯 Affected Product", "value": product_val[:200], "inline": True},
                {"name": "🛡 Official CNA Severity", "value": _format_official_cvss(mitre), "inline": True},
                {"name": "⏱ PoC vs. KEV Timeline", "value": f"**`{lead_str}`**", "inline": False},
                {"name": "📅 Earliest PoC Recorded", "value": f"`{format_clean_date(earliest_poc['timestamp_str'])}`", "inline": True},
                {"name": "🏛 CISA KEV Date Added", "value": f"`{kev.get('date_added') or format_clean_date(kev_dt)}`", "inline": True},
                {"name": "🏴 KEV Ransomware Use", "value": f"**`{ransom_use}`**", "inline": True},
                {"name": "🧬 Weakness (CWE)", "value": (mitre.get("cwe") or "`Not specified by CNA`")[:200], "inline": True},
                {"name": "🔬 Tracked Public PoCs", "value": "\n".join(poc_lines)[:1000], "inline": False},
                {
                    "name": "🔗 Authoritative References",
                    "value": (
                        f"[NVD Dossier](https://nvd.nist.gov/vuln/detail/{cve}) • "
                        f"[MITRE CVE Record](https://www.cve.org/CVERecord?id={cve})"
                    ),
                    "inline": False,
                },
            ]

            triggers.append(
                {
                    "metric_id": metric_id,
                    "trigger_type": "cve_poc_kev_convergence",
                    "subject": cve,
                    "metric_value": lead_str,
                    "sort_key": (3, kev_dt or now_utc),
                    "title": f"🚨 [CVE Lifecycle · PoC + KEV Convergence] {cve} ({product_val[:60]})",
                    "description": (mitre.get("description") or "Vulnerability has both public PoC code and confirmed CISA KEV active exploitation.")[:500],
                    "fields": fields,
                    "color": 0xE74C3C,
                    "mitre_tactics": "T1190 Exploit Public-Facing Application • T1203 Exploitation for Client Execution",
                }
            )

        # --- 2B. Curated Weaponization Milestone (Metasploit / Exploit-DB + CVE) ---
        curated_pocs = [p for p in pocs if p["source"] in ("Rapid7 Metasploit", "Exploit-DB")]
        if curated_pocs:
            if not mitre:
                mitre = await fetch_cve_enrichment(session, cve)
            if mitre.get("state") != "PUBLISHED":
                continue

            curated_sources = sorted({p["source"] for p in curated_pocs})
            gh_pocs = [p for p in pocs if p["source"] == "GitHub"]
            metric_id = f"cve_curated_{cve}_{'_'.join(s.split()[0].lower() for s in curated_sources)}"

            product_val = mitre.get("product") or (kev.get("product") if kev else None) or "Specified in CNA Record"
            mod_lines = []
            for p in pocs[:5]:
                if p.get("url"):
                    mod_lines.append(f"• **{p['source']}**: [`{p['title'][:60]}`]({p['url']})")
                else:
                    mod_lines.append(f"• **{p['source']}**: `{p['title'][:60]}`")

            fields = [
                {"name": "⚔️ Weaponization Stage", "value": f"**Curated Exploit (`{', '.join(curated_sources)}`)**", "inline": True},
                {"name": "🎯 Affected Product", "value": product_val[:200], "inline": True},
                {"name": "🛡 Official CNA Severity", "value": _format_official_cvss(mitre), "inline": True},
                {"name": "🧭 Official Attack Vector", "value": _format_official_vector(mitre), "inline": True},
                {"name": "🧬 Weakness (CWE)", "value": (mitre.get("cwe") or "`Not specified by CNA`")[:200], "inline": True},
                {"name": "📦 Correlated PoCs", "value": f"`{len(curated_pocs)} Curated` • `{len(gh_pocs)} GitHub`", "inline": True},
                {"name": "🔬 Exploit Modules & PoC Artifacts", "value": "\n".join(mod_lines)[:1000], "inline": False},
                {
                    "name": "🔗 Authoritative References",
                    "value": (
                        f"[MITRE CVE Record](https://www.cve.org/CVERecord?id={cve}) • "
                        f"[NVD Dossier](https://nvd.nist.gov/vuln/detail/{cve})"
                    ),
                    "inline": False,
                },
            ]

            triggers.append(
                {
                    "metric_id": metric_id,
                    "trigger_type": "cve_curated_weaponization",
                    "subject": cve,
                    "metric_value": f"Curated module in {', '.join(curated_sources)} ({len(pocs)} total PoCs)",
                    "sort_key": (2, data.get("latest_activity") or now_utc),
                    "title": f"⚔️ [CVE Lifecycle · Curated Exploit] {cve} — {', '.join(curated_sources)}",
                    "description": (mitre.get("description") or "Curated exploit module published for tracked CVE.")[:500],
                    "fields": fields,
                    "color": 0xE67E22,
                    "mitre_tactics": "T1588.005 Obtain Capabilities: Exploits • T1190 Exploit Public-Facing Application",
                }
            )

        # --- 2C. Multi-Source Advisory / CERT Convergence (>= 2 distinct feeds in threat_cache.db) ---
        distinct_adv_sources = {}
        for adv in advisories:
            src_name = adv["source"]
            if src_name not in distinct_adv_sources:
                distinct_adv_sources[src_name] = adv

        if len(distinct_adv_sources) >= 2:
            if not mitre:
                mitre = await fetch_cve_enrichment(session, cve)
            if mitre.get("state") == "REJECTED":
                continue

            src_list = sorted(distinct_adv_sources.keys())
            metric_id = f"cve_multi_adv_{cve}_{len(src_list)}"
            product_val = (
                mitre.get("product")
                or next((a["product"] for a in advisories if a.get("product")), None)
                or "Specified in Advisory"
            )

            adv_lines = []
            for s_name in src_list[:6]:
                a_obj = distinct_adv_sources[s_name]
                adv_lines.append(f"• **{s_name}** — Discovered `{format_clean_date(a_obj['discovered_at'])}`")

            poc_status = f"🔴 **`{len(pocs)} Public PoC(s) Tracked`**" if pocs else "🟢 `No Public PoC in Radar`"
            kev_status = "🔴 **`Listed on CISA KEV`**" if kev else "⚪ `Not on CISA KEV`"

            fields = [
                {"name": "📡 Cross-Feed Convergence", "value": f"**`{len(src_list)} Independent Feeds`**", "inline": True},
                {"name": "🎯 Affected Product", "value": product_val[:200], "inline": True},
                {"name": "🛡 Official CNA Severity", "value": _format_official_cvss(mitre), "inline": True},
                {"name": "💥 Public PoC Status", "value": poc_status, "inline": True},
                {"name": "🏛 CISA KEV Status", "value": kev_status, "inline": True},
                {"name": "🧬 Weakness (CWE)", "value": (mitre.get("cwe") or "`Not specified by CNA`")[:200], "inline": True},
                {"name": "🗓 Reporting Intelligence Feeds", "value": "\n".join(adv_lines)[:1000], "inline": False},
                {
                    "name": "🔗 Authoritative References",
                    "value": (
                        f"[MITRE CVE Record](https://www.cve.org/CVERecord?id={cve}) • "
                        f"[NVD Dossier](https://nvd.nist.gov/vuln/detail/{cve})"
                    ),
                    "inline": False,
                },
            ]

            triggers.append(
                {
                    "metric_id": metric_id,
                    "trigger_type": "cve_multi_advisory",
                    "subject": cve,
                    "metric_value": f"Reported by {len(src_list)} feeds ({', '.join(src_list)})",
                    "sort_key": (1 + (1 if pocs else 0), data.get("latest_activity") or now_utc),
                    "title": f"🛡 [CVE Lifecycle · Multi-Feed Convergence] {cve} ({len(src_list)} Feeds)",
                    "description": (mitre.get("description") or "Cross-agency / multi-feed vulnerability convergence detected.")[:500],
                    "fields": fields,
                    "color": 0x3498DB,
                    "mitre_tactics": "T1190 Exploit Public-Facing Application",
                }
            )

    triggers.sort(key=lambda x: x["sort_key"], reverse=True)
    return triggers


# ============================================================================
# CHANNEL 3: ADVERSARIAL & RANSOMWARE TEMPO METRICS (`metrics_adversary`)
# ============================================================================

async def evaluate_adversary_metrics() -> list[dict]:
    """
    Evaluate deterministic Mode A triggers for `metrics_adversary`:
      3A. Threat Actor 24h Velocity Surge (≥ 4 claims in 24h AND ≥ 2.0x 30-day daily average)
      3B. Verified Sector Targeting Wave (≥ 3 claims in 7 days with explicit source-reported `target_industry`)
      3C. Geographic Targeting Concentration Spike (≥ 4 claims in 24h in same ISO country across ≥ 2 actors)
    """
    triggers: list[dict] = []
    today_tag = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    week_tag = datetime.now(timezone.utc).strftime("%Y-W%W")

    async with open_db() as db:
        # --- 3A. Threat Actor Velocity Surge ---
        async with db.execute(
            """
            SELECT LOWER(TRIM(threat_actor)) as actor_key,
                   MAX(TRIM(threat_actor)) as display_actor,
                   SUM(CASE WHEN discovered_at >= datetime('now', '-1 day') THEN 1 ELSE 0 END) as d1,
                   SUM(CASE WHEN discovered_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) as d7,
                   SUM(CASE WHEN discovered_at >= datetime('now', '-30 days') THEN 1 ELSE 0 END) as d30
            FROM seen_events
            WHERE threat_actor IS NOT NULL
              AND TRIM(threat_actor) != ''
              AND LOWER(TRIM(threat_actor)) NOT IN ('unattributed', 'unknown', 'unspecified', 'anonymous', 'none')
            GROUP BY LOWER(TRIM(threat_actor))
            HAVING d1 >= 4
            ORDER BY d1 DESC, d7 DESC
            """
        ) as cur:
            actor_rows = await cur.fetchall()

        for actor_key, display_actor, d1, d7, d30 in actor_rows:
            d1, d7, d30 = int(d1 or 0), int(d7 or 0), int(d30 or 0)
            daily_avg_30 = max(d30, 1) / 30.0
            surge_ratio = d1 / daily_avg_30
            if surge_ratio < 2.0:
                continue

            async with db.execute(
                """
                SELECT title, source, country_code, target_industry, discovered_at
                FROM seen_events
                WHERE LOWER(TRIM(threat_actor)) = ?
                  AND discovered_at >= datetime('now', '-1 day')
                ORDER BY discovered_at DESC
                LIMIT 8
                """,
                (actor_key,),
            ) as vcur:
                recent_victims = await vcur.fetchall()

            victim_lines = []
            countries_24h = Counter()
            for v_title, v_src, v_cc, v_ind, v_dt in recent_victims:
                if v_cc:
                    countries_24h[v_cc] += 1
                cc_badge = f" (`{v_cc}`)" if v_cc else ""
                ind_badge = f" · `{v_ind}`" if v_ind else ""
                victim_lines.append(f"• **{v_title[:55]}**{cc_badge}{ind_badge} — *{v_src}* (`{v_dt[:16]} UTC`)")

            slug = re.sub(r"[^a-z0-9]", "", actor_key)
            profile = RANSOM_ACTOR_PROFILES.get(slug) or {}
            origin_str = profile.get("origin_country") or "Unknown / Unconfirmed in Dossier"
            stat_summary = (
                f"24h Surge      : {d1} claims in 24h ({surge_ratio:.1f}x 30d daily baseline)\n"
                f"Window Totals  : {d7} claims (7d) • {d30} claims (30d) • {daily_avg_30:.2f}/day avg"
            )
            dossier_field = format_threat_actor_info(display_actor, stat_summary)

            cc_summary = (
                ", ".join(f"`{c}` ({n})" for c, n in countries_24h.most_common(4))
                if countries_24h
                else "`No ISO country tag in source feed`"
            )

            metric_id = f"adversary_surge_{slug}_{today_tag}"
            fields = [
                {"name": "🏴 Threat Actor", "value": f"**{profile.get('actor') or display_actor}**", "inline": True},
                {"name": "📈 24h Claim Velocity", "value": f"**`{d1} Victims / 24h`**", "inline": True},
                {"name": "⚡ Surge Multiplier", "value": f"**`{surge_ratio:.1f}x` vs. 30d Baseline**", "inline": True},
                {"name": "📊 7d / 30d Volume", "value": f"`{d7} (7d)` • `{d30} (30d)` (`{daily_avg_30:.2f}/day`)", "inline": True},
                {"name": "🌍 Verified 24h Geographies", "value": cc_summary, "inline": True},
                {"name": "🧭 Assessed Origin", "value": f"`{origin_str}`", "inline": True},
                {
                    "name": f"🗂 Verified 24h Victim Claims (Showing {len(recent_victims)} of {d1})",
                    "value": "\n".join(victim_lines)[:1000] or "No victim records.",
                    "inline": False,
                },
                dossier_field,
            ]

            triggers.append(
                {
                    "metric_id": metric_id,
                    "trigger_type": "adversary_actor_surge",
                    "subject": display_actor,
                    "metric_value": f"{d1} claims in 24h ({surge_ratio:.1f}x 30d baseline)",
                    "sort_key": (3, d1, surge_ratio),
                    "title": f"🚨 [Adversary Tempo · Syndicate Surge] {profile.get('actor') or display_actor} ({d1} Claims / 24h)",
                    "description": (
                        f"**{profile.get('actor') or display_actor}** recorded `{d1}` distinct extortion/breach claims "
                        f"in the past 24 hours — **{surge_ratio:.1f}x** its 30-day daily average (`{daily_avg_30:.2f} claims/day`)."
                    ),
                    "fields": fields,
                    "color": 0xE74C3C,
                    "mitre_tactics": "T1486 Data Encrypted for Impact • T1567 Exfiltration Over Web Service",
                }
            )

        # --- 3B. Verified Sector Targeting Wave (Strictly source-reported target_industry) ---
        async with db.execute(
            """
            SELECT TRIM(target_industry) as sector,
                   COUNT(*) as cnt_7d,
                   COUNT(DISTINCT LOWER(COALESCE(threat_actor, 'unattributed'))) as actor_cnt
            FROM seen_events
            WHERE target_industry IS NOT NULL
              AND TRIM(target_industry) != ''
              AND discovered_at >= datetime('now', '-7 days')
            GROUP BY TRIM(target_industry)
            HAVING cnt_7d >= 2
            ORDER BY cnt_7d DESC
            """
        ) as cur:
            sector_rows = await cur.fetchall()

        for sector, cnt_7d, actor_cnt in sector_rows:
            cnt_7d = int(cnt_7d or 0)
            async with db.execute(
                """
                SELECT title, COALESCE(threat_actor, 'Unattributed'), country_code, source, discovered_at
                FROM seen_events
                WHERE TRIM(target_industry) = ?
                  AND discovered_at >= datetime('now', '-7 days')
                ORDER BY discovered_at DESC
                LIMIT 6
                """,
                (sector,),
            ) as scur:
                sec_events = await scur.fetchall()

            ev_lines = []
            actors_set = []
            for stitle, sactor, scc, ssrc, sdt in sec_events:
                if sactor not in actors_set:
                    actors_set.append(sactor)
                cc_str = f" (`{scc}`)" if scc else ""
                ev_lines.append(f"• **{stitle[:55]}**{cc_str} — Actor: `{sactor}` (*{ssrc}*, `{sdt[:10]}`)")

            sec_slug = re.sub(r"[^a-z0-9]+", "_", sector.lower()).strip("_")[:35]
            metric_id = f"adversary_sector_{sec_slug}_{week_tag}_{cnt_7d}"
            fields = [
                {"name": "🏭 Verified Target Sector", "value": f"**`{sector}`**", "inline": True},
                {"name": "📊 7-Day Verified Claims", "value": f"**`{cnt_7d} Breach / Extortion Claims`**", "inline": True},
                {"name": "🏴 Active Threat Actors", "value": ", ".join(f"`{a}`" for a in actors_set[:5]), "inline": True},
                {
                    "name": "🗂 Source-Verified Sector Claims (7d)",
                    "value": "\n".join(ev_lines)[:1000],
                    "inline": False,
                },
            ]

            triggers.append(
                {
                    "metric_id": metric_id,
                    "trigger_type": "adversary_sector_wave",
                    "subject": sector,
                    "metric_value": f"{cnt_7d} verified sector claims in 7d",
                    "sort_key": (2, cnt_7d, int(actor_cnt or 0)),
                    "title": f"🎯 [Adversary Tempo · Sector Targeting Wave] {sector} ({cnt_7d} Verified Claims / 7d)",
                    "description": (
                        f"Multiple source-verified breach/ransomware claims explicitly tagged under **{sector}** "
                        f"recorded within the past 7 days."
                    ),
                    "fields": fields,
                    "color": 0xE67E22,
                    "mitre_tactics": "T1486 Data Encrypted for Impact • T1657 Financial Theft",
                }
            )

        # --- 3C. Country Targeting Concentration Spike (24h vs 30d baseline on Ransomware/Breach feeds) ---
        async with db.execute(
            """
            SELECT UPPER(TRIM(country_code)) as cc,
                   SUM(CASE WHEN discovered_at >= datetime('now', '-1 day') THEN 1 ELSE 0 END) as d1,
                   SUM(CASE WHEN discovered_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) as d7,
                   SUM(CASE WHEN discovered_at >= datetime('now', '-30 days') THEN 1 ELSE 0 END) as d30,
                   COUNT(DISTINCT CASE WHEN discovered_at >= datetime('now', '-1 day') THEN LOWER(threat_actor) END) as actors_24h
            FROM seen_events
            WHERE country_code IS NOT NULL
              AND LENGTH(TRIM(country_code)) = 2
              AND source IN ('Ransomware.live', 'RansomLook', 'Ransomwatch', 'Dark Web Informer', 'ThreatCluster')
            GROUP BY UPPER(TRIM(country_code))
            HAVING d1 >= 3 AND actors_24h >= 1
            ORDER BY d1 DESC
            """
        ) as cur:
            cc_rows = await cur.fetchall()

        for cc, d1, d7, d30, actors_24h in cc_rows:
            d1, d7, d30 = int(d1 or 0), int(d7 or 0), int(d30 or 0)
            avg_30 = max(d30, 1) / 30.0
            ratio = d1 / avg_30
            if ratio < 1.3 and d1 < 5:
                continue

            async with db.execute(
                """
                SELECT title, COALESCE(threat_actor, 'Unattributed'), source, discovered_at
                FROM seen_events
                WHERE UPPER(TRIM(country_code)) = ?
                  AND source IN ('Ransomware.live', 'RansomLook', 'Ransomwatch', 'Dark Web Informer', 'ThreatCluster')
                  AND discovered_at >= datetime('now', '-1 day')
                ORDER BY discovered_at DESC
                LIMIT 7
                """,
                (cc,),
            ) as ccur:
                cc_victims = await ccur.fetchall()

            actor_counts = Counter(r[1] for r in cc_victims)
            actor_breakdown = ", ".join(f"**{a}** (`{n}`)" for a, n in actor_counts.most_common(5))
            v_lines = [
                f"• **{v_t[:55]}** — Actor: `{v_a}` (*{v_s}*, `{v_dt[:16]} UTC`)"
                for v_t, v_a, v_s, v_dt in cc_victims
            ]

            metric_id = f"adversary_country_{cc}_{today_tag}"
            fields = [
                {"name": "🌍 Target Country (ISO)", "value": f"**`{cc}`**", "inline": True},
                {"name": "📈 24h Victim Claims", "value": f"**`{d1} Claims / 24h`** (`{ratio:.1f}x` 30d avg)", "inline": True},
                {"name": "📊 7d / 30d Totals", "value": f"`{d7} (7d)` • `{d30} (30d)` (`{avg_30:.2f}/day`)", "inline": True},
                {"name": "🏴 Active Syndicates (24h)", "value": actor_breakdown or "`Unattributed`", "inline": False},
                {
                    "name": f"🗂 Verified 24h Victim Claims in `{cc}`",
                    "value": "\n".join(v_lines)[:1000],
                    "inline": False,
                },
            ]

            triggers.append(
                {
                    "metric_id": metric_id,
                    "trigger_type": "adversary_country_spike",
                    "subject": cc,
                    "metric_value": f"{d1} victim claims in {cc} over 24h ({ratio:.1f}x baseline)",
                    "sort_key": (1, d1, ratio),
                    "title": f"🌍 [Adversary Tempo · Country Targeting Spike] `{cc}` ({d1} Claims / 24h)",
                    "description": (
                        f"Elevated ransomware/extortion activity targeting organizations in **`{cc}`**: "
                        f"`{d1}` verified claims in the last 24h (`{ratio:.1f}x` the 30-day daily average)."
                    ),
                    "fields": fields,
                    "color": 0xD35400,
                    "mitre_tactics": "T1486 Data Encrypted for Impact",
                }
            )

    triggers.sort(key=lambda x: x["sort_key"], reverse=True)
    return triggers


# ============================================================================
# CHANNEL 4: MALWARE, C2 & PHISHING INFRASTRUCTURE METRICS (`metrics_infra`)
# ============================================================================

def _extract_clean_family(source: str, title: str, db_family: str | None) -> str | None:
    """Extract an explicitly attributed malware family name without guessing."""
    cand = (db_family or "").strip()
    if not cand and title:
        t = title.strip()
        if source == "ThreatFox":
            cand = t.split(" - ")[0].strip()
            if "·" in cand:
                cand = cand.split("·")[0].replace("(infra overlap)", "").strip()
        elif source == "URLhaus":
            cand = re.sub(r"\s+Payload$", "", t, flags=re.IGNORECASE).strip()
        elif source == "MalwareBazaar":
            cand = t
        elif source == "Feodo":
            cand = re.sub(r"^Feodo\s+|\s+C2$", "", t, flags=re.IGNORECASE).strip()

    if not cand:
        return None
    low = cand.lower()
    if low in GENERIC_MALWARE_TOKENS or low.startswith(("unknown", "unclassified")):
        return None
    # Reject raw IP-derived slugs like '5-178-101-94'
    if re.fullmatch(r"[\d\.\-:]+", low):
        return None
    return cand


async def evaluate_infra_metrics(session: aiohttp.ClientSession) -> list[dict]:
    """
    Evaluate deterministic Mode A triggers for `metrics_infra`:
      4A. Multi-Stage Malware Kill-Chain Convergence (Same named family active across ≥ 2 Abuse.ch feeds in 7d)
      4B. Malicious /24 C2 Subnet Hotspot (≥ 3 distinct malicious IPs in same /24) & Cross-Feed IP Overlap
      4C. Targeted Brand / Cloud-Stager Phishing Wave (≥ 3 OpenPhish URLs hitting same brand campaign in 7d)
    """
    triggers: list[dict] = []
    week_tag = datetime.now(timezone.utc).strftime("%Y-W%W")

    async with open_db() as db:
        async with db.execute(
            """
            SELECT event_id, source, discovered_at, ioc, title, tags, country_code, malware_family, asn
            FROM seen_events
            WHERE source IN ('ThreatFox', 'URLhaus', 'MalwareBazaar', 'Feodo', 'abuse.ch SSLBL', 'OpenPhish')
              AND discovered_at >= datetime('now', '-7 days')
            ORDER BY discovered_at DESC
            """
        ) as cur:
            infra_rows = await cur.fetchall()

    # --- 4A. Multi-Stage Malware Kill-Chain Convergence ---
    family_map: dict[str, dict] = {}
    for eid, src, disc_at, ioc, title, tags, cc, db_fam, db_asn in infra_rows:
        if src not in ("ThreatFox", "URLhaus", "MalwareBazaar", "Feodo"):
            continue
        fam = _extract_clean_family(src, str(title or ""), db_fam)
        if not fam:
            continue
        fkey = fam.lower()
        entry = family_map.setdefault(
            fkey,
            {
                "display_name": fam,
                "by_source": {"ThreatFox": [], "URLhaus": [], "MalwareBazaar": [], "Feodo": []},
                "latest_at": str(disc_at or ""),
            },
        )
        entry["by_source"][src].append(
            {
                "event_id": eid,
                "ioc": str(ioc or ""),
                "title": str(title or ""),
                "discovered_at": str(disc_at or ""),
                "country_code": cc,
            }
        )

    for fkey, fdata in family_map.items():
        active_sources = [s for s, items in fdata["by_source"].items() if len(items) > 0]
        total_hits = sum(len(items) for items in fdata["by_source"].values())
        if len(active_sources) < 2 or total_hits < 3:
            continue

        fam_name = fdata["display_name"]
        tf_items = fdata["by_source"]["ThreatFox"] + fdata["by_source"]["Feodo"]
        uh_items = fdata["by_source"]["URLhaus"]
        mb_items = fdata["by_source"]["MalwareBazaar"]

        stage_samples = []
        if uh_items:
            u0 = uh_items[0]
            stage_samples.append(f"• **Delivery (URLhaus)**: `{defang_url(u0['ioc'])[:80]}` (`{u0['discovered_at'][:16]} UTC`)")
        if mb_items:
            m0 = mb_items[0]
            stage_samples.append(f"• **Payload (MalwareBazaar)**: `SHA256:{m0['ioc'][:32]}...` (`{m0['discovered_at'][:16]} UTC`)")
        if tf_items:
            t0 = tf_items[0]
            stage_samples.append(f"• **C2 Node ({'Feodo' if t0['event_id'].startswith('feodo') else 'ThreatFox'})**: `{defang_url(t0['ioc'])[:80]}` (`{t0['discovered_at'][:16]} UTC`)")

        tier = len(active_sources)
        metric_id = f"infra_killchain_{re.sub(r'[^a-z0-9]', '', fkey)}_{week_tag}_t{tier}"
        fields = [
            {"name": "🦠 Malware Family", "value": f"**`{fam_name}`**", "inline": True},
            {"name": "🔗 Active Telemetry Stages", "value": f"**`{len(active_sources)} Feeds`** ({', '.join(active_sources)})", "inline": True},
            {"name": "📊 7-Day Indicator Volume", "value": f"**`{total_hits} Total IoCs`**", "inline": True},
            {"name": "📥 URLhaus Droppers", "value": f"`{len(uh_items)} URL(s)`", "inline": True},
            {"name": "🧬 MalwareBazaar Samples", "value": f"`{len(mb_items)} SHA256 Hash(es)`", "inline": True},
            {"name": "📡 ThreatFox / Feodo C2s", "value": f"`{len(tf_items)} C2 Node(s)`", "inline": True},
            {"name": "🔬 Verified Multi-Stage Observables (Latest per Stage)", "value": "\n".join(stage_samples)[:1000], "inline": False},
        ]

        triggers.append(
            {
                "metric_id": metric_id,
                "trigger_type": "infra_killchain_convergence",
                "subject": fam_name,
                "metric_value": f"{total_hits} IoCs across {', '.join(active_sources)}",
                "sort_key": (len(active_sources), total_hits, 0),
                "title": f"⚔️ [Infra Telemetry · Kill-Chain Convergence] {fam_name} ({len(active_sources)} Feeds / {total_hits} IoCs)",
                "description": (
                    f"Active multi-stage campaign correlation for **{fam_name}**: simultaneously observed across "
                    f"**{', '.join(active_sources)}** within the last 7 days."
                ),
                "fields": fields,
                "color": 0xE67E22 if len(active_sources) == 2 else 0xE74C3C,
                "mitre_tactics": "T1105 Ingress Tool Transfer • T1204 User Execution • T1071 Application Layer Protocol",
            }
        )

    # --- 4B. Malicious /24 Subnet Hotspot & Cross-Feed IP Overlap ---
    ip_events: dict[str, list[dict]] = {}
    subnet_events: dict[str, list[dict]] = {}

    for eid, src, disc_at, ioc, title, tags, cc, db_fam, db_asn in infra_rows:
        raw_ioc = str(ioc or "")
        m_ip = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", raw_ioc)
        if not m_ip:
            continue
        ip_str = m_ip.group(1)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                continue
        except ValueError:
            continue

        fam = _extract_clean_family(src, str(title or ""), db_fam) or str(title or src)[:40]
        rec_item = {
            "ip": ip_str,
            "ioc": raw_ioc,
            "source": src,
            "family": fam,
            "discovered_at": str(disc_at or ""),
            "country_code": cc,
            "asn": db_asn,
        }
        ip_events.setdefault(ip_str, []).append(rec_item)
        sub_cidr = ".".join(ip_str.split(".")[:3]) + ".0/24"
        subnet_events.setdefault(sub_cidr, []).append(rec_item)

    # 4B-1: Cross-Feed Single-IP Overlap (Same IP flagged in >= 2 distinct feeds)
    for ip_str, ev_list in ip_events.items():
        distinct_srcs = sorted({e["source"] for e in ev_list})
        if len(distinct_srcs) < 2:
            continue

        meta = await lookup_ip_metadata(session, ip_str)
        asn_label = f"{meta.get('as_num') or ''} {meta.get('org') or 'Unknown Host'}".strip()
        cc_label = meta.get("country_code") or next((e["country_code"] for e in ev_list if e.get("country_code")), "N/A")

        ev_lines = []
        for e in ev_list[:6]:
            ev_lines.append(
                f"• **{e['source']}**: `{defang_url(e['ioc'])[:65]}` — `{e['family']}` (`{e['discovered_at'][:16]} UTC`)"
            )

        metric_id = f"infra_ip_overlap_{ip_str.replace('.', '_')}_{week_tag}"
        fields = [
            {"name": "🖥 Flagged Host IP", "value": f"`{defang_url(ip_str)}`", "inline": True},
            {"name": "📡 Cross-Feed Overlap", "value": f"**`{len(distinct_srcs)} Feeds`** ({', '.join(distinct_srcs)})", "inline": True},
            {"name": "📊 Total Indicator Hits (7d)", "value": f"`{len(ev_list)} Hits`", "inline": True},
            {"name": "🏢 Routing / ASN", "value": f"`{asn_label}`", "inline": True},
            {"name": "🌍 Country", "value": f"`{cc_label}`", "inline": True},
            {
                "name": "🔎 OSINT Pivots",
                "value": (
                    f"[VirusTotal IP](https://www.virustotal.com/gui/ip-address/{ip_str}) • "
                    f"[Shodan Host](https://www.shodan.io/host/{ip_str}) • "
                    f"[URLScan](https://urlscan.io/ip/{ip_str})"
                ),
                "inline": True,
            },
            {"name": "🗂 Correlated Telemetry Records", "value": "\n".join(ev_lines)[:1000], "inline": False},
        ]

        triggers.append(
            {
                "metric_id": metric_id,
                "trigger_type": "infra_ip_overlap",
                "subject": ip_str,
                "metric_value": f"Host {ip_str} flagged across {', '.join(distinct_srcs)} ({len(ev_list)} hits)",
                "sort_key": (3, len(distinct_srcs), len(ev_list)),
                "title": f"🎯 [Infra Telemetry · Cross-Feed Host Overlap] {defang_url(ip_str)} ({', '.join(distinct_srcs)})",
                "description": (
                    f"Host `{defang_url(ip_str)}` (`{asn_label}`) was independently flagged across "
                    f"**{len(distinct_srcs)} distinct threat feeds** within the last 7 days."
                ),
                "fields": fields,
                "color": 0xE74C3C,
                "mitre_tactics": "T1583.003 Virtual Private Server • T1071 Application Layer Protocol",
            }
        )

    # 4B-2: /24 Subnet Hotspot (>= 4 distinct malicious IPs in the same /24 subnet in 7d)
    for sub_cidr, ev_list in subnet_events.items():
        distinct_ips = sorted({e["ip"] for e in ev_list})
        if len(distinct_ips) < 4:
            continue

        sample_ip = distinct_ips[0]
        meta = await lookup_ip_metadata(session, sample_ip)
        asn_label = f"{meta.get('as_num') or ''} {meta.get('org') or 'Unknown Host'}".strip()
        cc_label = meta.get("country_code") or next((e["country_code"] for e in ev_list if e.get("country_code")), "N/A")
        srcs = sorted({e["source"] for e in ev_list})
        fams = sorted({e["family"] for e in ev_list if e.get("family")})

        ip_summary_lines = []
        seen_sub_ips = set()
        for e in ev_list:
            if e["ip"] in seen_sub_ips:
                continue
            seen_sub_ips.add(e["ip"])
            ip_summary_lines.append(
                f"• `{defang_url(e['ioc'])[:60]}` — **{e['source']}** (`{e['family']}` · `{e['discovered_at'][:10]}`)"
            )
            if len(ip_summary_lines) >= 6:
                break

        metric_id = f"infra_subnet_{sub_cidr.replace('.', '_').replace('/', '_')}_{week_tag}"
        fields = [
            {"name": "🌐 Flagged /24 Subnet", "value": f"**`{sub_cidr}`**", "inline": True},
            {"name": "🖥 Distinct Malicious IPs", "value": f"**`{len(distinct_ips)} Distinct Hosts`** (`{len(ev_list)} hits`)", "inline": True},
            {"name": "🏢 Routing / ASN", "value": f"`{asn_label}` (`{cc_label}`)", "inline": True},
            {"name": "📡 Reporting Feeds", "value": ", ".join(f"`{s}`" for s in srcs), "inline": True},
            {"name": "🦠 Associated Families", "value": ", ".join(f"`{f[:30]}`" for f in fams[:4]), "inline": True},
            {
                "name": f"🗂 Verified Malicious Hosts in `{sub_cidr}` (Showing {len(ip_summary_lines)} of {len(distinct_ips)})",
                "value": "\n".join(ip_summary_lines)[:1000],
                "inline": False,
            },
        ]

        triggers.append(
            {
                "metric_id": metric_id,
                "trigger_type": "infra_subnet_hotspot",
                "subject": sub_cidr,
                "metric_value": f"{len(distinct_ips)} malicious IPs in {sub_cidr} ({asn_label})",
                "sort_key": (2, len(distinct_ips), len(ev_list)),
                "title": f"📡 [Infra Telemetry · Malicious /24 Subnet Cluster] {sub_cidr} ({len(distinct_ips)} Hosts)",
                "description": (
                    f"High-density malicious hosting cluster detected in **`{sub_cidr}`** (`{asn_label}`): "
                    f"`{len(distinct_ips)}` distinct IPv4 hosts flagged in the past 7 days."
                ),
                "fields": fields,
                "color": 0xF1C40F,
                "mitre_tactics": "T1583.003 Acquire Infrastructure • T1071 Application Layer Protocol",
            }
        )

    # --- 4C. Phishing Brand / Cloud-Stager Campaign Wave ---
    phish_campaigns: dict[str, list[dict]] = {}
    for eid, src, disc_at, ioc, title, tags, cc, db_fam, db_asn in infra_rows:
        if src != "OpenPhish":
            continue
        url_str = str(ioc or "").strip()
        if not url_str:
            continue
        camp = str(title or "").strip() or detect_target_campaign(url_str)
        if not camp or "Unattributed / Generic" in camp:
            continue
        phish_campaigns.setdefault(camp, []).append(
            {
                "url": url_str,
                "host": (urllib.parse.urlparse(url_str).hostname or "").lower(),
                "discovered_at": str(disc_at or ""),
                "country_code": cc,
                "asn": db_asn,
            }
        )

    for camp_name, p_items in phish_campaigns.items():
        distinct_urls = {p["url"] for p in p_items}
        if len(distinct_urls) < 3:
            continue

        distinct_hosts = {p["host"] for p in p_items if p["host"]}
        cloud_staged = sum(
            1 for p in p_items if any(d in p["host"] for d in ("pages.dev", "vercel.app", "netlify.app", "firebaseapp.com", "web.app"))
        )
        countries = Counter(p["country_code"] for p in p_items if p.get("country_code"))
        cc_str = ", ".join(f"`{c}` ({n})" for c, n in countries.most_common(4)) if countries else "`Unresolved / Various`"

        sample_lines = [
            f"• `{defang_url(p['url'])[:85]}` (`{p['discovered_at'][:16]} UTC`)"
            for p in p_items[:5]
        ]

        camp_slug = re.sub(r"[^a-z0-9]+", "_", camp_name.lower()).strip("_")[:35]
        tier = len(distinct_urls) // 3
        metric_id = f"infra_phish_{camp_slug}_{week_tag}_t{tier}"

        fields = [
            {"name": "🎣 Impersonated Brand / Lure", "value": f"**{camp_name}**", "inline": True},
            {"name": "📊 7-Day Phishing Volume", "value": f"**`{len(distinct_urls)} Live URLs`** (`{len(distinct_hosts)} Hosts`)", "inline": True},
            {"name": "☁️ Staging Breakdown", "value": f"`{cloud_staged} Cloud Stagers` • `{len(p_items) - cloud_staged} VPS/Custom`", "inline": True},
            {"name": "🌍 Hosting Geographies", "value": cc_str, "inline": True},
            {"name": "🗂 Verified Phishing Indicators (Defanged)", "value": "\n".join(sample_lines)[:1000], "inline": False},
        ]

        triggers.append(
            {
                "metric_id": metric_id,
                "trigger_type": "infra_phishing_wave",
                "subject": camp_name,
                "metric_value": f"{len(distinct_urls)} live phishing URLs ({len(distinct_hosts)} hosts)",
                "sort_key": (1, len(distinct_urls), len(distinct_hosts)),
                "title": f"🎣 [Infra Telemetry · Phishing Campaign Wave] {camp_name} ({len(distinct_urls)} URLs / 7d)",
                "description": (
                    f"Active credential-harvesting wave targeting **{camp_name}**: "
                    f"`{len(distinct_urls)}` distinct phishing URLs across `{len(distinct_hosts)}` domains recorded in 7 days."
                ),
                "fields": fields,
                "color": 0x9B59B6,
                "mitre_tactics": "T1566.002 Spearphishing Link • T1056.003 Web Portal Capture",
            }
        )

    triggers.sort(key=lambda x: x["sort_key"], reverse=True)
    return triggers


# ============================================================================
# TOP-LEVEL ORCHESTRATOR FOR ALL 4 REAL-TIME METRICS CHANNELS
# ============================================================================

async def evaluate_and_dispatch_metrics(session: aiohttp.ClientSession, *, dry_run: bool = False) -> dict[str, int]:
    """
    Evaluate all 4 Mode A real-time metrics channels against threat_cache.db + seen_pocs.db
    and dispatch any newly triggered alerts to their respective Discord webhooks.
    """
    await init_db()
    poc_records = await asyncio.to_thread(ensure_poc_radar_schema_and_load)
    cve_index = await build_verified_cve_index(session, poc_records)

    bounty_candidates = await evaluate_bounty_metrics(session, cve_index)
    cve_candidates = await evaluate_cve_lifecycle_metrics(session, cve_index)
    adversary_candidates = await evaluate_adversary_metrics()
    infra_candidates = await evaluate_infra_metrics(session)

    results = {
        "metrics_bounty": await dispatch_channel_triggers(
            session, "metrics_bounty", bounty_candidates, dry_run=dry_run
        ),
        "metrics_cve": await dispatch_channel_triggers(
            session, "metrics_cve", cve_candidates, dry_run=dry_run
        ),
        "metrics_adversary": await dispatch_channel_triggers(
            session, "metrics_adversary", adversary_candidates, dry_run=dry_run
        ),
        "metrics_infra": await dispatch_channel_triggers(
            session, "metrics_infra", infra_candidates, dry_run=dry_run
        ),
    }
    return results


async def _cli_main():
    parser = argparse.ArgumentParser(description="Homunculus Real-Time Mode A Metrics Engine (4 Channels)")
    parser.add_argument("--dry-run", action="store_true", help="Evaluate all 4 metric channels and print triggers without posting to Discord")
    args = parser.parse_args()

    connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300, family=socket.AF_INET)
    async with aiohttp.ClientSession(connector=connector) as session:
        res = await evaluate_and_dispatch_metrics(session, dry_run=args.dry_run)
        print(f"[*] Metrics Engine run complete. Dispatched counts: {res}")


if __name__ == "__main__":
    asyncio.run(_cli_main())
