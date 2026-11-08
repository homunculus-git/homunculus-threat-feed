import re
import urllib.parse

RANSOM_ACTOR_PROFILES = {
    "lockbit": {
        "actor": "LockBit 3.0",
        "origin_country": "Russia / CIS (High Confidence)",
        "mitre_type": "software",
        "mitre_id": "S1202",
        "malpedia": "win.lockbit",
    },
    "akira": {
        "actor": "Akira",
        "origin_country": "Russia / CIS (Moderate Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G1024",
        "malpedia": "win.akira",
    },
    "qilin": {
        "actor": "Qilin (Agenda)",
        "origin_country": "Russia / CIS (Moderate Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G1050",
        "malpedia": "win.agendacrypt",
    },
    "play": {
        "actor": "Play Ransomware",
        "origin_country": "Eastern Europe / CIS (Moderate Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G1040",
        "malpedia": "win.play",
    },
    "blackbasta": {
        "actor": "Black Basta",
        "origin_country": "Russia (High Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G1046",
        "malpedia": "win.blackbasta",
    },
    "cl0p": {
        "actor": "CL0P (TA505)",
        "origin_country": "Russia (High Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G0092",
        "malpedia": "win.clop",
    },
    "ransomhub": {
        "actor": "RansomHub",
        "origin_country": "Russia / Dispersed Affiliates (Moderate Confidence)",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.ransomhub",
    },
    "incransom": {
        "actor": "INC Ransom",
        "origin_country": "Dispersed / Multi-National (Moderate Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G1032",
        "malpedia": "win.inc",
    },
    "rhysida": {
        "actor": "Rhysida",
        "origin_country": "Russia / CIS (Moderate Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G1025",
        "malpedia": "win.rhysida",
    },
    "medusa": {
        "actor": "Medusa",
        "origin_country": "Unknown / Dispersed Affiliates",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.medusa",
    },
    "bianlian": {
        "actor": "BianLian",
        "origin_country": "Russia / Eastern Europe (Moderate Confidence)",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.bianlian",
    },
    "blackcat": {
        "actor": "BlackCat (ALPHV)",
        "origin_country": "Russia (High Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G1010",
        "malpedia": "win.blackcat",
    },
    "alphv": {
        "actor": "BlackCat (ALPHV)",
        "origin_country": "Russia (High Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G1010",
        "malpedia": "win.blackcat",
    },
    "cactus": {
        "actor": "Cactus",
        "origin_country": "Eastern Europe / Dispersed Affiliates",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.cactus",
    },
    "8base": {
        "actor": "8Base",
        "origin_country": "Russia / Eastern Europe (Moderate Confidence)",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.8base",
    },
    "cuba": {
        "actor": "Cuba Ransomware",
        "origin_country": "Russia (Moderate Confidence)",
        "mitre_type": "groups",
        "mitre_id": "G0125",
        "malpedia": "win.cuba",
    },
    "snatch": {
        "actor": "Snatch",
        "origin_country": "Russia (Moderate Confidence)",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.snatch",
    },
    "hunters": {
        "actor": "Hunters International",
        "origin_country": "Dispersed / Global (Moderate Confidence)",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.hunters_international",
    },
    "safepay": {
        "actor": "SafePay",
        "origin_country": "Unknown / Emerging Syndicate",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.safepay",
    },
    "thegentlemen": {
        "actor": "Thegentlemen",
        "origin_country": "Unknown / Emerging Syndicate",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.gentlemen",
    },
    "blacksuit": {
        "actor": "BlackSuit",
        "origin_country": "Russia / Eastern Europe",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.blacksuit",
    },
    "fog": {
        "actor": "Fog",
        "origin_country": "Unknown / Emerging Syndicate",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": "win.fog",
    },
    "embargo": {
        "actor": "Embargo",
        "origin_country": "Unknown / Emerging Syndicate",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": None,
    },
    "dragonforce": {
        "actor": "DragonForce",
        "origin_country": "Malaysia / Dispersed Affiliates",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": None,
    },
    "whitearmor": {
        "actor": "WhiteArmor",
        "origin_country": "Unknown / Emerging Syndicate",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": None,
    },
    "payload": {
        "actor": "Payload",
        "origin_country": "Unknown / Emerging Syndicate",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": None,
    },
    "n0n": {
        "actor": "N0n",
        "origin_country": "Unknown / Emerging Syndicate",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": None,
    },
    "boobaproject": {
        "actor": "Booba project",
        "origin_country": "Unknown / Emerging Syndicate",
        "mitre_type": None,
        "mitre_id": None,
        "malpedia": None,
    },
}

def format_threat_actor_info(
    threat_actor: str,
    stat_line: str = None,
    *,
    publisher: str = None,
    extra_dossier_link: str = None,
) -> dict:
    cleaned = (threat_actor or "").strip()
    slug = re.sub(r"[^a-z0-9]", "", cleaned.lower())

    if not slug or slug in ("unattributed", "unknown", "unspecified", "anonymous", "none", "na"):
        return {
            "name": "Threat Actor Info",
            "value": (
                "```yaml\n"
                "Name           : Unattributed\n"
                "Origin Country : Unknown / Unconfirmed\n"
                "Activity Stat  : No specific syndicate attributed to this claim\n"
                "```"
            ),
            "inline": False,
        }

    profile = RANSOM_ACTOR_PROFILES.get(slug)
    actor_name = profile["actor"] if profile else cleaned
    origin = profile.get("origin_country", "Unknown / Unconfirmed Origin") if profile else "Unknown / Unconfirmed Origin"
    stat = stat_line or "Activity Stat  : Active monitored syndicate in threat feed cache"

    dossier_links = []
    if profile and profile.get("mitre_id"):
        mtype = profile.get("mitre_type") or "groups"
        gid = profile["mitre_id"]
        dossier_links.append(f"[MITRE {gid}](https://attack.mitre.org/{mtype}/{gid}/)")
    else:
        q = urllib.parse.quote(actor_name)
        dossier_links.append(f"[Search MITRE](https://attack.mitre.org/?q={q})")

    malpedia_family = profile.get("malpedia") if profile else None
    if malpedia_family:
        dossier_links.append(f"[Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/{malpedia_family})")

    if extra_dossier_link:
        dossier_links.append(extra_dossier_link)
    else:
        group_slug = urllib.parse.quote(slug)
        if (publisher or "").strip().lower() == "ransomlook":
            dossier_links.append(f"[Ransomware.live](https://www.ransomware.live/group/{group_slug})")
        else:
            dossier_links.append(f"[RansomLook](https://www.ransomlook.io/group/{group_slug})")

    dossier = " • ".join(dossier_links)

    yaml_block = (
        "```yaml\n"
        f"Name           : {actor_name}\n"
        f"Origin Country : {origin}\n"
        f"{stat}\n"
        "```\n"
        f"🎯 Dossier: {dossier}"
    )

    return {
        "name": "Threat Actor Info",
        "value": yaml_block,
        "inline": False,
    }

format_actor_ttp_field = format_threat_actor_info

