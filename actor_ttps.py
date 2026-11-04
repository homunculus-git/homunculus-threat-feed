import re
import urllib.parse

RANSOM_ACTOR_PROFILES = {
    "lockbit": {
        "actor": "LockBit 3.0 (Black)",
        "assessed_base": "Russia / CIS (High Confidence)",
        "tools": "Mimikatz, Process Hacker, StealBit, rclone",
        "ttps": "T1190 (Exploit Public App) • T1059 (Scripting) • T1486 (Encryption)",
        "mitre_type": "software",
        "mitre_id": "S1202",
    },
    "akira": {
        "actor": "Akira",
        "assessed_base": "Russia / CIS (Moderate Confidence)",
        "tools": "AnyDesk, RustDesk, Advanced IP Scanner, rclone, PCHunter",
        "ttps": "T1133 (External Services) • T1567 (Exfil Over Cloud) • T1486 (Encryption)",
        "mitre_type": "groups",
        "mitre_id": "G1024",
    },
    "qilin": {
        "actor": "Qilin (Agenda)",
        "assessed_base": "Russia / CIS (Moderate Confidence)",
        "tools": "Cobalt Strike, PsExec, Chisel, MegaSync",
        "ttps": "T1566 (Phishing) • T1021 (Remote Services) • T1486 (Encryption)",
        "mitre_type": "groups",
        "mitre_id": "G1050",
    },
    "play": {
        "actor": "Play Ransomware",
        "assessed_base": "Eastern Europe / CIS (Moderate Confidence)",
        "tools": "AdFind, GMER, Cobalt Strike, SystemInformer",
        "ttps": "T1190 (Exploit Public App) • T1078 (Valid Accounts) • T1486 (Encryption)",
        "mitre_type": "groups",
        "mitre_id": "G1040",
    },
    "blackbasta": {
        "actor": "Black Basta (Storm-1811)",
        "assessed_base": "Russia (High Confidence)",
        "tools": "BitzTransfer, BSoft, PsExec, Quick Assist, SoftPerf",
        "ttps": "T1566 (Phishing) • T1684 (Impersonation) • T1486 (Encryption)",
        "mitre_type": "groups",
        "mitre_id": "G1046",
    },
    "cl0p": {
        "actor": "CL0P (TA505)",
        "assessed_base": "Russia (High Confidence)",
        "tools": "DEWMODE, TrueBot, SDBbot, Cobalt Strike",
        "ttps": "T1190 (Exploit Public App) • T1567 (Exfiltration) • T1499 (Exhaustion)",
        "mitre_type": "groups",
        "mitre_id": "G0092",
    },
    "ransomhub": {
        "actor": "RansomHub",
        "assessed_base": "Russia / Dispersed Affiliates (Moderate Confidence)",
        "tools": "EDRKillShifter, Mimikatz, PuTTY, Scapa",
        "ttps": "T1190 (Exploit Public App) • T1562 (Disable Defense) • T1486 (Encryption)",
        "mitre_type": None,
        "mitre_id": None,
    },
    "incransom": {
        "actor": "INC Ransom",
        "assessed_base": "Dispersed / Multi-National (Low Confidence)",
        "tools": "AnyDesk, MegaSync, Sshuttle, NetScan",
        "ttps": "T1190 (Exploit Public App) • T1021 (Remote Services) • T1486 (Encryption)",
        "mitre_type": "groups",
        "mitre_id": "G1032",
    },
    "rhysida": {
        "actor": "Rhysida",
        "assessed_base": "Russia / CIS (Moderate Confidence)",
        "tools": "PsExec, AnyDesk, Port Scanner, secretsdump",
        "ttps": "T1078 (Valid Accounts) • T1059 (Scripting) • T1486 (Encryption)",
        "mitre_type": "groups",
        "mitre_id": "G1025",
    },
    "medusa": {
        "actor": "Medusa",
        "assessed_base": "Unknown / Dispersed (Low Confidence)",
        "tools": "ConnectWise, PDQ Deploy, MegaSync, Angry IP Scanner",
        "ttps": "T1133 (External Services) • T1562 (Impair Defenses) • T1486 (Encryption)",
        "mitre_type": None,
        "mitre_id": None,
    },
}

def format_actor_ttp_field(threat_actor: str) -> dict:
    slug = re.sub(r"[^a-z0-9]", "", (threat_actor or "").lower())
    data = RANSOM_ACTOR_PROFILES.get(slug)

    if data:
        if data.get("mitre_id"):
            m_url = f"https://attack.mitre.org/{data['mitre_type']}/{data['mitre_id']}/"
            mitre_link = f"[MITRE {data['mitre_id']}]({m_url})"
        else:
            q = urllib.parse.quote(data["actor"])
            mitre_link = f"[Search MITRE](https://attack.mitre.org/?q={q})"

        base_val = data.get("assessed_base", "Unattributed / Global")
        val = (
            "```yaml\n"
            f"Adversary     : {data['actor']}\n"
            f"Status        : Active Threat Syndicate\n"
            f"Assessed Base : {base_val}\n"
            f"Typical Tools : {data['tools']}\n"
            f"Top TTPs      : {data['ttps']}\n"
            "```\n"
            f"🎯 Research: {mitre_link} • [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/actor.{slug})"
        )
    else:
        q = urllib.parse.quote(threat_actor or "Unattributed")
        val = (
            "```yaml\n"
            f"Adversary     : {threat_actor or 'Unattributed'}\n"
            "Status        : Emerging / Unprofiled Syndicate\n"
            "Assessed Base : Unattributed / Global\n"
            "Standard TTPs : T1190 (Edge Exploit) • T1133 (VPN/RDP) • T1567 (Exfil)\n"
            "```\n"
            f"🔍 Investigate: [Search MITRE ATT&CK](https://attack.mitre.org/?q={q}) • [Search Malpedia](https://malpedia.caad.fkie.fraunhofer.de/search?q={q})"
        )

    return {
        "name": "⚔️ Adversary Tradecraft & Known TTPs",
        "value": val,
        "inline": False,
    }
