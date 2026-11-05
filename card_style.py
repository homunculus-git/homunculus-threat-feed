"""card_style.py (v3) - presentation layer for Discord alert cards.

Re-arranges the fields of an embed into a clean executive layout. Nothing is removed.
Environment switches (all optional):
  CARD_STYLE=classic        bypass this module completely
  CARD_ANSI=0               plain code blocks (no colours; set in the shell, not .env)
  CARD_SUMMARY_FIRST=1      Intelligence Summary above the analysis blocks
  CARD_TITLES=styled|underline|plain   section-title look (default styled)
  CARD_HEADER=wide|compact  wide = date right-aligned (blank middle column), compact = no blank column
  CARD_SEVERITY=0           keep each channel's fixed colour bar and skip the Threat Level row
Run `python3 card_style.py` for a terminal preview, `python3 card_style.py send` to post samples.
"""
import os
import re
import textwrap

ESC = "\u001b"
ANSI = os.getenv("CARD_ANSI", "1") != "0"


def _c(code):
    return f"{ESC}[{code}m" if ANSI else ""


RESET, LABEL, VALUE, DIM = _c("0"), _c("1;34"), _c("0;37"), _c("0;30")
GREEN, YELLOW, RED, CYAN = _c("1;32"), _c("1;33"), _c("1;31"), _c("1;36")
TICKS = "`" * 3
FENCE = TICKS + "ansi" if ANSI else TICKS
BLANK = "\u200b"
MAX_LABEL, MAX_VALUE, CHUNK, WRAP = 22, 42, 980, 46

# Severity model (heuristic - tune freely): base level per channel, +1 per signal.
LEVELS = [("LOW", 0x3498DB, CYAN), ("MEDIUM", 0xF1C40F, VALUE), ("HIGH", 0xE67E22, YELLOW), ("CRITICAL", 0xE74C3C, RED)]
BASE = {"ransomware": 2, "vulnerabilities": 2, "malware": 1, "infrastructure": 1, "phishing": 1}
CONF_HIGH, CONF_LOW = 75, 40

DATE_RE = re.compile(r"\b(date|first seen|first observed|published|discovered)\b", re.I)
MD_RE = re.compile(r"(\*\*|__|`)")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
KV_BULLET = re.compile(r"^\s*[\u2022*-]\s*\*\*(.+?)\*\*\s*(.*)$")
KV_YAML = re.compile(r"^\s*(\S[^:\n]{0,26}?)\s+:\s+(.+?)\s*$")
FENCED = re.compile(r"^`{3}(\w*)\n(.*?)\n?`{3}$", re.S)
STAGE_HDR = re.compile(r"^\s*STAGE\s+(\d)\s+\u2503\s+(.+?)\s*$", re.I)
STAGE_VAL = re.compile(r"^\s*\u2570\u2500\s*(.+?)\s*$")
STAGE_BULLET = re.compile(r"^\s*[\u2022*-]\s*\*\*Stage\s+(\d)\s*\(([^)]*)\):?\*\*:?\s*(.*)$", re.I)


def _plain(value):
    return MD_RE.sub("", str(value)).strip()


def _label(name):
    return re.sub(r"^[^\w]+", "", str(name)).strip() or str(name)


def _blank(field):
    joined = str(field.get("name", "")) + str(field.get("value", ""))
    return not re.sub(r"[\u200b\s]", "", joined)


def _title(name):
    """Section title: no emoji, uppercase, Unicode sans-serif bold (works on every client)."""
    mode = os.getenv("CARD_TITLES", "styled").lower()
    if mode == "plain" or not name.strip(BLANK + " "):
        return name
    out = []
    for ch in _label(name).upper():
        if "A" <= ch <= "Z":
            out.append(chr(0x1D5D4 + ord(ch) - 65))
        elif "0" <= ch <= "9":
            out.append(chr(0x1D7EC + ord(ch) - 48))
        else:
            out.append(ch)
    text = "".join(out)
    return f"__{text}__" if mode == "underline" else text


def _c2_active(value):
    v = value.lower().strip()
    return not (v in ("", "-", "none") or v.startswith("no confirmed") or "p2p" in v)


def _tone(label, value):
    l, v = label.lower(), value.lower()
    if "confidence" in l:
        m = re.search(r"\d+", v)
        if m:
            n = int(m.group())
            return GREEN if n >= CONF_HIGH else YELLOW if n >= CONF_LOW else RED
    if "status" in l:
        if re.search(r"offline|dead|removed|404", v):
            return RED
        if re.search(r"not resolve|unresolved|failed|timed out|non-public", v):
            return YELLOW
        if re.search(r"online|live|active|resolves", v):
            return GREEN
    if "ransomware" in l and v.strip() == "known":
        return RED
    if "kev" in l and "cve-" in v:
        return RED
    if "vector" in l and "weaponized" in v:
        return YELLOW
    return VALUE


def _kv_lines(pairs, width=0):
    w = max(len(p[0]) for p in pairs)
    lines = []
    for item in pairs:
        label, value = item[0], item[1]
        tone = item[2] if len(item) > 2 else _tone(label, value)
        parts = textwrap.wrap(value, width, break_long_words=False, break_on_hyphens=False) if width else [value]
        parts = parts or ["-"]
        lines.append(f"{LABEL}{label:<{w}}{RESET} {DIM}\u2503{RESET} {tone}{parts[0]}{RESET}")
        for extra in parts[1:]:
            lines.append(f"{' ' * w} {DIM}\u2503{RESET} {tone}{extra}{RESET}")
    return lines


def _as_pairs(value):
    text = value.strip()
    fence = FENCED.match(text)
    lang, inner = (fence.group(1).lower(), fence.group(2)) if fence else ("", text)
    if lang not in ("", "yaml"):
        return None
    pairs = []
    for line in inner.split("\n"):
        if not line.strip():
            continue
        m = KV_BULLET.match(line)
        if m:
            pairs.append((m.group(1).strip().rstrip(":").strip(), _plain(m.group(2)) or "-"))
            continue
        m = KV_YAML.match(line) if lang == "yaml" else None
        if not m:
            return None
        pairs.append((m.group(1).strip(), _plain(m.group(2))))
    return pairs if len(pairs) >= 2 else None


def _stages(value):
    """Parse a kill-chain field (ANSI block or original bullets) into [[num, title, value], ...]."""
    text = ANSI_RE.sub("", value).strip()
    fence = FENCED.match(text)
    inner = fence.group(2) if fence else text
    stages, cur = [], None
    for line in inner.split("\n"):
        if not line.strip():
            continue
        b, h, v = STAGE_BULLET.match(line), STAGE_HDR.match(line), STAGE_VAL.match(line)
        if b:
            stages.append([b.group(1), b.group(2).strip(), _plain(b.group(3))])
            cur = None
        elif h:
            cur = [h.group(1), h.group(2).strip(), ""]
            stages.append(cur)
        elif v and cur is not None:
            cur[2] = _plain(v.group(1))
        else:
            return None
    return stages if len(stages) >= 2 and all(s[2] for s in stages) else None


def _stage_block(stages):
    lines = []
    for num, title, val in stages:
        tone = (RED if _c2_active(val) else YELLOW) if num == "2" else VALUE
        lines.append(f"{LABEL}STAGE {num}  \u2503  {title.upper()}{RESET}")
        parts = textwrap.wrap(val, WRAP - 6, break_long_words=False, break_on_hyphens=False) or ["-"]
        lines.append(f"{DIM}   \u2570\u2500{RESET} {tone}{parts[0]}{RESET}")
        lines += [f"      {tone}{p}{RESET}" for p in parts[1:]]
    return _code(lines)


def _code(lines):
    return FENCE + "\n" + "\n".join(lines) + "\n" + TICKS


def _chunks(lines, limit=CHUNK):
    chunks, cur, size = [], [], 0
    for line in lines:
        if cur and size + len(line) + 1 > limit:
            chunks.append(cur)
            cur, size = [], 0
        cur.append(line)
        size += len(line) + 1
    if cur:
        chunks.append(cur)
    return chunks


def _unfence(value):
    m = re.fullmatch(r"`([^`\n]+)`", value.strip())
    if m and len(m.group(1)) + 8 <= 1024:
        return TICKS + "\n" + m.group(1) + "\n" + TICKS
    return value


def _attack(footer_text):
    m = re.match(r"\s*ATT&CK:\s*(.+)", footer_text or "", re.I | re.S)
    if not m:
        return None
    rows = []
    for item in m.group(1).split("\u2022"):
        t = re.match(r"\s*(T\d{4}(?:\.\d{3})?)\s+(.+?)\s*$", item)
        if not t:
            return None
        rows.append((t.group(1), t.group(2)))
    return {"name": "MITRE ATT&CK", "value": _code(_kv_lines(rows)), "inline": False}


def _quote(desc):
    if not desc or re.search(r"(?m)^\s*>", desc):
        return desc
    quoted = "\n".join(("> " + ln) if ln.strip() else ln for ln in desc.split("\n"))
    return quoted if len(quoted) <= 2000 else desc


def _valid(embed):
    fields = embed.get("fields") or []
    if len(fields) > 25:
        return False
    total = len(embed.get("title", "")) + len(embed.get("description", ""))
    total += len((embed.get("footer") or {}).get("text", ""))
    for f in fields:
        if not f.get("name") or not f.get("value"):
            return False
        if len(f["name"]) > 256 or len(f["value"]) > 1024:
            return False
        total += len(f["name"]) + len(f["value"])
    return total <= 5900


def _signals(pairs, stages):
    sig = {}
    for label, value in pairs:
        l, v = label.lower(), value.lower()
        if "ransomware" in l and v.strip() == "known":
            sig["ransomware-linked"] = True
        if "kev" in l and "cve-" in v:
            sig["KEV match"] = True
        if "host status" in l and "online" in v:
            sig["live payload"] = True
        if "dns status" in l and v.startswith("live dns"):
            sig["live DNS"] = True
        if "confidence" in l:
            m = re.search(r"\d+", v)
            if m:
                sig["confidence"] = int(m.group())
    for num, _t, val in stages:
        if num == "2" and _c2_active(val):
            sig["active C2"] = True
    return sig


def _severity(channel, sig):
    if channel not in BASE:
        return None
    score, why = BASE[channel], []
    for key in ("KEV match", "ransomware-linked", "live payload", "active C2", "live DNS"):
        if sig.get(key):
            score += 1
            why.append(key)
    conf = sig.get("confidence")
    if conf is not None and conf >= CONF_HIGH:
        score += 1
        why.append(f"confidence {conf}%")
    elif conf is not None and conf < CONF_LOW:
        score -= 1
        why.append(f"confidence {conf}%")
    return LEVELS[max(0, min(3, score))], why


def _block_field(name, value):
    pairs = _as_pairs(value)
    if pairs:
        rendered = _code(_kv_lines(pairs, WRAP))
        if len(rendered) <= 1024:
            return {"name": name, "value": rendered, "inline": False}, pairs
    return {"name": name, "value": value, "inline": False}, []


def _style(embed, channel=None):
    date, rows, blocks, longs, links = None, [], [], [], []
    all_pairs, all_stages = [], []
    for f in embed.get("fields") or []:
        if _blank(f):
            continue
        name, value = str(f.get("name", "")), str(f.get("value", ""))
        plain, label = _plain(value), _label(name)
        single = "\n" not in value.strip() and not value.lstrip().startswith(TICKS)
        if date is None and single and DATE_RE.search(name) and len(plain) <= 60:
            date = {"name": label, "value": value, "inline": True}
        elif not single:
            stages = _stages(value)
            rendered = _stage_block(stages) if stages else None
            if stages and len(rendered) <= 1024:
                blocks.append({"name": name, "value": rendered, "inline": False})
                all_stages += stages
            else:
                field, pairs = _block_field(name, value)
                blocks.append(field)
                all_pairs += pairs
        elif "](" in value:
            if re.search(r"actor", name, re.I):
                blocks.append({"name": name, "value": value, "inline": False})
            else:
                links.append(f"**{label}** \u25B8 {value}")
        elif len(plain) <= MAX_VALUE and len(label) <= MAX_LABEL:
            rows.append({"label": label, "plain": plain or "-", "inline": bool(f.get("inline")), "f": f})
            all_pairs.append((label, plain))
        else:
            longs.append({"name": name, "value": _unfence(value), "inline": False})
            all_pairs.append((label, plain))

    level = None
    if os.getenv("CARD_SEVERITY", "1") != "0":
        level = _severity(channel, _signals(all_pairs, all_stages))

    head = []
    if date:
        pick = next((r for r in rows if r["inline"]), None)
        if pick:
            rows.remove(pick)
            first = {"name": str(pick["f"]["name"]), "value": str(pick["f"]["value"]), "inline": True}
        else:
            first = {"name": BLANK, "value": BLANK, "inline": True}
        spacer = [] if os.getenv("CARD_HEADER", "wide").lower() == "compact" else [{"name": BLANK, "value": BLANK, "inline": True}]
        head = [first] + spacer + [date]

    table = [(r["label"], r["plain"]) for r in rows]
    if level:
        (lvl_name, _bar, lvl_tone), why = level
        text = lvl_name + (f" ({', '.join(why)})" if why else "")
        table.insert(0, ("Threat Level", text, lvl_tone))
    summary = []
    if table:
        for n, chunk in enumerate(_chunks(_kv_lines(table, WRAP))):
            summary.append({"name": "Intelligence Summary" if n == 0 else BLANK, "value": _code(chunk), "inline": False})

    if os.getenv("CARD_SUMMARY_FIRST", "0") == "1":
        out = head + summary + blocks + longs
    else:
        out = head + blocks + summary + longs

    for n, chunk in enumerate(_chunks(links, 1000)):
        out.append({"name": "Investigate" if n == 0 else BLANK, "value": "\n".join(chunk), "inline": False})

    styled = dict(embed)
    attack = _attack((embed.get("footer") or {}).get("text"))
    if attack:
        out.append(attack)
        styled.pop("footer", None)
    styled["fields"] = [dict(f, name=_title(f["name"])) for f in out]
    styled["description"] = _quote(embed.get("description", ""))
    if level:
        styled["color"] = level[0][1]
    return styled


def style_embed(embed, channel=None):
    if os.getenv("CARD_STYLE", "pro").lower() == "classic":
        return embed
    try:
        styled = _style(embed, channel)
        return styled if _valid(styled) else embed
    except Exception:
        return embed


def _kc(stage1, stage2):
    return (TICKS + "ansi\n" + LABEL + "STAGE 1  \u2503  DELIVERY" + RESET + "\n" + VALUE + "   \u2570\u2500 " + stage1 + RESET
            + "\n" + LABEL + "STAGE 2  \u2503  COMMAND & CONTROL" + RESET + "\n" + VALUE + "   \u2570\u2500 " + stage2 + RESET + "\n" + TICKS)


_SBX = "[Scan on VirusTotal](https://www.virustotal.com/) \u2022 [Scan on URLScan.io](https://urlscan.io/) \u2022 [Search on Triage](https://tria.ge/)"


def _malware(title, family, status, c2, tags):
    return {
        "title": title,
        "description": "Automated intelligence correlation linking initial delivery to active command server.",
        "color": 0xE67E22,
        "fields": [
            {"name": "Malware Family", "value": f"**{family}**", "inline": True},
            {"name": BLANK, "value": BLANK, "inline": True},
            {"name": "Date Added", "value": "`03 Nov 2026 \u2022 16:40:12 UTC`", "inline": True},
            {"name": "Routing & ASN", "value": "`AS13335` Cloudflare, Inc. (United States)", "inline": False},
            {"name": "\U0001F3AF Cyber Kill Chain Correlation", "value": _kc("AS13335 Cloudflare, Inc. (United States)", c2), "inline": False},
            {"name": "Host Status", "value": status, "inline": True},
            {"name": "Campaign Tags", "value": f"`{tags}`", "inline": True},
            {"name": "Defanged Payload Link", "value": "`hxxp://198[.]51[.]100[.]7/bins/payload.sh`", "inline": False},
            {"name": "Safe Investigation Sandboxes", "value": _SBX, "inline": False},
            {"name": "Threat Database", "value": "[View URLhaus Dossier](https://urlhaus.abuse.ch/)", "inline": True},
        ],
        "footer": {"text": "ATT&CK: T1204.001 Malicious Link \u2022 T1105 Ingress Tool Transfer \u2022 T1071 C2 Protocols"},
    }


def _infra(title, family, conf, dns):
    return {
        "title": title,
        "description": "Community intelligence indicator linked to active adversary campaign.",
        "color": 0x8E44AD,
        "fields": [
            {"name": "Malware Campaign", "value": f"**{family}**", "inline": True},
            {"name": BLANK, "value": BLANK, "inline": True},
            {"name": "Date Discovered", "value": "`03 Nov 2026 \u2022 15:02:44 UTC`", "inline": True},
            {"name": "Indicator Type", "value": "`ip:port`", "inline": True},
            {"name": "Confidence Score", "value": f"`{conf}%`", "inline": True},
            {"name": "DNS Status", "value": f"**{dns}**", "inline": True},
            {"name": "Campaign Tags", "value": "`botnet, mozi`", "inline": False},
            {"name": "Defanged Indicator", "value": "`198[.]51[.]100[.]23:42151`", "inline": False},
            {"name": "Threat Database", "value": "[View ThreatFox Dossier](https://threatfox.abuse.ch/)", "inline": False},
        ],
        "footer": {"text": "ATT&CK: T1071 C2 Protocols \u2022 T1584 Compromise Infrastructure"},
    }


SAMPLES = [
    ("ransomware", {
        "title": "\U0001F6A8 Ransomware Alert: Northwind Logistics Ltd",
        "description": "**Extortion Notice / Group Claim:**\n>>> Northwind Logistics data will be published unless contact is made.",
        "color": 0xE74C3C,
        "fields": [
            {"name": "Publisher", "value": "Ransomware.live", "inline": True},
            {"name": BLANK, "value": BLANK, "inline": True},
            {"name": "Date Discovered", "value": "`03 Nov 2026 \u2022 16:15:22 UTC`", "inline": True},
            {"name": "Threat Actor Dossier", "value": "Qilin \u2022 [MITRE G1050](https://attack.mitre.org/groups/G1050/) \u2022 [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)", "inline": False},
            {"name": "Discovery Link", "value": "[Inspect Leak Page](https://www.ransomware.live/)", "inline": False},
            {"name": "\U0001F3AF Victim Attack Surface & Edge Exposure", "value": TICKS + "yaml\nTarget Domain : northwind-logistics.example (203.0.113.10)\nHosting / ASN : AS64500 Example Hosting [GB]\nEdge Gateways : vpn.northwind-logistics.example, citrix.northwind-logistics.example\nKEV Matches   : CVE-2024-3400 (Palo Alto PAN-OS)\nLikely Vector : Weaponized Edge N-Day (CVE-2024-3400)\n" + TICKS, "inline": False},
        ],
        "footer": {"text": "ATT&CK: T1486 Data Encrypted for Impact \u2022 T1567 Exfiltration Over Web Service"},
    }),
    ("malware", _malware("\u2694\uFE0F Kill Chain Alert: Lumma Stealer (Dropper & C2)", "Lumma Stealer", "\U0001F7E2 **URLhaus reports: online**", "185.220.101.5:443 (Active Lumma Stealer C2)", "elf, mirai")),
    ("malware", _malware("\u2694\uFE0F Kill Chain Alert: Unclassified Dropper (sample, quiet)", "Unclassified Dropper", "\U0001F534 **URLhaus reports: offline**", "No confirmed active C2 on record for campaign", "sh")),
    ("infrastructure", _infra("\U0001F575\uFE0F Threat Attribution: Mozi", "Mozi", 75, "Direct IP (no DNS lookup)")),
    ("infrastructure", _infra("\U0001F575\uFE0F Threat Attribution: Unknown (sample, low confidence)", "Unclassified", 30, "Does not resolve")),
    ("vulnerabilities", {
        "title": "\U0001F6A8 Vulnerability Alert: CVE-2024-3400",
        "description": "A command injection vulnerability in GlobalProtect allows unauthenticated remote code execution.",
        "color": 0xE67E22,
        "fields": [
            {"name": "Product", "value": "Palo Alto Networks PAN-OS", "inline": True},
            {"name": BLANK, "value": BLANK, "inline": True},
            {"name": "Date Discovered", "value": "`03 Nov 2026 \u2022 14:30:00 UTC`", "inline": True},
            {"name": "Ransomware Link", "value": "Known", "inline": True},
            {"name": "Required Action", "value": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.", "inline": False},
        ],
        "footer": {"text": "ATT&CK: T1190 Exploit Public-Facing Application"},
    }),
]


def _preview(embed):
    print("\n" + "=" * 72)
    print(f"[bar colour #{embed.get('color', 0):06X}]  {embed.get('title', '')}")
    if embed.get("description"):
        print(embed["description"])
    row = []
    for f in embed["fields"]:
        if f.get("inline"):
            row.append(f"{f['name'].strip(BLANK)}: {f['value'].strip(BLANK)}")
            continue
        if row:
            print("  |  ".join(row))
            row = []
        print("\n" + f["name"].strip(BLANK))
        print(f["value"].replace(TICKS + "ansi", "").replace(TICKS + "yaml", "").replace(TICKS, "").strip("\n"))
    if row:
        print("  |  ".join(row))
    if embed.get("footer"):
        print("\n" + embed["footer"]["text"])


def _send(channel, embed):
    import json
    import socket
    import urllib.request

    real = socket.getaddrinfo
    socket.getaddrinfo = lambda h, p, f=0, t=0, pr=0, fl=0: real(h, p, socket.AF_INET, t, pr, fl)
    env = {}
    for path in (".env", "../.env"):
        if os.path.exists(path):
            for line in open(path):
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    env[k] = v.strip("\"'")
            break
    hook = env.get("DISCORD_WEBHOOK_" + channel.upper())
    if not hook:
        print(f"[!] DISCORD_WEBHOOK_{channel.upper()} not found in .env")
        return
    req = urllib.request.Request(
        hook, data=json.dumps({"embeds": [embed]}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    urllib.request.urlopen(req, timeout=10)
    print(f"[+] Sent {channel} sample")


if __name__ == "__main__":
    import sys
    for chan, emb in SAMPLES:
        styled = style_embed(emb, chan)
        if len(sys.argv) > 1 and sys.argv[1] == "send":
            _send(chan, styled)
        else:
            _preview(styled)
