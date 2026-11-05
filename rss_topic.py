# rss_topic.py - keyword classifier for generic research RSS posts
import re

# (label, regex, ATT&CK technique or "")
# Order matters: first match wins. Techniques are only attached where the
# keyword implies a specific technique with reasonable confidence.
RULES = [
    ("🔒 Ransomware Research", r"ransomware|extortion|lockbit|blackcat|alphv|akira", "T1486 Data Encrypted for Impact"),
    ("🕵 Infostealer Research", r"info-?stealer|stealer|lumma|vidar|redline|raccoon|\bamos\b", "T1555 Credentials from Password Stores"),
    ("🎣 Phishing Research", r"phishing|smishing|vishing|credential harvest", "T1566 Phishing"),
    ("📦 Supply Chain Compromise", r"supply[- ]chain|malicious (npm|pypi|package)|typosquat", "T1195 Supply Chain Compromise"),
    ("🌐 Geopolitical / Nation-State", r"nation-state|state-sponsored|\bapt ?\d*\b|espionage|geopolit|\bwar\b|conflict|lazarus|sandworm|volt typhoon|salt typhoon", ""),
    ("🤖 AI & Security Research", r"\bai\b|\bllms?\b|\bagents?\b|machine learning|frontier model|generative", ""),
    ("💥 Vulnerability Research", r"cve-\d{4}|zero-?day|0-day|vulnerabilit|exploit", ""),
    ("🦠 Malware Analysis", r"malware|loader|botnet|backdoor|trojan|rootkit|implant|reverse engineering|\brat\b", ""),
]

DEFAULT_LABEL = "🔬 Threat Research"
DEFAULT_MITRE = "Not mapped"

_COMPILED = [(label, re.compile(pat, re.IGNORECASE), mitre) for label, pat, mitre in RULES]


def _match(text):
    for label, rx, mitre in _COMPILED:
        if rx.search(text):
            return label, (mitre or DEFAULT_MITRE)
    return None


def classify_rss_topic(title, body=""):
    """Return (label, mitre). Title is checked first, then title + start of body."""
    title = title or ""
    hit = _match(title)
    if hit:
        return hit
    hit = _match(f"{title} {(body or '')[:1500]}")
    if hit:
        return hit
    return DEFAULT_LABEL, DEFAULT_MITRE
