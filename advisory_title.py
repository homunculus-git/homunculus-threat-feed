# advisory_title.py - tidy government advisory titles (e.g. CERT-Bund/BSI tags)
import re

SEVERITY = {
    "niedrig": ("🟢", "Low"), "low": ("🟢", "Low"),
    "mittel": ("🟡", "Medium"), "medium": ("🟡", "Medium"), "moderate": ("🟡", "Medium"),
    "hoch": ("🟠", "High"), "high": ("🟠", "High"),
    "kritisch": ("🔴", "Critical"), "critical": ("🔴", "Critical"),
}
UPDATE_WORDS = {"update", "updated", "aktualisierung", "aktualisiert"}
NEW_WORDS = {"neu", "new"}
TAG = re.compile(r"^\s*\[([^\]]{2,20})\]\s*")


def tidy_advisory_title(title):
    """Strip leading [TAG] markers. Returns (clean_title, severity_or_None, updated_bool)."""
    severity, updated = None, False
    title = title or ""
    while True:
        m = TAG.match(title)
        if not m:
            break
        word = m.group(1).strip().lower()
        if word in SEVERITY:
            severity = SEVERITY[word]
        elif word in UPDATE_WORDS:
            updated = True
        elif word in NEW_WORDS:
            pass
        else:
            break
        title = title[m.end():]
    return title.strip(), severity, updated
