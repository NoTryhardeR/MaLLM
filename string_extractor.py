import re
from pathlib import Path
from typing import Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import MIN_STRING_LENGTH

# ── Classification patterns ───────────────────────────────────────────────────
# WHY regex? Fast, readable, and each pattern catches a specific artifact class.
PATTERNS = {
    "url": re.compile(
        r'https?://[^\s\x00-\x1f"\'<>]{4,}',
        re.IGNORECASE
    ),
    "ip_address": re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b'
    ),
    "registry": re.compile(
        r'HK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)'
        r'(?:\\[^\x00\s]{2,})+',
        re.IGNORECASE
    ),
    "file_path": re.compile(
        r'[A-Za-z]:\\(?:[^\x00\s\\/:*?"<>|]{1,255}\\)*[^\x00\s\\/:*?"<>|]{0,255}',
    ),
    "command": re.compile(
        r'(?:cmd\.exe|powershell|wscript|cscript|mshta|regsvr32|rundll32|schtasks)'
        r'(?:\s+[^\x00\n]{0,200})?',
        re.IGNORECASE
    ),
    "email": re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    ),
    "mutex": re.compile(
        r'(?:Global\\|Local\\)?[A-Za-z0-9_\-]{8,40}(?:Mutex|Lock|Event)',
        re.IGNORECASE
    ),
    "base64_blob": re.compile(
        r'[A-Za-z0-9+/]{40,}={0,2}'  # Long base64 strings → encoded payload?
    ),
    "onion": re.compile(
        r'[a-z2-7]{16,56}\.onion',
        re.IGNORECASE
    ),
}

# Words that strongly suggest malicious intent
MALICIOUS_KEYWORDS = [
    "ransom", "encrypt", "decrypt", "bitcoin", "wallet",
    "keylog", "password", "credential", "inject", "shellcode",
    "backdoor", "rootkit", "botnet", "payload", "dropper",
    "bypass", "privilege", "escalat", "dump", "exfil",
    "vssadmin", "shadow", "wbadmin", "bcdedit",  # ransomware favorites
]


def extract_strings(file_path: str, min_length: int = MIN_STRING_LENGTH) -> list[dict]:
    """
    Extract all printable ASCII strings from a binary file.

    WHY this approach vs just using the `strings` command?
        1. We run on Windows/Mac/Linux without needing external tools
        2. We immediately classify each string (URL, path, command...)
        3. We flag malicious keywords inline
        4. We return structured data (list of dicts) not raw text

    Returns:
        List of dicts: [{"value": "...", "type": "url", "suspicious": True}, ...]
    """
    path = Path(file_path)
    if not path.exists():
        return [{"error": f"File not found: {file_path}"}]

    raw = path.read_bytes()

    # ── Step 1: Extract all printable ASCII sequences ────────────────────────
    # WHY this regex: matches any run of printable ASCII chars (0x20-0x7E)
    # of length >= min_length. The \x20-\x7e range is the printable ASCII set.
    ascii_pattern = re.compile(
        rb'[ -~]{' + str(min_length).encode() + rb',}'
    )
    raw_strings = [m.group().decode('ascii', errors='ignore')
                   for m in ascii_pattern.finditer(raw)]

    # ── Step 2: Classify each string ─────────────────────────────────────────
    results = []
    seen = set()  # Deduplicate

    for s in raw_strings:
        if s in seen or len(s) < min_length:
            continue
        seen.add(s)

        string_type = "generic"
        suspicious = False

        # Try each pattern
        for pattern_name, pattern in PATTERNS.items():
            if pattern.search(s):
                string_type = pattern_name
                suspicious = True  # Any categorized string is noteworthy
                break

        # Check malicious keywords regardless of pattern match
        s_lower = s.lower()
        keyword_found = next(
            (kw for kw in MALICIOUS_KEYWORDS if kw in s_lower),
            None
        )
        if keyword_found:
            suspicious = True

        # Skip boring generic strings (short, no capitals, common words)
        if string_type == "generic" and not suspicious:
            # Only keep generic strings if they look interesting
            if len(s) < 8:
                continue
            # Skip strings that look like compiler artifacts
            if s.startswith(('.', '$', '?', '@')) and len(s) < 12:
                continue

        results.append({
            "value": s,
            "type": string_type,
            "suspicious": suspicious,
            "keyword_match": keyword_found,
        })

    # Sort: suspicious first, then by type
    results.sort(key=lambda x: (not x["suspicious"], x["type"]))
    return results


def summarize_for_prompt(strings: list[dict], max_strings: int = 30) -> str:
    """
    Format extracted strings for inclusion in an LLM prompt.

    WHY limit to 30?
        A typical PE file contains thousands of strings (DLL names, error
        messages, etc). Sending all of them to GPT wastes tokens and dilutes
        the important findings. We send ONLY the suspicious/classified ones,
        capped at max_strings.
    """
    if not strings:
        return "No interesting strings found."

    suspicious = [s for s in strings if s.get("suspicious")]
    generic = [s for s in strings if not s.get("suspicious")]

    lines = []

    if suspicious:
        lines.append(f"=== Suspicious Strings ({len(suspicious)} found) ===")
        for s in suspicious[:max_strings]:
            tag = f"[{s['type'].upper()}]"
            kw = f" (keyword: {s['keyword_match']})" if s.get('keyword_match') else ""
            lines.append(f"  {tag:<16} {s['value'][:120]}{kw}")

    if generic and len(lines) < max_strings:
        remaining = max_strings - len([l for l in lines if l.startswith('  ')])
        if remaining > 0 and generic:
            lines.append(f"\n=== Other Notable Strings (top {remaining}) ===")
            for s in generic[:remaining]:
                lines.append(f"  [GENERIC]        {s['value'][:120]}")

    lines.append(f"\nTotal strings extracted: {len(strings)}")
    return "\n".join(lines)


def get_statistics(strings: list[dict]) -> dict:
    """Return a summary dict of string analysis stats — useful for JSON output."""
    if not strings:
        return {}
    by_type = {}
    for s in strings:
        t = s["type"]
        by_type[t] = by_type.get(t, 0) + 1
    return {
        "total": len(strings),
        "suspicious": len([s for s in strings if s.get("suspicious")]),
        "by_type": by_type,
    }