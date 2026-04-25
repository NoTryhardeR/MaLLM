import math
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional
import sys
import os

# Add parent dir to path so we can import config
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import SUSPICIOUS_APIS, HIGH_ENTROPY_THRESHOLD

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.

    Formula: H = -Σ p(x) * log2(p(x))
    where p(x) is the probability of each byte value (0-255).

    WHY: High entropy (>7.0) suggests compressed, encrypted or obfuscated data.
         This is a classic malware indicator used by AV engines.
    """
    if not data:
        return 0.0
    # Count frequency of each byte value
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_pe_features(file_path: str) -> dict:
    """
    Main function: parse a PE file and return all static features.

    Args:
        file_path: Path to the .exe (or .dll, .sys) file

    Returns:
        dict with all extracted features, or error dict if parsing fails

    WHY return a dict?
        Dicts are easy to serialize to JSON (for storage in results/).
        They're also easy to pass to the prompt builder.
    """
    path = Path(file_path)

    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    # ── Basic file info (works even without pefile) ──────────────────────────
    raw_bytes = path.read_bytes()
    file_size = len(raw_bytes)

    features = {
        "file_name": path.name,
        "file_path": str(path.absolute()),
        "file_size_kb": round(file_size / 1024, 2),
        "md5": hashlib.md5(raw_bytes).hexdigest(),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "overall_entropy": calculate_entropy(raw_bytes),
        # PE-specific fields (filled below if pefile available)
        "machine_type": "unknown",
        "timestamp": "unknown",
        "entry_point": "unknown",
        "image_base": "unknown",
        "num_sections": 0,
        "sections": [],
        "imports": {},
        "suspicious_imports": {},
        "num_imports_total": 0,
        "is_packed": False,
        "is_pe": raw_bytes[:2] == b'MZ',  # MZ magic = DOS/PE header
    }

    if not features["is_pe"]:
        features["error"] = "Not a valid PE file (missing MZ header)"
        return features

    if not PEFILE_AVAILABLE:
        features["warning"] = "pefile not installed — install with: pip install pefile"
        return features

    # ── Parse with pefile ────────────────────────────────────────────────────
    try:
        pe = pefile.PE(file_path)

        # Machine architecture
        machine_map = {
            0x014c: "x86 (32-bit)",
            0x8664: "x86-64 (64-bit)",
            0x01c4: "ARM",
            0xaa64: "ARM64",
        }
        machine_code = pe.FILE_HEADER.Machine
        features["machine_type"] = machine_map.get(machine_code, f"Unknown ({hex(machine_code)})")

        # Compile timestamp
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            features["timestamp"] = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            features["timestamp"] = f"raw: {ts}"

        # Entry point and image base
        features["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        features["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)

        # ── Sections ─────────────────────────────────────────────────────────
        # WHY: Each section (.text = code, .data = data, .rsrc = resources)
        #      reveals structure. Unusual section names (.aaaa, .packed) → malware.
        sections_info = []
        has_high_entropy_section = False

        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            section_data = section.get_data()
            ent = calculate_entropy(section_data)

            if ent > HIGH_ENTROPY_THRESHOLD:
                has_high_entropy_section = True

            sections_info.append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "raw_size": section.SizeOfRawData,
                "entropy": ent,
                "suspicious": ent > HIGH_ENTROPY_THRESHOLD
            })

        features["sections"] = sections_info
        features["num_sections"] = len(sections_info)
        features["is_packed"] = has_high_entropy_section

        # ── Imports ───────────────────────────────────────────────────────────
        # WHY: The Import Address Table (IAT) tells us EXACTLY which Windows
        #      API functions the program uses. This is gold for malware analysis:
        #      - CreateRemoteThread → process injection
        #      - CryptEncrypt       → ransomware
        #      - SetWindowsHookEx   → keylogger
        imports_by_dll = {}
        suspicious_found = {}
        total_imports = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace')
                api_names = []

                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', errors='replace')
                        api_names.append(api_name)
                        total_imports += 1

                        # Check against our suspicious API list
                        for category, apis in SUSPICIOUS_APIS.items():
                            if any(api_name.startswith(sus) for sus in apis):
                                if category not in suspicious_found:
                                    suspicious_found[category] = []
                                suspicious_found[category].append(api_name)

                imports_by_dll[dll_name] = api_names

        features["imports"] = imports_by_dll
        features["suspicious_imports"] = suspicious_found
        features["num_imports_total"] = total_imports

        pe.close()

    except pefile.PEFormatError as e:
        features["error"] = f"PE parse error: {e}"
    except Exception as e:
        features["error"] = f"Unexpected error: {e}"

    return features


def summarize_for_prompt(features: dict) -> str:
    """
    Convert the full features dict into a compact, readable text
    that we can paste into an LLM prompt.

    WHY summarize?
        GPT-4 has a token limit. Sending ALL imports from ALL DLLs
        would waste tokens on boring things like kernel32.dll!GetModuleHandleA.
        We focus on the INTERESTING parts — suspicious APIs, high entropy,
        unusual sections.
    """
    lines = []
    lines.append(f"File: {features.get('file_name', 'unknown')}")
    lines.append(f"Size: {features.get('file_size_kb')} KB")
    lines.append(f"Architecture: {features.get('machine_type')}")
    lines.append(f"Compile timestamp: {features.get('timestamp')}")
    lines.append(f"Entry point: {features.get('entry_point')}")
    lines.append(f"SHA256: {features.get('sha256', '')[:16]}...")
    lines.append(f"Is likely packed/encrypted: {features.get('is_packed')}")
    lines.append(f"Overall entropy: {features.get('overall_entropy')}")
    lines.append("")

    # Sections
    lines.append(f"Sections ({features.get('num_sections')}):")
    for sec in features.get("sections", []):
        flag = " ⚠ HIGH ENTROPY" if sec.get("suspicious") else ""
        lines.append(f"  {sec['name']:<12} entropy={sec['entropy']}{flag}")
    lines.append("")

    # Suspicious imports only
    sus = features.get("suspicious_imports", {})
    if sus:
        lines.append("Suspicious API calls found:")
        for category, apis in sus.items():
            lines.append(f"  [{category.upper()}] {', '.join(apis)}")
    else:
        lines.append("No suspicious API calls detected in imports.")
    lines.append("")

    # Total imports count
    lines.append(f"Total imported functions: {features.get('num_imports_total')}")

    return "\n".join(lines)