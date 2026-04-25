import json
import time
from typing import Optional

from config import (
    OPENAI_API_KEY, OPENAI_MODEL,
    MAX_TOKENS, TEMPERATURE
)
from utils import info, warn, error, success

try:
    from openai import OpenAI

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


def query_llm(system_prompt: str, user_prompt: str,
              prompt_type: str = "understanding",
              retries: int = 3) -> dict:
    """
    Send a prompt to OpenAI GPT and return the parsed response.

    Args:
        system_prompt : The system-role message (LLM persona & rules)
        user_prompt   : The user-role message (actual analysis request)
        prompt_type   : "understanding" or "classification"
        retries       : How many times to retry on API error

    Returns:
        dict with keys:
          - raw_text      : full LLM response as string
          - parsed        : dict (for classification) or None
          - tokens_used   : total tokens consumed
          - model         : model name used
          - error         : error message if failed, else None

    WHY return a dict instead of just the text?
        We always want metadata (tokens used, model name) alongside the
        response — this is important for the thesis to report cost/usage.
    """
    if not OPENAI_AVAILABLE:
        return _mock_response(prompt_type)

    if not OPENAI_API_KEY:
        warn("No OPENAI_API_KEY set. Running in MOCK mode.")
        return _mock_response(prompt_type)

    client = OpenAI(api_key=OPENAI_API_KEY)

    for attempt in range(1, retries + 1):
        try:
            info(f"Sending prompt to {OPENAI_MODEL} (attempt {attempt}/{retries})...")

            response = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                # WHY temperature=0.2?
                # For classification/security analysis we want DETERMINISTIC
                # responses. Temperature=0 is fully deterministic, 0.2 adds
                # tiny variation to avoid repetitive phrasings.
            )

            raw_text = response.choices[0].message.content
            tokens_used = response.usage.total_tokens

            success(f"LLM responded. Tokens used: {tokens_used}")

            # For classification prompts, try to parse JSON
            parsed = None
            if prompt_type == "classification":
                parsed = _parse_classification_json(raw_text)

            return {
                "raw_text": raw_text,
                "parsed": parsed,
                "tokens_used": tokens_used,
                "model": OPENAI_MODEL,
                "error": None,
            }

        except Exception as e:
            err_msg = str(e)
            if attempt < retries:
                wait = 2 ** attempt  # Exponential backoff: 2s, 4s, 8s
                warn(f"API error: {err_msg}. Retrying in {wait}s...")
                time.sleep(wait)
            else:
                error(f"All {retries} attempts failed: {err_msg}")
                return {
                    "raw_text": "",
                    "parsed": None,
                    "tokens_used": 0,
                    "model": OPENAI_MODEL,
                    "error": err_msg,
                }


def _parse_classification_json(text: str) -> Optional[dict]:
    """
    Safely parse the JSON response from a classification prompt.

    WHY "safely"?
        GPT sometimes wraps JSON in markdown code blocks (```json ... ```).
        We strip those before parsing.
        We also validate that all required fields are present.
    """
    # Strip markdown fences
    clean = text.strip()
    if clean.startswith("```"):
        lines = clean.split("\n")
        clean = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        )

    try:
        data = json.loads(clean)

        # Validate required fields
        required = {"category", "confidence", "behaviors", "explanation", "risk_level"}
        missing = required - set(data.keys())
        if missing:
            warn(f"Classification JSON missing fields: {missing}")

        # Normalize types
        data["confidence"] = int(data.get("confidence", 50))
        data["behaviors"] = list(data.get("behaviors", []))

        return data

    except json.JSONDecodeError as e:
        warn(f"Could not parse classification JSON: {e}")
        warn(f"Raw text was: {text[:200]}...")
        # Fallback: extract category from text
        return _fallback_parse(text)


def _fallback_parse(text: str) -> dict:
    """
    If JSON parsing fails, do a best-effort extraction from the text.
    WHY: Better to return SOMETHING than crash the whole pipeline.
    """
    import re
    text_lower = text.lower()

    # Try to find a category
    from config import MALWARE_CATEGORIES
    found_category = "unknown"
    for cat in MALWARE_CATEGORIES:
        if cat.lower() in text_lower:
            found_category = cat
            break

    # Try to find a confidence number
    conf_match = re.search(r'(\d{1,3})\s*%', text)
    confidence = int(conf_match.group(1)) if conf_match else 50

    return {
        "category": found_category,
        "confidence": confidence,
        "behaviors": [],
        "key_indicators": [],
        "explanation": text[:200],
        "risk_level": "UNKNOWN",
        "parse_fallback": True,  # Flag that this was a fallback parse
    }


def _mock_response(prompt_type: str) -> dict:
    """
    Return a realistic mock response when no API key is set.

    WHY: During development and demo, you might not want to spend API tokens.
         The mock response allows testing the full pipeline end-to-end.
    """
    warn("Running in MOCK mode (no API key). Returning simulated response.")

    if prompt_type == "classification":
        mock_parsed = {
            "category": "dropper",
            "confidence": 87,
            "behaviors": ["process_injection", "persistence", "network_communication"],
            "key_indicators": [
                "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (classic injection triad)",
                "High entropy section (.text: 7.82) suggests packing",
                "C2 URL found in strings: http://185.220.101.45/drop.php"
            ],
            "explanation": "This executable performs process injection using the VirtualAllocEx/WriteProcessMemory/CreateRemoteThread triad and communicates with a known C2 IP.",
            "risk_level": "CRITICAL",
        }
        raw = json.dumps(mock_parsed, indent=2)
    else:
        raw = """
BEHAVIOR SUMMARY:
This executable implements a multi-stage dropper. It allocates executable memory
in a remote process using VirtualAllocEx, copies shellcode with WriteProcessMemory,
and executes it via CreateRemoteThread — the classic process injection triad.

SUSPICIOUS INDICATORS:
• VirtualAllocEx (PAGE_EXECUTE_READWRITE) → allocates writable+executable memory
• WriteProcessMemory → injects code into another process
• CreateRemoteThread → executes injected payload
• High section entropy (7.82) → binary is packed or contains encrypted payload
• C2 URL: http://185.220.101.45/drop.php → command-and-control communication

ATTACK TECHNIQUES (MITRE ATT&CK):
• T1055   — Process Injection
• T1027   — Obfuscated Files or Information (packing)
• T1071.001 — Web Protocols (C2 over HTTP)

RISK ASSESSMENT: CRITICAL
Evidence: Process injection + encrypted payload + active C2 communication
is a complete malware delivery chain.

ANALYST NOTES:
The compile timestamp (2024-01-15) is recent and may be legitimate.
However, the combination of injection APIs and C2 URL is definitive.
"""
        mock_parsed = None

    return {
        "raw_text": raw.strip(),
        "parsed": mock_parsed,
        "tokens_used": 0,
        "model": "MOCK",
        "error": None,
    }