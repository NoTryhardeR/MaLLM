from config import MALWARE_CATEGORIES, BEHAVIOR_LABELS

# ── System prompt (sent as the "system" role to GPT) ─────────────────────────
# WHY a system prompt?
# The system prompt sets the LLM's "persona" and constraints for the whole
# conversation. It's more effective than repeating instructions in every message.
SYSTEM_PROMPT = """You are an expert malware analyst and reverse engineer with 15 years of experience in Windows binary analysis, threat intelligence, and incident response.

Your task is to analyze static features extracted from Windows PE (Portable Executable) files and determine whether they exhibit malicious behavior.

Rules:
- Be precise and technical
- Base your analysis ONLY on the provided evidence
- Do not speculate beyond what the data shows
- When classifying, always return valid JSON in the exact format requested
- Treat high entropy + process injection APIs as strong malware indicators
"""


def build_understanding_prompt(pe_summary: str, strings_summary: str, asm_text: str) -> str:
    """
    Prompt Type 1: Deep behavioral understanding.

    WHY this structure?
        We provide evidence in order of reliability:
        1. PE features (objective, hard data)
        2. Strings (objective but needs interpretation)
        3. Disassembly (most detailed, most telling)

        Then we ask specific questions to guide the model.
        Asking for "step by step" analysis forces the model to reason
        through the evidence rather than jump to a conclusion.
    """
    return f"""You are analyzing a Windows PE executable. Below are the static analysis results.

══════════════════════════════════════════
 SECTION 1: PE STATIC FEATURES
══════════════════════════════════════════
{pe_summary}

══════════════════════════════════════════
 SECTION 2: EXTRACTED STRINGS
══════════════════════════════════════════
{strings_summary}

══════════════════════════════════════════
 SECTION 3: DISASSEMBLY (key functions)
══════════════════════════════════════════
{asm_text}

══════════════════════════════════════════
 ANALYSIS QUESTIONS
══════════════════════════════════════════
Please answer the following:

1. BEHAVIOR SUMMARY
   What does this program appear to do? Describe the main functionality step by step.

2. SUSPICIOUS INDICATORS
   List each suspicious indicator found (APIs, strings, entropy) and explain WHY it is suspicious.

3. ATTACK TECHNIQUES
   Map observed behaviors to MITRE ATT&CK techniques if applicable (e.g., T1055 Process Injection).

4. RISK ASSESSMENT
   Rate the overall risk: LOW / MEDIUM / HIGH / CRITICAL
   Justify your rating with specific evidence from the data above.

5. ANALYST NOTES
   Any additional observations (e.g., possible false positives, missing context).
"""


def build_classification_prompt(pe_summary: str, strings_summary: str, asm_text: str) -> str:
    """
    Prompt Type 2: Structured classification for evaluation.

    WHY JSON output?
        For the evaluation phase (Chapter 6), we need MACHINE-READABLE output.
        We can't compute Precision/Recall on free-form text — we need:
        - A single category label (e.g., "ransomware")
        - A confidence score (0-100)
        - A list of detected behaviors

        Asking GPT to respond in JSON + providing the exact schema
        dramatically improves parsing reliability.
    """
    categories_list = "\n".join(f"  - {c}" for c in MALWARE_CATEGORIES)
    behaviors_list = "\n".join(f"  - {b}" for b in BEHAVIOR_LABELS)

    return f"""You are classifying a Windows PE executable based on static analysis evidence.

══════════════════════════════════════════
 STATIC ANALYSIS EVIDENCE
══════════════════════════════════════════

[PE FEATURES]
{pe_summary}

[SUSPICIOUS STRINGS]
{strings_summary}

[DISASSEMBLY]
{asm_text}

══════════════════════════════════════════
 CLASSIFICATION TASK
══════════════════════════════════════════

Based on the evidence above, classify this executable.

Available categories:
{categories_list}

Available behavior labels (select ALL that apply):
{behaviors_list}

Respond ONLY with a JSON object in this EXACT format (no markdown, no extra text):
{{
  "category": "<one category from the list above>",
  "confidence": <integer 0-100>,
  "behaviors": ["<behavior1>", "<behavior2>"],
  "key_indicators": ["<indicator1>", "<indicator2>", "<indicator3>"],
  "explanation": "<one concise sentence explaining your classification>",
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>"
}}
"""


def build_prompt(prompt_type: str, pe_summary: str,
                 strings_summary: str, asm_text: str) -> tuple[str, str]:
    """
    Factory function — returns (system_prompt, user_prompt) tuple.

    WHY return a tuple?
        The OpenAI API separates system and user messages.
        Keeping them together here makes the client code cleaner.
    """
    if prompt_type == "classification":
        user_prompt = build_classification_prompt(pe_summary, strings_summary, asm_text)
    else:
        user_prompt = build_understanding_prompt(pe_summary, strings_summary, asm_text)

    return SYSTEM_PROMPT, user_prompt
