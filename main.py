"""
main.py — MalLLM Pipeline Orchestrator
=======================================
This is the ENTRY POINT of the entire system.

It orchestrates all modules in sequence:
    1. Load sample (PE file)
    2. Static feature extraction  (Analyzer/pe_extractor.py)
    3. String extraction           (Analyzer/string_extractor.py)
    4. Disassembly parsing         (Analyzer/disasm_parser.py)
    5. Prompt construction         (llm/prompt_builder.py)
    6. LLM query                   (llm/openai_client.py)
    7. Result storage              (results/<sample>.json)
    8. Evaluation (batch mode)     (evaluation/metrics.py)

WHY orchestration in main.py instead of a class?
    For a thesis prototype, a clear linear script is MORE readable than
    an elaborate class hierarchy. The professor can follow it line by line.
    Complexity should live in the modules, not in glue code.

USAGE:
    # Analyze a single file:
    python main.py --file samples/mystery.exe

    # Analyze a single file + disassembly:
    python main.py --file samples/mystery.exe --asm samples/mystery.asm

    # Batch mode (evaluate all samples with ground truth):
    python main.py --batch --labels samples/labels.json

    # Demo mode (no real .exe needed):
    python main.py --demo
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# ── Project imports ───────────────────────────────────────────────────────────
from config import RESULTS_DIR, SAMPLES_DIR
from utils  import info, success, warn, error, section

from analyzer.pe_extractor   import extract_pe_features
from analyzer.pe_extractor   import summarize_for_prompt as pe_summary_fn
from analyzer.string_extractor import extract_strings
from analyzer.string_extractor import summarize_for_prompt as str_summary_fn
from analyzer.string_extractor import get_statistics as str_stats_fn
from analyzer.disasm_parser  import (parse_asm_file,
                                     get_suspicious_functions_text,
                                     create_mock_disassembly)
from llm.prompt_builder      import build_prompt
from llm.openai_client       import query_llm
from Evaluation.metrics      import compute_metrics, print_report, save_evaluation_report


# ─────────────────────────────────────────────────────────────────────────────
def analyze_sample(file_path: str,
                   asm_path: Optional[str] = None,
                   prompt_type: str = "classification",
                   true_label: Optional[str] = None,
                   use_mock_asm: bool = False) -> dict:
    """
    Run the complete analysis pipeline on ONE sample.

    Args:
        file_path   : Path to .exe file
        asm_path    : Path to disassembly text file (optional)
        prompt_type : "classification" or "understanding"
        true_label  : Ground truth label for evaluation ("benign"/"malware")
        use_mock_asm: Use generated mock disassembly (for demo/testing)

    Returns:
        Complete result dict suitable for JSON storage
    """
    file_name = Path(file_path).name
    section(f"Analyzing: {file_name}")

    result = {
        "file_name"   : file_name,
        "file_path"   : file_path,
        "true_label"  : true_label,
        "analyzed_at" : datetime.now().isoformat(),
        "prompt_type" : prompt_type,
        "pe_features" : {},
        "string_stats": {},
        "llm_response": {},
        "prediction"  : {},
    }

    # ── STAGE 1: PE Feature Extraction ───────────────────────────────────────
    info("Stage 1/4 — Extracting PE features...")
    pe_features = extract_pe_features(file_path)
    result["pe_features"] = pe_features

    if "error" in pe_features and not pe_features.get("is_pe"):
        warn(f"PE parsing issue: {pe_features.get('error')}")
        # Continue anyway — strings and disassembly still work

    pe_text = pe_summary_fn(pe_features)
    success("PE features extracted.")

    # ── STAGE 2: String Extraction ────────────────────────────────────────────
    info("Stage 2/4 — Extracting strings...")
    strings = extract_strings(file_path)
    result["string_stats"] = str_stats_fn(strings)
    strings_text = str_summary_fn(strings)
    success(f"Strings extracted: {len(strings)} total, "
            f"{result['string_stats'].get('suspicious', 0)} suspicious.")

    # ── STAGE 3: Disassembly ──────────────────────────────────────────────────
    info("Stage 3/4 — Loading disassembly...")

    if use_mock_asm:
        # For demo/testing without Ghidra
        asm_text = create_mock_disassembly("dropper")
        warn("Using MOCK disassembly (demo mode).")
    elif asm_path and Path(asm_path).exists():
        parsed_asm = parse_asm_file(asm_path)
        asm_text   = get_suspicious_functions_text(parsed_asm)
        success(f"Disassembly loaded: {parsed_asm.get('total_functions')} functions, "
                f"{len(parsed_asm.get('suspicious_functions', []))} suspicious.")
    else:
        warn("No disassembly file provided. Skipping Stage 3.")
        asm_text = "No disassembly available for this sample."

    # ── STAGE 4: LLM Analysis ─────────────────────────────────────────────────
    info(f"Stage 4/4 — Sending to LLM ({prompt_type} prompt)...")
    system_prompt, user_prompt = build_prompt(
        prompt_type, pe_text, strings_text, asm_text
    )

    llm_result = query_llm(system_prompt, user_prompt, prompt_type)
    result["llm_response"] = {
        "raw_text"   : llm_result["raw_text"],
        "tokens_used": llm_result["tokens_used"],
        "model"      : llm_result["model"],
        "error"      : llm_result.get("error"),
    }

    if llm_result.get("parsed"):
        result["prediction"] = llm_result["parsed"]
    else:
        # For "understanding" prompts, create a minimal prediction dict
        result["prediction"] = {
            "category"   : "unknown",
            "confidence" : 0,
            "explanation": llm_result["raw_text"][:300],
        }

    # ── Print summary ─────────────────────────────────────────────────────────
    pred = result["prediction"]
    print(f"\n  ┌─ RESULT ───────────────────────────────")
    print(f"  │  Category   : {pred.get('category', 'unknown').upper()}")
    print(f"  │  Confidence : {pred.get('confidence', '?')}%")
    print(f"  │  Risk       : {pred.get('risk_level', '?')}")
    print(f"  │  Behaviors  : {', '.join(pred.get('behaviors', []))}")
    print(f"  │  Explanation: {pred.get('explanation', '')[:80]}...")
    if true_label:
        from Evaluation.metrics import binary_label
        match = binary_label(pred.get('category','')) == binary_label(true_label)
        icon  = "✓ CORRECT" if match else "✗ WRONG"
        print(f"  │  True label : {true_label}  →  {icon}")
    print(f"  └────────────────────────────────────────\n")

    return result


def save_result(result: dict) -> str:
    """Save analysis result as JSON. Returns the output file path."""
    safe_name = result["file_name"].replace(".", "_").replace(" ", "_")
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = RESULTS_DIR / f"{safe_name}_{ts}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    success(f"Result saved → {out_path}")
    return str(out_path)


# ─────────────────────────────────────────────────────────────────────────────
def run_demo():
    """
    Demo mode: analyze a FAKE sample to test the full pipeline.

    WHY demo mode?
        You may not have real PE files during development.
        Demo mode creates a synthetic sample and runs the full pipeline,
        so you can verify everything works end-to-end.
    """
    section("DEMO MODE — Synthetic Malware Sample")
    warn("No real .exe used. Using synthetic features for demonstration.")

    # Create a fake .exe-like file (just some bytes with MZ header)
    demo_path = SAMPLES_DIR / "demo_sample.bin"
    with open(demo_path, "wb") as f:
        # MZ header + some fake data
        f.write(b'MZ' + b'\x90' * 100 + b'http://evil-c2.ru/bot.php' +
                b'\x00' * 50 + b'VirtualAllocEx' + b'\x00' * 20 +
                b'WriteProcessMemory' + b'\x00' * 10 +
                b'cmd.exe /c powershell -enc aGVsbG8=' + b'\x00' * 200)

    result = analyze_sample(
        file_path   = str(demo_path),
        use_mock_asm= True,
        prompt_type = "classification",
        true_label  = "malware"
    )
    save_result(result)

    section("Demo Complete")
    info("The full pipeline ran successfully in demo mode.")
    info("For real analysis, provide a .exe file with: python main.py --file sample.exe")


# ─────────────────────────────────────────────────────────────────────────────
def run_batch(labels_file: str):
    """
    Batch mode: analyze multiple samples and compute evaluation metrics.

    The labels file is a JSON like:
    {
      "samples/mimic.exe"     : "malware",
      "samples/notepad.exe"   : "benign",
      "samples/keylogger.exe" : "malware"
    }
    """
    section("BATCH EVALUATION MODE")

    labels_path = Path(labels_file)
    if not labels_path.exists():
        error(f"Labels file not found: {labels_file}")
        sys.exit(1)

    with open(labels_path) as f:
        sample_labels = json.load(f)

    info(f"Found {len(sample_labels)} samples to analyze.")
    all_results = []

    for file_path, true_label in sample_labels.items():
        asm_path = file_path.replace(".exe", ".asm")
        asm_path = asm_path if Path(asm_path).exists() else None

        result = analyze_sample(
            file_path   = file_path,
            asm_path    = asm_path,
            prompt_type = "classification",
            true_label  = true_label,
        )
        save_result(result)
        all_results.append(result)

    # ── Compute and print evaluation metrics ──────────────────────────────────
    section("COMPUTING EVALUATION METRICS")
    metrics = compute_metrics(all_results)
    print_report(metrics)

    eval_path = RESULTS_DIR / f"evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_evaluation_report(metrics, str(eval_path))


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MalLLM — LLM-Based Malware Analysis Tool"
    )
    parser.add_argument("--file",   type=str, help="Path to .exe file to analyze")
    parser.add_argument("--asm",    type=str, help="Path to disassembly .asm file")
    parser.add_argument("--type",   type=str, default="classification",
                        choices=["classification", "understanding"],
                        help="Prompt type (default: classification)")
    parser.add_argument("--label",  type=str, help="True label for evaluation (benign/malware)")
    parser.add_argument("--batch",  action="store_true", help="Batch evaluation mode")
    parser.add_argument("--labels", type=str, help="JSON file with sample→label mapping")
    parser.add_argument("--demo",   action="store_true", help="Run demo mode (no real .exe needed)")

    args = parser.parse_args()

    if args.demo:
        run_demo()

    elif args.batch:
        if not args.labels:
            error("--batch requires --labels <path_to_labels.json>")
            sys.exit(1)
        run_batch(args.labels)

    elif args.file:
        result = analyze_sample(
            file_path   = args.file,
            asm_path    = args.asm,
            prompt_type = args.type,
            true_label  = args.label,
        )
        save_result(result)

    else:
        parser.print_help()
        print("\nQuick start:")
        print("  python main.py --demo                          # Test without real .exe")
        print("  python main.py --file sample.exe               # Analyze one file")
        print("  python main.py --file s.exe --asm s.asm        # With disassembly")
        print("  python main.py --batch --labels labels.json    # Evaluate multiple")
