import csv
import json
import random
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional
import sys

sys.path.insert(0, str(Path(__file__).parent))
from utils import info, success, warn, section
from llm.prompt_builder import SYSTEM_PROMPT
from llm.openai_client import query_llm

# ── Ποια features θα στείλουμε στο LLM ──────────────────────────────────────
# ΓΙΑΤΙ επιλέγουμε υποσύνολο;
#   Από τα 55 features, πολλά είναι τεχνικές διευθύνσεις (ImageBase,
#   AddressOfEntryPoint) που το LLM δεν μπορεί να ερμηνεύσει χωρίς
#   περισσότερο context. Επιλέγουμε τα features με τη ΜΕΓΑΛΥΤΕΡΗ
#   διακριτική ικανότητα (βάσει της ανάλυσής μας παραπάνω).

SELECTED_FEATURES = {
    # Entropy — strongest single indicator
    "SectionsMeanEntropy": "Mean section entropy (0-8, >7 = likely packed)",
    "SectionsMinEntropy": "Min section entropy",
    "SectionsMaxEntropy": "Max section entropy (>7.0 = HIGH RISK)",

    # Sections
    "SectionsNb": "Number of PE sections",
    "SectionsMeanRawsize": "Mean section raw size (bytes)",
    "SectionMaxRawsize": "Largest section raw size (bytes)",

    # Imports — API usage
    "ImportsNbDLL": "Number of imported DLLs",
    "ImportsNb": "Total number of imported functions",
    "ImportsNbOrdinal": "Imports by ordinal (obfuscation indicator)",

    # Exports
    "ExportNb": "Number of exported functions",

    # Resources
    "ResourcesNb": "Number of resources",
    "ResourcesMeanEntropy": "Mean resource entropy",
    "ResourcesMaxEntropy": "Max resource entropy",

    # Version / metadata
    "VersionInformationSize": "Size of version information (0 = often malware)",
    "LoadConfigurationSize": "Load configuration size",
}


# ─────────────────────────────────────────────────────────────────────────────
def load_dataset(csv_path: str) -> list[dict]:
    """
    Φόρτωση του MalwareData.csv.

    ΓΙΑΤΙ delimiter='|';
        Το dataset χρησιμοποιεί pipe (|) αντί για κόμμα ως separator.
        Αυτό είναι κοινό σε security datasets γιατί τα filenames
        μπορεί να περιέχουν κόμματα.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    info(f"Φόρτωση dataset: {path.name}")
    rows = []
    with open(path, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='|')
        for row in reader:
            rows.append(row)

    success(f"Φορτώθηκαν {len(rows):,} samples")
    return rows


def get_statistics(rows: list[dict]) -> dict:
    """Βασικά στατιστικά του dataset για το Chapter 3 (Dataset Description)."""
    total = len(rows)
    malware = sum(1 for r in rows if r.get('legitimate', '').strip() == '0')
    legit = sum(1 for r in rows if r.get('legitimate', '').strip() == '1')

    # Entropy stats
    ent_vals_m = []
    ent_vals_l = []
    for r in rows:
        try:
            v = float(r.get('SectionsMaxEntropy', 0) or 0)
            if r['legitimate'].strip() == '0':
                ent_vals_m.append(v)
            else:
                ent_vals_l.append(v)
        except:
            pass

    def avg(lst):
        return round(sum(lst) / len(lst), 3) if lst else 0

    return {
        "total": total,
        "malware": malware,
        "legitimate": legit,
        "malware_pct": round(malware / total * 100, 1),
        "legit_pct": round(legit / total * 100, 1),
        "avg_max_entropy_malware": avg(ent_vals_m),
        "avg_max_entropy_legit": avg(ent_vals_l),
        "high_entropy_malware_pct": round(
            sum(1 for v in ent_vals_m if v > 7.0) / len(ent_vals_m) * 100, 1
        ) if ent_vals_m else 0,
    }


def print_statistics(rows: list[dict]):
    """Εκτύπωση στατιστικών για Chapter 3."""
    stats = get_statistics(rows)
    section("DATASET STATISTICS — Chapter 3")
    print(f"""
  Total samples      : {stats['total']:,}
  Malware    (0)     : {stats['malware']:,}  ({stats['malware_pct']}%)
  Legitimate (1)     : {stats['legitimate']:,}  ({stats['legit_pct']}%)

  Class imbalance    : {stats['malware_pct']}% / {stats['legit_pct']}%
  → Dataset is IMBALANCED. Use F1-Score as primary metric.
  → Consider stratified sampling for evaluation.

  Avg max entropy (malware) : {stats['avg_max_entropy_malware']}
  Avg max entropy (legit)   : {stats['avg_max_entropy_legit']}
  Malware with entropy>7.0  : {stats['high_entropy_malware_pct']}%
  → Entropy is the strongest single discriminating feature.
""")


# ─────────────────────────────────────────────────────────────────────────────
def sample_dataset(rows: list[dict],
                   n: int = 100,
                   strategy: str = "balanced") -> list[dict]:
    """
    Επιλογή υποσυνόλου για LLM analysis.

    ΓΙΑΤΙ δεν στέλνουμε όλα τα 138k samples;
        1. Κόστος: κάθε LLM call κοστίζει tokens/χρήμα
        2. Χρόνος: 138k calls × ~2 sec = ~3 ημέρες
        3. Για πτυχιακή: 200-500 samples είναι επαρκή για στατιστικά valid αποτελέσματα

    Strategies:
        "balanced"    → ίσος αριθμός malware και legit (καλύτερο για F1)
        "proportional"→ διατηρεί 70/30 κατανομή (ρεαλιστικό σενάριο)
        "random"      → τυχαία επιλογή

    ΓΙΑΤΙ "balanced" είναι προτεινόμενο;
        Με imbalanced dataset (70/30), ένα naive μοντέλο που λέει
        πάντα "malware" έχει 70% accuracy. Balanced sampling εξαλείφει
        αυτή τη μεροληψία στην αξιολόγηση.
    """
    malware = [r for r in rows if r.get('legitimate', '').strip() == '0']
    legit = [r for r in rows if r.get('legitimate', '').strip() == '1']

    if strategy == "balanced":
        half = n // 2
        sampled = (random.sample(malware, min(half, len(malware))) +
                   random.sample(legit, min(half, len(legit))))
    elif strategy == "proportional":
        n_mal = int(n * 0.70)
        n_leg = n - n_mal
        sampled = (random.sample(malware, min(n_mal, len(malware))) +
                   random.sample(legit, min(n_leg, len(legit))))
    else:
        sampled = random.sample(rows, min(n, len(rows)))

    random.shuffle(sampled)
    info(f"Επιλέχθηκαν {len(sampled)} samples (strategy={strategy})")
    return sampled


# ─────────────────────────────────────────────────────────────────────────────
def row_to_prompt_text(row: dict) -> str:
    """
    Μετατροπή μιας γραμμής του CSV → κείμενο για το LLM prompt.

    ΓΙΑΤΙ αυτή η μετατροπή;
        Το LLM δεν καταλαβαίνει "SectionsMeanEntropy=7.82".
        Καταλαβαίνει "Mean section entropy: 7.82 — HIGH (>7.0 indicates packing)".
        Προσθέτουμε ερμηνεία σε κάθε τιμή για να βοηθήσουμε το LLM
        να κάνει καλύτερο reasoning.

    ΓΙΑΤΙ δεν στέλνουμε όλα τα 55 features;
        Πολλά features (ImageBase, CheckSum, BaseOfCode) είναι τεχνικές
        διευθύνσεις που δεν βοηθούν στην ταξινόμηση χωρίς τον binary.
        Επιλέγουμε τα 15 πιο discriminative features.
    """
    lines = [f"Sample: {row.get('Name', 'unknown')}"]
    lines.append("")
    lines.append("PE Static Analysis Features:")
    lines.append("─" * 40)

    for col, description in SELECTED_FEATURES.items():
        raw = row.get(col, '').strip()
        if not raw:
            continue
        try:
            val = float(raw)
            # Προσθέτουμε contextual flags για τα πιο σημαντικά features
            flag = ""
            if col == "SectionsMaxEntropy" and val > 7.0:
                flag = " ⚠ HIGH — likely packed/encrypted"
            elif col == "SectionsMaxEntropy" and val > 6.5:
                flag = " — elevated"
            elif col == "ImportsNb" and val == 0:
                flag = " ⚠ ZERO imports — likely packed"
            elif col == "VersionInformationSize" and val == 0:
                flag = " — no version info (common in malware)"
            elif col == "ImportsNbOrdinal" and val > 0:
                flag = " — uses ordinal imports (obfuscation)"

            lines.append(f"  {description:<45} {val:.3f}{flag}")
        except ValueError:
            lines.append(f"  {description:<45} {raw}")

    lines.append("")

    # Entropy assessment
    try:
        max_ent = float(row.get('SectionsMaxEntropy', 0) or 0)
        mean_ent = float(row.get('SectionsMeanEntropy', 0) or 0)
        if max_ent > 7.0:
            lines.append("Entropy Assessment: HIGH — file is likely packed or contains encrypted payload")
        elif max_ent > 6.5:
            lines.append("Entropy Assessment: MODERATE — possible packing or compression")
        else:
            lines.append("Entropy Assessment: NORMAL — no obvious packing indicators")
    except:
        pass

    return "\n".join(lines)


def build_csv_classification_prompt(row: dict) -> tuple[str, str]:
    """
    Χτίζει το classification prompt για ένα CSV sample.

    ΓΙΑΤΙ διαφορετικό prompt από τον pe_extractor;
        Εδώ έχουμε numerical features, όχι raw binary ή assembly.
        Το prompt πρέπει να εξηγεί στο LLM ΤΙ σημαίνουν οι αριθμοί,
        γιατί δεν έχει πρόσβαση στο ίδιο το αρχείο.
    """
    feature_text = row_to_prompt_text(row)

    system = """You are an expert malware analyst specializing in Windows PE (Portable Executable) static analysis.

You will be given numerical features extracted from a PE file using the pefile library.
These features describe the file's structure WITHOUT executing it (safe static analysis).

Your job: classify whether this PE file is malware or legitimate software based ONLY on the provided features.

Key knowledge you should apply:
- Section entropy > 7.0 strongly indicates packing/encryption (malware evasion technique)
- Zero imports often means the file is packed (imports are resolved at runtime)
- Legitimate software typically has version information; many malware samples do not
- More sections than usual (>6) can indicate code injection artifacts
- Ordinal imports are sometimes used to obfuscate API usage
"""

    user = f"""Classify this Windows PE executable as MALWARE or LEGITIMATE based on its static features.

{feature_text}

Respond ONLY with a JSON object in this exact format:
{{
  "category": "malware" or "benign",
  "confidence": <integer 0-100>,
  "key_indicators": ["<indicator1>", "<indicator2>", "<indicator3>"],
  "explanation": "<one concise sentence>",
  "risk_level": "LOW" or "MEDIUM" or "HIGH" or "CRITICAL"
}}"""

    return system, user


# ─────────────────────────────────────────────────────────────────────────────
def analyze_csv_sample(row: dict) -> dict:
    """
    Αναλύει ένα sample από το CSV και επιστρέφει structured result.
    Αυτό ενσωματώνεται στο κύριο pipeline (main.py).
    """
    true_label = "benign" if row.get('legitimate', '').strip() == '1' else "malware"

    system_prompt, user_prompt = build_csv_classification_prompt(row)
    llm_result = query_llm(system_prompt, user_prompt, prompt_type="classification")

    return {
        "file_name": row.get('Name', 'unknown'),
        "md5": row.get('md5', ''),
        "true_label": true_label,
        "analyzed_at": datetime.now().isoformat(),
        "source": "MalwareData.csv",
        "pe_features": {k: row.get(k, '') for k in SELECTED_FEATURES},
        "llm_response": {
            "raw_text": llm_result["raw_text"],
            "tokens_used": llm_result["tokens_used"],
            "model": llm_result["model"],
        },
        "prediction": llm_result.get("parsed") or {
            "category": "unknown", "confidence": 0
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
def run_batch_analysis(csv_path: str,
                       n_samples: int = 100,
                       strategy: str = "balanced",
                       output_dir: str = "results/",
                       seed: int = 42) -> list[dict]:
    """
    Κύρια function για batch analysis από το CSV.

    Args:
        csv_path   : path to MalwareData.csv
        n_samples  : πόσα samples να αναλύσουμε
        strategy   : "balanced", "proportional", ή "random"
        output_dir : πού να αποθηκεύσουμε τα results
        seed       : για reproducibility (ΣΗΜΑΝΤΙΚΟ για thesis!)

    ΓΙΑΤΙ seed;
        Reproducibility είναι απαίτηση επιστημονικής εργασίας.
        Με seed=42 (ή οποιοδήποτε σταθερό αριθμό), τα ίδια
        samples επιλέγονται κάθε φορά. Ο καθηγητής μπορεί
        να επαναλάβει το πείραμα και να πάρει τα ίδια αποτελέσματα.
    """
    random.seed(seed)

    rows = load_dataset(csv_path)
    sample = sample_dataset(rows, n=n_samples, strategy=strategy)

    out_path = Path(output_dir)
    out_path.mkdir(exist_ok=True)

    all_results = []
    section(f"Analyzing {len(sample)} samples from CSV")

    for i, row in enumerate(sample, 1):
        name = row.get('Name', f'sample_{i}')
        true = "benign" if row.get('legitimate', '').strip() == '1' else "malware"
        info(f"[{i:3}/{len(sample)}] {name[:40]:<40} (true={true})")

        result = analyze_csv_sample(row)
        all_results.append(result)

        # Αποθήκευση ατομικού result
        safe = name.replace('/', '_').replace('\\', '_')[:50]
        out_file = out_path / f"{safe}_{i:04d}.json"
        with open(out_file, 'w') as f:
            json.dump(result, f, indent=2)

        pred = result['prediction']
        match = "✓" if (pred.get('category', '') == true or
                        (pred.get('category', '') == 'malware' and true == 'malware') or
                        (pred.get('category', '') == 'benign' and true == 'benign')) else "✗"
        print(f"         → pred={pred.get('category', '?'):<8} conf={pred.get('confidence', '?')}%  {match}")

    success(f"Ολοκληρώθηκαν {len(all_results)} analyses → {out_path}")
    return all_results


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MalwareData.csv → LLM Analysis Pipeline"
    )
    parser.add_argument("--csv", default="MalwareData.csv",
                        help="Path to MalwareData.csv")
    parser.add_argument("--stats", action="store_true",
                        help="Εμφάνιση στατιστικών dataset")
    parser.add_argument("--sample", type=int, default=100,
                        help="Αριθμός samples για ανάλυση (default: 100)")
    parser.add_argument("--strategy", default="balanced",
                        choices=["balanced", "proportional", "random"],
                        help="Sampling strategy")
    parser.add_argument("--out", default="results/",
                        help="Output directory")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed για reproducibility")
    parser.add_argument("--preview", action="store_true",
                        help="Εμφάνιση prompt για 1 sample (χωρίς LLM call)")
    args = parser.parse_args()

    rows = load_dataset(args.csv)

    if args.stats:
        print_statistics(rows)

    elif args.preview:
        # Δείξε πώς μοιάζει το prompt για ένα malware sample
        mal_sample = next(r for r in rows if r.get('legitimate', '').strip() == '0')
        section("SAMPLE PROMPT PREVIEW (malware)")
        _, user_p = build_csv_classification_prompt(mal_sample)
        print(user_p)

    else:
        results = run_batch_analysis(
            csv_path=args.csv,
            n_samples=args.sample,
            strategy=args.strategy,
            output_dir=args.out,
            seed=args.seed,
        )

        # Αυτόματο evaluation μετά την ανάλυση
        from evaluation.metrics import compute_metrics, print_report

        metrics = compute_metrics(results)
        print_report(metrics)