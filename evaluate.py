import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
 
sys.path.insert(0, str(Path(__file__).parent))
 
from metrics import (
    compute_metrics,
    compute_multiclass_metrics,
    print_report,
    print_multiclass_report,
    save_evaluation_report,
    generate_thesis_summary,
)
from utils import info, success, warn, error, section
 
 
# ─────────────────────────────────────────────────────────────────────────────
def load_real_results(results_dir: str) -> list[dict]:
    """
    Φορτώνει ΠΡΑΓΜΑΤΙΚΑ JSON αποτελέσματα από τον φάκελο results/.
 
    Κάθε JSON αρχείο δημιουργήθηκε από:
        - main.py → save_result()          (ανά .exe ανάλυση)
        - dataset_loader.py → run_batch_analysis()  (ανά CSV sample)
 
    Δομή κάθε JSON:
    {
        "file_name"  : "sample.exe",
        "true_label" : "malware",       ← το πραγματικό label
        "prediction" : {
            "category"   : "dropper",   ← αυτό είπε το LLM
            "confidence" : 91,
            ...
        },
        "analyzed_at": "2026-04-19T..."
    }
 
    ΓΙΑΤΙ φορτώνουμε από JSON και όχι από μνήμη;
        Η ανάλυση (LLM calls) και η αξιολόγηση (metrics) είναι
        ανεξάρτητες διεργασίες. Μπορείς να τρέξεις ξανά το
        evaluation αλλάζοντας τον τρόπο υπολογισμού, χωρίς να
        ξαναπληρώσεις API calls.
    """
    path = Path(results_dir)
 
    if not path.exists():
        error(f"Φάκελος '{results_dir}' δεν βρέθηκε.")
        error("Τρέξε πρώτα: python main.py --demo")
        error("ή:          python dataset_loader.py --csv MalwareData.csv --sample 50")
        return []
 
    # Φορτώνουμε ΜΟΝΟ αρχεία ανάλυσης — εξαιρούμε evaluation reports
    # που αρχίζουν με "evaluation_" ή "chapter6_"
    exclude_prefixes = ("evaluation_", "chapter6_")
    json_files = sorted([
        f for f in path.glob("*.json")
        if not any(f.name.startswith(p) for p in exclude_prefixes)
    ])
 
    if not json_files:
        warn(f"Δεν βρέθηκαν αρχεία ανάλυσης στο '{results_dir}'.")
        warn("Τρέξε πρώτα: python main.py --file sample.exe --label malware")
        warn("ή:          python dataset_loader.py --csv MalwareData.csv --sample 50")
        return []
 
    info(f"Φόρτωση {len(json_files)} αρχείων από '{results_dir}'...")
 
    results = []
    skipped = 0
 
    for f in json_files:
        try:
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
 
            # Έλεγχος ότι το αρχείο έχει τα απαραίτητα πεδία
            has_true_label  = bool(data.get("true_label", "").strip())
            has_prediction  = bool(data.get("prediction", {}).get("category", ""))
 
            if not has_true_label:
                warn(f"  Παράλειψη {f.name} — λείπει true_label")
                warn(f"  (Χρησιμοποίησε --label malware/benign στο main.py)")
                skipped += 1
                continue
 
            if not has_prediction:
                warn(f"  Παράλειψη {f.name} — λείπει prediction.category")
                skipped += 1
                continue
 
            results.append(data)
 
        except json.JSONDecodeError as e:
            warn(f"  Σφάλμα ανάγνωσης {f.name}: {e}")
            skipped += 1
 
    success(f"Φορτώθηκαν {len(results)} έγκυρα αποτελέσματα"
            + (f" ({skipped} παραλείφθηκαν)" if skipped else ""))
 
    # Εκτύπωση σύντομης επισκόπησης
    if results:
        malware_n = sum(1 for r in results if r["true_label"] != "benign")
        benign_n  = len(results) - malware_n
        sources   = set(r.get("source", "exe") for r in results)
        info(f"  Malware: {malware_n} | Benign: {benign_n} | "
             f"Πηγή: {', '.join(sources)}")
 
    return results
 
 
# ─────────────────────────────────────────────────────────────────────────────
def run_unit_test_metrics():
    """
    Ελέγχει ότι το evaluation/metrics.py λειτουργεί σωστά.
 
    ΓΙΑΤΙ αυτό υπάρχει;
        Πριν εκτελέσεις evaluation σε πραγματικά δεδομένα, θέλεις
        να ξέρεις ότι οι τύποι είναι σωστοί. Αυτό είναι unit test —
        επαληθεύει τη ΛΟΓΙΚΗ του κώδικα, όχι την ποιότητα του LLM.
 
        Παράδειγμα: αν TP=5, FP=1, FN=1, TN=3:
            Precision = 5/(5+1) = 83.3%  ← ξέρουμε ΑΠΟ ΜΑΘΗΜΑΤΙΚΑ ότι αυτό είναι σωστό
            Recall    = 5/(5+1) = 83.3%
            F1        = 83.3%
        Επαληθεύουμε ότι ο κώδικας βγάζει αυτά τα νούμερα.
 
    ΣΗΜΑΝΤΙΚΟ: Αυτά τα δεδομένα ΔΕΝ χρησιμοποιούνται για
               αξιολόγηση του LLM — μόνο για έλεγχο του κώδικα.
    """
    section("UNIT TEST — Έλεγχος ορθότητας metrics module")
    warn("Αυτά είναι ΣΥΝΘΕΤΙΚΑ δεδομένα για έλεγχο κώδικα.")
    warn("ΔΕΝ αντιπροσωπεύουν απόδοση του LLM.")
    print()
 
    # Γνωστά αποτελέσματα με προκαθορισμένη σωστή απάντηση
    # TP=5, TN=3, FP=1, FN=1 → Precision=83.3%, Recall=83.3%, F1=83.3%
    test_data = [
        {"file_name": "test_tp1.exe", "true_label": "malware",
         "prediction": {"category": "dropper",   "confidence": 91}},
        {"file_name": "test_tp2.exe", "true_label": "malware",
         "prediction": {"category": "keylogger", "confidence": 88}},
        {"file_name": "test_tp3.exe", "true_label": "malware",
         "prediction": {"category": "ransomware","confidence": 96}},
        {"file_name": "test_tp4.exe", "true_label": "malware",
         "prediction": {"category": "trojan",    "confidence": 83}},
        {"file_name": "test_tp5.exe", "true_label": "malware",
         "prediction": {"category": "rootkit",   "confidence": 79}},
        {"file_name": "test_tn1.exe", "true_label": "benign",
         "prediction": {"category": "benign",    "confidence": 95}},
        {"file_name": "test_tn2.exe", "true_label": "benign",
         "prediction": {"category": "benign",    "confidence": 92}},
        {"file_name": "test_tn3.exe", "true_label": "benign",
         "prediction": {"category": "benign",    "confidence": 88}},
        {"file_name": "test_fn.exe",  "true_label": "malware",  # FN
         "prediction": {"category": "benign",    "confidence": 52}},
        {"file_name": "test_fp.exe",  "true_label": "benign",   # FP
         "prediction": {"category": "dropper",   "confidence": 68}},
    ]
 
    metrics = compute_metrics(test_data)
 
    # Επαλήθευση αναμενόμενων τιμών
    expected = {"accuracy": 80.0, "precision": 83.33, "recall": 83.33, "f1_score": 83.33}
    all_ok = True
 
    print("  Αναμενόμενες τιμές vs Υπολογισμένες:")
    for key, exp_val in expected.items():
        got_val = metrics[key]
        ok = abs(got_val - exp_val) < 0.1
        icon = "✓" if ok else "✗"
        if not ok:
            all_ok = False
        print(f"  {icon} {key:<12}: expected={exp_val}%  got={got_val}%")
 
    print()
    if all_ok:
        success("Όλοι οι υπολογισμοί είναι ΣΩΣΤΟΙ — το module λειτουργεί.")
        success("Μπορείς τώρα να τρέξεις με πραγματικά δεδομένα.")
    else:
        error("Βρέθηκε σφάλμα στους υπολογισμούς — έλεγξε το evaluation/metrics.py")
 
 
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="MalLLM Evaluation — Chapter 6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Παραδείγματα:
  # Πλήρες evaluation από πραγματικά αποτελέσματα:
  python evaluate.py --results results/ --save --thesis
 
  # Έλεγχος ότι ο κώδικας λειτουργεί (χωρίς LLM):
  python evaluate.py --test-metrics
        """
    )
 
    parser.add_argument(
        "--results",
        type=str,
        default="results/",
        help="Φάκελος με JSON αποτελέσματα από main.py / dataset_loader.py"
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Αποθήκευση evaluation report σε JSON"
    )
    parser.add_argument(
        "--thesis",
        action="store_true",
        help="Παραγωγή Chapter 6 draft text"
    )
    parser.add_argument(
        "--test-metrics",
        action="store_true",
        dest="test_metrics",
        help="Unit test: ελέγχει ότι οι υπολογισμοί metrics είναι σωστοί"
    )
 
    args = parser.parse_args()
 
    # ── Unit test mode ────────────────────────────────────────────────────────
    if args.test_metrics:
        run_unit_test_metrics()
        return
 
    # ── Κανονική λειτουργία: πραγματικά δεδομένα ─────────────────────────────
    section("EVALUATION — Πραγματικά αποτελέσματα LLM")
    results = load_real_results(args.results)
 
    if not results:
        return
 
    # ── Binary evaluation ─────────────────────────────────────────────────────
    # Πρωτεύουσα ερώτηση: malware ή benign;
    # Αυτά τα νούμερα μπαίνουν στον κεντρικό πίνακα του Chapter 6.
    metrics = compute_metrics(results)
    print_report(metrics)
 
    # ── Multi-class evaluation ────────────────────────────────────────────────
    # Δευτερεύουσα ερώτηση: ποιο ΤΥΠΟ malware είναι;
    # Δείχνει αν το LLM διακρίνει dropper από ransomware.
    print()
    mc_metrics = compute_multiclass_metrics(results)
    print_multiclass_report(mc_metrics)
 
    # ── Thesis draft ──────────────────────────────────────────────────────────
    if args.thesis:
        summary = generate_thesis_summary(metrics, mc_metrics)
        print(summary)
        thesis_path = Path("results/chapter6_draft.txt")
        thesis_path.parent.mkdir(exist_ok=True)
        thesis_path.write_text(summary, encoding="utf-8")
        success(f"Chapter 6 draft → {thesis_path}")
 
    # ── Αποθήκευση ───────────────────────────────────────────────────────────
    if args.save:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_evaluation_report(metrics,
                               f"results/evaluation_binary_{ts}.json")
        save_evaluation_report(mc_metrics,
                               f"results/evaluation_multiclass_{ts}.json")
 
 
if __name__ == "__main__":
    main()