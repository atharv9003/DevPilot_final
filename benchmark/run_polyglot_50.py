"""
DevPilot 3.0 Polyglot 50-Scenario Empirical Benchmark Runner
Executes all 50 ground-truth polyglot scenarios across Python, JavaScript, TypeScript, Java, and C/C++.
Computes empirical TP, FP, TN, FN, Precision, Recall, F1, FPR, and FNR.
"""
import os
import sys
import json
import time
import tempfile
import pandas as pd
from typing import Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmark.polyglot_benchmark_50 import get_50_polyglot_benchmark_samples, PolyglotBenchmarkSample
from src.analysis.languages.manager import MultiLanguageManager
from src.analysis.ast_scanner import ASTCodeScanner


def get_extension_for_language(lang: str) -> str:
    mapping = {
        "Python": ".py",
        "JavaScript": ".js",
        "TypeScript": ".ts",
        "Java": ".java",
        "C/C++": ".cpp"
    }
    return mapping.get(lang, ".txt")


def run_polyglot_benchmark(output_dir: str = "benchmark/results") -> Dict[str, Any]:
    os.makedirs(output_dir, exist_ok=True)
    samples = get_50_polyglot_benchmark_samples()
    manager = MultiLanguageManager()
    ast_scanner = ASTCodeScanner()

    print(f"================================================================================")
    print(f"DevPilot Polyglot 50-Scenario Benchmark: Running {len(samples)} Scenarios")
    print(f"================================================================================")

    results: List[Dict[str, Any]] = []

    overall_tp = 0
    overall_fp = 0
    overall_tn = 0
    overall_fn = 0

    lang_stats: Dict[str, Dict[str, int]] = {}

    for idx, sample in enumerate(samples, start=1):
        ext = get_extension_for_language(sample.language)
        lang = sample.language

        if lang not in lang_stats:
            lang_stats[lang] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "total": 0}
        lang_stats[lang]["total"] += 1

        with tempfile.TemporaryDirectory(prefix=f"bm_{sample.id}_") as tmpdir:
            fpath = os.path.join(tmpdir, f"sample_{sample.id}{ext}")
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write(sample.code_content)

            start_t = time.time()
            detected_issues = []

            try:
                # For Python, run both the multi-language adapter and the deep AST scanner
                if lang == "Python":
                    adapter = manager.adapters.get("Python")
                    adapter_issues = adapter.scan_file(fpath, repo_root=tmpdir) if adapter else []
                    ast_issues = ast_scanner.scan_file(fpath, repo_root=tmpdir)
                    # Merge issues
                    combined = {iss.id: iss for iss in (adapter_issues + ast_issues)}
                    detected_issues = list(combined.values())
                else:
                    adapter = manager.adapters.get(lang)
                    if adapter:
                        detected_issues = adapter.scan_file(fpath, repo_root=tmpdir)
            except Exception as e:
                print(f"Error scanning {sample.id}: {e}")

            duration_ms = round((time.time() - start_t) * 1000, 2)

            num_issues = len(detected_issues)
            issue_titles = [i.title for i in detected_issues]
            issue_lines = [i.line_number for i in detected_issues]

            # Classification
            if sample.is_vulnerable:
                if num_issues > 0:
                    outcome = "TP"
                    overall_tp += 1
                    lang_stats[lang]["TP"] += 1
                else:
                    outcome = "FN"
                    overall_fn += 1
                    lang_stats[lang]["FN"] += 1
            else:
                # Clean sample
                if num_issues == 0:
                    outcome = "TN"
                    overall_tn += 1
                    lang_stats[lang]["TN"] += 1
                else:
                    outcome = "FP"
                    overall_fp += 1
                    lang_stats[lang]["FP"] += 1

            status_icon = "PASS" if outcome in ("TP", "TN") else "FAIL"
            print(f"[{idx:02d}/50] {sample.id:<7} | {lang:<10} | ExpVuln: {str(sample.is_vulnerable):<5} | Detected: {num_issues:<2} | Outcome: {outcome:<2} [{status_icon}] ({duration_ms}ms)")

            results.append({
                "id": sample.id,
                "language": lang,
                "category": sample.category,
                "title": sample.title,
                "severity": sample.severity,
                "cwe": sample.cwe,
                "expected_line": sample.expected_line,
                "is_vulnerable": sample.is_vulnerable,
                "detected_count": num_issues,
                "detected_titles": "; ".join(issue_titles),
                "detected_lines": str(issue_lines),
                "outcome": outcome,
                "duration_ms": duration_ms
            })

    # Metrics calculation
    def calc_metrics(tp: int, fp: int, tn: int, fn: int):
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        return {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "Accuracy": round(acc * 100, 2),
            "Precision": round(prec * 100, 2),
            "Recall": round(rec * 100, 2),
            "F1_Score": round(f1 * 100, 2),
            "FPR": round(fpr * 100, 2),
            "FNR": round(fnr * 100, 2)
        }

    overall_metrics = calc_metrics(overall_tp, overall_fp, overall_tn, overall_fn)
    per_language_metrics = {}
    for lang, st in lang_stats.items():
        per_language_metrics[lang] = calc_metrics(st["TP"], st["FP"], st["TN"], st["FN"])

    summary = {
        "total_scenarios": len(samples),
        "overall": overall_metrics,
        "per_language": per_language_metrics,
        "details": results
    }

    # Save to disk
    json_path = os.path.join(output_dir, "polyglot_50_benchmark_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    csv_path = os.path.join(output_dir, "polyglot_50_benchmark_results.csv")
    pd.DataFrame(results).to_csv(csv_path, index=False)

    print("\n================================================================================")
    print("BENCHMARK EXECUTION SUMMARY")
    print("================================================================================")
    print(f"Total Scenarios Evaluated: {len(samples)}")
    print(f"Overall TP: {overall_tp} | TN: {overall_tn} | FP: {overall_fp} | FN: {overall_fn}")
    print(f"Accuracy:   {overall_metrics['Accuracy']}%")
    print(f"Precision:  {overall_metrics['Precision']}%")
    print(f"Recall:     {overall_metrics['Recall']}%")
    print(f"F1-Score:   {overall_metrics['F1_Score']}%")
    print(f"FPR:        {overall_metrics['FPR']}%")
    print(f"FNR:        {overall_metrics['FNR']}%")
    print("================================================================================")
    print("\nPer-Language Breakdown:")
    for lang, m in per_language_metrics.items():
        print(f" - {lang:<11}: P={m['Precision']:>5}% | R={m['Recall']:>5}% | F1={m['F1_Score']:>5}% | TP={m['TP']}, TN={m['TN']}, FP={m['FP']}, FN={m['FN']}")
    print("================================================================================\n")

    return summary


if __name__ == "__main__":
    run_polyglot_benchmark()
