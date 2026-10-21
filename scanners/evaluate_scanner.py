
from pathlib import Path
import json

from scanners.semgrep_scanner import scan_project
from backend.scanner.normalizer import normalize_findings

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
SAFE_DIR = TESTS / "safe_test"

VULNERABLE_FILES = [
    TESTS / "VulnerableController.java",
    TESTS / "python_test" / "app.py",
    TESTS / "node_test" / "app.js",
    TESTS / "dotnet_test" / "Program.cs",
]

SOURCE_EXTENSIONS = {".java", ".py", ".js", ".ts", ".cs"}


def is_sql_injection(finding):
    vulnerability = str(finding.get("vulnerability", "")).lower()
    rule_id = str(finding.get("rule_id", "")).lower()
    description = str(finding.get("description", "")).lower()

    return (
        "sql injection" in vulnerability
        or "sql-injection" in rule_id
        or "sqli" in rule_id
        or "sql injection" in description
    )


def normalized_path(file_path):
    path = Path(file_path)
    if not path.is_absolute():
        path = ROOT / path
    return str(path.resolve()).lower()


def main():
    print("=" * 55)
    print("AUTOMATED SECURITY SCANNER EVALUATION")
    print("=" * 55)

    safe_files = [
        path
        for path in SAFE_DIR.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
    ]

    vulnerable_files = [
        path for path in VULNERABLE_FILES if path.is_file()
    ]

    if not vulnerable_files or not safe_files:
        print("ERROR: Vulnerable or safe test files are missing.")
        print(f"Vulnerable files found: {len(vulnerable_files)}")
        print(f"Safe files found: {len(safe_files)}")
        return

    print("\nScanning vulnerable test fixtures...")
    vulnerable_raw = scan_project(str(TESTS))
    vulnerable_findings = [
        finding
        for finding in normalize_findings(vulnerable_raw)
        if is_sql_injection(finding)
    ]

    vulnerable_detected_paths = {
        normalized_path(finding["file"])
        for finding in vulnerable_findings
        if finding.get("file")
    }

    print("\nScanning safe test fixtures...")
    safe_raw = scan_project(str(SAFE_DIR))
    safe_findings = [
        finding
        for finding in normalize_findings(safe_raw)
        if is_sql_injection(finding)
    ]

    safe_flagged_paths = {
        normalized_path(finding["file"])
        for finding in safe_findings
        if finding.get("file")
    }

    tp = sum(
        normalized_path(path) in vulnerable_detected_paths
        for path in vulnerable_files
    )
    fn = len(vulnerable_files) - tp

    fp = sum(
        normalized_path(path) in safe_flagged_paths
        for path in safe_files
    )
    tn = len(safe_files) - fp

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    accuracy = (
        (tp + tn) / (tp + tn + fp + fn)
        if tp + tn + fp + fn
        else 0.0
    )

    results = {
        "evaluation_type": "SQL injection fixture-level evaluation",
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision_percent": round(precision * 100, 2),
        "recall_percent": round(recall * 100, 2),
        "f1_score_percent": round(f1 * 100, 2),
        "accuracy_percent": round(accuracy * 100, 2),
        "vulnerable_fixtures": len(vulnerable_files),
        "safe_fixtures": len(safe_files),
        "sql_injection_findings_in_vulnerable_scan": len(
            vulnerable_findings
        ),
        "sql_injection_findings_in_safe_scan": len(safe_findings),
    }

    print("\n" + "=" * 55)
    print("EVALUATION RESULTS")
    print("=" * 55)
    print(f"True Positives (TP):  {tp}")
    print(f"False Positives (FP): {fp}")
    print(f"True Negatives (TN):  {tn}")
    print(f"False Negatives (FN): {fn}")
    print("-" * 55)
    print(f"Accuracy:  {results['accuracy_percent']}%")
    print(f"Precision: {results['precision_percent']}%")
    print(f"Recall:    {results['recall_percent']}%")
    print(f"F1-score:  {results['f1_score_percent']}%")

    output_file = ROOT / "reports" / "evaluation_report.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8",
    )

    print(f"\nEvaluation report saved to:\n{output_file}")
    print("\nEvaluation completed.")


if __name__ == "__main__":
    main()
