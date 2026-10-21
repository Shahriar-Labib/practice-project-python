
from pathlib import Path

from scanners.semgrep_scanner import scan_project
from backend.scanner.normalizer import normalize_findings


def is_sql_injection(finding):
    return "sql injection" in finding.get("vulnerability", "").lower()


def is_inside_safe_test(finding):
    normalized_path = finding.get("file", "").replace("\\", "/").lower()
    return "/safe_test/" in f"/{normalized_path.strip('/')}/"


def main():
    print("=" * 55)
    print("SAFE-CODE FALSE-POSITIVE TEST")
    print("=" * 55)

    safe_data = scan_project("tests/safe_test")
    safe_findings = normalize_findings(safe_data or {})
    safe_sql_findings = [
        finding for finding in safe_findings
        if is_sql_injection(finding)
    ]

    print("\nSafe test files scanned.")
    print("SQL injection findings in safe fixtures:",
          len(safe_sql_findings))

    for finding in safe_sql_findings:
        print(
            "POTENTIAL FALSE POSITIVE:",
            finding.get("file"),
            "line",
            finding.get("line"),
            "rule",
            finding.get("rule_id"),
        )

    print("\n" + "=" * 55)
    print("VULNERABLE-CODE DETECTION TEST")
    print("=" * 55)

    vulnerable_data = scan_project("tests")
    vulnerable_findings = normalize_findings(vulnerable_data or {})

    vulnerable_sql_findings = [
        finding for finding in vulnerable_findings
        if is_sql_injection(finding)
        and not is_inside_safe_test(finding)
    ]

    print("SQL injection findings in vulnerable fixtures:",
          len(vulnerable_sql_findings))

    for finding in vulnerable_sql_findings:
        print(
            "DETECTED:",
            finding.get("file"),
            "line",
            finding.get("line"),
            "risk",
            finding.get("severity"),
        )

    print("\n" + "=" * 55)
    print("TEST SUMMARY")
    print("=" * 55)

    safe_passed = len(safe_sql_findings) == 0
    vulnerable_passed = len(vulnerable_sql_findings) > 0

    print("Safe-code test:", "PASS" if safe_passed else "FAIL")
    print(
        "Vulnerable-code test:",
        "PASS" if vulnerable_passed else "FAIL",
    )

    if safe_passed and vulnerable_passed:
        print("\nBoth tests passed.")
    else:
        print("\nReview the findings above before claiming success.")

    if not safe_passed or not vulnerable_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
