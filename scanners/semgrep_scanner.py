import json
import subprocess
from pathlib import Path
from backend.scanner.normalizer import normalize_findings


def scan_project(project_path: str):
    project = Path(project_path)

    command = [
        "semgrep",
        "scan",
        "--config",
        "auto",
        "--json",
        str(project)
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode not in [0, 1]:
        raise RuntimeError(
            f"Semgrep failed:\n{result.stderr}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(
            f"Could not parse Semgrep output:\n{result.stdout}"
        )


if __name__ == "__main__":
    findings = scan_project("tests")

    normalized = normalize_findings(findings)

    for finding in normalized:
        print("\n------------------------------")
        print("Vulnerability:", finding["vulnerability"])
        print("Severity:", finding["severity"])
        print("Confidence:", finding["confidence"])
        print("File:", finding["file"])
        print("Line:", finding["line"])
        print("Code:", finding["code"])
        print("CWE:", finding["cwe"])
        print("OWASP:", finding["owasp"])
        print("Description:", finding["description"])
        print("Recommendation:", finding["recommendation"])