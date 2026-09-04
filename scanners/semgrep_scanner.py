import json
import subprocess
from pathlib import Path
from backend.scanner.normalizer import normalize_findings


def find_java_files(project_path):
    project = Path(project_path)

    ignored_dirs = {
        ".git",
        ".idea",
        "venv",
        "target",
        "build",
        "node_modules"
    }

    java_files = []

    for file in project.rglob("*.java"):

        # Ignore unwanted directories
        if any(part in ignored_dirs for part in file.parts):
            continue

        java_files.append(file.resolve())

    return java_files


def scan_project(project_path: str):

    project = Path(project_path).resolve()

    java_files = find_java_files(project)

    print("Project:", project)
    print("Java files found:", len(java_files))

    if not java_files:
        print("No Java files found.")
        return {"results": []}

    command = [
        "semgrep",
        "scan",
        "--config",
        "auto",
        "--no-git-ignore",
        "--json"
    ]

    # Add every Java file explicitly
    command.extend(str(file) for file in java_files)

    print("\nRunning Semgrep...")
    
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    print("Return code:", result.returncode)

    if result.stderr:
        print("\nSemgrep information:")
        print(result.stderr)

    try:
        data = json.loads(result.stdout)

        print("\nFindings:", len(data.get("results", [])))

        return data

    except json.JSONDecodeError:
        print("\nSTDOUT:")
        print(result.stdout)

        raise RuntimeError(
            "Could not parse Semgrep output."
        )


if __name__ == "__main__":

    findings = scan_project("tests")

    normalized = normalize_findings(findings)

    print("\n==============================")
    print("NORMALIZED SECURITY FINDINGS")
    print("==============================")

    for finding in normalized:

        print("\n------------------------------")
        print("Vulnerability:", finding["vulnerability"])
        print("Risk:", finding["severity"])
        print("Confidence:", finding["confidence"])
        print("File:", finding["file"])
        print("Line:", finding["line"])
        print("Code:", finding["code"])
        print("CWE:", finding["cwe"])
        print("OWASP:", finding["owasp"])
        print("Description:", finding["description"])
        print("Recommendation:", finding["recommendation"])