import json
import subprocess
import webbrowser
from pathlib import Path
from backend.scanner.normalizer import normalize_findings
from backend.scanner.report_generator import generate_json_report
from backend.scanner.html_report_generator import generate_html_report
from backend.scanner.detector import detect_framework


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


def find_python_files(project_path):
    """Find Python files while ignoring common generated directories."""
    ignored_dirs = {
        ".git",
        ".idea",
        "venv",
        ".venv",
        "__pycache__",
        "node_modules",
        "build",
        "dist",
    }

    project = Path(project_path).resolve()
    python_files = []

    for file_path in project.rglob("*.py"):
        if any(part in ignored_dirs for part in file_path.parts):
            continue

        python_files.append(file_path)

    return python_files



def scan_project(project_path: str):

    project = Path(project_path).resolve()

    java_files = find_java_files(project)
    python_files = find_python_files(project)

    source_files = java_files + python_files

    print(f"Java files found: {len(java_files)}")
    print(f"Python files found: {len(python_files)}")

    if not source_files:
        print("No supported source files found.")
        return {}

    print("Project:", project)
    

    if not java_files:
        print("No Java files found.")

    if not python_files:
        print("No Python files found.")

    command = [
        "semgrep",
        "scan",
        "--config",
        "auto",
        "--no-git-ignore",
        "--json"
    ]

    # Add all supported source files explicitly
    command.extend(str(file) for file in source_files)

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

    project_path = "tests"

    framework = detect_framework(project_path)

    print("\n==============================")
    print("PROJECT FRAMEWORK")
    print("==============================")
    print("Detected framework:", framework)

    findings = scan_project(project_path)

    normalized = normalize_findings(findings)

    generate_json_report(
        normalized,
        project_path=project_path,
        output_path="reports/security_report.json",
        framework=framework
    )

    html_report_path = generate_html_report(
        normalized,
        project_path=project_path,
        output_path="reports/security_report.html",
        framework=framework
    )

    webbrowser.open(
        Path(html_report_path).resolve().as_uri()
    )

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