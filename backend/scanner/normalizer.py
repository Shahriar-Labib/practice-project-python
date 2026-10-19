
from pathlib import Path

from backend.scanner.risk_engine import calculate_risk


def get_code_snippet(file_path, line_number):
    try:
        path = Path(file_path)

        if not path.exists():
            return "Code snippet unavailable."

        lines = path.read_text(
            encoding="utf-8",
            errors="replace"
        ).splitlines()

        if line_number <= 0 or line_number > len(lines):
            return "Code snippet unavailable."

        return lines[line_number - 1].strip()

    except (OSError, ValueError):
        return "Code snippet unavailable."


def normalize_findings(semgrep_data):
    findings = []
    seen = set()

    for result in semgrep_data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        vulnerability_classes = metadata.get(
            "vulnerability_class", []
        )

        vulnerability = (
            vulnerability_classes[0]
            if vulnerability_classes
            else "Security Issue"
        )

        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0] if cwe_list else "Unknown"

        owasp_list = metadata.get("owasp", [])
        owasp = owasp_list[0] if owasp_list else "Unknown"

        file_path = result.get("path", "Unknown")
        line = result.get("start", {}).get("line", 0)

        # Use the vulnerability, file, line, and code
        # to avoid removing distinct findings.
        code = get_code_snippet(file_path, line)

        duplicate_key = (
            vulnerability,
            file_path,
            line,
            code
        )

        if duplicate_key in seen:
            continue

        seen.add(duplicate_key)

        confidence = metadata.get("confidence", "UNKNOWN")

        # Preserve the original Semgrep severity.
        semgrep_severity = extra.get("severity", "UNKNOWN")

        # Calculate our own risk level.
        risk_level = calculate_risk(
            vulnerability,
            confidence
        )


        finding = {
            "vulnerability": vulnerability,
            "semgrep_severity": semgrep_severity,
            "severity": risk_level,
            "confidence": confidence,
            "file": file_path,
            "line": line,
            "code": code,
            "cwe": cwe,
            "owasp": owasp,
            "description": extra.get(
                "message",
                "Security vulnerability detected."
            ),
            "recommendation": get_recommendation(vulnerability, file_path)
        }

        findings.append(finding)

    return findings


def get_recommendation(vulnerability, file_path=""):
    """Return security recommendations appropriate to the source language."""

    vulnerability = (vulnerability or "").strip().lower()
    file_path = (file_path or "").lower()

    if "sql injection" in vulnerability:
        if file_path.endswith(".py"):
            return (
                "Use parameterized SQL queries instead of string "
                "concatenation. For SQLite, use placeholders such as "
                "'?' and pass user input as query parameters."
            )

        if file_path.endswith(".java"):
            return (
                "Use java.sql.PreparedStatement with parameterized "
                "queries, or a safe ORM, instead of building SQL "
                "queries using user input."
            )

        return (
            "Use parameterized SQL queries or a safe ORM instead of "
            "building SQL queries using user input."
        )

    if "cross-site scripting" in vulnerability:
        return (
            "Encode untrusted output appropriately and use your "
            "framework's built-in output-escaping features."
        )

    if "command injection" in vulnerability:
        return (
            "Avoid constructing shell commands from user input. "
            "Use safe APIs and pass arguments separately."
        )

    if "path traversal" in vulnerability:
        return (
            "Validate and normalize file paths, and ensure resolved "
            "paths remain inside the intended directory."
        )

    if "hardcoded secret" in vulnerability:
        return (
            "Move secrets to environment variables or a secure "
            "secrets manager, and rotate exposed credentials."
        )

    return (
        "Review the finding and follow the relevant framework's "
        "secure coding practices."
    )