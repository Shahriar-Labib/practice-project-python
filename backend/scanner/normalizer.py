
from pathlib import Path

from backend.scanner.risk_engine import calculate_risk


def get_code_snippet(file_path, line_number, context=2):
    """Return the reported source line with nearby numbered lines."""
    try:
        path = Path(file_path)

        if not path.is_file():
            return "Code snippet unavailable."

        lines = path.read_text(
            encoding="utf-8",
            errors="replace"
        ).splitlines()

        if not isinstance(line_number, int):
            return "Code snippet unavailable."

        if line_number < 1 or line_number > len(lines):
            return "Code snippet unavailable."

        start = max(1, line_number - context)
        end = min(len(lines), line_number + context)
        width = len(str(end))
        snippet = []

        for number in range(start, end + 1):
            marker = ">" if number == line_number else " "
            snippet.append(
                f"{marker} {number:>{width}} | {lines[number - 1]}"
            )

        return "\n".join(snippet)

    except (OSError, ValueError, TypeError):
        return "Code snippet unavailable."


def first_metadata_value(value, default="Unknown"):
    """Safely get the first value from Semgrep metadata."""
    if isinstance(value, list):
        return value[0] if value else default

    if isinstance(value, str) and value.strip():
        return value

    return default


def normalize_findings(semgrep_data):
    findings = []
    seen = set()

    for result in semgrep_data.get("results", []):
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = result.get("start") or {}

        rule_id = result.get("check_id", "unknown")
        file_path = result.get("path", "Unknown")
        line = start.get("line", 0)

        vulnerability = first_metadata_value(
            metadata.get("vulnerability_class"),
            "Security Issue"
        )

        cwe = first_metadata_value(
            metadata.get("cwe")
        )

        owasp = first_metadata_value(
            metadata.get("owasp")
        )

        confidence = str(
            metadata.get("confidence", "UNKNOWN")
        ).upper()

        semgrep_severity = str(
            extra.get("severity", "UNKNOWN")
        ).upper()

        code = get_code_snippet(file_path, line)

        # Preserve findings from different rules at the same location.
        duplicate_key = (
            rule_id,
            file_path,
            line,
            code
        )

        if duplicate_key in seen:
            continue

        seen.add(duplicate_key)

        risk_level = calculate_risk(
            vulnerability,
            confidence
        )

        findings.append({
            "rule_id": rule_id,
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
            "recommendation": get_recommendation(
                vulnerability,
                file_path
            )
        })

    return findings


def get_recommendation(vulnerability, file_path=""):
    """Return a recommendation based on vulnerability and file type."""

    vulnerability = (vulnerability or "").strip().lower()
    file_path = (file_path or "").lower()

    if "sql injection" in vulnerability:
        if file_path.endswith(".py"):
            return (
                "Use parameterized SQL queries instead of string "
                "concatenation. For SQLite, use '?' placeholders and "
                "pass user input separately as query parameters."
            )

        if file_path.endswith(".java"):
            return (
                "Use java.sql.PreparedStatement with parameterized "
                "queries, or a safe ORM, instead of building SQL "
                "queries using user input."
            )

        if file_path.endswith(".cs"):
            return (
                "Use parameterized SQL commands with SqlParameter "
                "instead of concatenating user input into SQL."
            )

        if file_path.endswith((".js", ".ts")):
            return (
                "Use parameterized queries supported by your database "
                "driver instead of concatenating request input into SQL."
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

    if "cross-site request forgery" in vulnerability or "csrf" in vulnerability:
        return (
            "Apply appropriate CSRF protection to state-changing "
            "requests, using framework-supported tokens or equivalent "
            "protections suited to your authentication method."
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
