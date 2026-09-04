from pathlib import Path

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

    except Exception:
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

        # Deduplicate based on vulnerability + file
        duplicate_key = (
            vulnerability,
            file_path
        )

        if duplicate_key in seen:
            continue

        seen.add(duplicate_key)

        semgrep_severity = extra.get(
            "severity",
            "WARNING"
        )

        if semgrep_severity == "ERROR":
            severity = "HIGH"
        elif semgrep_severity == "WARNING":
            severity = "MEDIUM"
        else:
            severity = "LOW"

        finding = {
            "vulnerability": vulnerability,
            "severity": severity,
            "confidence": metadata.get(
                "confidence",
                "UNKNOWN"
            ),
            "file": file_path,
            "line": line,
            "code": get_code_snippet(file_path, line),
            "cwe": cwe,
            "owasp": owasp,
            "description": extra.get(
                "message",
                "Security vulnerability detected."
            ),
            "recommendation": get_recommendation(
                vulnerability
            )
        }

        findings.append(finding)

    return findings


def get_recommendation(vulnerability):

    recommendations = {
        "SQL Injection":
            "Use PreparedStatement or a safe ORM instead of building SQL queries using user input.",

        "Command Injection":
            "Avoid executing commands using unsanitized user input. Use safe APIs and validate input.",

        "Path Traversal":
            "Validate and sanitize file paths. Restrict file access to the intended directory.",

        "Hardcoded Secret":
            "Move passwords, API keys, and secrets to environment variables or a secure secret manager.",

        "Cross-Site Scripting":
            "Validate and encode user-controlled output before rendering it.",

        "Insecure Deserialization":
            "Avoid deserializing untrusted data and use safe serialization mechanisms."
    }

    return recommendations.get(
        vulnerability,
        "Review the reported code and apply secure coding practices."
    )