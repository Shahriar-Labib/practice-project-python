
def calculate_risk(vulnerability, confidence):
    """
    Estimate risk from vulnerability type and detection confidence.

    This is a project-defined risk estimate, not proof that a
    vulnerability is exploitable.
    """

    vulnerability = (vulnerability or "").strip().lower()
    confidence = (confidence or "LOW").strip().upper()

    if confidence not in {"HIGH", "MEDIUM", "LOW"}:
        confidence = "LOW"

    high_risk = (
        "sql injection",
        "command injection",
        "path traversal",
        "remote code execution",
        "insecure deserialization",
    )

    medium_risk = (
        "cross-site scripting",
        "hardcoded secret",
        "weak cryptography",
        "sensitive information exposure",
    )

    if any(term in vulnerability for term in high_risk):
        if confidence in {"HIGH", "MEDIUM"}:
            return "HIGH"
        return "MEDIUM"

    if any(term in vulnerability for term in medium_risk):
        if confidence == "HIGH":
            return "MEDIUM"
        return "LOW"

    return "LOW"
