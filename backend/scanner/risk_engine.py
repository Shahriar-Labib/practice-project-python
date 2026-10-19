
def calculate_risk(vulnerability, confidence):
    """
    Calculate risk using vulnerability severity and confidence.

    Confidence affects the final risk level, but a low-confidence
    finding is not automatically considered harmless.
    """

    vulnerability = (vulnerability or "").strip().lower()
    confidence = (confidence or "LOW").strip().upper()

    high_risk = [
        "sql injection",
        "command injection",
        "path traversal",
        "remote code execution",
        "insecure deserialization",
    ]

    medium_risk = [
        "cross-site scripting",
        "hardcoded secret",
        "weak cryptography",
        "sensitive information exposure",
    ]

    if vulnerability in high_risk:
        if confidence == "HIGH":
            return "HIGH"
        elif confidence == "MEDIUM":
            return "HIGH"
        else:
            return "MEDIUM"

    if vulnerability in medium_risk:
        if confidence == "HIGH":
            return "MEDIUM"
        return "LOW"

    return "LOW"
