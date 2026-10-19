
from backend.scanner.risk_engine import calculate_risk

test_cases = [
    ("SQL Injection", "HIGH"),
    ("SQL Injection", "MEDIUM"),
    ("SQL Injection", "LOW"),
    ("Cross-Site Scripting", "HIGH"),
    ("Cross-Site Scripting", "LOW"),
    ("Unknown Vulnerability", "HIGH"),
]

print("RISK ENGINE TEST RESULTS")
print("=" * 45)

for vulnerability, confidence in test_cases:
    risk = calculate_risk(vulnerability, confidence)

    print(
        f"Vulnerability: {vulnerability:30} "
        f"Confidence: {confidence:6} "
        f"Calculated Risk: {risk}"
    )
