
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def generate_json_report(findings, project_path, output_path,framework="Unknown"):
    """
    Generate a JSON security report from normalized findings.
    """

    project = Path(project_path).resolve()

    # Count findings by risk level
    severity_counts = Counter(
        finding.get("severity", "LOW")
        for finding in findings
    )

    # Build the report
    report = {
        "project": str(project),
        "framework": framework,
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "summary": {
            "total_findings": len(findings),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0)
        },
        "findings": findings
    }

    # Create the output directory if necessary
    output_file = Path(output_path).resolve()
    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Save JSON report
    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("\nJSON report saved successfully!")
    print("Report location:", output_file)

    return report
