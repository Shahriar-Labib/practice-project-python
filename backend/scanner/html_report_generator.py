
import html
from pathlib import Path
from datetime import datetime, timezone


def generate_html_report(
    findings,
    project_path,
    output_path,
    framework="Unknown"
):
    """Generate a professional HTML security report."""

    project = Path(project_path).resolve()

    high = sum(
        1 for f in findings
        if f.get("severity") == "HIGH"
    )
    medium = sum(
        1 for f in findings
        if f.get("severity") == "MEDIUM"
    )
    low = sum(
        1 for f in findings
        if f.get("severity") == "LOW"
    )

    scan_time = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    def safe(value):
        return html.escape(
            str(value if value is not None else "")
        )

    finding_cards = []

    for index, finding in enumerate(findings, start=1):
        risk = str(
            finding.get("severity", "LOW")
        ).upper()

        risk_class = (
            risk.lower()
            if risk in {"HIGH", "MEDIUM", "LOW"}
            else "unknown"
        )

        semgrep_severity = str(
            finding.get("semgrep_severity", "UNKNOWN")
        ).upper()

        semgrep_class = (
            semgrep_severity.lower()
            if semgrep_severity in {
                "ERROR", "WARNING", "INFO"
            }
            else "unknown"
        )

        confidence = str(
            finding.get("confidence", "UNKNOWN")
        ).upper()

        card = f"""
        <article class="finding">
            <div class="finding-heading">
                <div>
                    <p class="finding-number">
                        FINDING #{index}
                    </p>
                    <h2>
                        {safe(finding.get(
                            "vulnerability", "Security Issue"
                        ))}
                    </h2>
                </div>

                <span class="badge risk-{safe(risk_class)}">
                    {safe(risk)} RISK
                </span>
            </div>

            <div class="badge-row">
                <span class="label-badge">
                    Semgrep Severity: {safe(semgrep_severity)}
                </span>

                <span class="label-badge">
                    Detection Confidence: {safe(confidence)}
                </span>
            </div>

            <div class="metadata">
                <p>
                    <strong>Rule ID:</strong>
                    <code>{safe(finding.get("rule_id", "Unknown"))}</code>
                </p>
                <p>
                    <strong>File:</strong>
                    <code>{safe(finding.get("file", "Unknown"))}</code>
                </p>
                <p>
                    <strong>Reported line:</strong>
                    {safe(finding.get("line", "Unknown"))}
                </p>
            </div>

            <h3>Vulnerable Code</h3>
            <pre><code>{safe(finding.get(
                "code", "Code unavailable"
            ))}</code></pre>

            <h3>Description</h3>
            <p>{safe(finding.get(
                "description", "No description available."
            ))}</p>

            <div class="reference">
                <p>
                    <strong>CWE:</strong>
                    {safe(finding.get("cwe", "Unknown"))}
                </p>
                <p>
                    <strong>OWASP:</strong>
                    {safe(finding.get("owasp", "Unknown"))}
                </p>
            </div>

            <div class="recommendation">
                <h3>Recommended Fix</h3>
                <p>{safe(finding.get(
                    "recommendation",
                    "Review and fix the reported code."
                ))}</p>
            </div>
        </article>
        """

        finding_cards.append(card)

    if finding_cards:
        findings_html = "\n".join(finding_cards)
    else:
        findings_html = """
        <div class="empty-state">
            <h2>No findings detected</h2>
            <p>
                No security findings were returned by the scanner.
                This does not guarantee that the project is
                vulnerability-free.
            </p>
        </div>
        """

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Security Scan Report</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 32px 18px;
            background: #f1f5f9;
            color: #1e293b;
            font-family: Arial, Helvetica, sans-serif;
            line-height: 1.65;
        }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}

        header {{
            background: linear-gradient(135deg, #172554, #1e40af);
            color: white;
            padding: 32px;
            border-radius: 16px;
            margin-bottom: 24px;
            overflow-wrap: anywhere;
        }}

        header h1 {{
            margin: 0 0 6px;
            font-size: 30px;
        }}

        header .subtitle {{
            color: #dbeafe;
            margin-top: 0;
        }}

        .project-info {{
            margin-top: 22px;
            padding-top: 14px;
            border-top: 1px solid #ffffff35;
        }}

        .project-info p {{
            margin: 7px 0;
        }}

        .section-title {{
            margin: 28px 0 14px;
            font-size: 22px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
        }}

        .summary-card {{
            background: white;
            padding: 22px;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 3px 12px #0f172a08;
        }}

        .summary-card p {{
            margin: 0;
            color: #64748b;
            font-size: 14px;
        }}

        .summary-card .number {{
            font-size: 32px;
            font-weight: 700;
            line-height: 1.5;
        }}

        .high-text {{
            color: #b91c1c;
        }}

        .medium-text {{
            color: #b45309;
        }}

        .low-text {{
            color: #15803d;
        }}

        .finding {{
            background: white;
            padding: 26px;
            margin-bottom: 20px;
            border: 1px solid #e2e8f0;
            border-radius: 14px;
            box-shadow: 0 3px 12px #0f172a08;
            overflow-wrap: anywhere;
        }}

        .finding-heading {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }}

        .finding-heading h2 {{
            margin: 0;
            font-size: 21px;
        }}

        .finding-number {{
            margin: 0 0 3px;
            color: #64748b;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
        }}

        .badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 12px;
            white-space: nowrap;
        }}

        .risk-high {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .risk-medium {{
            background: #fef3c7;
            color: #92400e;
        }}

        .risk-low {{
            background: #dcfce7;
            color: #166534;
        }}

        .risk-unknown {{
            background: #e2e8f0;
            color: #334155;
        }}

        .badge-row {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 16px 0;
        }}

        .label-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 7px;
            background: #eff6ff;
            color: #1e40af;
            font-size: 12px;
            font-weight: 600;
        }}

        .metadata {{
            background: #f8fafc;
            border-radius: 8px;
            padding: 10px 14px;
        }}

        .metadata p {{
            margin: 5px 0;
        }}

        .metadata code {{
            overflow-wrap: anywhere;
        }}

        h3 {{
            margin: 22px 0 7px;
            font-size: 16px;
        }}

        pre {{
            background: #0f172a;
            color: #e2e8f0;
            padding: 17px;
            border-radius: 9px;
            overflow-x: auto;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            font-size: 13px;
            line-height: 1.6;
        }}

        .reference {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 10px 15px;
            border-radius: 9px;
            margin-top: 18px;
        }}

        .reference p {{
            margin: 5px 0;
        }}

        .recommendation {{
            background: #f0fdf4;
            border-left: 4px solid #16a34a;
            padding: 10px 16px;
            margin-top: 18px;
            border-radius: 4px 9px 9px 4px;
        }}

        .recommendation h3 {{
            margin-top: 5px;
            color: #166534;
        }}

        .recommendation p {{
            margin-bottom: 5px;
        }}

        .empty-state {{
            background: white;
            border: 1px solid #e2e8f0;
            padding: 28px;
            border-radius: 12px;
        }}

        footer {{
            text-align: center;
            color: #64748b;
            margin-top: 34px;
            padding-top: 20px;
            border-top: 1px solid #cbd5e1;
            font-size: 13px;
        }}

        @media (max-width: 760px) {{
            .summary {{
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }}

            .finding-heading {{
                align-items: flex-start;
            }}

            header {{
                padding: 24px;
            }}
        }}

        @media (max-width: 450px) {{
            .summary {{
                grid-template-columns: 1fr 1fr;
                gap: 9px;
            }}

            .summary-card {{
                padding: 14px;
            }}

            .finding {{
                padding: 18px;
            }}

            .finding-heading {{
                flex-direction: column;
            }}
        }}

        @media print {{
            body {{
                background: white;
                padding: 0;
            }}

            header {{
                background: white;
                color: #172554;
                border: 1px solid #cbd5e1;
            }}

            header .subtitle {{
                color: #334155;
            }}

            .summary-card, .finding {{
                box-shadow: none;
                break-inside: avoid;
            }}

            .finding {{
                border: 1px solid #cbd5e1;
            }}

            pre {{
                color: #111827;
                background: #f1f5f9;
                border: 1px solid #cbd5e1;
            }}
        }}
    </style>
</head>

<body>
    <main class="container">
        <header>
            <h1>Security Scan Report</h1>
            <p class="subtitle">
                Automated Static Code Analysis System
            </p>

            <div class="project-info">
                <p><strong>Project:</strong> {safe(project)}</p>
                <p><strong>Framework:</strong> {safe(framework)}</p>
                <p><strong>Generated:</strong> {safe(scan_time)}</p>
            </div>
        </header>

        <section class="summary">
            <div class="summary-card">
                <p>Total Findings</p>
                <div class="number">{len(findings)}</div>
            </div>

            <div class="summary-card">
                <p>High Risk</p>
                <div class="number high-text">{high}</div>
            </div>

            <div class="summary-card">
                <p>Medium Risk</p>
                <div class="number medium-text">{medium}</div>
            </div>

            <div class="summary-card">
                <p>Low Risk</p>
                <div class="number low-text">{low}</div>
            </div>
        </section>

        <h2 class="section-title">Detected Security Findings</h2>

        <section>
            {findings_html}
        </section>

        <footer>
            Generated by the Automated Static Code Analysis System.
            Static analysis results require human review and do not
            guarantee that all security vulnerabilities have been detected.
        </footer>
    </main>
</body>
</html>
"""

    output_file = Path(output_path).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(report_html, encoding="utf-8")

    print("\nHTML report generated successfully!")
    print("Report location:", output_file)

    return str(output_file)
