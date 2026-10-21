
from pathlib import Path
import json

from flask import Flask, render_template_string, request, send_file

from scanners.semgrep_scanner import scan_project
from backend.scanner.normalizer import normalize_findings
from backend.scanner.report_generator import generate_json_report
from backend.scanner.html_report_generator import generate_html_report
from backend.scanner.detector import detect_framework


BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Multi-Framework Security Scanner</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f3f5f9;
            color: #202938;
        }
        header {
            background: #172554;
            color: white;
            padding: 28px 6%;
        }
        header h1 { margin: 0 0 8px; font-size: 27px; }
        header p { margin: 0; color: #dbeafe; }
        main { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .panel {
            background: white;
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 22px;
            box-shadow: 0 3px 12px #1725540d;
        }
        input {
            width: 100%;
            padding: 12px;
            margin: 10px 0 14px;
            border: 1px solid #cbd5e1;
            border-radius: 7px;
            font-size: 15px;
        }
        button, .report-link {
            display: inline-block;
            background: #1d4ed8;
            color: white;
            border: 0;
            border-radius: 7px;
            padding: 12px 20px;
            font-size: 15px;
            text-decoration: none;
            cursor: pointer;
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 22px;
        }
        .stat {
            background: white;
            padding: 20px;
            border-radius: 10px;
            border-top: 4px solid #64748b;
        }
        .stat h3 { margin: 0 0 12px; font-size: 14px; color: #64748b; }
        .number { font-size: 30px; font-weight: bold; }
        .high { color: #b91c1c; }
        .medium { color: #b45309; }
        .low { color: #047857; }
        .framework { line-height: 1.8; overflow-wrap: anywhere; }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 720px; }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }
        th { background: #f8fafc; }
        .pill {
            display: inline-block;
            padding: 5px 9px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            background: #e2e8f0;
        }
        .pill-HIGH { background: #fee2e2; color: #991b1b; }
        .pill-MEDIUM { background: #fef3c7; color: #92400e; }
        .pill-LOW { background: #d1fae5; color: #065f46; }
        details { min-width: 180px; }
        summary { cursor: pointer; color: #1d4ed8; }
        pre {
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            background: #f8fafc;
            padding: 12px;
            border-radius: 6px;
            font-size: 12px;
        }
        .error {
            padding: 14px;
            background: #fee2e2;
            color: #991b1b;
            border-radius: 8px;
        }
        .muted { color: #64748b; }
        @media (max-width: 700px) {
            .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            header h1 { font-size: 22px; }
        }
    </style>
</head>
<body>
<header>
    <h1>Multi-Framework Security Scanner</h1>
    <p>Automated Static Code Analysis and Vulnerability Risk Assessment</p>
</header>

<main>
    <section class="panel">
        <h2>Scan a Project</h2>
        <form method="POST">
            <label for="project_path">Local project folder path</label>
            <input
                id="project_path"
                name="project_path"
                value="{{ project_path }}"
                placeholder="Example: D:\\Projects\\MyBackend"
                required
            >
            <button type="submit">Scan Project</button>
        </form>
        <p class="muted">Scans supported Java, Python, JavaScript and C# source files.</p>
    </section>

    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}

    {% if scanned %}
        <section class="panel">
            <h2>Scan Overview</h2>
            <p><strong>Project:</strong> {{ scanned_path }}</p>
            <p class="framework">
                <strong>Detected frameworks:</strong> {{ framework }}
            </p>
            <p>
                <a class="report-link" href="/report" target="_blank">
                    Open Full HTML Report
                </a>
                &nbsp;
                <a class="report-link" href="/json-report">
                    Download JSON Report
                </a>
            </p>
        </section>

        <div class="cards">
            <div class="stat">
                <h3>Total Findings</h3>
                <div class="number">{{ findings|length }}</div>
            </div>
            <div class="stat">
                <h3>High Risk</h3>
                <div class="number high">{{ counts.HIGH }}</div>
            </div>
            <div class="stat">
                <h3>Medium Risk</h3>
                <div class="number medium">{{ counts.MEDIUM }}</div>
            </div>
            <div class="stat">
                <h3>Low Risk</h3>
                <div class="number low">{{ counts.LOW }}</div>
            </div>
        </div>

        <section class="panel">
            <h2>Security Findings</h2>
            {% if findings %}
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Vulnerability</th>
                            <th>Risk</th>
                            <th>Confidence</th>
                            <th>File / Line</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for finding in findings %}
                        <tr>
                            <td>{{ loop.index }}</td>
                            <td>{{ finding.vulnerability }}</td>
                            <td>
                                <span class="pill pill-{{ finding.severity }}">
                                    {{ finding.severity }}
                                </span>
                            </td>
                            <td>{{ finding.confidence }}</td>
                            <td>
                                {{ finding.file }}<br>
                                <strong>Line:</strong> {{ finding.line }}
                            </td>
                            <td>
                                <details>
                                    <summary>View details</summary>
                                    <p><strong>Rule:</strong> {{ finding.rule_id }}</p>
                                    <p><strong>CWE:</strong> {{ finding.cwe }}</p>
                                    <p><strong>OWASP:</strong> {{ finding.owasp }}</p>
                                    <p><strong>Description:</strong>
                                        {{ finding.description }}</p>
                                    <p><strong>Recommended fix:</strong>
                                        {{ finding.recommendation }}</p>
                                    <p><strong>Code context:</strong></p>
                                    <pre>{{ finding.code }}</pre>
                                </details>
                            </td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
                <p>No findings were returned for this scan.</p>
            {% endif %}
        </section>
    {% endif %}
</main>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    project_path = "tests"
    findings = []
    framework = ""
    scanned_path = ""
    error = None
    scanned = False

    if request.method == "POST":
        project_path = request.form.get("project_path", "").strip()

        try:
            project = Path(project_path).expanduser().resolve()

            if not project.exists() or not project.is_dir():
                raise ValueError("Please enter a valid existing folder path.")

            if not project.is_relative_to(BASE_DIR):
                raise ValueError(
                    "For this initial version, scan folders inside the "
                    "scanner project directory."
                )

            scanned_path = str(project)
            framework = detect_framework(str(project))

            raw_data = scan_project(str(project))
            findings = normalize_findings(raw_data or {})

            generate_json_report(
                findings,
                project_path=str(project),
                output_path=str(REPORTS_DIR / "security_report.json"),
                framework=framework,
            )

            generate_html_report(
                findings,
                project_path=str(project),
                output_path=str(REPORTS_DIR / "security_report.html"),
                framework=framework,
            )

            scanned = True

        except Exception as exc:
            error = str(exc)

    counts = {
        "HIGH": sum(f.get("severity") == "HIGH" for f in findings),
        "MEDIUM": sum(f.get("severity") == "MEDIUM" for f in findings),
        "LOW": sum(f.get("severity") == "LOW" for f in findings),
    }

    return render_template_string(
        HTML,
        project_path=project_path,
        scanned_path=scanned_path,
        framework=framework,
        findings=findings,
        counts=counts,
        scanned=scanned,
        error=error,
    )


@app.route("/report")
def html_report():
    report = REPORTS_DIR / "security_report.html"
    if not report.is_file():
        return "Run a scan first to generate the HTML report.", 404
    return send_file(report)


@app.route("/json-report")
def json_report():
    report = REPORTS_DIR / "security_report.json"
    if not report.is_file():
        return "Run a scan first to generate the JSON report.", 404
    return send_file(report, as_attachment=True)



@app.route("/evaluation")
def evaluation_report():
    evaluation_file = REPORTS_DIR / "evaluation_report.json"

    if not evaluation_file.exists():
        return (
            "Evaluation report not found. "
            "Run: python scanners/evaluate_scanner.py",
            404,
        )

    with evaluation_file.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Scanner Evaluation</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 900px;
                margin: 35px auto;
                padding: 20px;
                background: #f4f6f9;
                color: #202938;
            }
            h1 { margin-bottom: 8px; }
            .note { color: #5b6575; margin-bottom: 24px; }
            .grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 16px;
            }
            .card {
                background: white;
                padding: 22px;
                border-radius: 10px;
                box-shadow: 0 2px 8px #00000010;
            }
            .metric { font-size: 28px; font-weight: bold; }
            .label { color: #5b6575; margin-top: 8px; }
            table {
                width: 100%;
                border-collapse: collapse;
                background: white;
                margin-top: 24px;
            }
            th, td {
                padding: 13px;
                border-bottom: 1px solid #e5e7eb;
                text-align: left;
            }
            a { display: inline-block; margin-top: 22px; }
        </style>
    </head>
    <body>
        <h1>Scanner Evaluation</h1>
        <p class="note">
            SQL injection fixture-level evaluation.
            Results apply only to the current test dataset.
        </p>

        <div class="grid">
            <div class="card">
                <div class="metric">{{ data.accuracy_percent }}%</div>
                <div class="label">Accuracy</div>
            </div>
            <div class="card">
                <div class="metric">{{ data.precision_percent }}%</div>
                <div class="label">Precision</div>
            </div>
            <div class="card">
                <div class="metric">{{ data.recall_percent }}%</div>
                <div class="label">Recall</div>
            </div>
            <div class="card">
                <div class="metric">{{ data.f1_score_percent }}%</div>
                <div class="label">F1-score</div>
            </div>
        </div>

        <h2>Confusion Matrix Counts</h2>
        <table>
            <tr><th>Measure</th><th>Count</th></tr>
            <tr><td>True Positives (TP)</td>
                <td>{{ data.true_positives }}</td></tr>
            <tr><td>False Positives (FP)</td>
                <td>{{ data.false_positives }}</td></tr>
            <tr><td>True Negatives (TN)</td>
                <td>{{ data.true_negatives }}</td></tr>
            <tr><td>False Negatives (FN)</td>
                <td>{{ data.false_negatives }}</td></tr>
        </table>

        <p class="note">
            Vulnerable fixtures: {{ data.vulnerable_fixtures }} |
            Safe fixtures: {{ data.safe_fixtures }}
        </p>

        <a href="/">← Back to Scanner Dashboard</a>
    </body>
    </html>
    """, data=data)



if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
