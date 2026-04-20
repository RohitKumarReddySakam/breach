"""
Report generator — produces HTML, JSON, and text pentest reports.
"""
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107", "LOW": "#17a2b8", "INFO": "#6c757d",
}


def generate_html_report(scan: dict) -> str:
    """Generate a self-contained HTML pentest report."""
    findings = scan.get("findings", [])
    findings_sorted = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4))

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    risk_score = scan.get("risk_score", 0)
    grade = _risk_grade(risk_score)

    findings_html = ""
    for i, f in enumerate(findings_sorted, 1):
        sev = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "#6c757d")
        cves = ", ".join(f.get("cve_ids", [])) or "N/A"
        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="badge" style="background:{color}">{sev}</span>
                <strong>{i}. {f.get('title', 'Unknown')}</strong>
                <span class="port-badge">Port {f.get('port', 'N/A')}</span>
            </div>
            <p><strong>Description:</strong> {f.get('description', '')}</p>
            <p><strong>Evidence:</strong> <code>{f.get('evidence', '')}</code></p>
            <p><strong>Recommendation:</strong> {f.get('recommendation', '')}</p>
            <p><strong>CVE References:</strong> {cves}</p>
        </div>"""

    open_ports_html = ""
    for p in scan.get("open_ports", []):
        banner = p.get("banner", "")[:60] + "..." if len(p.get("banner", "")) > 60 else p.get("banner", "")
        open_ports_html += f"""
        <tr>
            <td>{p.get('port')}</td>
            <td>{p.get('service', 'unknown')}</td>
            <td><code>{banner}</code></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Pentest Report — {scan.get('target', 'Unknown')}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; background: #f5f5f5; }}
.container {{ max-width: 1100px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.1); }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
h2 {{ color: #1a1a2e; margin-top: 30px; }}
.summary {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 15px; margin: 20px 0; }}
.stat {{ text-align: center; padding: 20px; border-radius: 6px; color: #fff; }}
.grade {{ font-size: 3em; font-weight: bold; text-align: center; padding: 20px; border-radius: 50%; width: 80px; height: 80px; line-height: 80px; display: inline-block; }}
.badge {{ padding: 3px 10px; border-radius: 3px; color: #fff; font-size: .8em; font-weight: bold; }}
.finding {{ border-left: 4px solid #e74c3c; padding: 15px 20px; margin: 15px 0; background: #fafafa; border-radius: 0 6px 6px 0; }}
.finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
.port-badge {{ background: #eee; padding: 2px 8px; border-radius: 3px; font-size: .85em; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #eee; }}
th {{ background: #f0f0f0; font-weight: bold; }}
code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-size: .9em; }}
.footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #999; font-size: .85em; }}
</style>
</head>
<body>
<div class="container">
  <h1>Penetration Test Report</h1>
  <table style="margin-bottom:20px">
    <tr><td><strong>Target:</strong></td><td>{scan.get('target', 'N/A')}</td></tr>
    <tr><td><strong>Scan Date:</strong></td><td>{scan.get('scan_time', 'N/A')}</td></tr>
    <tr><td><strong>Open Ports:</strong></td><td>{scan.get('open_count', 0)}</td></tr>
    <tr><td><strong>Risk Score:</strong></td><td>{risk_score}/100</td></tr>
    <tr><td><strong>Grade:</strong></td><td>{grade}</td></tr>
  </table>

  <h2>Executive Summary</h2>
  <div class="summary">
    <div class="stat" style="background:#dc3545">
      <div style="font-size:2em;font-weight:bold">{sev_counts['CRITICAL']}</div>
      <div>Critical</div>
    </div>
    <div class="stat" style="background:#fd7e14">
      <div style="font-size:2em;font-weight:bold">{sev_counts['HIGH']}</div>
      <div>High</div>
    </div>
    <div class="stat" style="background:#ffc107;color:#333">
      <div style="font-size:2em;font-weight:bold">{sev_counts['MEDIUM']}</div>
      <div>Medium</div>
    </div>
    <div class="stat" style="background:#17a2b8">
      <div style="font-size:2em;font-weight:bold">{sev_counts['LOW']}</div>
      <div>Low</div>
    </div>
  </div>

  <h2>Open Ports</h2>
  <table>
    <tr><th>Port</th><th>Service</th><th>Banner</th></tr>
    {open_ports_html}
  </table>

  <h2>Findings ({len(findings_sorted)})</h2>
  {findings_html if findings_sorted else '<p>No vulnerabilities found.</p>'}

  <div class="footer">
    <p>Generated by BREACH &mdash; {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
    <p><em>This report is for authorized security assessments only.</em></p>
  </div>
</div>
</body>
</html>"""


def generate_json_report(scan: dict) -> str:
    return json.dumps({
        "report_type": "pentest",
        "generated_at": datetime.utcnow().isoformat(),
        "target": scan.get("target"),
        "scan_id": scan.get("id"),
        "risk_score": scan.get("risk_score", 0),
        "risk_grade": _risk_grade(scan.get("risk_score", 0)),
        "open_ports": scan.get("open_ports", []),
        "findings": scan.get("findings", []),
        "summary": {
            "critical": sum(1 for f in scan.get("findings", []) if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in scan.get("findings", []) if f.get("severity") == "HIGH"),
            "medium": sum(1 for f in scan.get("findings", []) if f.get("severity") == "MEDIUM"),
            "low": sum(1 for f in scan.get("findings", []) if f.get("severity") == "LOW"),
        },
    }, indent=2)


def _risk_grade(score: float) -> str:
    if score == 0:
        return "A+"
    if score <= 10:
        return "A"
    if score <= 25:
        return "B"
    if score <= 45:
        return "C"
    if score <= 65:
        return "D"
    return "F"
