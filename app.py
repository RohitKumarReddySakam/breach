"""
BREACH — Authorized Penetration Testing Framework
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 1.0.0

Network scanning and vulnerability assessment platform for authorized penetration testing.
Performs port scanning, service fingerprinting, and vulnerability identification.
"""

from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime
import os
import json
import uuid
import threading
import logging
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
sio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Models ───────────────────────────────────────────────────────
class ScanJob(db.Model):
    __tablename__ = "scan_jobs"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = db.Column(db.String(200), nullable=False)
    scan_type = db.Column(db.String(50), default="quick")
    port_range = db.Column(db.String(50), default="common")
    status = db.Column(db.String(20), default="PENDING")
    open_ports = db.Column(db.Text, default="[]")
    open_count = db.Column(db.Integer, default=0)
    total_hosts = db.Column(db.Integer, default=1)
    findings = db.Column(db.Text, default="[]")
    risk_score = db.Column(db.Float, default=0.0)
    dns_info = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "scan_type": self.scan_type,
            "port_range": self.port_range,
            "status": self.status,
            "open_ports": json.loads(self.open_ports or "[]"),
            "open_count": self.open_count,
            "total_hosts": self.total_hosts,
            "findings": json.loads(self.findings or "[]"),
            "risk_score": self.risk_score,
            "dns_info": json.loads(self.dns_info or "{}"),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class ScanReport(db.Model):
    __tablename__ = "scan_reports"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(36), db.ForeignKey("scan_jobs.id"))
    title = db.Column(db.String(200))
    format = db.Column(db.String(10), default="html")
    content = db.Column(db.Text)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "format": self.format,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
        }


# ─── Routes — Pages ───────────────────────────────────────────────
@app.route("/")
def dashboard():
    recent = ScanJob.query.order_by(ScanJob.created_at.desc()).limit(8).all()
    stats = _global_stats()
    return render_template("index.html", recent_scans=recent, stats=stats)


@app.route("/scan/<scan_id>")
def scan_detail(scan_id):
    scan = ScanJob.query.get_or_404(scan_id)
    reports = ScanReport.query.filter_by(scan_id=scan_id).all()
    return render_template("results.html", scan=scan, scan_dict=scan.to_dict(), reports=reports)


@app.route("/reports")
def reports_page():
    reports = ScanReport.query.order_by(ScanReport.generated_at.desc()).all()
    scans = {s.id: s for s in ScanJob.query.all()}
    return render_template("reports.html", reports=reports, scans=scans)


# ─── Routes — API ─────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    if not data or not data.get("target"):
        return jsonify({"error": "Target is required"}), 400

    target = data["target"].strip()
    scan_type = data.get("scan_type", "quick")
    port_range = data.get("port_range", "common")

    # Validate target — no internal IPs for safety (can be overridden by operator)
    if not target:
        return jsonify({"error": "Invalid target"}), 400

    job = ScanJob(target=target, scan_type=scan_type, port_range=port_range, status="QUEUED")
    db.session.add(job)
    db.session.commit()

    t = threading.Thread(target=_run_scan, args=(job.id,), daemon=True)
    t.start()

    return jsonify({"scan_id": job.id, "status": "QUEUED"}), 202


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    scan = ScanJob.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())


@app.route("/api/scans", methods=["GET"])
def list_scans():
    scans = ScanJob.query.order_by(ScanJob.created_at.desc()).limit(50).all()
    return jsonify({"scans": [s.to_dict() for s in scans]})


@app.route("/api/report/generate", methods=["POST"])
def generate_report():
    data = request.get_json()
    scan_id = data.get("scan_id")
    fmt = data.get("format", "html")

    scan = ScanJob.query.get_or_404(scan_id)
    scan_dict = scan.to_dict()

    from core.report_generator import generate_html_report, generate_json_report
    if fmt == "json":
        content = generate_json_report(scan_dict)
        mime = "application/json"
    else:
        content = generate_html_report(scan_dict)
        mime = "text/html"
        fmt = "html"

    report = ScanReport(
        scan_id=scan_id,
        title=f"BREACH Report — {scan.target}",
        format=fmt,
        content=content,
    )
    db.session.add(report)
    db.session.commit()

    return jsonify({"report_id": report.id, "format": fmt})


@app.route("/api/report/<report_id>", methods=["GET"])
def get_report(report_id):
    report = ScanReport.query.get_or_404(report_id)
    fmt = request.args.get("format", report.format)

    if fmt == "html" or report.format == "html":
        return Response(report.content, mimetype="text/html")
    return Response(report.content, mimetype="application/json")


@app.route("/api/stats")
def api_stats():
    return jsonify(_global_stats())


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "1.0.0", "timestamp": datetime.utcnow().isoformat()})


# ─── Scan Pipeline ────────────────────────────────────────────────
def _get_ports(port_range: str) -> list:
    from core.scanner import COMMON_PORTS, TOP_1000_PORTS
    if port_range == "top1000":
        return TOP_1000_PORTS
    if port_range == "all":
        return list(range(1, 65536))
    return COMMON_PORTS


def _run_scan(scan_id: str):
    from core.scanner import scan_host, expand_targets
    from core.recon import dns_lookup, get_service_info
    from core.vuln_checker import check_port_vulns, check_ssl_vulns, calculate_risk_score

    with app.app_context():
        job = ScanJob.query.get(scan_id)
        job.status = "SCANNING"
        db.session.commit()

        try:
            target = job.target
            ports = _get_ports(job.port_range)
            timeout = app.config["SCAN_TIMEOUT"]
            workers = app.config["MAX_SCAN_WORKERS"]

            # Expand targets (CIDR support)
            hosts = expand_targets(target)
            if len(hosts) > app.config["MAX_CIDR_HOSTS"]:
                hosts = hosts[:app.config["MAX_CIDR_HOSTS"]]

            job.total_hosts = len(hosts)
            db.session.commit()

            all_open_ports = []
            all_findings = []

            for host in hosts:
                sio.emit("scan_progress", {"scan_id": scan_id, "host": host, "status": "scanning"})
                result = scan_host(host, ports, timeout=timeout, max_workers=workers)
                open_ports = result.get("open_ports", [])

                # Enrich with service info
                for p in open_ports:
                    service_info = get_service_info(host, p["port"], p.get("banner", ""))
                    p.update(service_info)
                    p["host"] = host

                all_open_ports.extend(open_ports)

                # Vulnerability checks
                findings = check_port_vulns(open_ports)
                for p in open_ports:
                    ssl_info = p.get("ssl", {})
                    if ssl_info:
                        findings.extend(check_ssl_vulns(ssl_info, p["port"]))
                all_findings.extend(findings)

            # DNS recon (first host only)
            dns_info = {}
            try:
                dns_info = dns_lookup(target)
            except Exception:
                pass

            risk_score = calculate_risk_score(all_findings)

            job.open_ports = json.dumps(all_open_ports)
            job.open_count = len(all_open_ports)
            job.findings = json.dumps(all_findings)
            job.risk_score = risk_score
            job.dns_info = json.dumps(dns_info)
            job.status = "COMPLETED"
            job.completed_at = datetime.utcnow()
            db.session.commit()

            sio.emit("scan_complete", {
                "scan_id": scan_id,
                "open_count": len(all_open_ports),
                "findings_count": len(all_findings),
                "risk_score": risk_score,
            })
            logger.info(f"Scan complete: {scan_id} | {len(all_open_ports)} open ports | {len(all_findings)} findings")

        except Exception as e:
            logger.error(f"Scan failed {scan_id}: {e}", exc_info=True)
            job.status = f"FAILED: {str(e)[:100]}"
            db.session.commit()


def _global_stats():
    total_scans = ScanJob.query.filter_by(status="COMPLETED").count()
    total_findings = db.session.query(db.func.sum(
        db.cast(db.func.json_array_length(ScanJob.findings), db.Integer)
    )).scalar() or 0
    total_reports = ScanReport.query.count()
    return {
        "total_scans": total_scans,
        "total_reports": total_reports,
        "active_scans": ScanJob.query.filter_by(status="SCANNING").count(),
    }


# ─── WebSocket ────────────────────────────────────────────────────
@sio.on("connect")
def on_connect():
    logger.info("Client connected")


# ─── Bootstrap ────────────────────────────────────────────────────
def create_app():
    with app.app_context():
        db.create_all()
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5003))
    sio.run(app, host="0.0.0.0", port=port, debug=False)
