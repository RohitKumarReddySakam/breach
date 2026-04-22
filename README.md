<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&amp;weight=700&amp;size=28&amp;duration=3000&amp;pause=1000&amp;color=64FFDA&amp;center=true&amp;vCenter=true&amp;width=750&amp;lines=BREACH;Authorized+Penetration+Testing+Framework;Port+Scan+%7C+DNS+Recon+%7C+SSL+Analysis;CVSS+Risk+Scoring+%7C+HTML%2FJSON+Reports" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![CVSS](https://img.shields.io/badge/CVSS-v3.1-F97316?style=for-the-badge)](https://www.first.org/cvss/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Automate reconnaissance, vulnerability detection, and professional report generation for authorized penetration testing engagements.**

<br/>

[![Ports](https://img.shields.io/badge/Ports-Top_1000-64ffda?style=flat-square)](.)
[![Services](https://img.shields.io/badge/Services-18_Vuln_Profiles-64ffda?style=flat-square)](.)
[![Reports](https://img.shields.io/badge/Reports-HTML_%2B_JSON-64ffda?style=flat-square)](.)
[![Async](https://img.shields.io/badge/Scanning-Async_Threaded-22c55e?style=flat-square)](.)

</div>

> ⚠️ **AUTHORIZED USE ONLY** — For use against systems you own or have explicit written authorization to test. Unauthorized scanning is illegal under CFAA, CMA, and equivalent laws worldwide.

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Purpose

Manual penetration testing reconnaissance takes hours of repetitive work. This framework automates the systematic phases of an authorized assessment:

| Phase | What It Does |
|-------|-------------|
| **Discovery** | CIDR/range expansion, top-1000 port scan, service detection |
| **Reconnaissance** | DNS A/MX/NS/TXT/PTR records + subdomain enumeration |
| **SSL Analysis** | TLS version, certificate validity, cipher assessment |
| **Vuln Correlation** | Port→CVE mapping for 18 common services |
| **Reporting** | Self-contained HTML + structured JSON |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Target (IP / CIDR / hostname)
         │  POST /api/scan
         ▼
┌──────────────────────────────────────────┐
│         Scan Pipeline (background)        │
│                                           │
│  1. expand_targets   CIDR → IP list      │
│  2. scan_host        Top-1000 ports       │
│  3. dns_lookup       A/MX/NS/TXT/PTR     │
│  4. check_port_vulns Service→CVE map     │
│  5. check_ssl_vulns  TLS + cert check    │
│  6. risk_score       Composite 0–10      │
└───────────────────┬──────────────────────┘
                    │
        ┌───────────▼──────────┐
        │   Report Generator   │
        │   HTML (standalone)  │
        │   JSON (structured)  │
        └───────────┬──────────┘
                    │
        ┌───────────▼──────────┐
        │  Dashboard + API     │
        │  WebSocket progress  │
        └──────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔍 Vulnerability Detections

<details>
<summary><b>🚨 Service Exposure (Port-Based)</b></summary>

| Port | Service | Severity | CVSS |
|------|---------|----------|------|
| 23 | Telnet | CRITICAL | 9.8 |
| 6379 | Redis | CRITICAL | 9.8 |
| 2375 | Docker API | CRITICAL | 9.8 |
| 9200 | Elasticsearch | CRITICAL | 9.8 |
| 27017 | MongoDB | CRITICAL | 9.8 |
| 445 | SMB | HIGH | 8.1 |
| 3389 | RDP | HIGH | 8.1 |
| 5900 | VNC | HIGH | 8.1 |
| 21 | FTP | HIGH | 7.5 |
| 3306 | MySQL | HIGH | 7.5 |

</details>

<details>
<summary><b>🎯 Banner-Based Detections</b></summary>

| Pattern | Detection |
|---------|-----------|
| `OpenSSH [1-6]` | Outdated SSH with known CVEs |
| `Apache/2.[0-3]` | End-of-life Apache version |
| `vsftpd 2.3.4` | Backdoored vsftpd (CVE-2011-2523) |

</details>

<details>
<summary><b>🔐 TLS Weaknesses</b></summary>

| Check | Severity |
|-------|----------|
| TLS 1.0 supported | HIGH |
| TLS 1.1 supported | HIGH |
| RC4/DES/EXPORT cipher | CRITICAL |
| Certificate expired | CRITICAL |
| Expiring in < 30 days | MEDIUM |

</details>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/breach.git
cd breach

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python app.py
# → http://localhost:5003
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/breach.git
cd breach
docker build -t breach .
docker run -p 5003:5003 breach
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Start a scan
POST /api/scan
{
  "target": "192.168.1.0/24",
  "scan_type": "standard",
  "options": {"top_ports": true, "dns": true, "ssl": true}
}
# → {"scan_id": "<id>", "status": "running"}

# Get results
GET /api/scan/<scan_id>

# Generate report
POST /api/report/generate
{"scan_id": "<id>", "format": "html"}
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
breach/
├── app.py                     # Flask application & REST API
├── wsgi.py                    # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── core/
│   ├── scanner.py             # Port scan, banner grab, SSL check
│   ├── recon.py               # DNS recon, subdomain enum
│   ├── vuln_checker.py        # Port/banner/TLS vuln correlation
│   └── report_generator.py    # HTML + JSON reports
│
├── templates/
│   ├── index.html             # Scanner dashboard
│   ├── results.html           # Scan results
│   └── reports.html           # Report archive
│
├── static/                    # CSS + JavaScript
└── tests/                     # 12 pytest tests
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📋 Authorized Use

✅ Authorized penetration testing (written permission) &nbsp;|&nbsp; ✅ Internal assessments &nbsp;|&nbsp; ✅ CTF competitions &nbsp;|&nbsp; ✅ Security labs

❌ Unauthorized scanning &nbsp;|&nbsp; ❌ Third-party infrastructure without engagement letter

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"Built to eliminate the 2-hour manual recon phase of every engagement — systematic, repeatable, and properly documented."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/breach?style=social)](https://github.com/RohitKumarReddySakam/breach)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
