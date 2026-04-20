"""
Vulnerability checker — identifies issues based on open ports, banners, and service versions.
No exploitation — passive identification only.
"""
import re
import logging

logger = logging.getLogger(__name__)

# (port, condition, severity, title, description, recommendation, cve_refs)
PORT_VULNS = [
    (23, None, "CRITICAL", "Telnet Exposed",
     "Telnet transmits credentials and data in plaintext.",
     "Disable Telnet; use SSH instead.", ["CWE-319"]),

    (21, None, "HIGH", "FTP Service Exposed",
     "FTP may allow anonymous login and transmits credentials in cleartext.",
     "Disable anonymous FTP; use SFTP/FTPS.", ["CWE-319"]),

    (445, None, "HIGH", "SMB Service Exposed",
     "SMB exposed to network; risk of EternalBlue and related exploits.",
     "Restrict SMB access; apply patches; disable SMBv1.", ["CVE-2017-0144"]),

    (3389, None, "HIGH", "RDP Exposed",
     "RDP exposed externally; risk of BlueKeep and brute force.",
     "Restrict RDP to VPN; enable NLA; apply patches.", ["CVE-2019-0708"]),

    (5900, None, "MEDIUM", "VNC Exposed",
     "VNC remote desktop may lack strong authentication.",
     "Restrict VNC access; enforce authentication.", []),

    (6379, None, "CRITICAL", "Redis Exposed Without Auth",
     "Redis commonly deployed without authentication; allows data theft and RCE.",
     "Bind to localhost; enable requirepass.", ["CVE-2022-0543"]),

    (27017, None, "HIGH", "MongoDB Exposed",
     "MongoDB may be accessible without authentication.",
     "Enable MongoDB authentication; restrict network access.", []),

    (9200, None, "HIGH", "Elasticsearch Exposed",
     "Elasticsearch API may be accessible without authentication.",
     "Enable security features; restrict network access.", []),

    (2375, None, "CRITICAL", "Docker Daemon Exposed",
     "Unauthenticated Docker daemon allows full host compromise.",
     "Remove external exposure; use TLS authentication.", []),

    (4444, None, "CRITICAL", "Metasploit Default Port Open",
     "Port 4444 is Metasploit's default listener port.",
     "Investigate immediately — may indicate active C2.", []),

    (8888, None, "MEDIUM", "Jupyter Notebook Exposed",
     "Jupyter Notebook may allow unauthenticated code execution.",
     "Add authentication; restrict network access.", []),
]

# Banner-based vulnerability patterns
BANNER_VULNS = [
    (r"OpenSSH[_\s]+(5\.|6\.[0-6])", "HIGH",
     "Outdated OpenSSH Version",
     "OpenSSH version is below 7.0 and may contain critical vulnerabilities.",
     "Upgrade to OpenSSH 9.x.", ["CVE-2016-0777", "CVE-2016-0778"]),

    (r"Apache/(1\.|2\.[0-3])", "HIGH",
     "Outdated Apache Version",
     "Apache version is outdated and may contain unpatched CVEs.",
     "Upgrade to Apache 2.4.57+.", []),

    (r"nginx/1\.(1[0-7])\.", "MEDIUM",
     "Outdated nginx Version",
     "nginx version may be missing security patches.",
     "Upgrade to latest stable nginx.", []),

    (r"Microsoft-IIS/[456789]", "MEDIUM",
     "Older IIS Version Detected",
     "IIS version may have unpatched vulnerabilities.",
     "Upgrade to IIS 10 and apply latest patches.", []),

    (r"vsftpd\s+2\.(0\.|1\.|2\.[0-2])", "HIGH",
     "Vulnerable vsftpd Version",
     "vsftpd 2.3.4 contained a backdoor; older versions have vulnerabilities.",
     "Upgrade to vsftpd 3.x.", ["CVE-2011-2523"]),

    (r"220.*\bFTP\b", "LOW",
     "FTP Banner Disclosed",
     "FTP server exposes version information in banner.",
     "Suppress FTP banner or remove version info.", []),

    (r"Server:\s*Apache", "INFO",
     "Apache Server Header Disclosed",
     "Web server discloses technology via Server header.",
     "Set ServerTokens Prod in Apache config.", []),
]

# TLS/SSL issues
TLS_VULNS = [
    ("TLSv1", "HIGH", "TLS 1.0 Enabled",
     "TLS 1.0 is deprecated and vulnerable to BEAST and POODLE attacks.",
     "Disable TLS 1.0 and 1.1; enable TLS 1.2/1.3 only.", ["CVE-2014-3566"]),

    ("TLSv1.1", "MEDIUM", "TLS 1.1 Enabled",
     "TLS 1.1 is deprecated; should be disabled.",
     "Disable TLS 1.1; use TLS 1.2/1.3.", []),

    ("RC4", "HIGH", "Weak RC4 Cipher Suite",
     "RC4 cipher is cryptographically broken.",
     "Remove RC4 from cipher suite configuration.", ["CVE-2015-2808"]),

    ("DES", "HIGH", "Weak DES/3DES Cipher",
     "DES and 3DES ciphers are vulnerable to Sweet32 attacks.",
     "Remove DES/3DES from cipher configuration.", ["CVE-2016-2183"]),

    ("EXPORT", "CRITICAL", "Export-Grade Cipher (FREAK)",
     "Export cipher suites are vulnerable to FREAK attack.",
     "Remove all EXPORT cipher suites immediately.", ["CVE-2015-0204"]),
]


def check_port_vulns(open_ports: list) -> list:
    """Check open ports against known vulnerability patterns."""
    findings = []
    port_set = {p["port"] for p in open_ports}
    port_banners = {p["port"]: p.get("banner", "") for p in open_ports}

    for port, condition, severity, title, desc, rec, cves in PORT_VULNS:
        if port in port_set:
            findings.append({
                "title": title,
                "severity": severity,
                "port": port,
                "description": desc,
                "recommendation": rec,
                "cve_ids": cves,
                "evidence": f"Port {port} is open",
            })

    # Check banners
    for port, banner in port_banners.items():
        if not banner:
            continue
        for pattern, severity, title, desc, rec, cves in BANNER_VULNS:
            if re.search(pattern, banner, re.IGNORECASE):
                findings.append({
                    "title": title,
                    "severity": severity,
                    "port": port,
                    "description": desc,
                    "recommendation": rec,
                    "cve_ids": cves,
                    "evidence": f"Banner: {banner[:100]}",
                })

    return findings


def check_ssl_vulns(ssl_info: dict, port: int) -> list:
    """Check SSL/TLS configuration for vulnerabilities."""
    if not ssl_info:
        return []

    findings = []
    version = ssl_info.get("tls_version", "")
    cipher = ssl_info.get("cipher", "")
    expires = ssl_info.get("expires", "")

    for tls_ver, severity, title, desc, rec, cves in TLS_VULNS:
        if tls_ver in version or (cipher and tls_ver in cipher):
            findings.append({
                "title": title,
                "severity": severity,
                "port": port,
                "description": desc,
                "recommendation": rec,
                "cve_ids": cves,
                "evidence": f"TLS version: {version}, Cipher: {cipher}",
            })

    if not ssl_info.get("valid") and ssl_info.get("error"):
        findings.append({
            "title": "SSL Certificate Issue",
            "severity": "MEDIUM",
            "port": port,
            "description": f"SSL error: {ssl_info['error']}",
            "recommendation": "Obtain a valid certificate from a trusted CA.",
            "cve_ids": [],
            "evidence": str(ssl_info.get("error", "")),
        })

    return findings


def calculate_risk_score(findings: list) -> float:
    """Calculate a 0-100 risk score from findings."""
    weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}
    score = sum(weights.get(f.get("severity", "INFO"), 0) for f in findings)
    return min(round(score, 1), 100.0)
