"""
Port scanner and host discovery module using native sockets.
No external tools required — pure Python implementation.
"""
import socket
import ssl
import threading
import ipaddress
import subprocess
import platform
import time
import struct
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Well-known service names
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB", 1433: "MSSQL", 1521: "Oracle",
    2222: "SSH-Alt", 4444: "Metasploit", 8081: "HTTP-Alt2", 9090: "Prometheus",
    6443: "Kubernetes", 2379: "etcd", 2380: "etcd-peer", 10250: "Kubelet",
}

BANNER_PROBES = {
    21: b"",
    22: b"",
    25: b"EHLO pentest.local\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",
    143: b"",
}


def ping_host(host: str, timeout: float = 1.0) -> bool:
    """Check if host is alive using ICMP ping."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "1", "-W", str(int(timeout * 1000)), host],
            capture_output=True, timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        # Fallback: try TCP connect to common port
        return tcp_connect(host, 80, timeout) or tcp_connect(host, 22, timeout)


def tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """Attempt TCP connection to determine if port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab service banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            probe = BANNER_PROBES.get(port, b"")
            if probe:
                sock.sendall(probe)
            sock.settimeout(timeout)
            banner = sock.recv(256)
            return banner.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def check_ssl(host: str, port: int, timeout: float = 3.0) -> dict:
    """Check SSL/TLS certificate details."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                version = tls.version()
                return {
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else None,
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "expires": cert.get("notAfter", "") if cert else "",
                    "valid": True,
                }
    except ssl.SSLError as e:
        return {"valid": False, "error": str(e)}
    except Exception:
        return {}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Scan a single port and collect service info."""
    result = {
        "port": port,
        "state": "closed",
        "service": SERVICE_MAP.get(port, "unknown"),
        "banner": "",
        "ssl": {},
    }
    if tcp_connect(host, port, timeout):
        result["state"] = "open"
        result["banner"] = grab_banner(host, port)
        if port in (443, 8443, 8080):
            result["ssl"] = check_ssl(host, port)
    return result


def scan_host(host: str, ports: list, timeout: float = 1.0,
              max_workers: int = 50, progress_cb=None) -> dict:
    """
    Scan multiple ports on a single host concurrently.
    Returns structured scan result.
    """
    start = time.time()
    open_ports = []
    filtered_ports = []
    scanned = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result["state"] == "open":
                    open_ports.append(result)
                scanned += 1
                if progress_cb:
                    progress_cb(scanned, len(ports))
            except Exception:
                scanned += 1

    duration = round(time.time() - start, 2)
    open_ports.sort(key=lambda x: x["port"])

    return {
        "host": host,
        "alive": bool(open_ports),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "scanned_count": scanned,
        "duration_seconds": duration,
        "scan_time": datetime.utcnow().isoformat(),
    }


def expand_targets(target: str) -> list:
    """
    Expand target string to list of IPs.
    Supports: single IP, CIDR notation, hostname.
    """
    targets = []
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 1024:
            raise ValueError("CIDR range too large (max /22)")
        targets = [str(ip) for ip in network.hosts()]
    except ValueError:
        targets = [target]
    return targets


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 2222, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 8888, 9200, 9090, 27017,
]

TOP_1000_PORTS = list(range(1, 1001))
