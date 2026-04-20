"""
Reconnaissance module — DNS enumeration, WHOIS, subdomain discovery.
Pure Python, no external CLI tools.
"""
import socket
import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def dns_lookup(target: str) -> dict:
    """Perform DNS record enumeration for a domain."""
    result = {
        "target": target,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname": None,
        "reverse_dns": None,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Try basic socket resolution
    try:
        ip = socket.gethostbyname(target)
        result["a_records"] = [ip]
    except Exception:
        pass

    if not DNS_AVAILABLE:
        return result

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        for rtype in ("A", "MX", "NS", "TXT"):
            try:
                answers = resolver.resolve(target, rtype)
                key = f"{rtype.lower()}_records"
                if rtype == "MX":
                    result[key] = [str(r.exchange).rstrip(".") for r in answers]
                elif rtype == "NS":
                    result[key] = [str(r).rstrip(".") for r in answers]
                elif rtype == "TXT":
                    result[key] = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
                else:
                    result[key] = [str(r) for r in answers]
            except Exception:
                pass

        # Reverse DNS
        if result["a_records"]:
            try:
                rev = dns.reversename.from_address(result["a_records"][0])
                rdns = resolver.resolve(rev, "PTR")
                result["reverse_dns"] = str(list(rdns)[0]).rstrip(".")
            except Exception:
                pass

    except Exception as e:
        logger.debug(f"DNS lookup error for {target}: {e}")

    return result


def enumerate_subdomains(domain: str, wordlist: list = None) -> list:
    """Attempt subdomain enumeration from a wordlist."""
    if wordlist is None:
        wordlist = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "vpn", "ssh", "remote", "portal", "dashboard",
            "app", "cdn", "static", "media", "blog", "docs",
        ]

    found = []
    for sub in wordlist:
        candidate = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(2)
            ip = socket.gethostbyname(candidate)
            found.append({"subdomain": candidate, "ip": ip})
        except Exception:
            pass

    return found


def get_service_info(host: str, port: int, banner: str) -> dict:
    """Build service fingerprint from banner and port."""
    info = {"port": port, "banner": banner[:200] if banner else "", "version": None, "product": None}

    version_patterns = [
        (r"OpenSSH[_\s]+([\d.]+)", "OpenSSH"),
        (r"Apache/([\d.]+)", "Apache httpd"),
        (r"nginx/([\d.]+)", "nginx"),
        (r"Microsoft-IIS/([\d.]+)", "IIS"),
        (r"vsftpd\s+([\d.]+)", "vsftpd"),
        (r"ProFTPD\s+([\d.]+)", "ProFTPD"),
        (r"Postfix\s+\(([^)]+)\)", "Postfix"),
        (r"MySQL\s+([\d.]+)", "MySQL"),
    ]

    for pattern, product in version_patterns:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            info["product"] = product
            info["version"] = m.group(1)
            break

    return info
