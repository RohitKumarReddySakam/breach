"""Tests for BREACH penetration testing framework"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.scanner import expand_targets, SERVICE_MAP, COMMON_PORTS
from core.vuln_checker import check_port_vulns, check_ssl_vulns, calculate_risk_score
from core.report_generator import generate_json_report, _risk_grade


def test_expand_single_ip():
    targets = expand_targets("192.168.1.1")
    assert targets == ["192.168.1.1"]


def test_expand_cidr():
    targets = expand_targets("192.168.1.0/30")
    assert len(targets) == 2
    assert "192.168.1.1" in targets


def test_expand_cidr_too_large():
    import pytest
    with pytest.raises(ValueError, match="too large"):
        expand_targets("10.0.0.0/1")


def test_service_map_has_common_ports():
    assert 22 in SERVICE_MAP
    assert 80 in SERVICE_MAP
    assert 443 in SERVICE_MAP
    assert 3389 in SERVICE_MAP


def test_common_ports_list():
    assert len(COMMON_PORTS) > 10
    assert 22 in COMMON_PORTS
    assert 443 in COMMON_PORTS


def test_check_port_vulns_telnet():
    open_ports = [{"port": 23, "banner": "", "service": "Telnet"}]
    findings = check_port_vulns(open_ports)
    assert any(f["severity"] == "CRITICAL" for f in findings)
    assert any("Telnet" in f["title"] for f in findings)


def test_check_port_vulns_redis():
    open_ports = [{"port": 6379, "banner": "", "service": "Redis"}]
    findings = check_port_vulns(open_ports)
    assert any(f["severity"] == "CRITICAL" for f in findings)


def test_check_port_vulns_clean():
    open_ports = [{"port": 443, "banner": "TLS", "service": "HTTPS"}]
    findings = check_port_vulns(open_ports)
    assert isinstance(findings, list)


def test_banner_vuln_openssh_old():
    open_ports = [{"port": 22, "banner": "SSH-2.0-OpenSSH_6.2", "service": "SSH"}]
    findings = check_port_vulns(open_ports)
    assert any("OpenSSH" in f["title"] for f in findings)


def test_calculate_risk_score_empty():
    score = calculate_risk_score([])
    assert score == 0.0


def test_calculate_risk_score_critical():
    findings = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]
    score = calculate_risk_score(findings)
    assert score > 0


def test_risk_grade():
    assert _risk_grade(0) == "A+"
    assert _risk_grade(5) == "A"
    assert _risk_grade(30) == "B"
    assert _risk_grade(90) == "F"


def test_generate_json_report():
    scan = {
        "id": "test-id",
        "target": "192.168.1.1",
        "scan_time": "2025-01-01T00:00:00",
        "open_ports": [{"port": 22, "service": "SSH"}],
        "findings": [{"title": "Test", "severity": "HIGH", "port": 22}],
        "risk_score": 25.0,
    }
    import json
    report = json.loads(generate_json_report(scan))
    assert report["target"] == "192.168.1.1"
    assert len(report["findings"]) == 1
    assert report["summary"]["high"] == 1
