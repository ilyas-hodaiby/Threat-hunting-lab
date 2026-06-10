#!/usr/bin/env python3
"""
Log Parser — Threat Hunting Lab
Analyst: Ilyas Hodaiby
Parses Windows Event Logs and Web Access Logs
to detect IOCs from IR-2025-001
"""

import re
import json
import sys
from datetime import datetime
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# ─── CONFIG ───────────────────────────────────────────────────────────────────

# IOCs from IR-2025-001
MALICIOUS_IPS = {
    "171.251.232.40",
    "68.183.47.68",
    "160.187.246.170",
    "10.10.157.155",
    "10.14.94.82"
}

MALICIOUS_USERS = {"A1berto", "oliver.thompson"}
MALICIOUS_TOOLS = ["Hydra", "sqlmap", "nikto", "nmap"]
SUSPICIOUS_URLS = ["/wp-corn.php", "/wp-login.php", "/boaform/admin/formLogin"]
BRUTE_FORCE_THRESHOLD = 5

# ─── PARSERS ──────────────────────────────────────────────────────────────────

def parse_web_log_line(line: str) -> dict:
    """Parse Apache/Nginx access log line"""
    pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/[\d.]+"\s+'
        r'(?P<status>\d+)\s+(?P<bytes>\d+)'
        r'(?:\s+"[^"]*"\s+"(?P<useragent>[^"]*)")?'
    )
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return {}


def parse_windows_event(line: str) -> dict:
    """Parse Windows Event Log line"""
    result = {}
    patterns = {
        "event_code": r'EventCode[=:\s]+(\d+)',
        "src_ip": r'Source.*?(\d+\.\d+\.\d+\.\d+)',
        "username": r'(?:Account Name|User)[\s:]+(\S+)',
        "computer": r'Computer(?:Name)?[\s:]+(\S+)',
        "logon_type": r'Logon Type[\s:]+(\d+)'
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            result[key] = match.group(1)
    return result


# ─── DETECTORS ────────────────────────────────────────────────────────────────

def detect_brute_force(log_lines: list) -> list:
    """Detect brute force patterns from failed logins"""
    failed_logins = defaultdict(int)
    alerts = []

    for line in log_lines:
        parsed = parse_web_log_line(line)
        if parsed:
            # Check for Hydra user agent
            ua = parsed.get("useragent", "")
            if any(tool.lower() in ua.lower() for tool in MALICIOUS_TOOLS):
                alerts.append({
                    "type": "ATTACK_TOOL_DETECTED",
                    "severity": "HIGH",
                    "ip": parsed.get("ip"),
                    "tool": ua,
                    "url": parsed.get("url"),
                    "timestamp": parsed.get("time")
                })

            # Count requests per IP per URL
            ip = parsed.get("ip", "")
            url = parsed.get("url", "")
            if "/wp-login" in url or "/login" in url:
                failed_logins[ip] += 1

    # Alert on IPs exceeding threshold
    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "type": "BRUTE_FORCE_DETECTED",
                "severity": "CRITICAL",
                "ip": ip,
                "attempts": count,
                "description": f"Brute force detected — {count} login attempts"
            })

    return alerts


def detect_malicious_ips(log_lines: list) -> list:
    """Detect known malicious IPs in logs"""
    alerts = []
    for line in log_lines:
        for ip in MALICIOUS_IPS:
            if ip in line:
                alerts.append({
                    "type": "KNOWN_MALICIOUS_IP",
                    "severity": "HIGH",
                    "ip": ip,
                    "line": line.strip()
                })
    return alerts


def detect_suspicious_urls(log_lines: list) -> list:
    """Detect suspicious URL patterns"""
    alerts = []
    for line in log_lines:
        parsed = parse_web_log_line(line)
        if parsed:
            url = parsed.get("url", "")
            for suspicious_url in SUSPICIOUS_URLS:
                if suspicious_url in url:
                    alerts.append({
                        "type": "SUSPICIOUS_URL_ACCESS",
                        "severity": "HIGH",
                        "ip": parsed.get("ip"),
                        "url": url,
                        "timestamp": parsed.get("time"),
                        "description": f"Suspicious URL accessed: {url}"
                    })
    return alerts


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def analyze_log_file(filepath: str):
    """Analyze a log file for threats"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  LOG PARSER — Threat Hunting Lab")
    print(f"  Analyst: Ilyas Hodaiby")
    print(f"  File: {filepath}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found: {filepath}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.YELLOW}[*] Loaded {len(lines)} log lines{Style.RESET_ALL}\n")

    all_alerts = []

    # Run detectors
    print(f"{Fore.YELLOW}[*] Running brute force detection...{Style.RESET_ALL}")
    all_alerts.extend(detect_brute_force(lines))

    print(f"{Fore.YELLOW}[*] Checking for malicious IPs...{Style.RESET_ALL}")
    all_alerts.extend(detect_malicious_ips(lines))

    print(f"{Fore.YELLOW}[*] Scanning for suspicious URLs...{Style.RESET_ALL}")
    all_alerts.extend(detect_suspicious_urls(lines))

    # Print results
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  ANALYSIS RESULTS — {len(all_alerts)} alerts found")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    critical = [a for a in all_alerts if a.get("severity") == "CRITICAL"]
    high = [a for a in all_alerts if a.get("severity") == "HIGH"]

    if critical:
        print(f"{Fore.RED}[CRITICAL] {len(critical)} critical alerts:{Style.RESET_ALL}")
        for alert in critical:
            print(f"  → {alert['type']}: {alert.get('ip', 'N/A')} "
                  f"— {alert.get('description', '')}")

    if high:
        print(f"\n{Fore.YELLOW}[HIGH] {len(high)} high alerts:{Style.RESET_ALL}")
        for alert in high[:10]:
            print(f"  → {alert['type']}: {alert.get('ip', 'N/A')}")

    # Save report
    output_file = f"log_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(all_alerts, f, indent=2)

    print(f"\n{Fore.GREEN}[+] Report saved: {output_file}{Style.RESET_ALL}\n")
    return all_alerts


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: python log_parser.py <logfile>{Style.RESET_ALL}")
        print(f"Example: python log_parser.py access.log")
        sys.exit(1)

    analyze_log_file(sys.argv[1])
