#!/usr/bin/env python3
"""
IOC Enricher — Threat Hunting Lab
Analyst: Ilyas Hodaiby
Enriches IOCs (IPs, hashes, domains) using VirusTotal and AbuseIPDB APIs
"""

import requests
import json
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

# IOCs from Threat Hunting Lab IR-2025-001
IOCS = {
    "ips": [
        "171.251.232.40",
        "68.183.47.68",
        "160.187.246.170",
        "10.10.157.155",
        "10.14.94.82"
    ],
    "domains": [
        "update-service.xyz"
    ],
    "urls": [
        "/wp-corn.php",
        "/wp-login.php"
    ]
}

# ─── FUNCTIONS ────────────────────────────────────────────────────────────────

def check_ip_virustotal(ip: str) -> dict:
    """Check IP reputation on VirusTotal"""
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(
            f"{VT_BASE}/ip_addresses/{ip}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0),
                "country": data["data"]["attributes"].get("country", "Unknown"),
                "asn": data["data"]["attributes"].get("asn", "Unknown"),
                "source": "VirusTotal"
            }
    except Exception as e:
        return {"ip": ip, "error": str(e)}
    return {"ip": ip, "error": "No response"}


def check_ip_abuseipdb(ip: str) -> dict:
    """Check IP reputation on AbuseIPDB"""
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(
            f"{ABUSE_BASE}/check",
            headers=headers,
            params=params,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "ip": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "source": "AbuseIPDB"
            }
    except Exception as e:
        return {"ip": ip, "error": str(e)}
    return {"ip": ip, "error": "No response"}


def enrich_all_iocs():
    """Enrich all IOCs and print results"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  IOC ENRICHER — Threat Hunting Lab IR-2025-001")
    print(f"  Analyst: Ilyas Hodaiby")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    results = []

    for ip in IOCS["ips"]:
        print(f"{Fore.YELLOW}[*] Checking IP: {ip}{Style.RESET_ALL}")

        # VirusTotal check
        vt_result = check_ip_virustotal(ip)
        if "malicious" in vt_result:
            color = Fore.RED if vt_result["malicious"] > 0 else Fore.GREEN
            print(f"  {color}[VT] Malicious: {vt_result['malicious']}/91 | "
                  f"Country: {vt_result['country']} | "
                  f"ASN: {vt_result['asn']}{Style.RESET_ALL}")

        # AbuseIPDB check
        abuse_result = check_ip_abuseipdb(ip)
        if "abuse_score" in abuse_result:
            color = Fore.RED if abuse_result["abuse_score"] > 0 else Fore.GREEN
            print(f"  {color}[Abuse] Score: {abuse_result['abuse_score']}% | "
                  f"Reports: {abuse_result['total_reports']} | "
                  f"ISP: {abuse_result['isp']}{Style.RESET_ALL}")

        results.append({"ip": ip, "vt": vt_result, "abuse": abuse_result})
        print()

    # Save results
    output_file = f"ioc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"{Fore.GREEN}[+] Report saved: {output_file}{Style.RESET_ALL}")
    return results


def print_summary(results: list):
    """Print summary of findings"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("  ENRICHMENT SUMMARY")
    print(f"{'='*60}{Style.RESET_ALL}")

    malicious_ips = []
    for r in results:
        vt = r.get("vt", {})
        if vt.get("malicious", 0) > 0:
            malicious_ips.append(r["ip"])

    if malicious_ips:
        print(f"\n{Fore.RED}[!] MALICIOUS IPs FOUND:{Style.RESET_ALL}")
        for ip in malicious_ips:
            print(f"  → {ip}")
    else:
        print(f"\n{Fore.GREEN}[+] No malicious IPs detected{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Total IOCs checked: {len(results)}{Style.RESET_ALL}\n")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    results = enrich_all_iocs()
    print_summary(results)
