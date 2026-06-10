#!/usr/bin/env python3
"""
SOAR Lite — Threat Hunting Lab
Analyst: Ilyas Hodaiby
Lightweight SOAR automation — alert triage,
IOC enrichment, and TheHive case creation
"""

import requests
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ─── CONFIG ───────────────────────────────────────────────────────────────────

THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "YOUR_THEHIVE_API_KEY"

CORTEX_URL = "http://localhost:9001"
CORTEX_API_KEY = "YOUR_CORTEX_API_KEY"

# Alert severity mapping
SEVERITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

# ─── THEHIVE FUNCTIONS ────────────────────────────────────────────────────────

def create_thehive_alert(title: str, description: str,
                          severity: str, iocs: list) -> dict:
    """Create alert in TheHive"""
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    artifacts = []
    for ioc in iocs:
        artifact = {
            "dataType": ioc["type"],
            "data": ioc["value"],
            "message": ioc.get("context", "")
        }
        artifacts.append(artifact)

    payload = {
        "title": title,
        "description": description,
        "severity": SEVERITY.get(severity, 2),
        "date": int(datetime.now().timestamp() * 1000),
        "tags": ["threat-hunting", "IR-2025-001", "automated"],
        "artifacts": artifacts,
        "source": "Threat Hunting Lab — SOAR Lite",
        "sourceRef": f"THL-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    }

    try:
        response = requests.post(
            f"{THEHIVE_URL}/api/alert",
            headers=headers,
            json=payload,
            timeout=10
        )
        if response.status_code in [200, 201]:
            return response.json()
        else:
            return {"error": f"Status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def create_thehive_case(title: str, description: str,
                         severity: str, tasks: list) -> dict:
    """Create case in TheHive"""
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "title": title,
        "description": description,
        "severity": SEVERITY.get(severity, 2),
        "tags": ["threat-hunting", "IR-2025-001"],
        "tasks": [{"title": task} for task in tasks]
    }

    try:
        response = requests.post(
            f"{THEHIVE_URL}/api/case",
            headers=headers,
            json=payload,
            timeout=10
        )
        if response.status_code in [200, 201]:
            return response.json()
        else:
            return {"error": f"Status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ─── CORTEX FUNCTIONS ─────────────────────────────────────────────────────────

def run_cortex_analyzer(ioc_value: str,
                         ioc_type: str,
                         analyzer: str) -> dict:
    """Run Cortex analyzer on IOC"""
    headers = {
        "Authorization": f"Bearer {CORTEX_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "dataType": ioc_type,
        "data": ioc_value,
        "analyzerId": analyzer
    }

    try:
        response = requests.post(
            f"{CORTEX_URL}/api/analyzer/{analyzer}/run",
            headers=headers,
            json=payload,
            timeout=30
        )
        if response.status_code in [200, 201]:
            return response.json()
        else:
            return {"error": f"Status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ─── PLAYBOOKS ────────────────────────────────────────────────────────────────

def playbook_brute_force(src_ip: str, target_user: str,
                          attempt_count: int):
    """Automated response to brute force detection"""
    print(f"\n{Fore.RED}[!] PLAYBOOK: Brute Force Response{Style.RESET_ALL}")
    print(f"    IP: {src_ip} | User: {target_user} | Attempts: {attempt_count}")

    # Step 1 — Create TheHive alert
    print(f"\n{Fore.YELLOW}[*] Step 1: Creating TheHive alert...{Style.RESET_ALL}")
    alert = create_thehive_alert(
        title=f"Brute Force Detected — {src_ip} → {target_user}",
        description=(
            f"Brute force attack detected from {src_ip} "
            f"targeting account {target_user}. "
            f"{attempt_count} failed attempts detected. "
            f"MITRE ATT&CK: T1110.001"
        ),
        severity="HIGH",
        iocs=[
            {"type": "ip", "value": src_ip, "context": "Brute force source"},
            {"type": "other", "value": target_user, "context": "Targeted account"}
        ]
    )

    if "error" not in alert:
        print(f"{Fore.GREEN}    [+] Alert created: {alert.get('id', 'N/A')}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}    [-] Alert failed: {alert['error']}{Style.RESET_ALL}")

    # Step 2 — Enrich IP via Cortex
    print(f"\n{Fore.YELLOW}[*] Step 2: Enriching IP via Cortex...{Style.RESET_ALL}")
    enrichment = run_cortex_analyzer(src_ip, "ip", "VirusTotal_GetReport_3_0")
    print(f"    Result: {json.dumps(enrichment, indent=2)[:100]}...")

    # Step 3 — Recommended actions
    print(f"\n{Fore.CYAN}[*] Step 3: Recommended Actions:{Style.RESET_ALL}")
    actions = [
        f"Block IP {src_ip} at firewall",
        f"Reset password for account {target_user}",
        "Enable MFA on affected account",
        "Review all successful logins from this IP",
        "Check for lateral movement post-compromise"
    ]
    for i, action in enumerate(actions, 1):
        print(f"    {i}. {action}")


def playbook_c2_detection(c2_ip: str, backdoor_url: str):
    """Automated response to C2 detection"""
    print(f"\n{Fore.RED}[!] PLAYBOOK: C2 Detection Response{Style.RESET_ALL}")
    print(f"    C2 IP: {c2_ip} | Backdoor: {backdoor_url}")

    # Create TheHive case
    print(f"\n{Fore.YELLOW}[*] Creating TheHive case...{Style.RESET_ALL}")
    case = create_thehive_case(
        title=f"C2 Channel Detected — {c2_ip}",
        description=(
            f"C2 communication detected from {c2_ip} "
            f"via backdoor file {backdoor_url}. "
            f"Beaconing every ~6 seconds. "
            f"MITRE ATT&CK: T1071.001, T1505.003"
        ),
        severity="CRITICAL",
        tasks=[
            "Block C2 IP at firewall",
            "Remove backdoor file from web server",
            "Forensic analysis of web server",
            "Identify all commands executed via C2",
            "Assess data exfiltration scope",
            "Patch WordPress installation"
        ]
    )

    if "error" not in case:
        print(f"{Fore.GREEN}    [+] Case created: {case.get('id', 'N/A')}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}    [-] Case failed: {case['error']}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}[*] Recommended Actions:{Style.RESET_ALL}")
    actions = [
        f"Immediately block {c2_ip} at WAF",
        f"Remove {backdoor_url} from web server",
        "Capture memory image before remediation",
        "Review all POST requests to backdoor URL",
        "Rotate all WordPress credentials"
    ]
    for i, action in enumerate(actions, 1):
        print(f"    {i}. {action}")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def run_ir_2025_001():
    """Run automated response for IR-2025-001"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  SOAR LITE — IR-2025-001 Automated Response")
    print(f"  Analyst: Ilyas Hodaiby")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}{Style.RESET_ALL}")

    # Playbook 1 — Brute Force
    playbook_brute_force(
        src_ip="10.10.157.155",
        target_user="oliver.thompson",
        attempt_count=7
    )

    print(f"\n{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")

    # Playbook 2 — C2 Detection
    playbook_c2_detection(
        c2_ip="171.251.232.40",
        backdoor_url="/wp-corn.php"
    )

    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"  SOAR LITE — Playbooks Complete")
    print(f"{'='*60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    run_ir_2025_001()
