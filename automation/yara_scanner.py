#!/usr/bin/env python3
"""
YARA Scanner — Threat Hunting Lab
Analyst: Ilyas Hodaiby
Scans files and directories using YARA rules
created during malware analysis (Module 4)
"""

import os
import sys
import json
import hashlib
from datetime import datetime
from colorama import Fore, Style, init

try:
    import yara
except ImportError:
    print("Install yara-python: pip install yara-python")
    sys.exit(1)

init(autoreset=True)

# ─── YARA RULES ───────────────────────────────────────────────────────────────

YARA_RULES = {
    "FakeSvchost32": """
rule FakeSvchost32 {
    meta:
        description = "Detects fake svchost32.exe"
        author = "Ilyas Hodaiby"
        date = "2025-09-14"
        severity = "HIGH"
        mitre = "T1543.003"

    strings:
        $path = "C:\\\\Users\\\\Public\\\\svchost32" nocase
        $reg  = "WindowsUpdate32" nocase
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $c2   = "update-service.xyz" nocase

    condition:
        $path or ($api1 and $api2) or $c2
}
""",
    "WPCornWebShell": """
rule WPCornWebShell {
    meta:
        description = "Detects wp-corn.php web shell"
        author = "Ilyas Hodaiby"
        date = "2025-09-14"
        severity = "CRITICAL"
        mitre = "T1505.003"

    strings:
        $eval  = "eval(base64_decode"
        $post  = "doing_wp_corn"
        $cmd   = "$_POST['cmd']"

    condition:
        $eval and ($post or $cmd)
}
""",
    "HydraUserAgent": """
rule HydraUserAgent {
    meta:
        description = "Detects Hydra attack tool in web logs"
        author = "Ilyas Hodaiby"
        date = "2025-09-14"
        severity = "HIGH"
        mitre = "T1110"

    strings:
        $hydra = "Mozilla/5.0 (Hydra)" nocase
        $wplogin = "/wp-login.php"

    condition:
        $hydra or ($hydra and $wplogin)
}
""",
    "BackdoorAccount": """
rule BackdoorAccount {
    meta:
        description = "Detects backdoor account creation commands"
        author = "Ilyas Hodaiby"
        date = "2025-09-14"
        severity = "CRITICAL"
        mitre = "T1136.001"

    strings:
        $cmd1 = "net user /add A1berto" nocase
        $cmd2 = "net user /add" nocase
        $wmic = "wmic" nocase
        $node = "/node:WORKSTATION" nocase

    condition:
        $cmd1 or ($cmd2 and $wmic) or ($wmic and $node)
}
"""
}

# ─── FUNCTIONS ────────────────────────────────────────────────────────────────

def compile_rules() -> yara.Rules:
    """Compile all YARA rules"""
    try:
        combined = "\n".join(YARA_RULES.values())
        rules = yara.compile(source=combined)
        print(f"{Fore.GREEN}[+] Compiled {len(YARA_RULES)} YARA rules{Style.RESET_ALL}")
        return rules
    except yara.SyntaxError as e:
        print(f"{Fore.RED}[!] YARA syntax error: {e}{Style.RESET_ALL}")
        sys.exit(1)


def get_file_hash(filepath: str) -> dict:
    """Calculate MD5 and SHA256 of file"""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    except Exception:
        return {"md5": "error", "sha256": "error"}


def scan_file(filepath: str, rules: yara.Rules) -> list:
    """Scan a single file with YARA rules"""
    matches = []
    try:
        results = rules.match(filepath)
        for match
