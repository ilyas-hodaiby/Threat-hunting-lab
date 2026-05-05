# Module 2 — SOAR Automation

**Tools:** ElastAlert · TheHive · Cortex  
**Analyst:** Ilyas Hodaiby  
**Status:** 

---

## Overview

This module documents the full SOAR pipeline — from alert detection in Splunk through to automated case management and IOC enrichment in TheHive/Cortex. The workflow eliminates manual steps between detection and investigation, reducing mean time to respond.

This directly mirrors the SOAR workflow I operated during my time as a Junior SOC Analyst, where TheHive and Cortex were used daily for case management and automated IOC analysis.

---

## SOAR Workflow

```
1. Splunk detects anomaly
         ↓
2. ElastAlert fires (threshold exceeded)
         ↓
3. TheHive case auto-created with alert metadata pre-filled
         ↓
4. Cortex automatically runs:
   → AbuseIPDB analyser on source IP
   → VirusTotal analyser on file hash
   → Shodan lookup on attacker IP
         ↓
5. Analyst reviews enriched case
         ↓
6. Case closed with full IR report
```
---

## ElastAlert Configuration

```yaml
name: SSH Brute Force — SOAR Trigger
type: frequency
index: wazuh-alerts-*
num_events: 10
timeframe:
  minutes: 5

filter:
  - term:
      rule.id: "5763"

alert:
  - hivealerter

hive_connection:
  hive_host: http://localhost
  hive_port: 9000
  hive_apikey: YOUR_API_KEY

hive_alert_config:
  type: external
  source: ElastAlert
  severity: 2
  tags:
    - brute-force
    - ssh
    - T1110.001
  title: "SSH Brute Force Detected — {data.srcip}"
  description: >
    ElastAlert detected 10+ SSH authentication failures from the same source IP within 5 minutes. Wazuh rule 5763 triggered. Automatic Cortex enrichment initiated.
```
---

## Cortex Analysers Used

| Analyser | IOC Type | What It Returns |
|---|---|---|
| AbuseIPDB | IP address | Abuse score, total reports, country |
| VirusTotal | IP, hash, domain | Detection ratio, malware family |
| Shodan | IP address | Open ports, services, geolocation |
| URLScan | URL/domain | Screenshot, DNS, HTTP headers |

---

## TheHive Case Template

```json
{
  "title": "SSH Brute Force — Automated Detection",
  "severity": 2,
  "tags": ["brute-force", "T1110.001", "automated"],
  "tasks": [
    {
      "title": "1 — Verify alert",
      "description": "Check Splunk for full context"
    },
    {
      "title": "2 — Review Cortex results",
      "description": "Check AbuseIPDB + VirusTotal scores"
    },
    {
      "title": "3 — Check for successful login",
      "description": "Search for EventCode 4624 from attacker IP"
    },
    {
      "title": "4 — Contain if needed",
      "description": "Block attacker IP at firewall"
    },
    {
      "title": "5 — Document and close",
      "description": "Write findings and close case"
    }
  ]
}
```
---

## Results — SOAR vs Manual

| Metric | Manual Process | SOAR Automated |
|---|---|---|
| Time to case creation | 5-10 minutes | < 30 seconds |
| IOC enrichment | 10-15 minutes | < 2 minutes |
| Human error risk | High | Minimal |
| Consistency | Variable | 100% consistent |
| Mean Time to Respond | 20-30 minutes | 5-8 minutes |

---

## SOC Context

From my experience , we used TheHive and Cortex daily. Cases were created manually by N1 analysts and enriched using Cortex analysers. This module automates that entire process — the same outcome but without manual intervention, freeing the analyst to focus on investigation rather than administration.
