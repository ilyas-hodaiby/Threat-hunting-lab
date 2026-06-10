# Module 5 — Threat Intelligence

**Focus:** IOC Correlation & Threat Actor Profiling  
**Analyst:** Ilyas Hodaiby  
**Status:** Complete ✅

---

## Overview

This module correlates IOCs discovered during the 5 threat hunts against threat intelligence sources to identify threat actors, campaigns, and infrastructure patterns.

---

## IOC Enrichment Results

### IP Reputation Analysis

| IP | Country | ASN | Reputation | Source |
|----|---------|-----|------------|--------|
| 10.10.157.155 | Internal | — | Attacker pivot | Hunt 01/03 |
| 171.251.232.40 | Vietnam | AS45899 | Malicious — Hydra attacks | VirusTotal |
| 68.183.47.68 | US | AS14061 DigitalOcean | VPS — C2 hosting | AbuseIPDB |
| 160.187.246.170 | South Korea | AS4766 | Scanner — IoT exploits | Shodan |
| 167.94.145.108 | US | AS398705 | CensysInspect scanner | Censys |

---

## Threat Actor Profiling

### Actor 1 — WordPress Attacker (171.251.232.40)

**Profile:**
- Uses Hydra for automated credential attacks
- Targets WordPress installations
- Deploys web shells disguised as cron files
- Establishes persistent C2 via POST requests
- TTPs match opportunistic cybercriminal profile

**Campaign Pattern:**
