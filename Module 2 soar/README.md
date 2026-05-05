# Module 2 — SOAR Automation

**Tools:** ElastAlert · TheHive · Cortex  
**Analyst:** Ilyas Hodaiby  
**Status:** Complete ✅

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
