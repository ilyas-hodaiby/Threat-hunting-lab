# Datasets Used in This Project

## 1. BOTS (Boss of the SOC) — Splunk
**Source:** https://github.com/splunk/botsv1  
**Type:** Windows logs, network traffic, web logs  
**Use:** Hunt 01 (Lateral Movement), Hunt 03 (Credential Access)  
**How to use:**
```bash
# Download and import into Splunk
# Follow instructions at github.com/splunk/botsv1
```
## 2. EVTX Attack Samples
**Source:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  
**Type:** Windows Event Logs (.evtx)  
**Use:** Hunt 02 (Persistence), Hunt 03 (Credential Access)  
**How to use:**
```bash
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
```

## 3. OTRF Security Datasets
**Source:** https://github.com/OTRF/Security-Datasets  
**Type:** Endpoint and network telemetry  
**Use:** Hunt 04 (Exfiltration), Hunt 05 (C2)  
**How to use:**
```bash
git clone https://github.com/OTRF/Security-Datasets
