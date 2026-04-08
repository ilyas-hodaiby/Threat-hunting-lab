# 🔍 Threat Hunting Lab — Real Dataset Analysis

> **Ilyas Hodaiby** — Hands-on threat hunting project using real-world datasets, Splunk, ELK Stack, and Python automation. Built on skills from 1+ year SOC experience and MSc Computer Science studies.

---

## 📌 Overview

This project documents structured threat hunting investigations against real-world attack datasets. Each hunt follows a hypothesis-driven methodology aligned with MITRE ATT&CK, combining the detection engineering skills developed during my time as a Junior SOC Analyst with advanced data analysis techniques from my MSc studies.

The goal is to simulate how a real threat hunter operates — not just responding to alerts, but proactively searching for hidden adversary behaviour across endpoint and network telemetry.

---

## 🧠 Methodology

Each hunt follows this structured approach:

```
1. Hypothesis Formation
   └── Based on threat intelligence or MITRE ATT&CK technique

2. Data Collection
   └── Identify relevant log sources and datasets

3. Investigation
   └── Build and execute queries (Splunk / ELK)
   └── Analyse patterns and anomalies

4. IOC Extraction
   └── Document indicators of compromise

5. MITRE ATT&CK Mapping
   └── Map findings to specific techniques

6. Reporting
   └── Structured hunt report with findings
```

---

## 🛠️ Tools & Technologies

| Tool | Purpose |
|---|---|
| **Splunk** | Primary SIEM — log search and correlation |
| **ELK Stack** | Secondary analysis — Elasticsearch + Kibana |
| **Python** | Automation — IOC enrichment and log parsing |
