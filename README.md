# 🔍 Threat Hunting Lab — Real Dataset Analysis

> **Ilyas Hodaiby** — Hands-on threat hunting project using real-world datasets, Splunk, ELK Stack, and Python automation. Built on skills from 1+ year SOC experience and MSc Computer Science studies.

---

## 📌 Overview

This project documents a complete SOC pipeline from threat hunting through to incident response :

- **Threat Hunting** — 5 hypothesis-driven investigations against real datasets
- **SOAR Automation** — ElastAlert → TheHive → Cortex automated workflow
- **Digital Forensics** — Memory and endpoint artefact analysis
- **Malware Analysis** — Static and dynamic analysis with YARA rules
- **Threat Intelligence** — IOC correlation and threat actor profiling
- **Incident Response** — Full IR lifecycle with formal reporting

---
## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    LAB ENVIRONMENT                       │
│                                                         │
│  ┌──────────┐  attack  ┌──────────────────────────┐    │
│  │  Kali    │─────────►│  Ubuntu 22.04            │    │
│  │  Linux   │          │  Wazuh Agent             │    │
│  │          │          │                          │    │
│  └──────────┘          └────────────┬─────────────┘    │
│                                     │ logs              │
│                                     ▼                   │
│                    ┌────────────────────────────┐       │
│                    │   Splunk Free (Windows)     │       │
│                    │   Log analysis + Hunting    │       │
│                    └──────────────┬─────────────┘       │
│                                   │ alert               │
│                                   ▼                     │
│              ┌────────────────────────────────────┐     │
│              │  SOAR Pipeline                      │     │
│              │  ElastAlert → TheHive → Cortex      │     │
│              └────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```


## 🧠 Methodology

Each hunt follows this structured approach:

```
1. Hypothesis Formation
   └── Based on MITRE ATT&CK technique or threat intelligence

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
| **Wireshark** | Network traffic analysis |
| **MITRE ATT&CK Navigator** | Technique mapping and coverage |
| **VirusTotal API** | IOC reputation checking |
| **AbuseIPDB API** | IP reputation enrichment |
| **Any.run** | Sandbox analysis |
---

## 📂 Repository Structure
```
threat-hunting-lab/
│
├── README.md
│
├── module-1-threat-hunting/
│   ├── README.md
│   ├── hunt-01-lateral-movement/
│   ├── hunt-02-persistence/
│   ├── hunt-03-credential-access/
│   ├── hunt-04-exfiltration/
│   └── hunt-05-c2-detection/
```
## 🎯 Hunt Scenarios
| Hunt | Technique | MITRE ID | Dataset | Status |
|---|---|---|---|---|
| [Lateral Movement Detection](hunts/hunt-01-lateral-movement/) | Pass the Hash / RDP | T1550.002 | BOTS v1 | ✅ Complete |
| [Persistence via Registry](hunts/hunt-02-persistence/) | Registry Run Keys | T1547.001 | EVTX Attack Samples | ✅ Complete |
| [Credential Access](hunts/hunt-03-credential-access/) | OS Credential Dumping | T1003 | BOTS v2 | 🔄 In Progress |
| [Data Exfiltration](hunts/hunt-04-exfiltration/) | Exfil Over C2 | T1041 | Malware Traffic | ⬜ Planned |
| [C2 Detection](hunts/hunt-05-c2-detection/) | Application Layer Protocol | T1071 | PCAP Analysis | ⬜ Planned |

---

## 🔗 Datasets Used

| Dataset | Source | Type |
|---|---|---|
| **BOTS v1 & v2** | Splunk Boss of the SOC | Windows + Network logs |
| **EVTX Attack Samples** | github.com/sbousseaden | Windows Event Logs |
| **OTRF Security Datasets** | github.com/OTRF | Endpoint telemetry |
| **Malware Traffic Analysis** | malware-traffic-analysis.net | PCAP files |
| **Zeek Logs** | zeek.org | Network metadata |

---

## 🤖 Automation Scripts
