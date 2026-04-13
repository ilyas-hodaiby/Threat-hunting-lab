# 🔍 Threat Hunting Lab 

> **Ilyas Hodaiby** — A comprehensive threat hunting and incident response lab demonstrating SOC Analyst capabilities.
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%206%25-red)](https://tryhackme.com/p/ilyas.ho)
[![GitHub](https://img.shields.io/badge/SOC%20Homelab-View%20Project-blue)](https://github.com/ilyas-hodaiby/soc-homelab)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange)](https://attack.mitre.org)

---

## 📌 Overview

This project documents a complete SOC pipeline from threat hunting through to incident response:

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
│

---
```
## 🎯 Modules Overview

| Module | Focus | Tools | Status |
|---|---|---|---|
| 1 — Threat Hunting | 5 hunt scenarios | Splunk, ELK |

## 👤 About

**Ilyas Hodaiby** | Junior SOC Analyst → N2 Level

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/ilyas-hodaiby-7216a3238)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%206%25-red)](https://tryhackme.com/p/ilyas.ho)
[![SOC Lab](https://img.shields.io/badge/SOC-Homelab-green)](https://github.com/ilyas-hodaiby/soc-homelab)
