# Incident Response Report
## IR-2025-001 — Multi-Stage Attack Campaign

**Classification:** Confidential  
**Analyst:** Ilyas Hodaiby  
**Date:** 2025-09-14  
**Status:** Closed ✅  
**Severity:** Critical  

---

## Executive Summary

A multi-stage attack campaign was detected targeting a Windows enterprise environment and a public-facing WordPress web server. The attacker conducted credential brute forcing, established persistence via a backdoor account and web shell, and maintained C2 communication through a fake WordPress cron file. The attack spanned approximately 45 minutes from initial access to C2 establishment.

---

## Timeline of Events

| Time | Event |
|------|-------|
| 2025-08-30 09:50:02 | Brute force begins — 7 failed logins against oliver.thompson |
| 2025-08-30 09:50:24 | Brute force succeeds — oliver.thompson compromised |
| 2025-08-30 09:42:00 | Lateral movement spike — 13 logins in 30 seconds |
| 2022-05-11 22:32:18 | Persistence — Cybertees\James creates backdoor account A1berto |
| 2025-09-14 21:20:00 | Web attack begins — Hydra targets WordPress login |
| 2025-09-14 21:20:34 | 316 Hydra requests in 60 seconds — wp-login.php |
| 2025-09-14 21:26:28 | C2 established — wp-corn.php first POST request |
| 2025-09-14 22:04:01 | C2 beaconing — wp-corn.php every 6 seconds |

---

## Attack Chain — MITRE ATT&CK
