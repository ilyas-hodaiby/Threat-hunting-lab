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
Initial Access          Credential Access       Persistence
T1190 WordPress    →    T1110.001 Brute    →    T1136.001 Account
Exploit                 Force oliver.           Creation A1berto
thompson
Lateral Movement        C2                      Exfiltration
T1021 Valid        →    T1071.001 HTTP     →    T1020 Automated
Accounts                POST wp-corn.php        1.5MB via HTTP

---

## Affected Systems

| System | IP | Compromise Level |
|--------|----|-----------------|
| WIN-H015 | 10.10.157.155 target | Full compromise |
| WordPress Server | web-alert index | Web shell installed |
| WORKSTATION6 | Remote WMI target | Backdoor account |

---

## Hunt 01 Findings — Lateral Movement

**Technique:** T1550.002 Pass the Hash  
**Key Evidence:**
- `10.10.157.155` → `oliver.thompson` → `WIN-H015` — 4 successful logins
- `10.14.94.82` → `Administrator` → `WIN-H015` — 4 successful logins
- Burst of 13 logins at 09:42:00 — automated lateral movement tool
- EventCode 4624 LogonType 3 — network authentication

**Detection Query:**
```splunk
index=win-alert EventCode=4624
| stats count by src_ip, user, ComputerName
| sort -count
```

---

## Hunt 02 Findings — Persistence

**Technique:** T1136.001 Create Local Account  
**Key Evidence:**
- `Cybertees\James` executed `net user /add A1berto paw0rd1`
- Used `WMIC.exe /node:WORKSTATION6` — remote execution
- PowerShell → WMIC → net.exe chain at 2022-05-11 22:32:18
- Sysmon EventID 13 — 1,143 registry modifications detected

**Detection Query:**
```splunk
index=main sourcetype=event_logs EventID=1
| where User="Cybertees\\James"
| table _time, Image, ParentImage, CommandLine
```

---

## Hunt 03 Findings — Credential Access

**Technique:** T1110.001 Brute Force  
**Key Evidence:**
- `10.10.157.155` → 7 failed logins (4625) against `oliver.thompson`
- Followed immediately by 4 successful logins (4624)
- All attempts against `WIN-H015` in 22-second window
- Secondary IP `10.14.94.82` also authenticated successfully

**Detection Query:**
```splunk
index=win-alert EventCode=4625 OR EventCode=4624
| stats count by EventCode, src_ip, user
| sort -count
```

---

## Hunt 04 Findings — Web Attack & Exfiltration

**Technique:** T1190 Exploit Public-Facing Application  
**Key Evidence:**
- `171.251.232.40` using Hydra tool — 316 requests to `/wp-login.php`
- `1,595,492 bytes` transferred via WordPress login page
- `/wp-corn.php` backdoor file accessed — fake WordPress cron
- `/boaform/admin/formLogin` — IoT router exploit attempt

**Detection Query:**
```splunk
index=web-alert
| search _raw="*Hydra*"
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```

---

## Hunt 05 Findings — C2 Detection

**Technique:** T1071.001 Web Protocols  
**Key Evidence:**
- `171.251.232.40` → 331 requests spike at 21:20 PM
- `/wp-corn.php` POST requests every ~6 seconds — C2 beaconing
- Hydra tool confirmed via user agent string
- Secondary C2 check-in from `68.183.47.68` at 22:07

**Detection Query:**
```splunk
index=web-alert
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=1m
| stats count by _time, src_ip
| where count > 50
```

---

## Full IOC List

| Type | Value | Hunt | Context |
|------|-------|------|---------|
| IP | 10.10.157.155 | H01, H03 | Primary attacker — brute force |
| IP | 10.14.94.82 | H01, H03 | Secondary attacker |
| IP | 171.251.232.40 | H04, H05 | WordPress attacker — Hydra |
| IP | 68.183.47.68 | H05 | Secondary C2 |
| IP | 160.187.246.170 | H04 | Router exploit |
| User | oliver.thompson | H01, H03 | Compromised account |
| User | Administrator | H01 | Targeted account |
| User | Cybertees\James | H02 | Attacker account |
| Account | A1berto | H02 | Backdoor account |
| Password | paw0rd1 | H02 | Hardcoded credential |
| Host | WIN-H015 | H01, H03 | Compromised host |
| Host | WORKSTATION6 | H02 | Remote target |
| URL | /wp-corn.php | H04, H05 | C2 backdoor |
| URL | /wp-login.php | H04, H05 | Brute force target |
| Tool | Hydra | H04, H05 | Attack tool |
| Tool | WMIC.exe | H02 | Lateral movement |

---

## Containment Actions

1. **Immediate** — Block IPs `10.10.157.155`, `10.14.94.82`, `171.251.232.40` at firewall
2. **Immediate** — Disable account `oliver.thompson` pending investigation
3. **Immediate** — Delete backdoor account `A1berto`
4. **Immediate** — Remove `/wp-corn.php` from web server
5. **Short term** — Reset all passwords on `WIN-H015`
6. **Short term** — Audit all accounts created after 2022-05-11
7. **Long term** — Deploy MFA on all user accounts
8. **Long term** — Implement WAF with rate limiting on WordPress

---

## Lessons Learned

1. Brute force attacks succeeded due to lack of account lockout policy
2. Backdoor account `A1berto` went undetected — no user account auditing
3. WordPress login had no rate limiting — enabled Hydra attack
4. C2 channel via fake cron file — file integrity monitoring needed
5. Multiple attacker IPs — need automated IP reputation checking

---

## Recommendations

| Priority | Action | Owner |
|----------|--------|-------|
| Critical | Enable account lockout after 5 failures | IT Admin |
| Critical | Deploy WAF on WordPress | SecOps |
| High | Implement MFA for all accounts | IT Admin |
| High | File integrity monitoring on web root | SecOps |
| Medium | User account audit monthly | SOC |
| Medium | Splunk alerting for brute force | SOC Analyst |
| Low | Security awareness training | HR + IT |

---

## Analyst Notes

This investigation demonstrates a complete attack chain from initial reconnaissance through to C2 establishment. The attacker showed sophisticated TTPs including living-off-the-land techniques (WMIC, net.exe), tool obfuscation (fake WordPress files), and multi-vector attacks (Windows + Web simultaneously).

All findings were detected using Splunk SPL queries against real log data. Detection rules have been created for Splunk and Wazuh to prevent future incidents.

**Analyst:** Ilyas Hodaiby  
**TryHackMe:** Top 6% globally  
**Tools Used:** Splunk, Sysmon, Windows Event Logs, Web Access Logs
