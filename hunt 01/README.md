# Hunt 01 — Lateral Movement Detection

**MITRE ATT&CK:** T1550.002 — Pass the Hash  
**Dataset:** BOTS v1 (Splunk Boss of the SOC)  
**Analyst:** Ilyas Hodaiby  
**Status:** Complete ✅

---

## Hypothesis

> An attacker who has compromised an initial endpoint will attempt lateral movement using stolen NTLM hashes to authenticate to other systems without knowing the plaintext password. This behaviour leaves specific patterns in Windows Security Event Logs — particularly EventCode 4624 with LogonType 3 from unusual source IPs.

---

## Log Sources Analysed

| Source | Events | Purpose |
|---|---|---|
| Windows Security Logs | EventCode 4624, 4625, 4648 | Authentication events |
| Windows System Logs | EventCode 7045 | New service installation |
| Network logs | SMB traffic | Lateral movement traffic |
| Sysmon logs | EventCode 1, 3 | Process + network connections |

---

## Investigation

### Step 1 — Baseline Normal Authentication

First, I established what normal authentication looks like in this environment:

```Splunk
index=botsv1 EventCode=4624 
| stats count by LogonType, src_ip 
| sort - count
```

**Findings:**
- LogonType 2 (Interactive) = normal user logins at workstations
- LogonType 10 (Remote Interactive) = RDP sessions
- LogonType 3 (Network) = should only come from known servers

---

### Step 2 — Hunt for Anomalous Network Logons

```Splunk
index=botsv1 EventCode=4624 LogonType=3
| stats count by src_ip, dest, user 
| where count > 3
| sort - count
```

**Findings:**
- Source IP `192.168.250.100` authenticated to 7 different hosts using LogonType 3
- All authentications occurred within a 12-minute window
- Username used: `SYSTEM` and `Administrator`

---
### Step 3 — Correlate with Failed Authentications

```Splunk
index=botsv1 EventCode=4625 
| stats count by src_ip, dest, user
| sort - count
```

**Findings:**
- Same source IP `192.168.250.100` had 23 failed attempts before successful LogonType 3
- Pattern consistent with automated credential testing (Pass the Hash toolkit)

---
### Step 4 — Check for Service Installation Post-Compromise

```Splunk
index=botsv1 EventCode=7045
| table _time, ComputerName, ServiceName, ServiceFileName
| sort - _time
```

**Findings:**
- New service `PSEXESVC` installed on 3 hosts within minutes of successful lateral movement
- Confirms PsExec-based lateral movement technique

---
### Step 5 — Network Traffic Correlation

```Splunk
index=botsv1 sourcetype=stream:smb 
  src_ip="192.168.250.100"
| stats count by dest_ip, path
| sort - count
```

**Findings:**
- High volume SMB traffic from attacker IP to multiple destinations
- Access to `ADMIN$` share on multiple hosts — confirms PsExec lateral movement

---

---

## IOCs Extracted

| Type | Value | Context |
|---|---|---|
| Source IP | 192.168.250.100 | Attacker pivot point |
| Technique | Pass the Hash + PsExec | Lateral movement method |
| Service | PSEXESVC | Persistence mechanism on remote hosts |
| Logon Type | 3 (Network) | Authentication pattern |
| Event Codes | 4624, 4625, 7045 | Key detection events |
| Timeframe | ~12 minutes | Full lateral movement campaign |

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Pass the Hash | T1550.002 | LogonType 3 from single IP to multiple hosts |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | ADMIN$ share access |
| System Services: Service Execution | T1569.002 | PSEXESVC installation |
| Lateral Tool Transfer | T1570 | Tools moved via SMB |

---

## Detection Rules Created

### Wazuh Custom Rule
```xml
<rule id="100010" level="12" frequency="5" timeframe="300">
  <if_matched_sid>60122</if_matched_sid>
  <same_source_ip/>
  <same_field>win.eventdata.logonType</same_field>
  <description>Possible Pass-the-Hash: Multiple network logons from same source</description>
  <mitre>
    <id>T1550.002</id>
  </mitre>
</rule>
```

### Splunk Detection Alert
```Splunk
index=* EventCode=4624 LogonType=3
| stats dc(dest) as unique_targets count by src_ip, user
| where unique_targets >= 3 AND count >= 5
| eval alert="Possible Lateral Movement — Pass the Hash"
```

