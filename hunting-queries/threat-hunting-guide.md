# Threat Hunting Guide

> Proactive threat hunting queries and methodologies for the SOC. Use these to search for threats that have bypassed automated detection.

---

## 🎯 Hunting Principles

1. **Hypothesis-driven** — Start with a specific threat scenario (e.g., "assume phishing succeeded")
2. **Evidence-based** — Always collect artifacts; don't rely on memory
3. **Time-boxed** — Each hunt should have a defined scope and end date
4. **Documented** — All hunts must produce a hunt report regardless of findings

---

## Hunt 1: Living-off-the-Land (LOLBin) Abuse

**Hypothesis:** An attacker is using built-in Windows tools to evade detection.

### Suspicious PowerShell Execution
```
# Splunk SPL
index=windows EventCode=4103 OR EventCode=4104
| where match(ScriptBlockText, "(?i)(IEX|Invoke-Expression|downloadstring|bypass|hidden|encodedcommand)")
| stats count by ComputerName, UserName, ScriptBlockText
| where count < 5
| sort -count
```

### WMIC Remote Execution
```
# KQL (Sentinel)
DeviceProcessEvents
| where ProcessCommandLine contains "wmic" and ProcessCommandLine contains "/node:"
| where InitiatingProcessFileName !in ("svchost.exe", "msiexec.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

---

## Hunt 2: Lateral Movement via RDP

**Hypothesis:** An attacker is moving laterally using stolen credentials and RDP.

### RDP Connections to Unusual Hosts
```
# Splunk SPL
index=windows EventCode=4624 LogonType=10
| stats count dc(WorkstationName) as unique_sources by TargetUserName, IpAddress
| where unique_sources > 3 OR count > 20
| sort -count
```

### New Admin Account Creation After Hours
```
# KQL (Sentinel)
SecurityEvent
| where EventID == 4720 and TimeGenerated between (datetime(00:00) .. datetime(06:00))
| project TimeGenerated, AccountName, SubjectUserName, Computer
```

---

## Hunt 3: Data Staging and Exfiltration

**Hypothesis:** An attacker is staging data for exfiltration.

### Large Archive Creation
```
# Splunk SPL
index=windows EventCode=4663
| where TargetFilename matches ".*.(zip|7z|rar|tar|gz)$"
| stats sum(ObjectSize) as total_bytes by SubjectUserName, TargetFilename
| where total_bytes > 104857600
| sort -total_bytes
```

### Unusual Outbound Data Volume
```
# Generic (adapt to SIEM)
source=network_flow dest_port IN (443, 80, 8080, 21, 22)
| stats sum(bytes_out) as outbound by src_ip, dest_ip
| where outbound > 500000000
| sort -outbound
```

---

## Hunt 4: Persistence Mechanisms

**Hypothesis:** Malware has established persistence on endpoints.

### Scheduled Task Creation
```
# KQL (Sentinel)
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where InitiatingProcessFileName !in ("svchost.exe", "taskeng.exe", "taskhostw.exe")
| project Timestamp, DeviceName, AccountName, AdditionalFields, InitiatingProcessCommandLine
```

### New Autorun Registry Keys
```
# Splunk SPL
index=windows EventCode=13
| where TargetObject matches ".*\\(Run|RunOnce|Services)\\.*"
| where NOT Image IN ("C:\\Windows\\System32\\msiexec.exe")
| stats count by ComputerName, Image, TargetObject, Details
```

---

## Hunt Report Template

After each hunt, complete the following:

| Field | Value |
|-------|-------|
| Hunt Name | |
| Hypothesis | |
| Date Start | |
| Date End | |
| Analyst | |
| Data Sources Used | |
| Findings | Positive / Negative |
| IOCs Identified | |
| Recommendations | |
| Escalated to IR? | Yes / No |

---
*Schedule hunts: Weekly (targeted), Monthly (comprehensive)*
