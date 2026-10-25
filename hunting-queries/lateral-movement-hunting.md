# Threat Hunting Queries — Lateral Movement & C2

> **OPSEC Note:** All IP addresses, hostnames and hashes shown below are
> placeholder examples only. Replace with your environment's actual baselines
> and threat-intelligence feeds before running in production.

---

## 1. SMB Lateral Movement (T1021.002)

### KQL — Microsoft Sentinel / Defender for Endpoint

```kql
// Detect unusual SMB connections across internal hosts
// Baseline: normal service accounts and known admin hosts
let KnownAdminHosts = dynamic(["admin-ws-01", "jump-server-01"]);  // tune per env
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| where not(InitiatingProcessAccountName has_any ("system", "network service"))
| where not(DeviceName has_any (KnownAdminHosts))
| summarize
    ConnectionCount = count(),
    UniqueTargets = dcount(RemoteIP),
    TargetList = make_set(RemoteIP, 20)
  by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(TimeGenerated, 1h)
| where UniqueTargets > 3  // adjust threshold for your environment
| sort by UniqueTargets desc
```

**Hunt hypothesis:** A single host making SMB connections to many internal
peers within a short window is a strong indicator of lateral movement or
ransomware pre-staging.

**Tuning notes:**
- Raise `UniqueTargets` threshold after baselining your environment
- Add known backup/patch management servers to the exclusion list

---

### SPL — Splunk Enterprise Security

```spl
index=wineventlog EventCode=4648
| eval is_smb=if(match(TargetServerName, "\\\\.*"), 1, 0)
| where is_smb=1
| stats
    count AS auth_attempts,
    dc(TargetServerName) AS unique_targets,
    values(TargetServerName) AS targets
  BY SubjectUserName, IpAddress, _time span=1h
| where unique_targets > 3
| table _time SubjectUserName IpAddress unique_targets auth_attempts targets
| sort - unique_targets
```

**Data source:** Windows Security Event Log (EventID 4648 — explicit credential logon)

---

## 2. C2 Beaconing via DNS (T1071.004)

### KQL — Microsoft Sentinel

```kql
// Detect high-frequency, low-variance DNS queries — typical C2 beaconing pattern
DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "A"
| where not(Name endswith ".microsoft.com"
         or Name endswith ".windows.com"
         or Name endswith ".office.com"
         or Name endswith ".azure.com")
| summarize
    QueryCount = count(),
    UniqueClients = dcount(ClientIP),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by Name, bin(TimeGenerated, 5m)
| extend IntervalSeconds = datetime_diff('second', LastSeen, FirstSeen)
| where QueryCount > 10 and IntervalSeconds > 0
| extend QueriesPerMinute = todouble(QueryCount) / (todouble(IntervalSeconds) / 60.0)
| where QueriesPerMinute > 2  // more than once every 30 seconds
| sort by QueriesPerMinute desc
| project Name, QueryCount, QueriesPerMinute, UniqueClients, FirstSeen, LastSeen
```

**Hunt hypothesis:** Malware C2 channels often beacon at a fixed interval
(e.g. every 30–60 s). High query volume with low jitter against an uncommon
domain is a strong C2 indicator.

---

### SPL — Splunk Enterprise Security

```spl
index=dns
| stats
    count AS query_count,
    dc(src_ip) AS unique_sources,
    earliest(_time) AS first_seen,
    latest(_time) AS last_seen
  BY query
| eval interval_seconds = last_seen - first_seen
| where interval_seconds > 0
| eval qpm = round(query_count / (interval_seconds / 60.0), 2)
| where qpm > 2 AND query_count > 10
| eval domain_length = len(query)
| where domain_length > 20          ``` long random-looking subdomains
| sort - qpm
| table query domain_length query_count qpm unique_sources first_seen last_seen
```

---

## 3. Pass-the-Hash / Credential Reuse (T1550.002)

### KQL — Microsoft Sentinel

```kql
// Detect NTLM logons from hosts where the user has no interactive session
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 3        // Network logon
| where AuthenticationPackageName == "NTLM"
| where not(TargetUserName endswith "$")  // exclude machine accounts
| join kind=leftanti (
    SecurityEvent
    | where EventID == 4624
    | where LogonType in (2, 10)  // Interactive or RemoteInteractive
    | project TargetUserName, IpAddress, TimeGenerated
  ) on TargetUserName, IpAddress
| summarize
    NTLMLogons = count(),
    TargetHosts = make_set(Computer, 10)
  by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where NTLMLogons > 2
| sort by NTLMLogons desc
```

**Hunt hypothesis:** An account authenticated via NTLM (network logon) from
an IP with no corresponding interactive logon may indicate pass-the-hash.

---

## Usage Instructions

1. Copy the query for your SIEM platform (KQL for Sentinel/MDE, SPL for Splunk).
2. Adjust the time window and thresholds to match your environment baseline.
3. Replace placeholder exclusion lists with your actual known-good hosts.
4. Log findings in your hunting journal; escalate confirmed hits to IR.
5. Convert validated detections into Sigma rules in `sigma/` for ongoing coverage.

## MITRE ATT&CK Coverage

| Query | Tactic | Technique |
|-------|--------|-----------|
| SMB Lateral Movement | Lateral Movement | T1021.002 |
| C2 DNS Beaconing | Command & Control | T1071.004 |
| Pass-the-Hash | Lateral Movement | T1550.002 |
