# MITRE ATT&CK Coverage Matrix

**Framework Version:** ATT&CK v14 (Enterprise)
**Last Updated:** 2026-01-01
**Coverage Target:** > 70% of high-priority tactics

---

## Coverage Status Key

| Symbol | Meaning |
|--------|---------|
| ✅ | Detection rule in production |
| 🧪 | Rule in testing/staging |
| 🔍 | Hunt query available |
| ⚠️ | Partial coverage (tuning needed) |
| ❌ | No coverage — gap |
| N/A | Not applicable to environment |

---

## TA0001 — Initial Access

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Phishing — Malicious Attachment | T1566.001 | sigma/initial-access/office-macro-execution.yml | ✅ | Critical | Covers Office macro spawning child processes |
| Phishing — Spear Phishing Link | T1566.002 | — | 🔍 | High | Hunt query in threat-hunting-guide.md |
| Valid Accounts — Domain Accounts | T1078.002 | sigma/credential-access/brute-force-login.yml | ✅ | Medium | Covers brute force leading to valid account use |
| Exploit Public-Facing Application | T1190 | — | ❌ | High | Gap — needs WAF/IDS alert integration |
| Drive-by Compromise | T1189 | — | ❌ | High | Gap — proxy-based detection needed |

**Coverage: 2/5 (40%) — Priority gap: T1190, T1189**

---

## TA0002 — Execution

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| PowerShell | T1059.001 | sigma/execution/powershell-encoded-command.yml | ✅ | High | Covers encoded commands |
| Windows Command Shell | T1059.003 | — | ⚠️ | Medium | Partially via Office macro rule |
| Visual Basic / VBScript | T1059.005 | sigma/initial-access/office-macro-execution.yml | ✅ | Critical | wscript/cscript child process detection |
| Scheduled Task/Job | T1053.005 | sigma/persistence/scheduled-task-creation.yml | ✅ | High | Covers schtasks and PowerShell |
| WMIC | T1047 | — | ❌ | High | Gap — needs dedicated WMIC abuse rule |
| Mshta | T1218.005 | — | ⚠️ | High | Partially covered via Office macro child process |

**Coverage: 4/6 (67%) — Priority gap: T1047**

---

## TA0003 — Persistence

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Scheduled Task/Job | T1053.005 | sigma/persistence/scheduled-task-creation.yml | ✅ | High | Production |
| Registry Run Keys / Startup Folder | T1547.001 | — | ❌ | High | Gap — needs registry monitoring rule |
| Create Account | T1136 | — | ❌ | High | Gap — needs account creation detection |
| Web Shell | T1505.003 | — | ❌ | Critical | Gap — needs web server log monitoring |
| Valid Accounts | T1078 | sigma/credential-access/brute-force-login.yml | ⚠️ | Medium | Indirect via brute force rule |

**Coverage: 1/5 (20%) — HIGH PRIORITY GAPS: T1547.001, T1136, T1505.003**

---

## TA0004 — Privilege Escalation

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Scheduled Task/Job | T1053.005 | sigma/persistence/scheduled-task-creation.yml | ✅ | High | Dual-use detection |
| Valid Accounts | T1078 | sigma/credential-access/brute-force-login.yml | ⚠️ | Medium | Indirect |
| Process Injection | T1055 | — | ❌ | Critical | Gap — needs memory/API monitoring |
| Access Token Manipulation | T1134 | — | ❌ | High | Gap |
| Sudo/Sudo Caching (Linux) | T1548.003 | — | N/A | — | Windows-focused environment |

**Coverage: 1/4 (25%) — Priority gap: T1055**

---

## TA0005 — Defense Evasion

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Indicator Removal — Clear Windows Event Logs | T1070.001 | sigma/defense-evasion/event-log-clearing.yml | ✅ | High | Production |
| Obfuscated Files/Encoded Commands | T1027 | sigma/execution/powershell-encoded-command.yml | ✅ | High | Covers PowerShell encoding |
| Signed Binary Proxy Execution — Mshta | T1218.005 | — | ⚠️ | High | Partial via Office macro rule |
| Signed Binary Proxy Execution — Rundll32 | T1218.011 | — | ❌ | High | Gap |
| Masquerading | T1036 | — | ❌ | Medium | Gap |

**Coverage: 2/5 (40%) — Priority gap: T1218.011**

---

## TA0006 — Credential Access

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Brute Force | T1110 | sigma/credential-access/brute-force-login.yml | ✅ | Medium | EventID 4625 threshold detection |
| OS Credential Dumping — LSASS | T1003.001 | — | ❌ | Critical | Gap — needs Sysmon + LSASS access rule |
| Credentials in Files | T1552.001 | — | ❌ | High | Gap |
| Steal or Forge Kerberos Tickets | T1558 | — | ❌ | High | Gap — Kerberoasting detection needed |

**Coverage: 1/4 (25%) — Priority gap: T1003.001 (CRITICAL)**

---

## TA0007 — Discovery

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Network Service Discovery | T1046 | sigma/discovery/network-reconnaissance.yml | ✅ | Medium | Covers scanning tools and native commands |
| Remote System Discovery | T1018 | sigma/discovery/network-reconnaissance.yml | ✅ | Medium | Covered in same rule |
| Account Discovery | T1087 | sigma/discovery/network-reconnaissance.yml | ⚠️ | Medium | Partial via net.exe commands |
| System Information Discovery | T1082 | sigma/discovery/network-reconnaissance.yml | ⚠️ | Low | Partial via whoami/ipconfig |
| Domain Trust Discovery | T1482 | sigma/discovery/network-reconnaissance.yml | ✅ | High | nltest /domain_trusts detection |

**Coverage: 3/5 (60%)**

---

## TA0008 — Lateral Movement

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Pass the Hash | T1550.002 | sigma/lateral-movement/pass-the-hash.yml | ✅ | High | NTLM logon type 3 detection |
| Remote Services — RDP | T1021.001 | hunting-queries/threat-hunting-guide.md | 🔍 | High | Hunt query available |
| Remote Services — SMB/Windows Admin Shares | T1021.002 | — | ❌ | High | Gap |
| Lateral Tool Transfer | T1570 | — | ❌ | High | Gap — needs file copy monitoring |

**Coverage: 1/4 (25%) — Priority gap: T1021.002**

---

## TA0009 — Collection

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Data Staged — Local | T1074.001 | hunting-queries/threat-hunting-guide.md | 🔍 | High | Hunt query: large archive creation |
| Archive Collected Data | T1560 | hunting-queries/threat-hunting-guide.md | 🔍 | High | Hunt query available |
| Email Collection | T1114 | — | ❌ | High | Gap — needs Exchange/M365 rule |

**Coverage: 0/3 production (hunt queries only) — Priority: build production rules**

---

## TA0010 — Exfiltration

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Exfiltration Over C2 Channel | T1041 | sigma/impact/ransomware-file-encryption.yml | ⚠️ | Critical | Partial — ransomware context only |
| Exfiltration to Cloud Storage | T1567.002 | hunting-queries/threat-hunting-guide.md | 🔍 | High | Hunt query: outbound volume |
| Transfer Data to Cloud Account | T1537 | — | ❌ | High | Gap — needs CASB integration |

**Coverage: 0/3 production — Priority: dedicated exfiltration detection rules**

---

## TA0040 — Impact

| Technique | ID | Rule File | Status | Severity | Notes |
|-----------|----|-----------|--------|----------|-------|
| Data Encrypted for Impact (Ransomware) | T1486 | sigma/impact/ransomware-file-encryption.yml | ✅ | Critical | Bulk rename + shadow copy deletion |
| Inhibit System Recovery | T1490 | sigma/impact/ransomware-file-encryption.yml | ✅ | Critical | vssadmin / bcdedit detection |
| Service Stop | T1489 | — | ❌ | High | Gap |

**Coverage: 2/3 (67%)**

---

## Overall Coverage Summary

| Tactic | Rules | Coverage | Priority |
|--------|-------|----------|----------|
| TA0001 Initial Access | 2/5 | 40% | 🔴 HIGH |
| TA0002 Execution | 4/6 | 67% | 🟡 MEDIUM |
| TA0003 Persistence | 1/5 | 20% | 🔴 HIGH |
| TA0004 Privilege Escalation | 1/4 | 25% | 🔴 HIGH |
| TA0005 Defense Evasion | 2/5 | 40% | 🟡 MEDIUM |
| TA0006 Credential Access | 1/4 | 25% | 🔴 HIGH |
| TA0007 Discovery | 3/5 | 60% | 🟡 MEDIUM |
| TA0008 Lateral Movement | 1/4 | 25% | 🔴 HIGH |
| TA0009 Collection | 0/3 | 0% | 🔴 HIGH |
| TA0010 Exfiltration | 0/3 | 0% | 🔴 HIGH |
| TA0040 Impact | 2/3 | 67% | 🟢 GOOD |
| **TOTAL** | **17/47** | **36%** | |

## Top 5 Detection Gaps to Close (Q1 Priority)

| # | Technique | ID | Why Critical |
|---|-----------|-----|-------------|
| 1 | OS Credential Dumping (LSASS) | T1003.001 | Used in almost every major breach |
| 2 | Registry Run Key Persistence | T1547.001 | Common malware persistence mechanism |
| 3 | Web Shell | T1505.003 | High-impact, low-noise initial foothold |
| 4 | SMB Lateral Movement | T1021.002 | Core lateral movement technique |
| 5 | WMIC Execution | T1047 | LOLBin abuse in majority of campaigns |
