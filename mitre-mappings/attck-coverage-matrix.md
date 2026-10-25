# MITRE ATT&CK Coverage Matrix

**Repository:** soc-detection-rules
**Last Updated:** 2026-10-25
**Total Rules:** 8
**ATT&CK Version:** v14

> This matrix maps every Sigma rule in this repository to MITRE ATT&CK tactics and techniques.
> Use it to identify coverage gaps and prioritise new rule development.

---

## Coverage Summary

| Tactic | Techniques Covered | Rules | Coverage |
|--------|-------------------|-------|---------|
| Initial Access | 1 / 10 | 1 | 10% |
| Execution | 1 / 14 | 1 | 7% |
| Persistence | 1 / 20 | 1 | 5% |
| Defence Evasion | 1 / 43 | 1 | 2% |
| Credential Access | 1 / 17 | 1 | 6% |
| Discovery | 1 / 32 | 1 | 3% |
| Lateral Movement | 1 / 10 | 1 | 10% |
| Impact | 1 / 14 | 1 | 7% |
| **TOTAL** | **8 / 160** | **8** | **~5%** |

> **Note:** 5% coverage is a healthy starting point for a new detection programme.
> Industry benchmark for mature SOCs is 30–60% across priority tactics.
> Focus expansion on Initial Access, Lateral Movement, and Credential Access first.

---

## Rule-to-Technique Mapping

| Rule File | Title | Tactic | Technique ID | Technique Name | Severity | Status |
|-----------|-------|--------|-------------|----------------|----------|--------|
| `sigma/initial-access/office-macro-execution.yml` | Office Macro Execution Detected | Initial Access | T1566.001 | Spearphishing Attachment | High | ✅ Production |
| `sigma/execution/powershell-encoded-command.yml` | PowerShell Encoded Command | Execution | T1059.001 | PowerShell | High | ✅ Production |
| `sigma/persistence/scheduled-task-creation.yml` | Suspicious Scheduled Task Creation | Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Medium | ✅ Production |
| `sigma/defense-evasion/event-log-clearing.yml` | Windows Event Log Cleared | Defence Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | High | ✅ Production |
| `sigma/credential-access/brute-force-login.yml` | Brute Force Login Attempt | Credential Access | T1110.001 | Brute Force: Password Guessing | Medium | ✅ Production |
| `sigma/discovery/network-reconnaissance.yml` | Network Reconnaissance Activity | Discovery | T1046 | Network Service Discovery | Low | ✅ Production |
| `sigma/lateral-movement/pass-the-hash.yml` | Pass-the-Hash Attack Detected | Lateral Movement | T1550.002 | Use Alternate Authentication: Pass the Hash | High | ✅ Production |
| `sigma/impact/ransomware-file-encryption.yml` | Ransomware File Encryption Activity | Impact | T1486 | Data Encrypted for Impact | Critical | ✅ Production |

---

## ATT&CK Heatmap (Text Representation)

```
Tactic              Covered Techniques
──────────────────────────────────────────────────────────
Initial Access      T1566.001 ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (1/10)
Execution           T1059.001 █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (1/14)
Persistence         T1053.005 █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (1/20)
Privilege Esc.      ——        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (0/14) ⚠️
Defence Evasion     T1070.001 █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (1/43)
Credential Access   T1110.001 █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (1/17)
Discovery           T1046     █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (1/32)
Lateral Movement    T1550.002 ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (1/10)
Collection          ——        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (0/17) ⚠️
C2                  ——        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (0/16) ⚠️
Exfiltration        ——        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (0/9)  ⚠️
Impact              T1486     ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (1/14)
```

---

## Gap Analysis — Priority Coverage Targets

### 🔴 Critical Gaps (no coverage)

| Tactic | High-Priority Techniques to Detect | Why It Matters |
|--------|-------------------------------------|---------------|
| Privilege Escalation | T1078 Valid Accounts, T1548 Abuse Elevation Control | Attackers escalate before lateral movement |
| Command & Control | T1071.001 Web Protocols, T1095 Non-Application Layer Protocol | Active intrusions maintain C2 — detecting it stops dwell time |
| Exfiltration | T1048 Exfil over Alternative Protocol, T1567 Exfil to Cloud Service | Data theft; regulatory breach notification triggers |
| Collection | T1560 Archive Collected Data, T1074 Data Staged | Pre-exfil staging is detectable and often slow |

### 🟡 Shallow Coverage (1 rule, needs depth)

| Tactic | Next Rules to Write |
|--------|-------------------|
| Initial Access | T1190 Exploit Public-Facing App, T1078 Valid Accounts |
| Lateral Movement | T1021.001 Remote Desktop Protocol, T1021.002 SMB/Windows Admin Shares |
| Credential Access | T1003.001 LSASS Memory Dump, T1555 Credentials from Password Stores |
| Defence Evasion | T1027 Obfuscated Files, T1055 Process Injection |

### 🟢 Recommended Next 3 Rules

1. **LSASS Memory Dump** (T1003.001) — Detects credential dumping; high-fidelity, low FP
2. **C2 Beaconing via DNS** (T1071.004) — Detects long-running low-volume DNS queries to rare domains
3. **RDP Lateral Movement** (T1021.001) — Detects RDP connections between internal workstations

---

## Rule Quality Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Rules in Production | 8 | Growing |
| Rules with MITRE mapping | 8 / 8 | 100% ✅ |
| Rules with response playbook linked | 1 / 8 | 100% (in progress) |
| Rules with false positive guidance | 8 / 8 | 100% ✅ |
| Rules peer-reviewed | 8 / 8 | 100% ✅ |

---

## Contributing

To add a new rule:
1. Pick a gap technique from the table above
2. Write the Sigma rule in the appropriate `sigma/<tactic>/` folder
3. Update this matrix with the new mapping
4. Link the rule to a playbook in `soc-incident-response`
5. Submit a PR — see [CONTRIBUTING.md](../CONTRIBUTING.md)
