[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Last Commit](https://img.shields.io/github/last-commit/reninjk/soc-detection-rules)](https://github.com/reninjk/soc-detection-rules/commits/main) [![Issues](https://img.shields.io/github/issues/reninjk/soc-detection-rules)](https://github.com/reninjk/soc-detection-rules/issues) [![Sigma Rules](https://img.shields.io/badge/Sigma_Rules-12-blueviolet?style=flat)](https://github.com/reninjk/soc-detection-rules/tree/main/sigma) [![ATT&CK Coverage](https://img.shields.io/badge/ATT%26CK-10_Tactics-E4002B?style=flat)](https://github.com/reninjk/soc-detection-rules/blob/main/mitre-mappings/attck-coverage-matrix.md)

# 🔍 SOC Detection Rules

> A structured library of detection rules, threat hunting queries, and MITRE ATT&CK
> coverage analysis for Security Operations Centres.
> Rules are written in vendor-agnostic **Sigma** format, convertible to Splunk SPL,
> Microsoft Sentinel KQL, and Elastic EQL.

---

## 📊 Current Coverage — October 2026

| Tactic | Rules | Key Techniques |
|--------|-------|----------------|
| Initial Access | 1 | T1566 Phishing |
| Execution | 1 | T1059 Scripting |
| Persistence | 1 | T1053 Scheduled Task |
| Privilege Escalation | 1 | T1053.005 Scheduled Task |
| Defence Evasion | 1 | T1562 Disable Tools |
| Credential Access | 2 | T1003.001 LSASS Dump, T1110 Brute Force |
| Discovery | 1 | T1082 System Information |
| Lateral Movement | 2 | T1021.001 RDP, T1021.002 SMB |
| Command & Control | 1 | T1071.004 DNS Beaconing |
| Impact | 1 | T1486 Data Encrypted |
| **TOTAL** | **12** | 10 of 14 ATT&CK tactics covered |

> Full coverage matrix with gap analysis: [mitre-mappings/attck-coverage-matrix.md](mitre-mappings/attck-coverage-matrix.md)

---

## 📁 Repository Structure

```
soc-detection-rules/
├── sigma/                     # Sigma detection rules (vendor-agnostic)
│   ├── command-and-control/   # T1071 DNS beaconing
│   ├── credential-access/     # T1003 LSASS dump, T1110 brute force
│   ├── defense-evasion/       # T1562 disable tools
│   ├── discovery/             # T1082 system info
│   ├── execution/             # T1059 scripting
│   ├── impact/                # T1486 ransomware
│   ├── initial-access/        # T1566 phishing
│   ├── lateral-movement/      # T1021 RDP/SMB
│   ├── persistence/           # T1053 scheduled task
│   └── privilege-escalation/  # T1053.005 scheduled task privesc
├── hunting-queries/           # KQL + SPL hunting queries
│   ├── lateral-movement-hunting.md   # SMB, RDP, Pass-the-Hash
│   └── threat-hunting-guide.md       # Methodology and best practices
└── mitre-mappings/
    └── attck-coverage-matrix.md      # Gap analysis and coverage heatmap
```

---

## 🚀 Quick Start

### Convert a Sigma rule to your SIEM

```bash
# Install sigma-cli
pip install sigma-cli

# Convert to Splunk SPL
sigma convert -t splunk sigma/credential-access/lsass-memory-dump.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t sentinel sigma/command-and-control/c2-dns-beaconing.yml

# Convert to Elastic EQL
sigma convert -t elastic-eql sigma/lateral-movement/rdp-lateral-movement.yml
```

### Validate all rules

```bash
sigma check sigma/**/*.yml
```

---

## 🎯 Rule Quality Standards

Each rule in this library meets the following criteria:

- ✅ **MITRE ATT&CK tagged** — every rule maps to at least one technique
- ✅ **False positive documented** — known FP sources listed and filtered where possible
- ✅ **Response guidance included** — `response:` block with analyst action steps
- ✅ **Tuning notes included** — environment-specific thresholds clearly marked
- ✅ **OPSEC safe** — no real IOCs, credentials, or infrastructure data

---

## 📖 Rule Writing Guide

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full rule contribution guide, including:
- Sigma field naming conventions
- Required metadata fields (id, status, author, date, tags)
- Testing procedure before submitting a PR
- How to convert and validate rules before merging

---

## 📬 Contributing

Pull requests welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
All rules must pass `sigma check` validation before merge.
