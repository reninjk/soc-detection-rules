# 🔍 SOC Detection Rules

> SIEM detection rules, Sigma rules, threat hunting queries, and MITRE ATT&CK mappings for the Security Operations Center.

## 📁 Repository Structure

```
soc-detection-rules/
├── sigma/
│   ├── initial-access/
│   │   ├── phishing-attachment-execution.yml
│   │   └── suspicious-email-link-click.yml
│   ├── credential-access/
│   │   ├── brute-force-login.yml
│   │   └── credential-dumping.yml
│   ├── lateral-movement/
│   │   └── suspicious-rdp-connection.yml
│   ├── exfiltration/
│   │   └── large-data-transfer.yml
│   └── impact/
│       └── ransomware-file-encryption.yml
├── hunting-queries/
│   ├── threat-hunting-guide.md
│   ├── suspicious-process-trees.md
│   └── beaconing-detection.md
├── mitre-mappings/
│   └── attck-coverage-matrix.md
└── .github/
    └── workflows/
        └── validate-sigma.yml
```

## 📐 Rule Format: Sigma

All detection rules in this repo use the [Sigma](https://sigmahq.io/) generic signature format, which can be converted to any SIEM (Splunk, Elasticsearch, Microsoft Sentinel, QRadar, etc.).

### Converting Sigma Rules

```bash
# Install sigma-cli
pip install sigma-cli

# Convert to Splunk SPL
sigma convert -t splunk sigma/initial-access/phishing-attachment-execution.yml

# Convert to KQL (Microsoft Sentinel)
sigma convert -t microsoft365defender sigma/credential-access/brute-force-login.yml

# Convert to Elastic EQL
sigma convert -t elasticsearch sigma/lateral-movement/suspicious-rdp-connection.yml
```

## 🎯 MITRE ATT&CK Coverage

| Tactic | Technique | Rule | Severity |
|--------|-----------|------|----------|
| Initial Access | T1566 - Phishing | phishing-attachment-execution.yml | High |
| Credential Access | T1110 - Brute Force | brute-force-login.yml | Medium |
| Credential Access | T1003 - OS Credential Dumping | credential-dumping.yml | Critical |
| Lateral Movement | T1021 - Remote Services | suspicious-rdp-connection.yml | High |
| Exfiltration | T1041 - Exfil Over C2 | large-data-transfer.yml | High |
| Impact | T1486 - Data Encrypted | ransomware-file-encryption.yml | Critical |

## 📊 Rule Severity Levels

| Level | Description | Response SLA |
|-------|-------------|-------------|
| **Critical** | High-fidelity, immediate threat | 15 minutes |
| **High** | Strong indicator, investigate fast | 1 hour |
| **Medium** | Context needed, correlate | 4 hours |
| **Low** | Informational, hunt use only | 24 hours |

## 🔧 Rule Lifecycle

1. **Draft** → Author creates rule, internal review
2. **Testing** → Deploy in detection-only mode, tune FP rate
3. **Staging** → Monitor for 2 weeks, validate alert volume
4. **Production** → Full deployment, alerting enabled
5. **Deprecated** → Rule retired, documented reason

## 🛡️ Rule Quality Standards

Every production rule must have:
- [ ] MITRE ATT&CK tactic and technique mapped
- [ ] False positive rate < 5%
- [ ] Linked IR playbook or runbook
- [ ] Test cases documented
- [ ] Reviewed by SOC Manager

## 🔗 Related Repositories

- [soc-incident-response](../soc-incident-response) — IR playbooks triggered by these detections
- [soc-automation](../soc-automation) — Automated responses to these alerts
- [soc-compliance-reporting](../soc-compliance-reporting) — Detection coverage reports

---
*Maintained by the SOC Manager | Review cycle: Monthly*
