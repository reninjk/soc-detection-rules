# Contributing to soc-detection-rules

Thank you for helping improve the SOC's detection capability. Every rule added here directly improves our ability to detect adversary behaviour.

## What Belongs Here

- Sigma rules for new attack techniques or sub-techniques
- Improvements to existing rules (reduced false positives, better field coverage)
- MITRE ATT&CK coverage matrix updates
- Threat hunting queries and guides
- Rule tuning documentation

## What Does Not Belong Here

- Real IOC values (IPs, hashes, domains) from live incidents — use the TI platform
- SIEM-specific query syntax (rules must stay in Sigma format for portability)
- Rules with hardcoded internal hostnames, usernames, or asset names
- API keys, credentials, or any secrets

## Rule Quality Bar

All new Sigma rules must include:
- Valid Sigma schema header (title, id, status, description, references)
- At least one MITRE ATT&CK technique tag (`attack.tXXXX`)
- `logsource` and `detection` sections
- `falsepositives` field (even if "Unknown")
- `level` set to: informational / low / medium / high / critical
- Tested against sample log data before submitting

## Contribution Process

1. Open a GitHub issue using the **New Detection Rule** template
2. Branch: `feat/rule-name-technique` (e.g., `feat/wmi-persistence-t1047`)
3. Submit a PR — complete the PR template
4. Peer review required from a senior analyst before merge
5. New critical/high rules require SOC Manager sign-off

## Sigma Rule Linting

Before submitting, validate your rule locally:
```bash
pip install sigma-cli
sigma check sigma/your-category/your-rule.yml
```

## Commit Messages

```
feat: add WMI persistence detection (T1047)
fix: reduce false positives in scheduled-task-creation rule
docs: update MITRE coverage matrix with new rules
```

## Questions

Open a GitHub Discussion or contact the detection engineering lead via the internal SOC channel.
