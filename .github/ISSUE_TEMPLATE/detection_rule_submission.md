---
name: Detection Rule Submission
about: Submit a new Sigma rule or detection query mapped to MITRE ATT&CK
title: '[RULE] '
labels: new-rule
assignees: reninjk
---

## Rule Name
A descriptive name for the detection rule.

## MITRE ATT&CK Mapping
- Tactic: [e.g., TA0001 - Initial Access]
- Technique: [e.g., T1566 - Phishing]
- Sub-technique: [e.g., T1566.001 - Spearphishing Attachment]

## Description
What does this rule detect? What attacker behaviour does it identify?

## Rule Logic
```yaml
# Paste your Sigma rule here
title: Example
status: experimental
description: Detects ...
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'example'
    condition: selection
```

## Data Sources Required
- [ ] Windows Event Logs
- [ ] Sysmon
- [ ] EDR telemetry
- [ ] Network logs
- [ ] Other: ___

## False Positive Rate
Expected false positive rate: Low / Medium / High

## Testing Notes
How was this rule tested? What environment / log source was used?
