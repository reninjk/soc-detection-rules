## Summary
<!-- What does this rule detect, and why is it needed? -->

## Type of Change
- [ ] New Sigma rule
- [ ] Rule improvement (false positive reduction, field coverage, logic fix)
- [ ] MITRE ATT&CK coverage matrix update
- [ ] Threat hunting query
- [ ] Documentation fix

## Rule Details (for new rules)
| Field | Value |
|-------|-------|
| MITRE Technique | T1XXX.XXX |
| Sigma Level | informational / low / medium / high / critical |
| Log Source | windows / linux / proxy / dns / edr |
| Tested Against | [SIEM or log sample] |

## Checklist
- [ ] Rule passes `sigma check` with no errors
- [ ] No real IOCs, internal hostnames, or asset identifiers in rule conditions
- [ ] MITRE ATT&CK tags present in the `tags` field
- [ ] `falsepositives` field completed (not left blank)
- [ ] `status` field set correctly (stable / test / experimental)
- [ ] MITRE coverage matrix updated if new technique covered
- [ ] Tested against sample log data — confirm true positive fires
- [ ] False positive rate assessed — document in PR if > 5%

## Review Requirements
- [ ] Peer review by senior analyst
- [ ] SOC Manager sign-off for critical/high level rules

## Related Issue
Closes #

## Reviewer Notes
<!-- Paste a sample log event that triggers this rule (anonymised/fictional data only) -->
