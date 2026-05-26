# Security Policy

## Repository Overview

This repository contains **Sigma detection rules and threat hunting queries**. Rules are written in a vendor-neutral format and must not contain environment-specific data.

## Sensitive Data Policy

The following must **never** be committed:

- Real IOC values (IP addresses, domains, file hashes) from live incidents
- Internal hostnames, usernames, or asset identifiers in rule conditions
- API keys, credentials, or tokens of any kind
- SIEM connection details or internal infrastructure references

All detection logic must use **generic field names** following the Sigma specification. Environment-specific field mappings belong in your SIEM's Sigma backend configuration, not in the rules themselves.

## Reporting a Security Issue

If you identify a detection gap, a rule that could be weaponised by an adversary (e.g., reveals detection thresholds), or a process concern:

1. Do **not** open a public GitHub issue
2. Contact the SOC detection engineering lead or SOC Manager directly
3. For rules that reveal sensitive detection logic: treat as TLP:AMBER — discuss internally before any public disclosure

## Rule Classification

Rules contain a `level` field:
- **critical / high**: Reviewed by SOC Manager before merge
- **medium / low / informational**: Peer review by senior analyst sufficient

Rules containing logic derived from internal threat intelligence or custom hunting hypotheses should be marked `status: experimental` until validated.

## Supported Versions

Only the `main` branch is maintained. Rules are reviewed:
- When a new MITRE ATT&CK version is published
- After a significant internal incident reveals a detection gap
- Quarterly as part of the detection engineering programme review

## Compliance

Detection rules in this repository support:
- ISO 27001:2022 Annex A 8.16 — Monitoring Activities
- CIS Controls v8 — Control 13: Network Monitoring and Defence
- NIST CSF 2.0 — Detect: Continuous Monitoring (DE.CM)
