# IOC Tables — {{REPORT_TITLE}} ({{ALIASES}})

Extracted from the [CTI Research report](cti-research-{{SLUG}}-with-nav.pdf) for correlation and triage. **Do not use as standalone attribution proof.** Validate with current telemetry before blocking.

**Evidence cutoff:** {{EVIDENCE_CUTOFF}} · **Sources:** [R1](SOURCE_URL_1), [R2](SOURCE_URL_2)

---

## Network IOCs (IP/CIDR)

| Indicator | Evidence | Freshness | Action |
|-----------|----------|-----------|--------|
| (add IPs) | near-hard / soft | stable_tracking / maybe_expired / volatile | Hunt; conditional block after local validation |

---

## Domain / URL / Infrastructure IOCs

| Indicator | Context | Evidence | Action |
|-----------|---------|----------|--------|
| (add domains/URLs, defanged) | (e.g. C2, phishing, payload) | near-hard / soft | Block / Alert / Hunt |

---

## File / Artifact IOCs (names)

| Indicator | Context | Evidence | Action |
|-----------|---------|----------|--------|
| (add filenames, services) | (e.g. loader, wiper, driver) | near-hard / soft | Hunt + detonation / quarantine |

---

## Hash IOCs — SHA-256

| Hash | File / context | Evidence | Action |
|------|----------------|----------|--------|
| (add hashes) | (filename or lineage) | hard / near-hard / stable_tracking | Block + hunt |

---

## Hash IOCs — MD5 (optional / legacy)

| Hash | Context | Action |
|------|---------|--------|
| (add if applicable) | Campaign / lineage / artifact | Hunt / Block + hunt |

---

## Hash IOCs — SHA-1 (optional)

| Hash | File / context | Evidence | Action |
|------|----------------|----------|--------|
| (add if applicable) | (e.g. Industroyer2 chain) | hard / stable | Block + hunt |

---

## Behavioral / Command-Line IOCs

| Indicator | Context | Action |
|-----------|---------|--------|
| (e.g. vssadmin Delete Shadows, bcdedit, kill-list) | (destructive / persistence / anti-forensics) | Alert / Hunt / playbook trigger |

---

## Actor Channel / Messaging (soft IOCs)

| Indicator | Use |
|-----------|-----|
| (e.g. Telegram, X handle) | Monitor + timeline correlation only |

---

## Defender usage notes

- Revalidate all network indicators against current blocklists and passive DNS before production blocking.
- Treat channel/claim-only indicators as soft IOCs until telemetry confirms compromise.
- Prioritize multi-signal correlation (IOC + behavior + campaign context) over single-indicator decisions.
