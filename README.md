# CTI

Evidence-labeled cyber threat intelligence reports designed to become hunts, detections, pivots, and defensible assessments.

![License](https://img.shields.io/github/license/anpa1200/CTI)
![Last commit](https://img.shields.io/github/last-commit/anpa1200/CTI)

## Demo

Add screenshots of one HTML report, the evidence-label rubric, and the template directory.

## What This Is For

This repository is for CTI analysts, SOC leads, and detection engineers who need structured threat reports with explicit confidence discipline. Each report should make clear what is observed, reported, assessed, or claimed.

## What It Produces

| Output | Use |
|---|---|
| PDF report | Formal reading and sharing |
| HTML report | Web review |
| Evidence labels | Claim discipline |
| Actor notes | Research continuity |
| Templates | Repeatable CTI production |

## Reports

| Report | Format | Evidence model | Assessment confidence summary |
|---|---|---|---|
| Handala / Void Manticore | PDF + HTML | Observed / Reported / Assessed / Claimed | [user: confirm summary] |
| Sandworm / APT44 | PDF + HTML | Observed / Reported / Assessed / Claimed | [user: confirm summary] |
| MuddyWater / Seedworm | PDF + HTML | Observed / Reported / Assessed / Claimed | [user: confirm summary] |

## Quick Start

```bash
git clone https://github.com/anpa1200/CTI.git
cd CTI
find . -maxdepth 3 -type f | sort
```

## How It Works

```mermaid
flowchart LR
  Sources[Sources] --> Evidence[Evidence labeling]
  Evidence --> Assessment[Analytic assessment]
  Assessment --> Attack[ATT&CK mapping]
  Attack --> Detection[Hunts / detections]
  Detection --> Report[PDF / HTML report]
```

## Coverage

| Area | Coverage |
|---|---|
| Actors | Handala / Void Manticore, Sandworm / APT44, MuddyWater / Seedworm |
| Labels | Observed, Reported, Assessed, Claimed |
| Outputs | PDF, HTML, templates |
| Use case | CTI, SOC handoff, detection planning |

## Related Sites And Articles

- Israel CTI knowledge base: https://anpa1200.github.io/israel-government-threat-actors-cti/
- CTI Analyst Field Manual: https://anpa1200.github.io/cti-analyst-field-manual/
- Attribution Methodology: https://medium.com/@1200km/attribution-methodology-how-to-build-defend-and-challenge-a-threat-actor-attribution-071066437ced
- Infrastructure Pivoting: https://infosecwriteups.com/infrastructure-pivoting-how-cti-analysts-expand-from-a-single-ioc-to-a-full-attacker-network
- ATT&CK as a Working Tool: https://medium.com/@1200km/att-ck-as-a-working-tool-theory-and-hands-on-practical-usage-d63835c9f101

## How To Cite

Use the report title, repository URL, commit hash, and access date. See `CITATION.cff`.

## Research Charter

See `RESEARCH-CHARTER.md`.

## Limitations And Honesty

Public-source CTI is bounded by available reporting. Reports should not overstate attribution beyond evidence quality.

## License

CC BY 4.0 recommended for reports and prose.

## Security Policy

See `SECURITY.md`.
