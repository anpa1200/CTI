# Research Charter

This repository uses evidence labels to separate observation, reporting, assessment, and claims.

| Label | Meaning | Use |
|---|---|---|
| Observed | Directly visible in an artifact, dataset, sample, log, or cited primary source. | Strongest factual basis. |
| Reported | Stated by a cited external source. | Attribute the claim to the source. |
| Assessed | Analyst judgment based on multiple evidence points. | Include confidence and reasoning. |
| Claimed | Stated by an actor, victim, vendor, or third party without independent confirmation. | Do not treat as verified. |

## Rules

- Do not overstate attribution.
- Keep source links near the claim they support.
- Mark uncertainty explicitly.
- Separate infrastructure overlap from actor attribution.
- Prefer detection-ready output: ATT&CK mapping, hunt hypothesis, IOC context, and recommended telemetry.
