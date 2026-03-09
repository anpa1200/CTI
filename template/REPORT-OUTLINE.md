# Report outline — long-form CTI research article

Use this outline when writing the research (e.g. for Medium). Adapt sections to the actor and available evidence.

---

## 1. Title and subtitle

- **Title:** CTI Research: {{REPORT_TITLE}}
- **Subtitle:** Evidence-Labeled Threat Intelligence Assessment and SOC Defensive Guidance ({{DATE_RANGE}})

---

## 2. Table of contents (for reader / for build script)

List main sections so the HTML/PDF builder can generate a clickable TOC.

---

## 3. Report metadata

- Evidence cutoff date
- Primary sources / baseline advisories
- Author and canonical link

---

## 4. Methodology & evidence labels

- **Observed** — direct analysis or vendor technical write-up
- **Reported** — cited from another publication
- **Assessed** — analytic inference from multiple sources
- **Claimed** — actor/persona claim (unverified)

---

## 5. Confidence & what changes confidence

- What raises or lowers confidence in attribution and impact
- Shelf life of IOCs (network vs behavioral)

---

## 6. Executive summary

- 2–4 paragraphs: who, time range, main TTPs, key defensive takeaways

---

## 7. Alias / cluster crosswalk

- All known names for the actor (vendor aliases, CISA, MITRE, etc.)

---

## 8. Key judgments

- KJ1, KJ2, … with confidence (High / Medium-High / Medium / Low) and references [Rx]

---

## 9. Activity timeline

- Chronological milestones with [Observed/Reported/Assessed] and [Rx]

---

## 10. Confirmed vs claimed matrix

- Table or list: what is confirmed by evidence vs what is only claimed

---

## 11. Public presence / information operations (if applicable)

- Channels, personas, narrative themes

---

## 12. Targeting and victimology

- Sectors, regions, victim types; [Observed/Reported] and [Rx]

---

## 13. Tactics, techniques, and procedures (TTPs)

- Initial access, execution, persistence, privilege escalation, defense evasion, credential access, C2, impact
- Tag with evidence level and [Rx]

---

## 14. ATT&CK-oriented mapping (analyst view)

- MITRE ATT&CK Enterprise (and ICS if relevant) technique IDs with short description and [Rx]

---

## 15. Detection and response priorities

- Priority 1…N: what defenders should do first (governance, detection, response)

---

## 16. Detection engineering pack (SOC-ready)

- Concrete detection ideas: rules, data sources, logic, response actions

---

## 17. Wiper / disruption first 30 minutes (defensive mini-playbook)

- Step-by-step: isolate, revoke, block, collect, validate, hunt (adapt title if no wiper)

---

## 18. Controls mapping (NIST CSF-lite)

- Identify, Protect, Detect, Respond, Recover — short bullets

---

## 19. IOC compendium (public reporting)

- Network, domain, hash, file, behavioral IOCs with evidence/freshness tags
- Or “see Appendix / IOCs.md”

---

## 20. Common patterns and cross-group correlation

- Overlap with other clusters, shared TTPs, caveats

---

## 21. Confidence gaps and collection gaps

- What is unknown or disputed; what would improve confidence

---

## 22. Practical defensive actions (next 30 days)

- Numbered list of concrete actions for defenders

---

## 23. References

- [R1], [R2], … with full title, source, URL (for in-text citations and HTML links)

---

## 24. Appendices (optional)

- Appendix A: IOC compendium (if not in main body)
- Appendix B: ATT&CK mapping (if not in main body)
- Appendix C: YARA / Sigma (if you have them)
