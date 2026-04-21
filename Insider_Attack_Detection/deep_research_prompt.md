# Deep Research Prompt — Insider Attack Detection

You are an expert detection engineer and threat intelligence analyst. Produce a comprehensive technical research report on detecting malicious insider threats — employees or contractors who abuse legitimate access to steal data, commit sabotage, or assist external attackers.

## Research Task

Analyse available IR reports, CERT/CMU insider threat case studies, DBIR data, Mandiant M-Trends, and academic UEBA research. Ground every detection claim in a cited source or label it [Inferred].

Cover the following insider threat categories with real documented cases for each: data exfiltration, sabotage, privilege abuse, financial fraud, departing employee, and insider collaborating with external attacker.

## Detection Coverage

For each detection method provide: what behaviour it catches, required log source/telemetry, specific event IDs or fields where applicable, detection logic, false positive sources, and a real-world example.

Cover detection from simple to complex:

1. **Deterministic rules** — bulk file copy to USB, email forwarding to personal address, large SharePoint downloads, print volume spikes, post-termination access attempts, audit log deletion
2. **Behavioural heuristics** — after-hours access, access outside role scope, peer-group deviation, data staging pattern (compress + copy + external destination), departing employee volume spike
3. **Identity and privilege anomalies** — access to systems with no prior history, lateral movement with valid credentials, new admin account creation outside change windows, access creep from role changes
4. **Exfiltration path coverage** — email, USB, personal cloud sync, SaaS upload (Slack/GitHub/Jira), printing, screenshot tools, covert channels
5. **Sabotage signals** — mass deletion, backup removal, logic bomb artifacts (scheduled tasks, WMI subscriptions), CI/CD pipeline tampering, config changes outside change windows
6. **UEBA and anomaly models** — entity risk scoring, peer-group clustering, sequence anomaly, graph analytics on access patterns
7. **Covering-tracks detection** — log clearing, anti-forensic tool execution, timestomping, PowerShell history deletion

## Output Structure

1. Introduction — why insider detection is structurally harder than external threat detection
2. Insider Threat Taxonomy and Kill Chain (CMU SEI model)
3. Documented Case Studies — 8 real cases: signals present in retrospect, what was missed, what triggered detection
4. Detection Methods — sections 1–7 above with full coverage
5. Detection Priority Matrix — effort vs. coverage
6. Required Telemetry — what must be collected before any detection works
7. Legal and Privacy Constraints — monitoring limits under GDPR, US law, and Australian Privacy Act
8. Implementation Guidance — phased programme
9. Conclusion and coverage gaps
10. References

## Key Questions to Answer

- What percentage of insider cases are detected by technical controls vs. human tip? (cite CERT/DBIR data)
- Average dwell time for insider threats vs. external attackers?
- Which insider categories have the weakest technical detection surface?
- Where does DLP consistently fail and why?
- How does detection differ for privileged users vs. standard employees?
