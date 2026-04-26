# CTI Research: LLM/AI/MCP Usage in the Cyber Kill Chain

*Evidence-Labeled Threat Intelligence Assessment and SOC Defensive Guidance (2023 - March 2026)*

## Table of Contents

- [Report Metadata](#report-metadata)
- [Revision History](#revision-history)
- [Methodology & Evidence Labels](#methodology--evidence-labels)
- [Confidence & What Changes Confidence](#confidence--what-changes-confidence)
- [Executive Summary](#executive-summary)
- [Key Judgments with Confidence Levels](#key-judgments-with-confidence-levels)
- [Threat Landscape: Actor Classes and AI Adoption](#threat-landscape-actor-classes-and-ai-adoption)
- [AI/MCP in the Kill Chain: Stage-by-Stage Analysis](#aimcp-in-the-kill-chain-stage-by-stage-analysis)
- [Case Study: FortiGate Campaign at Scale (January-February 2026)](#case-study-fortigate-campaign-at-scale-january-february-2026)
- [MCP-Specific Risk Model](#mcp-specific-risk-model)
- [Detection Engineering: SOC-Ready Rules](#detection-engineering-soc-ready-rules)
- [Mini Playbook: First 30 Minutes](#mini-playbook-first-30-minutes)
- [Practical Defensive Actions: 30 Days](#practical-defensive-actions-30-days)
- [Intelligence Gaps](#intelligence-gaps)
- [Appendix A: ATT&CK-Oriented Mapping](#appendix-a-attck-oriented-mapping)
- [References](#references)

---

## Report Metadata

- **Document classification:** Public-release CTI product. All sources are open and publicly available.
- **Author:** Andrey Pautov
- **Date:** March 8, 2026
- **Assessment window:** 2023 - March 2026
- **Evidence cutoff (collection freeze):** March 8, 2026 (UTC)
- **Analytic intent:** Convert public-source reporting into evidence-labeled, SOC-actionable CTI on AI-enabled offensive operations and MCP-related attack pathways.
- **Scope note:** MCP abuse claims are currently unevenly evidenced; several high-impact narratives remain single-source and are treated as hunting hypotheses until independently replicated.

---

## Revision History

**Version 1.0** - March 8, 2026. Initial release.

---

## Methodology & Evidence Labels

This document uses six evidence labels applied consistently to factual and analytical claims.

- **Observed:** direct technical artifacts in primary reporting (samples, reverse engineering, telemetry, logs, infrastructure artifacts).
- **Reported:** documented by authoritative sources where full victim-side telemetry is not fully public.
- **Observed/Reported:** mixed evidence where parts are directly technical and parts are source-reported.
- **Assessed:** analytical conclusion synthesized from multiple Observed and Reported items; not standalone proof.
- **Partially Corroborated:** at least one technical artifact exists, but complete kill-chain or independent replication is incomplete.
- **Claimed:** assertion without sufficient independent technical validation.

Additional notation:
- **[single-source primary reporting]:** claim currently supported by one primary technical source.
- **[CORRECTION] marker:** correction of common analytical error or overclaim in public discourse.

> **Analytic rule:** "AI involvement" does not imply "AI autonomy." Assistance, augmentation, and autonomous decisioning are treated as distinct categories.

---

## Confidence & What Changes Confidence

- **High confidence:** multi-source convergence across independent technical reporting and/or high-quality telemetry with consistent artifacts.
- **Medium-High confidence:** strong convergence with bounded artifact gaps.
- **Medium confidence:** plausible and partially supported, but source breadth or replication depth remains limited.
- **Low confidence:** claim-led narrative with limited corroboration.

**What increases confidence:**
- Independent telemetry from multiple vendors.
- Reproducible malware behavior showing runtime LLM/API interaction.
- Time-overlapping infrastructure and workflow reuse across campaigns.
- Clear distinction between actor prompts, model output, and final operational actions.

**What decreases confidence:**
- Single-source reporting with no independent replication.
- Circular citation chains.
- Conflation of proof-of-concept with operational deployment.
- Claims of "full autonomy" without verifiable logs/traces.

---

## Executive Summary

[Observed/Reported] By March 2026, AI has moved from peripheral tooling into recurring operational use across multiple stages of the cyber kill chain. The strongest evidence supports **AI as a force multiplier** for reconnaissance, phishing content generation, scripting, post-compromise prioritization, and operator troubleshooting, rather than universal end-to-end autonomy. [R1][R2][R3][R4][R5][R6][R7][R8][R9]

[Reported] A major inflection point is the January-February 2026 FortiGate campaign documented by Amazon Threat Intelligence: a financially motivated, Russian-speaking actor compromised more than 600 devices in 55+ countries while relying primarily on security hygiene weaknesses (exposed interfaces, weak credentials, missing MFA), then using AI services to scale planning and execution. [R1]

[Observed/Reported] GTIG reporting documents malware patterns where LLM APIs are integrated directly into runtime workflows (for example, just-in-time command generation/obfuscation behaviors), indicating an early shift from "AI for preparation" toward "AI in execution loops." [R3]

[Reported] Model-provider disruption reports (OpenAI, Anthropic) consistently indicate that most observed malicious usage still centers on acceleration of existing tradecraft, not breakthrough novel capability. [R5][R6][R7][R8][R9][R10][R11]

[Assessed] The principal 2026 risk is **industrialized throughput**: lower-skilled actors can run more campaigns, with faster adaptation and lower unit cost per target. Defensive advantage now depends on detection/containment speed, strict identity controls, and hardened AI-agent/MCP integration boundaries.

---

## Key Judgments with Confidence Levels

**Judgment 1.** AI is now operationally embedded in attacker workflows across recon, social engineering, tooling, and post-exploitation support. **Confidence: High.** [R1][R2][R3][R4][R5][R6][R7][R8][R9]

**Judgment 2.** Most observed actor benefit is increased speed/scale, not reliable full autonomy in complex hardened environments. **Confidence: High.** [R1][R2][R4][R5][R8][R9]

**Judgment 3.** Runtime LLM-assisted malware behavior exists in the wild, but broad prevalence remains limited. **Confidence: Medium-High.** [R3]

**Judgment 4.** MCP expands attack surface through trust-boundary confusion (prompt injection, tool poisoning, over-privileged tool execution, token misuse), and mature controls are still unevenly deployed. **Confidence: Medium-High.** [R12][R13][R14][R15][R18]

**Judgment 5.** High-visibility "AI-orchestrated campaign" claims can be directionally correct but require independent replication before broad generalization. **Confidence: Medium.** [R10][R16]

**Judgment 6.** For defenders, identity and exposure hygiene (MFA, management-plane restriction, least privilege) remains the highest-return control even under AI-enabled offensive pressure. **Confidence: High.** [R1][R2][R3][R14][R17][R18]

---

## Threat Landscape: Actor Classes and AI Adoption

### State-Aligned Activity

[Reported] Google and Microsoft reporting describe PRC-, RU-, IR-, and DPRK-aligned activity leveraging LLMs for reconnaissance, target research, social engineering preparation, and scripting support. [R2][R3][R4]

[Reported] OpenAI disruption reports similarly document state-linked clusters using models for campaign enablement tasks, while generally not demonstrating autonomous high-complexity breakthrough operations. [R5][R6][R7][R8][R9]

### Financially Motivated Activity

[Observed/Reported] The FortiGate campaign demonstrates the most operationally consequential pattern: AI-accelerated exploitation of common misconfiguration and identity weaknesses at global scale. [R1]

[Assessed] Criminal adoption is likely to outpace high-end state workflows in volume because AI most strongly amplifies routine but high-yield tasks.

### Ecosystem Trend

[Reported] Across vendors, the trendline is consistent: AI is becoming an embedded co-pilot for offensive operations, while fully autonomous kill chains remain rare and heavily context-dependent. [R1][R2][R3][R4][R5][R10]

---

## AI/MCP in the Kill Chain: Stage-by-Stage Analysis

### 1. Reconnaissance

[Observed/Reported] LLMs are used to prioritize targets, summarize scan results, profile organizations and personnel, and accelerate OSINT synthesis. [R1][R2][R3][R4]

[Assessed] The key effect is compression of pre-intrusion planning time.

### 2. Weaponization

[Reported] Actors use LLMs to generate/adapt phishing templates, scripts, payload wrappers, and obfuscation logic. [R2][R3][R5][R8]

[Partially Corroborated] Runtime LLM/API-linked malware behavior has been reported in selected families, but prevalence and durability remain under active observation. [R3]

### 3. Delivery

[Reported] AI improves linguistic quality and localization of phishing and pretexting, including enterprise-tailored social engineering. [R2][R3][R4][R17]

### 4. Exploitation

[Observed/Reported] In the FortiGate case, AI augmented exploitation planning and operator decision support, including task trees and handling of variable target topologies. [R1]

[Assessed] AI currently improves operator decision speed more than exploit novelty.

### 5. Installation/Persistence

[Reported] AI-assisted scripting is used to modify persistence logic and automate repetitive post-exploitation setup steps. [R2][R3][R5]

### 6. Command and Control

[Partially Corroborated] Some campaigns indicate AI-assisted command generation and adaptive command selection loops, but hard telemetry for autonomous closed-loop C2 remains limited in open reporting. [R3][R10][R16]

### 7. Actions on Objectives

[Observed/Reported] In financially motivated operations, AI augments lateral movement planning, identity abuse workflowing, and backup-target discovery/prioritization. [R1][R2]

[Assessed] AI's strongest impact at this stage is workflow optimization and operator scale.

### 8. Monetization/Influence Layer

[Reported] AI is widely used for fraud pretexting, influence content generation, and campaign scaling in BEC/scam ecosystems. [R2][R5][R8][R17]

---

## Case Study: FortiGate Campaign at Scale (January-February 2026)

[Observed/Reported] Amazon Threat Intelligence reported that between **January 11, 2026 and February 18, 2026**, a Russian-speaking financially motivated actor compromised over 600 FortiGate devices across 55+ countries. [R1]

Key technical observations:

- [Observed] Primary entry condition: exposed management interfaces with weak credentials and single-factor authentication.
- [Reported] No FortiGate zero-day was required for the observed compromises.
- [Observed/Reported] Actor used AI systems for task decomposition, planning, and adaptation at scale.
- [Observed] Infrastructure indicators included IPs such as `212.11.64.250` and `185.196.11.225`.

[Assessed] This campaign is a benchmark for AI-enabled offense industrialization: it demonstrates that operational scale can be achieved through process automation around known weakness classes, without novel exploit discovery.

---

## MCP-Specific Risk Model

[Reported] MCP provides a standard way for models/agents to call tools and access context, which improves productivity but introduces new security-critical trust boundaries. [R12][R13]

### High-Risk Failure Modes

- **Indirect prompt injection via tool/content channel**  
[Reported] Malicious instructions embedded in external content can alter agent behavior unless strict isolation and policy gating are enforced. [R13][R14]

- **Tool poisoning and over-privileged execution**  
[Reported] MCP server/tool trust assumptions can be abused where capability exposure exceeds least-privilege needs. [R13][R15][R18]

- **Confused deputy and authorization leakage**  
[Reported] MCP guidance explicitly warns against weak token handling patterns (for example token passthrough). [R12][R13]

- **Supply-chain style server risk**  
[Reported] Third-party MCP servers can act as high-impact transitive trust points if not sandboxed and audited. [R13][R15]

### Evidence Boundary

[Partially Corroborated] Public reporting confirms plausible and demonstrated abuse paths, but large-scale independently replicated "MCP-native intrusion epidemics" are not yet broadly documented in open sources as of March 8, 2026. [R15][R16]

---

## Detection Engineering: SOC-Ready Rules

### High Priority

- Alert on unusual outbound connections from security/network management hosts to public LLM APIs during active incident windows.
- Detect login bursts against management interfaces (for example FortiGate HTTPS admin ports) followed by immediate configuration/export activity.
- Correlate AI API usage spikes with post-compromise actions (credential dumping tools, AD discovery, backup server targeting).
- Flag agent/tool chains where untrusted retrieved content is fed directly into privileged tool execution.
- Alert on unauthorized creation or modification of MCP tool configuration, credentials, or server endpoints.
- Detect use of privileged tokens by AI agents outside approved execution contexts.

### Medium Priority

- Monitor for frequent prompt-like command templates in script logs that indicate machine-generated operator loops.
- Hunt for rapid script mutation patterns across short intervals (possible AI-assisted re-generation).
- Baseline approved AI-provider traffic and alert on new model endpoints or anomalous model/provider switching.
- Detect fallback behavior where actors pivot quickly across many low-hardened targets after failed attempts.

---

## Mini Playbook: First 30 Minutes

1. Isolate affected management-plane assets and revoke exposed admin credentials.
2. Enforce emergency MFA on remote administration paths where feasible.
3. Block suspicious IPs/domains and throttle/deny unexpected AI API egress from sensitive segments.
4. Snapshot current device and identity telemetry before containment changes.
5. Audit AI agent/MCP integrations for over-privileged tools and active sessions.
6. Disable untrusted MCP servers and rotate associated secrets/tokens.
7. Hunt for lateral movement toward AD, backup infrastructure, and identity stores.
8. Preserve model/tool interaction logs for forensic reconstruction.
9. Validate backup integrity and restore-path security.

---

## Practical Defensive Actions: 30 Days

1. Restrict all security appliance management interfaces to private/admin-only networks.
2. Enforce phishing-resistant MFA for all privileged and remote access workflows.
3. Implement explicit allowlists for AI API egress by segment, host, and service account.
4. Deploy policy gates between retrieved external content and tool execution in agent workflows.
5. Prohibit MCP token passthrough patterns and enforce OAuth token audience/expiry checks.
6. Sandbox all high-risk MCP tools with minimal filesystem/network permissions.
7. Create behavioral detections for AI-assisted operator loops and rapid script regeneration.
8. Run tabletop scenarios: `AI-assisted recon -> credential abuse -> AD pivot -> backup denial`.
9. Build incident runbooks that combine identity containment with AI-integrations containment.
10. Maintain an internal evidence rubric separating `AI-assisted`, `AI-integrated`, and `AI-autonomous` claims.

---

## Intelligence Gaps

- Independent replication of large-scale MCP-specific attack chains remains limited.
- Reliable telemetry standards for "AI in the loop" attribution are not yet mature across vendors.
- Runtime LLM-dependent malware prevalence is still under-characterized by sector and geography.
- Quantitative measures of "attacker skill uplift" vary and are not standardized.
- Public datasets linking AI-assisted intrusion timelines to breakout-time compression remain sparse.
- Distinguishing prompt-generated operator artifacts from normal scripting at scale remains difficult.

---

## Appendix A: ATT&CK-Oriented Mapping

### Reconnaissance / Resource Development

- **T1595** Active Scanning: AI-assisted prioritization and scan interpretation.
- **T1583 / T1584** Acquire/Compromise Infrastructure: rapid scaling of staging infrastructure decisions.

### Initial Access

- **T1078** Valid Accounts: credential abuse at scale with AI-assisted triage.
- **T1566** Phishing: LLM-generated and localized lure content.
- **T1190** Exploit Public-Facing Application: operational exploitation of exposed management planes.

### Execution / Persistence

- **T1059** Command and Scripting Interpreter: AI-assisted script generation/adaptation.
- **T1053** Scheduled Task/Job: automated persistence scripting in post-compromise workflows.

### Credential Access / Lateral Movement

- **T1003** OS Credential Dumping: guided operator workflows and command generation.
- **T1021** Remote Services: AI-assisted movement planning in enterprise environments.

### Command and Control / Exfiltration

- **T1071** Application Layer Protocol: standard C2 overlays with AI-assisted operator decisioning.
- **T1567** Exfiltration Over Web Service: cloud/API-enabled staging and transfer workflows.

---

## References

**[R1]** AWS Security Blog. *AI-augmented threat actor accesses FortiGate devices at scale.* February 20, 2026.  
https://aws.amazon.com/blogs/security/ai-augmented-threat-actor-accesses-fortigate-devices-at-scale/

**[R2]** Microsoft Security Blog. *AI as tradecraft: How threat actors operationalize AI.* March 6, 2026.  
https://www.microsoft.com/en-us/security/blog/2026/03/06/ai-as-tradecraft-how-threat-actors-operationalize-ai/

**[R3]** Google Threat Intelligence Group. *Threat actor usage of AI tools.* November 5, 2025.  
https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools

**[R4]** Google Threat Intelligence Group. *Adversarial misuse of generative AI.* January 29, 2025.  
https://cloud.google.com/blog/topics/threat-intelligence/adversarial-misuse-generative-ai

**[R5]** OpenAI. *Disrupting malicious uses of AI: February 2026 report.* February 25, 2026.  
https://openai.com/index/disrupting-malicious-ai-uses/

**[R6]** OpenAI. *Disrupting malicious uses of AI: October 2025 report.* October 8, 2025.  
https://openai.com/global-affairs/disrupting-malicious-uses-of-ai-october-2025-update/

**[R7]** OpenAI. *Disrupting malicious uses of AI: June 2025 report (PDF).* June 2025.  
https://cdn.openai.com/threat-intelligence-reports/5f73af09-a3a3-4a55-992e-069237681620/disrupting-malicious-uses-of-ai-june-2025.pdf

**[R8]** OpenAI. *Disrupting malicious uses of AI.* February 21, 2025.  
https://openai.com/global-affairs/disrupting-malicious-uses-of-ai/

**[R9]** OpenAI. *Disrupting malicious uses of AI by state-affiliated threat actors.* February 14, 2024.  
https://openai.com/index/disrupting-malicious-uses-of-ai-by-state-affiliated-threat-actors/

**[R10]** Anthropic. *Disrupting the first reported AI-orchestrated cyber espionage campaign.* November 13, 2025.  
https://www.anthropic.com/news/disrupting-AI-espionage

**[R11]** Anthropic. *Building and evaluating AI defenders at the inflection point.* October 6, 2025.  
https://www.anthropic.com/research/building-and-evaluating-ai-defenders-at-the-inflection-point

**[R12]** Model Context Protocol. *Specification 2025-11-25: Authorization.*  
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

**[R13]** Model Context Protocol. *Specification 2025-06-18: Security Best Practices.*  
https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

**[R14]** Microsoft Developer Blogs. *How Microsoft mitigates indirect prompt injection attacks for MCP.* April 14, 2025.  
https://devblogs.microsoft.com/blog/how-microsoft-mitigates-indirect-prompt-injection-attacks-for-mcp/

**[R15]** Kaspersky. *MCP can be exploited by attackers and puts systems at risk, Kaspersky warns.* September 15, 2025.  
https://www.kaspersky.com/about/press-releases/mcp-can-be-exploited-by-attackers-and-puts-systems-at-risk-kaspersky-warns

**[R16]** Cyber and Ramen. *LLMs in the kill chain: inside a custom MCP targeting FortiGate devices across continents.* February 21, 2026.  
https://cyberandramen.net/2026/02/21/llms-in-the-kill-chain-inside-a-custom-mcp-targeting-fortigate-devices-across-continents/

**[R17]** OWASP. *Top 10 for LLM Applications 2025.*  
https://owasp.org/www-project-top-10-for-large-language-model-applications/
https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf

**[R18]** OWASP. *MCP Top 10: MCP06 Tool Poisoning.*  
https://genai.owasp.org/resource/mcp-top-10/mcp06-tool-poisoning/

---

*Evidence cutoff: March 8, 2026 (UTC). All sources are publicly available. This is an open-source intelligence analysis product. Reliability labels [Observed], [Reported], [Observed/Reported], [Assessed], [Partially Corroborated], and [Claimed] are used throughout; [single-source primary reporting] is applied as an additional evidentiary caveat where relevant.*

*Disclaimer: Do not use single-source or low-confidence claims as the sole basis for legal, regulatory, or policy attribution statements.*
