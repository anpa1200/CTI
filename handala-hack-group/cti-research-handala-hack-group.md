# CTI Research: Handala Hack Group (aka Handala Hack Team)

*Evidence-Labeled Threat Intelligence Assessment and SOC Defensive Guidance (December 2023 to March 2026)*

## Table of Contents
- [Report Metadata](#report-metadata)
- [Methodology & Evidence Labels](#methodology--evidence-labels)
- [Confidence & What Changes Confidence](#confidence--what-changes-confidence)
- [Executive Summary](#executive-summary)
- [Alias / Cluster Crosswalk](#alias--cluster-crosswalk)
- [Key Judgments](#key-judgments)
- [Activity Timeline (2023–2026)](#activity-timeline-20232026)
- [Confirmed vs Claimed Matrix](#confirmed-vs-claimed-matrix)
- [Public Presence and Information Operations Footprint](#public-presence-and-information-operations-footprint)
- [Targeting and Victimology](#targeting-and-victimology)
- [Tactics, Techniques, and Procedures (Observed/Reported)](#tactics-techniques-and-procedures-observedreported)
- [ATT&CK-Oriented Mapping (Analyst View)](#attck-oriented-mapping-analyst-view)
- [Detection and Response Priorities](#detection-and-response-priorities)
- [Detection Engineering Pack (SOC-Ready)](#detection-engineering-pack-soc-ready)
- [Wiper First 30 Minutes (Defensive Mini-Playbook)](#wiper-first-30-minutes-defensive-mini-playbook)
- [Controls Mapping (NIST CSF-Lite)](#controls-mapping-nist-csf-lite)
- [Comprehensive IOC Compendium (Public Reporting)](#comprehensive-ioc-compendium-public-reporting)
- [Overall Statistics, Common Patterns, and Cross-Group Correlation](#overall-statistics-common-patterns-and-cross-group-correlation)
- [VirusTotal Spot-Check (Quota-Limited)](#virustotal-spot-check-quota-limited)
- [Confidence and Gaps](#confidence-and-gaps)
- [Practical Defensive Actions (Next 30 Days)](#practical-defensive-actions-next-30-days)
- [Appendix B: Volatile Indicators (Rotate Quickly)](#appendix-b-volatile-indicators-rotate-quickly)
- [References](#references)
- [Editorial Change Log](#editorial-change-log)

### Table Navigation
- [Table 4: Controls Mapping (NIST CSF-Lite)](#table-4-controls-mapping-nist-csf-lite)
- [Table 5: Network IOCs (IP/CIDR)](#table-5-network-iocs-ipcidr)
- [Table 6: URL and Infrastructure IOCs](#table-6-url-and-infrastructure-iocs)
- [Table 7: Common/Benign Services Used in Chain](#table-7-commonbenign-services-used-in-chain)
- [Table 8: Actor Channel and Messaging IOCs](#table-8-actor-channel-and-messaging-iocs)
- [Table 9: Core Delivery/Impact Artifacts](#table-9-core-deliveryimpact-artifacts)
- [Table 10: Wiper and Destructive Lineage Artifacts](#table-10-wiper-and-destructive-lineage-artifacts)
- [Table 11: Hash IOCs (SHA256)](#table-11-hash-iocs-sha256)
- [Table 12: Hash IOCs (MD5)](#table-12-hash-iocs-md5)

---

## Report Metadata
- **Author:** Andrey Pautov
- **Date:** March 6, 2026
- **Scope:** Threat actor profile and defensive implications
- **Assessment window:** December 2023 to March 2026
- **Evidence cutoff (collection freeze):** March 5, 2026 (UTC)

---

## Methodology & Evidence Labels
- **Observed:** directly documented technical evidence in primary technical/government reporting (for example: hashes, malware behavior, telemetry-backed procedure descriptions).
- **Reported:** described by reputable external reporting (vendor intelligence, government advisories, established press), but not independently re-validated in this report.
- **Assessed:** analytic inference derived from multiple Observed/Reported items; used for synthesis, not as standalone proof.
- **Claimed:** actor-channel or press-amplified claims without sufficient technical corroboration in public artifacts.
- **Partially corroborated:** used in the Confirmed vs Claimed Matrix only. Denotes events where at least one technical artifact or vendor technical report exists, but full victim-side forensic detail or complete kill-chain confirmation is not publicly available. Epistemically closer to "Reported" than "Observed."
- **Partially corroborated — rule of use:** apply only when at least one technical artifact exists (for example: hash, sample, infrastructure indicator, or behavior chain). Press-only narrative coverage without technical artifacts is excluded.
- **Analytic rule:** actor claims are treated as collection leads, not confirmation.

---

## Confidence & What Changes Confidence
- **High confidence:** converging technical reporting across independent primary sources with artifact-level overlap.
- **Medium-High confidence:** direct primary-source equivalence statements or near-converging technical reporting with minor gaps.
- **Medium confidence:** partial convergence, but either incomplete forensic detail or cluster-level (not incident-level) attribution.
- **Low confidence:** claim-led events lacking technical artifacts.
- **What increases confidence:** victim-side telemetry (EDR/SIEM), email traces, malware samples/hashes, sinkhole/passive-DNS corroboration, and independent IR confirmation from affected organizations.
- **What decreases confidence:** single-source narratives, circular citation loops, and actor-post claims without technical evidence.

---

## Executive Summary
Handala (also presented as "Handala Hack Team") is a politically aligned hack-and-leak threat persona whose operations are designed to create both **technical disruption** and **information shock**. The group has primarily targeted Israeli organizations, with occasional spillover into regional ecosystems through supply-chain and partner-connected pathways. Their campaign pattern combines intrusion activity, selective data theft, destructive actions, and fast public messaging intended to amplify fear, uncertainty, and reputational pressure.

This actor should be evaluated as an **influence-enabled intrusion threat**, not only a traditional cybercrime or espionage actor. In practice, the technical compromise is often one component of a broader operation where public claims, timed leaks, and narrative control are used to magnify impact beyond direct system damage. For executive audiences, this means risk should be measured in three dimensions at once: operational downtime, legal/regulatory exposure from data loss, and external trust erosion.

As of the evidence cutoff (**March 5, 2026 UTC**), open vendor reporting has converged strongly on the identity of Handala Hack with Iranian MOIS-linked cluster **Void Manticore (Storm-0842/Storm-842/BANISHED KITTEN/Dune — naming variants across vendors)**. Attribution confidence has strengthened materially over the assessment window:
- Early 2024 reporting contained higher uncertainty at operation level.
- By 2025–2026, five or more independent vendors and government sources converged on strong MOIS-aligned cluster identity assessments.
- Individual incident claims from actor channels still require independent forensic corroboration.

The observed tradecraft pattern is generally **pragmatic rather than novel**. Reporting frequently points to phishing, social-engineering lures tied to current events, abuse of trusted sender or supplier channels, staged payload delivery via commercial file-sharing services (Storj, Mega), and wiper-linked impact paths. This suggests Handala does not require cutting-edge zero-day capability in every campaign; instead, it achieves effect through speed, timing, target selection, and rapid transition from initial access to public pressure operations.

From a business risk perspective, organizations with high external visibility, public-service dependency, or concentrated third-party service reliance face disproportionate exposure. Particularly at risk are environments where security update trust workflows are weak, `.msi`/installer controls are permissive, and incident communications are not prepared for claim-driven campaigns. In these conditions, even a partial compromise can escalate into a strategic incident because narrative impact may outpace technical containment.

Bottom line: Handala should be treated as a persistent regional threat persona where **disruption + leak + influence** are fused into a single operating concept, with high-confidence cluster-level overlap to MOIS-linked infrastructure in current open reporting. Defenders should prioritize supplier-channel trust controls, phishing hardening for event-themed lures, wiper-resilience (offline recovery), and communications playbooks that separate verified compromise evidence from adversary propaganda.

> This report does not independently validate victim compromise and should be read as structured normalization of open-source reporting. Attribution statements are strongest at cluster level and should not be interpreted as exclusive proof for every actor-branded incident.

---

## Alias / Cluster Crosswalk
| Label | Classification | Notes |
|---|---|---|
| **Handala / Handala Hack Team** | Threat persona / public-facing brand | Primarily used for messaging, claim dissemination, and campaign branding. |
| **Void Manticore** | Operational cluster (Check Point naming) | Directly equated with the Handala Hack persona by Check Point Research: *"Void Manticore (Handala Hack)"* [R5]. Also linked in reporting to Israel-focused destructive operations; assessed overlap with Microsoft clusters, not strict one-to-one equivalence at every incident level. [R2][R11] |
| **BANISHED KITTEN** | Operational cluster (CrowdStrike naming) | CrowdStrike tracking name for the same Iran-nexus, MOIS-linked adversary that uses the Handala Hack Team persona for operations against Israel. [R23c][R23d] |
| **Storm-0842 / Storm-842 / DEV-0842** | Operational cluster aliases (Microsoft/vendor naming variants) | Microsoft/vendor naming variants with assessed overlap to other vendor tracking, but potentially different cluster boundaries. [R2][R11][R19] |
| **Dune** | Operational cluster alias (Recorded Future / additional vendor naming) | Additional vendor tracking name for the same MOIS-linked cluster. [R23d][R23e] |
| **Scarred Manticore / Storm-0861** | Operational/access cluster | Reported as access-side component cooperating with destructive operators. [R2][R19] |

> [Assessed] Cross-vendor naming crosswalks indicate overlap, not identity at every incident level; operator, infrastructure, and campaign boundaries may differ by vendor model. The cluster-level equivalence between Void Manticore, BANISHED KITTEN, Dune, and the Handala Hack persona is directly stated by multiple primary sources and should be treated as high-confidence at the persona/cluster level.

### Attribution Link Analysis (Analyst View)
`Handala Hack Persona (public claims/leaks channels) ↔ Void Manticore (Check Point) ↔ Storm-0842/842 (Microsoft) ↔ COBALT MYSTIQUE (Sophos) ↔ BANISHED KITTEN (CrowdStrike) ↔ Dune (Recorded Future)`

```text
                   +-----------------------------+
                   | Handala Hack Team (Persona)|
                   +--------------+--------------+
                                  |
                    direct equivalence in CPR [R5]
                                  |
                   +--------------v--------------+
                   | Void Manticore (Check Point)|
                   +--+--------------------+-----+
                      |                    |
        vendor alias crosswalk [R19]       | vendor alias crosswalk [R11]
                      |                    |
         +------------v-----------+   +----v-----------------------+
         | Storm-0842/842 (MSFT)  |   | COBALT MYSTIQUE (Sophos)  |
         +------------+-----------+   +----------------------------+
                      |
        vendor alias convergence [R23c][R23d][R23e]
                      |
         +------------v-----------------------------+
         | BANISHED KITTEN (CrowdStrike) / Dune RF |
         +--------------------+---------------------+
                              |
          recurring infra set (example: 64.176.172.0/24) [R2]
```

`Cluster-confidence anchor:` Check Point direct equivalence statement `Void Manticore (Handala Hack)` + cross-vendor naming convergence + recurring infrastructure intersections in reported operations (for example, `64.176.172.0/24` set). [R2][R5][R11][R19][R23c][R23d][R23e]

---

## Key Judgments

1. **Operational doctrine is "disrupt + leak + amplify."** Handala activity repeatedly combines technical intrusion/disruption with rapid public claim dissemination through social/messaging channels, indicating a deliberate information-operations layer rather than incidental publicity. **Confidence: High.** [R1][R5][R9][R10][R12]
   **Evidence:** vendor technical reporting + OSINT platform activity patterns; actor channels used as supporting context and early-warning feed.
   **To increase confidence:** victim-side timing correlation between compromise telemetry and claim-post chronology.

2. **Targeting emphasizes Israeli entities with civilian-impact leverage and symbolic value.** Open reporting spans public and private targets, including incidents involving educational/emergency communication contexts and healthcare infrastructure, consistent with pressure-oriented campaign design. **Confidence: High.** [R3][R4][R13][R17]
   **Evidence:** threat-intel weekly reporting + established press + incident summaries.
   **To increase confidence:** independently published victim IR summaries and infrastructure-level forensic artifacts.

3. **Initial access and delivery are typically pragmatic, not novel.** The strongest documented cases show phishing/current-events lures and trusted-channel abuse (including supplier/CRM pathways and commercial file-sharing services), suggesting reliable operator tradecraft without dependence on advanced zero-day capability. **Confidence: Medium-High.** [R1][R3][R5][R14]
   **Evidence:** vendor technical reports and campaign chain documentation.
   **To increase confidence:** complete kill-chain telemetry (mail trace → endpoint process tree → network egress) from multiple victims.

4. **Destructive capability is operationally meaningful, not theoretical.** Technical reporting describes wiper-linked behaviors and destructive execution paths across at least six confirmed phases, demonstrating that impact objectives include system denial and data destruction, not only exfiltration/leak activity. **Confidence: High.** [R1][R2][R5]
   **Evidence:** malware and destructive procedure descriptions in technical reporting.
   **To increase confidence:** additional signed forensic writeups with file-impact metrics and recovery timelines.

5. **Attribution is strongest at cluster level; incident-level certainty varies.** Multiple independent vendors and government sources directly link the Handala Hack persona to MOIS-aligned clusters (Void Manticore / BANISHED KITTEN / Storm-0842 or Storm-842 / Dune naming variants), while actor-channel claims remain unevenly corroborated per incident. **Confidence: Medium-High.** [R2][R5][R6][R11][R23c][R23d][R23e]
   **Evidence:** Check Point Research directly equates Void Manticore with the Handala Hack persona [R5]; CrowdStrike tracks the same cluster as BANISHED KITTEN [R23c]; cross-vendor alias mapping + cluster lineage reporting + multi-vendor convergence context [R2][R11][R19][R23d][R23e], plus recurring infrastructure intersections in reported campaigns (`64.176.169.22`, `64.176.172.101`, `64.176.172.165`, `64.176.172.235`, `64.176.173.77`, `64.176.172.0/24`) [R2]. Confidence is Medium-High (not High) because it covers both cluster-level identity (strong) and incident-level certainty for individual actor-channel claims (variable).
   **To increase confidence:** shared infrastructure reuse with temporal overlap plus malware-code lineage analysis tied to specific incidents.

6. **Business impact is magnified by narrative velocity.** Claim and leak messaging can outpace forensic validation, forcing organizations into high-pressure legal, reputational, and executive response cycles before technical scoping is complete. **Confidence: Medium.** [R9][R12][R16]
   **Evidence:** channel activity patterns + media amplification timelines + campaign retrospectives. *(Note: confidence is bounded at Medium because evidence consists of observed outputs — channel activity and media amplification — rather than operational planning artifacts or documented actor intent.)*
   **To increase confidence:** documented incident communications timelines from affected organizations showing decision pressure before forensic closure.

---

## Activity Timeline (2023–2026)

> Default evidence handling for this section:
> - Statements are **[Reported]** unless explicitly marked **[Assessed]** or **[Claimed]**.
> - **[Claimed]** entries are not treated as confirmation and require independent technical validation.
> - **Post-February 2025 note:** Handala's own public channels (including primary Telegram) went silent after approximately February 9, 2025, before resuming in approximately July 2025. Activity attributed to Handala in the interim and subsequent phases represents researcher/vendor cluster-level attribution (Void Manticore / BANISHED KITTEN) rather than actor self-claims via the group's own infrastructure. This distinction is noted in relevant phase Claims sections. [R23a][R23b][R23d]

---

### October–November 2023 (Pre-Brand Operational Context)
- [Reported] Microsoft and Check Point documented MOIS-linked destructive activity in Israel involving BiBi wiper variants and cooperation patterns between access and destructive operators (Storm-0861 with Storm-0842 in Microsoft naming). [R2][R19]
- [Reported] This period is the operational backdrop for later Handala-branded activity and explains why attribution is more stable at cluster level than per individual post/claim. [R2][R19]

#### TTPs (Reported)
- **Initial access (`T1190`):** exploitation of public-facing SharePoint (`CVE-2019-0604`) in related Iran-linked destructive operations. [R8]
- **Persistence (`T1505.003`):** ASPX webshell use (`pickers.aspx`, `error4.aspx`, `ClientBin.aspx`). [R8]
- **Credential/privilege operations (`T1003.001`, `T1069`):** LSASS dumping and Exchange mailbox-search cmdlets (`New-MailboxSearch`, `Get-Recipient`). [R8]
- **Lateral movement (`T1021.001`, `T1021.002`):** RDP/SMB-heavy movement patterns with internal pivoting. [R8]
- **Impact (`T1485`, `T1561`, `T1490`):** paired encryptor/wiper behavior (`GoXML.exe`, `cl.exe`, `rwdsk.sys`) and BiBi-family destructive logic. [R2][R8]

#### TTPs (Assessed)
- [Assessed] The access-to-impact handoff model seen later under Handala branding was already operationally established in this lineage period. [R2][R8][R19]
- [Assessed] CVE-2019-0604 is referenced here as lineage context from MOIS-linked historical operations documented in the pre-brand period. It is not assessed as a dominant or universal access vector for 2023–2026 Handala-related incidents. For broader cross-group context, see the Cross-Group Correlation section. [R8]

#### Claims (Unverified)
- [Claimed] No phase-specific actor branding claims are central here; this phase is primarily cluster-lineage reporting.

#### IOC/Hunting Leads
- **Lineage IOC note:** treat these as cluster-lineage indicators, not standalone attribution proof; validate with current telemetry before blocking. [R2][R8]
- **Host artifacts:** `error4.aspx`, `ClientBin.aspx`, `pickers.aspx`, `cl.exe`, `GoXML.exe`, `rwdsk.sys`, `mellona.exe`, `disable_defender.exe`. [R8]
- **Network indicators:** `64.176.169.22`, `64.176.172.235`, `64.176.172.165`, `64.176.173.77`, `64.176.172.101`. [R2]
- **Sample hashes:** `d0c03d40772cd468325bbc522402f7b737f18b8f37a89bacc5c8a00c2b87bfc6`, `deeaf85b2725289d5fc262b4f60dda0c68ae42d8d46d0dc19b9253b451aea25a`, `87f0a902d6b2e2ae3647f10ea214d19db9bd117837264ae15d622b5314ff03a5`, `85fa58cc8c4560adb955ba0ae9b9d6cab2c381d10dbd42a0bceb8b62a92b7636`, `74d8d60e900f931526a911b7157511377c0a298af986d42d373f51aac4f362f6`, `cc77e8ab73b577de1924e2f7a93bcfd852b3c96c6546229bc8b80bf3fd7bf24e`. [R2]

---

### December 2023 (Public Emergence of Handala Persona)
- [Reported] Trellix places Handala emergence in December 2023, with first X post on **December 18, 2023**. [R1]
- [Reported] Early messaging already combined target naming and psychological pressure framing. [R1][R9]

#### TTPs (Reported)
- **Persona/channel establishment (`T1585.001`):** rapid setup/use of social and messaging channels. [R1][R9][R10]
- **Information staging:** taunting and victim-name publication patterns. [R1][R9]

#### TTPs (Assessed)
- [Assessed] Communication infrastructure was built as an operational component, not as post-incident publicity. [R1][R9]

#### Claims (Unverified)
- [Claimed] Early breach claims in this phase should be treated as directional until matched with victim telemetry. [R9][R10]

#### IOC/Hunting Leads
- `https://t.me/HANDALA_RSS` [R10]
- Monitor abrupt actor-branded victim naming bursts in channel timelines. [R1][R9]

---

### December 2023–February 2024 (Early Claim-Led Campaigning)
- [Reported] Cyberint described phishing/defacement/leak-claim activity with ideological framing. [R9]

#### TTPs (Reported)
- **Phishing/social engineering (`T1566`, `T1204`)**. [R9]
- **Defacement signaling (`T1491`)**. [R9]

#### TTPs (Assessed)
- [Assessed] Reputation-building through repeated claim cadence appears central in this period. [R9]

#### Claims (Unverified)
- [Claimed] Leak assertions and partial-proof releases in this phase remain unevenly corroborated in public artifacts. [R9]

#### IOC/Hunting Leads
- Soft indicators: defacement references, claim screenshots, teaser leak fragments. [R9][R10]

---

### March–June 2024 (Escalation of Claimed Target Set)
- [Reported] Additional claim campaigns expanded to defense/technology-adjacent targets and ransomware/leak assertions. [R9]

#### TTPs (Reported)
- **Target-set expansion behaviors (`T1591`)**. [R9]
- **Narrative amplification through repeated victim rollups**. [R9]

#### TTPs (Assessed)
- [Assessed] Strategic effect in this phase relied more on coercive messaging tempo than on highly novel technical means. [R9]

#### Claims (Unverified)
- [Claimed] Claimed compromises and extortion narratives in this window are primarily claim-led and require independent verification. [R9]

#### IOC/Hunting Leads
- Soft indicators: synchronized "new victim list" waves across channels. [R9][R10]

---

### May 2024 (Attribution Convergence and "Void Manticore" Framing)
- [Reported] Check Point linked Israel-focused destructive activity to Void Manticore and described overlap with Scarred Manticore victim sets. [R2]
- [Reported] Sophos provides alias context for `COBALT MYSTIQUE` in overlap analysis with `Void Manticore` and `Storm-0842` naming. [R11]

#### TTPs (Reported)
- **Access-to-impact handoff model** across cooperating clusters. [R2][R11]
- **Destructive endpoint operations (`T1485`, `T1561`, `T1490`)**. [R2]

#### TTPs (Assessed)
- [Assessed] Cluster-level attribution confidence in this phase is stronger than incident-level certainty for every actor-branded claim. [R2][R11]

#### Claims (Unverified)
- [Claimed] Actor-branded claims still require forensic closure even when cluster-level linkage is strong. [R2][R9]

#### IOC/Hunting Leads
- Reuse lineage IOCs (`cl.exe`, `rwdsk.sys`, listed hashes, `64.176.172.0/24` context) as hunt pivots. [R2]

---

### July 2024 (CrowdStrike-Lure Wiper Campaign)
- [Reported; includes artifacts] Trellix documented the lure chain (`phishing/PDF` → `update.zip` → `CrowdStrike.exe` → destructive stage). [R1]
- [Reported] BleepingComputer coverage reflects the same campaign pattern for defender dissemination. [R14]

#### TTPs (Reported)
- **Lure-driven initial access (`T1566`, `T1204`)**. [R1][R14]
- **Payload staging (`T1105`):** malicious payload hosted on Storj file share (`storjshare.io`). [R1]
- **Destructive execution (`T1485`, `T1561`)**. [R1]
- **Exfiltration via web/messaging APIs (`T1567.002` pattern)**. [R1]

#### TTPs (Assessed)
- [Assessed] Current-events lure timing was used to compress defender decision time and improve execution probability. [R1][R14]

#### Claims (Unverified)
- [Claimed] No major additional claim-only elements dominate this phase relative to technical reporting.

#### IOC/Hunting Leads
- Artifacts (campaign-reported; enforce by hash/context where possible): `update.zip`, `CrowdStrike.exe`, `rwdsk.sys`, `RawDisk3`; `cl.exe` is context-dependent and should be treated as hard only with hash/driver/service corroboration. [R1][R5][R14]
- Delivery infrastructure: Storj file share (`storjshare.io`) used for payload hosting in this campaign. Distinct from Mega file share used in the December 2024–January 2025 CRM-linked campaign.

---

### August 2024 (Platform Pressure and Information Friction)
- [Reported] The Record documented X account suspension on **August 21, 2024** and continuation via other channels. [R12]
- [Reported] ODNI/FBI/CISA issued election-influence statement on **August 19, 2024** in the same period context. [R20]

#### TTPs (Reported)
- **Channel migration/resilience (`T1585.001` — operational use of alternate channels on both Telegram and X platform):** Post-ban activity migrated to `@Handala_Backup` on X and continued via pre-existing Telegram infrastructure (`t.me/HANDALA_RSS`, `t.me/s/handala_backup_357`). These are separate platform assets, not a single unified channel. [R9][R10][R12][R18]

#### TTPs (Assessed)
- [Assessed] Distribution-channel disruption increased friction but did not materially interrupt campaign continuity. [R9][R12][R18]

#### Claims (Unverified)
- [Claimed] Post-ban actor messaging streams remain claim feeds unless corroborated by independent technical evidence. [R10][R18]

#### IOC/Hunting Leads
- Telegram channels (active before and after X ban): `https://t.me/HANDALA_RSS` [R10], `https://t.me/s/handala_backup_357` [R18]
- X (Twitter) backup account active post-ban: `@Handala_Backup` [R12]
- Note: The Telegram channels and the X backup account are distinct infrastructure on separate platforms; do not conflate them as a single migration artifact.

---

### September–October 2024 (High-Impact Claims Against Strategic Targets)
- [Reported] Press and ICT described claims against strategic Israeli targets, including large-volume theft assertions. [R16][R17]

#### TTPs (Reported)
- **Strategic victim signaling and coercive narrative framing**. [R16][R17]

#### TTPs (Assessed)
- [Assessed] This phase prioritized influence effects and symbolic target selection over publicly validated technical disclosure. [R16][R17]

#### Claims (Unverified)
- [Claimed] Soreq/Shin Bet-adjacent compromise claims and 197GB exfil assertions remain claim-heavy in open sources. [R16][R17]

#### IOC/Hunting Leads
- Soft IOC: claim bundles naming strategic institutions and high-volume theft assertions. [R16][R17]

---

### December 2024–January 2025 (ReutOne Supply-Chain Style Campaign)
- [Reported] Check Point weekly reporting described Handala claims tied to ReutOne/CRM pathway. [R3]
- [Reported] Check Point retrospective added technical chain detail: recipients were instructed to "back up" their files by downloading a malicious `.msi` installer hosted on **Mega file share**, followed by wiper behavior upon execution. [R5]

#### TTPs (Reported)
- **Trusted-relationship abuse (`T1199`)**. [R3][R5]
- **Installer-led execution/destructive follow-on (`T1204`, `T1059`, `T1485`)**. [R5]
- **Valid Accounts abuse (`T1078`):** compromised supplier/CRM account context used to increase delivery credibility. [R3][R5]

#### TTPs (Assessed)
- [Assessed] Authenticated business context increased delivery credibility and downstream blast radius risk. Hosting payload on Mega (a legitimate, widely trusted file-sharing service) further reduced recipient suspicion. [R3][R5]

#### Claims (Unverified)
- [Claimed] Cross-country victim-scope claims in this phase require case-by-case forensic confirmation. [R3]

#### IOC/Hunting Leads
- Hard IOC: `6eb7dbf27a25639c7f11c05fd88ea2a301e0ca93d3c3bdee1eb5917fc60a56ff` (`.msi`). [R5]
- Delivery infrastructure: malicious `.msi` hosted on **Mega file share** (`mega.nz` or `mega.io`). Monitor for `.msi` downloads originating from Mega in enterprise egress logs, particularly in combination with supplier/business-context email lures. Distinct from the Storj-based hosting observed in the July 2024 CrowdStrike-lure campaign. [R5]

---

### January 2025 (Kindergarten Siren/PA System Incident)
- [Reported] Press and weekly TI described panic-button/emergency audio abuse across approximately 20 educational sites and parallel intimidation messaging. [R4][R13][R17]
- [Reported] The Record identified **Maagar-Tec**, an Israeli electronics firm operating panic button systems in schools, as the compromised provider through which the siren activation occurred. The company confirmed it disconnected affected systems and launched an investigation. [R13]

#### TTPs (Reported)

> ⚠️ **Caveat:** The technical intrusion path for this incident is not fully resolved in public reporting (see Claims section below). The TTPs listed here describe *observed operational effects* and reported messaging behaviors, not a confirmed kill-chain. Do not treat these as documented attacker procedures without a validated intrusion path.

- **Emergency communication workflow abuse**. [R13][R17]
- **Mass intimidation messaging**. [R13][R17]

#### TTPs (Assessed)
- [Assessed] The objective was high-visibility civilian psychological impact with limited need for complex malware tradecraft. [R4][R13]

#### Claims (Unverified)
- [Claimed] Exact technical intrusion path and full scope remain partially unresolved in public reporting. [R13][R17]
- [Claimed] Handala claimed to have wiped Maagar-Tec systems following the siren activation; this wiper claim is unverified in public technical reporting and is not counted in the confirmed destructive/wiper phase total.

#### IOC/Hunting Leads
- Soft IOCs: out-of-schedule siren/PA events with synchronized intimidation SMS bursts. [R13][R17]
- Vendor/supplier pivot: Maagar-Tec (panic button / PA system vendor) identified as access point; any organizations using this vendor's systems should validate access logs and system integrity for the January 2025 window. [R13]

---

### February 2025 (Leak and Pressure Operations; Final Self-Claimed Phase)
- [Reported] Additional leak campaigns referenced personal-data and weapons-holder data exposure themes. [R15][R16]
- [Reported] OP Innovate analysis indicates that Handala's own public channels (including primary Telegram) went silent after approximately **February 9, 2025**, making this the last phase with confirmed actor self-claims via the group's own infrastructure. [R23a][R23b]

#### TTPs (Reported)
- **Doxing/exposure pressure behaviors**. [R15][R16]
- **Sustained release cadence across channels**. [R9][R16]

#### TTPs (Assessed)
- [Assessed] Campaign value in this period was primarily reputational and societal pressure amplification. [R9][R16]

#### Claims (Unverified)
- [Claimed] Published leak-scope assertions remain variably corroborated by independent technical reporting. [R15][R16]

#### IOC/Hunting Leads
- Soft IOC: leak-drop waves tied to civilian registry themes. [R15][R16]

---

### June 2025 (Wiper Activity During Iran–Israel Escalation)
- [Reported] Check Point Research tracked a Handala Hack wiper event in June 2025, coinciding with the twelve-day Iran–Israel escalation period. This is the only primary-vendor-confirmed destructive technical activity listed for this phase; narrative/influence operations continued in parallel. [R5]
- [Reported] This phase marks the resumption of Handala/Void Manticore cluster activity following the February–June 2025 communications gap on the group's own public channels. [R5][R23a][R23b]

#### TTPs (Reported)
- **Destructive execution — wiper deployment (`T1485`):** wiper activity tracked by Check Point Research in the June 2025 escalation window. [R5]

#### TTPs (Assessed)
- [Assessed] Wiper deployment during a high-visibility kinetic escalation window is consistent with the cluster's established doctrine of synchronizing technical disruption with geopolitical tension peaks. [R5]

#### Claims (Unverified)
- [Claimed] Specific victim claims and technical details for the June 2025 wiper have not been released publicly by Check Point at the time of this report's evidence cutoff.
- [Assessed] Post-February 2025 Handala attributions represent researcher/vendor cluster-level attribution (Void Manticore / BANISHED KITTEN), not actor self-claims via the group's own infrastructure. [R23c][R23d]

#### IOC/Hunting Leads
- Technical pivot: Check Point Research has confirmed wiper activity in this phase [R5]; consumers should request Check Point private intelligence for campaign-specific artifact details not yet released publicly. Treat the June 2025 window as a confirmed destructive-activity period when scoping retrospective hunt queries.

---

### July 2025 (Hack-and-Leak Against Iran International)
- [Reported] RRM Canada documented a Handala/BANISHED KITTEN hack-and-leak operation targeting Iran International, involving data exfiltration affecting five journalists. [R23d][R23f]

#### TTPs (Reported)
- **Hack-and-leak with targeted journalist exposure (`T1591`, `T1567.002` pattern)**. [R23d][R23f]

#### TTPs (Assessed)
- [Assessed] Targeting Iran International — a prominent Persian-language media outlet — is consistent with MOIS operational interests and the cluster's pattern of combining technical compromise with high-profile narrative pressure. [R23d][R23f]

#### Claims (Unverified)
- [Claimed] Full scope of data accessed and actor self-claims require forensic validation.
- [Assessed] Post-February 2025 Handala attributions represent researcher/vendor cluster-level attribution, not actor self-claims via the group's own infrastructure. [R23c][R23d]

#### IOC/Hunting Leads
- Soft IOC: sudden publication of journalist personal data tied to Persian-language media organizations. [R23d][R23f]

---

### October 2025 (International Airport Claim)
- [Reported] Open-source claim tracking reported a Handala/BANISHED KITTEN-associated claim of access to Suvarnabhumi Airport (Bangkok) systems. [R23g]

#### TTPs (Reported)
- **High-profile infrastructure claim — aviation sector**. [R23g]

#### TTPs (Assessed)
- [Assessed] Aviation sector claims in non-Israeli geographies represent potential cluster expansion beyond primary targeting geography, possibly for international pressure effects. [R23g]

#### Claims (Unverified)
- [Claimed] Airport access claim has not been independently confirmed by technical reporting at evidence cutoff.
- [Assessed] Post-February 2025 Handala attributions represent researcher/vendor cluster-level attribution. [R23c][R23d]

#### IOC/Hunting Leads
- Soft IOC: access claims naming international transport infrastructure. [R23g]

---

### November–December 2025 (Bennett Telegram Compromise and "Bibi Gate" Wave)
- [Reported] JNS stated Bennett office confirmation of Telegram account compromise, without confirmed phone-level compromise. [R21]
- [Reported] Israel Hayom/ICT described "Bibi Gate" claim escalation with mixed verified/unverified elements. [R16][R22]
- [Reported] Secondary reporting citing KELA technical analysis of the Bennett/Braverman incident found that the majority of "1,900 chats" cited by the actor consisted of empty contact cards auto-generated by Telegram during phone contact synchronization; fewer than 40 messages with actual content were present. This indicates the actor materially overstated the data scope of the claimed compromise. [R23i][R23j]

#### TTPs (Reported)
- **High-profile account targeting/session compromise behavior**. [R21]
- **Rapid narrative amplification around elite targets**. [R16][R22]

#### TTPs (Assessed)
- [Assessed] Mixing authentic data with auto-generated Telegram artifacts increases verification burden and extends influence effects even when actual data volume is limited. [R21][R22][R23i][R23j]

#### Claims (Unverified)
- [Claimed] Several political leak assertions in this period remained under review at publication time. [R16][R22]
- [Assessed] Secondary coverage of KELA analysis indicates the actor significantly overstated the data scope of the Bennett account compromise. Treat all claim-volume figures from actor channels as unverified until independently validated. [R23i][R23j]
- [Assessed] Post-February 2025 Handala attributions represent researcher/vendor cluster-level attribution. [R23c][R23d]

#### IOC/Hunting Leads
- Account signals: unexpected Telegram sessions/device fingerprints/geolocations for high-profile users. [R21]
- Validation note: when actor claims specific data volumes from account compromises, independently verify before treating as confirmed scope. [R23i][R23j]

---

### February 2026 (Technical Consolidation; Clalit Healthcare Campaign)
- [Reported] Check Point retrospective documented likely large-scale phishing, compromised CRM-linked sender path, malicious `.msi`, and destructive endpoint behavior. [R5]
- [Reported] Handala/BANISHED KITTEN claimed an attack on **Clalit**, Israel's largest healthcare organization, in February 2026. [R23h]

#### TTPs (Reported)
- **Broad phishing distribution (`T1566`)**. [R5]
- **Trusted sender compromise (`T1199`)**. [R5]
- **Installer-led destructive behavior (`T1204`, `T1485`, `T1490`)**. [R5]

#### TTPs (Assessed)
- [Assessed] This phase provides one of the strongest public bridges between claim-layer activity and concrete technical procedures. [R5]
- [Assessed] Healthcare sector targeting (Clalit) is consistent with the cluster's established pattern of selecting organizations with high civilian-impact leverage and symbolic value. [R23h]

#### Claims (Unverified)
- [Claimed] Clalit attack scope and technical details remain unverified in public primary-source reporting at evidence cutoff.
- [Assessed] Post-February 2025 Handala attributions represent researcher/vendor cluster-level attribution. [R23c][R23d]

#### IOC/Hunting Leads
- Hard IOC: `6eb7dbf27a25639c7f11c05fd88ea2a301e0ca93d3c3bdee1eb5917fc60a56ff`. [R5]

---

### March 2026 (Regional Escalation and Claimed Cross-Border Activity)
- [Reported] Unit 42 (published **March 2, 2026**) assessed elevated Iran-related cyber risk and included Handala among prominent personas in the operating environment. [R6]

#### TTPs (Reported)
- **Opportunistic sector targeting under escalation conditions**. [R6]
- **Influencer/public-figure intimidation campaign behavior**. [R6]

#### TTPs (Assessed)
- [Assessed] Public claim velocity in escalation windows can outpace forensic closure and increase communications risk. [R6][R9]

#### Claims (Unverified)
- [Claimed] Energy/fuel and cross-border claim streams in this window require strict evidence separation before external confirmation. [R6][R10][R18]
- [Assessed] Post-February 2025 Handala attributions represent researcher/vendor cluster-level attribution. [R23c][R23d]

#### IOC/Hunting Leads
- Soft IOC: rapid claim surges naming critical sectors/public figures; correlate with local telemetry windows before attribution decisions. [R6]

---

### Timeline Synthesis
- [Assessed] Across 2023–2026, the recurring operational cycle is: opportunistic access → staging → disruptive/destructive or leak action → claim publication → amplification → repeat. [R1][R2][R5][R9][R12]
- [Assessed] This cycle reduces defender decision time and can produce strategic impact even when technical novelty is limited. [R1][R2][R5][R9][R12]
- [Assessed] The February–June 2025 communications gap on the group's own channels did not halt cluster operations; wiper activity (June 2025) and hack-and-leak operations (July 2025) continued under researcher attribution to the Void Manticore / BANISHED KITTEN cluster. [R5][R23a][R23b][R23d][R23f]

### Operational Model (Text Diagram)
`Access → Stage Payload (via Storj / Mega / other commercial hosting) → Impact (Disrupt/Wipe/Leak) → Public Claim → Amplify Across Channels → Repeat`

---

## Confirmed vs Claimed Matrix

| Event | Source Type | Status | Evidence | Notes / Limitations | Actions |
|---|---|---|---|---|---|
| CrowdStrike-themed phishing/wiper chain (July 2024) | Vendor technical + press | **Partially corroborated** | Infection-chain, artifacts, behavior patterns in technical reporting; payload on Storj | Public victim-side forensic detail remains limited | Prioritize detection rules for installer chains and destructive behavior |
| Void Manticore / BANISHED KITTEN / Storm linkage to Handala persona | Vendor technical + alias crosswalk | **Corroborated (cluster level)** | Check Point direct equivalence statement [R5]; CrowdStrike BANISHED KITTEN tracking [R23c]; cross-vendor naming convergence [R2][R11][R19][R23d][R23e] | Does not prove every Handala-branded incident individually | Use cluster-level correlation model; high confidence at persona/cluster level |
| CRM/supplier-channel campaign (Dec 2024–Jan 2025) | Vendor weekly + retrospective technical | **Partially corroborated** | `.msi` hash, trusted-sender pathway reporting, Mega hosting detail [R5] | Full victim inventory/scope not publicly complete | Enforce supplier-channel trust controls and `.msi` controls; monitor Mega egress |
| Kindergarten siren incidents (January 2025) | Press + weekly TI | **Reported** | Multi-source reporting on emergency workflow abuse; Maagar-Tec identified as access point [R13] | Intrusion path details not fully public; actor wiper claim unverified | Trigger OT-adjacent incident validation playbook; vendor-pivot hunt on Maagar-Tec |
| Bennett Telegram account compromise (Dec 2025) | Press + official office statement + secondary reporting citing KELA analysis | **Partially corroborated** | Public statement confirms account access occurred; secondary coverage citing KELA found <40 real messages vs claimed 1,900 chats — actor overstated scope [R23i][R23j] | Confirms account compromise event; actor claim volume materially inflated | Treat as confirmed account compromise; apply claim-scope deflation to all actor volume assertions |
| June 2025 wiper activity | Vendor technical (Check Point) | **Partially corroborated** | Check Point Untold Stories timeline [R5] | Full artifact details not yet publicly released | Treat June 2025 as confirmed destructive-activity window; request vendor private intelligence |
| High-profile political leak waves | Press + actor channels | **Claim-only** | Narrative/timeline consistency across channels | Artifact authenticity and scope vary by claim | Treat as collection lead; require forensic confirmation before attribution |

---

## Public Presence and Information Operations Footprint
- [Reported] **Telegram ecosystem:** Handala-associated channels are repeatedly cited as primary leak/claim dissemination infrastructure, including both main and backup streams. Active self-claims via own channels through approximately February 9, 2025. [R9][R10][R18][R23a][R23b]
- [Reported] **Social media migration pattern:** reported suspension on mainstream platform(s) followed by backup channel usage and renewed message distribution. [R12]
- [Reported] **Forum footprint:** OSINT reporting references BreachForums-linked persona activity, but forum-origin claims require independent validation. [R9]
- [Assessed] **Operational implication:** messaging infrastructure is an attack amplifier; channel output should remain unverified until corroborated by local telemetry. [R9][R12]
- [Assessed] **Post-February 2025 framing:** activity attributed to Handala after approximately February 9, 2025 is primarily vendor/researcher cluster attribution (Void Manticore / BANISHED KITTEN) rather than actor self-published claims. This does not reduce operational risk but affects how confidence should be calibrated for specific incidents. [R23a][R23b][R23c][R23d]

---

## Targeting and Victimology
Observed victim focus in open reporting includes:
- [Reported] **Public services / civilian-impact organizations:** education, emergency-communications-adjacent environments, healthcare (Clalit, February 2026). [R4][R13][R17][R23h]
- [Reported] **Supplier and CRM ecosystem:** third-party and trusted-sender pathways with downstream victim potential. [R3][R5]
- [Reported] **Political principals / public figures / media organizations:** high-visibility individuals, affiliated communication channels, and Persian-language press (Iran International, July 2025). [R16][R21][R22][R23d][R23f]
- [Reported] **Critical sectors:** escalation-period references to energy/fuel, nationally sensitive institutions, and international aviation. [R6][R16][R17][R23g]

---

## Tactics, Techniques, and Procedures (Observed/Reported)

### Initial Access and Delivery
- [Reported] Spearphishing and lure-based delivery (including current-event themed campaigns).
- [Reported] Distribution through trusted or semi-trusted channels (e.g., compromised provider accounts, CRM-linked sender paths).
- [Reported] Commercial file-sharing services used for payload delivery: Storj (July 2024), Mega (December 2024–January 2025).

### Execution and Operations
- [Reported] Staged payload delivery (installer/script chain — `.zip`, `.msi`, `.ps1`).
- [Reported] Use of common administrative and scripting paths.
- [Reported] Wiper-style destructive actions and operational disruption.

### Impact and Influence
- [Reported] Data theft plus timed publication ("hack-and-leak").
- [Reported] Defacement/intimidation messaging to amplify public impact.
- [Reported] Emergency communication system abuse (PA/siren systems).
- [Assessed] Campaign framing designed to increase psychological pressure; actor claim volumes frequently overstated relative to confirmed data scope.

---

## ATT&CK-Oriented Mapping (Analyst View)

| Technique ID | Technique Name | Phase | Source Reference |
|---|---|---|---|
| `T1003.001` | OS Credential Dumping: LSASS Memory | [Reported] October–November 2023 | [R8] |
| `T1021.001` | Remote Services: Remote Desktop Protocol | [Reported] October–November 2023 | [R8] |
| `T1021.002` | Remote Services: SMB/Windows Admin Shares | [Reported] October–November 2023 | [R8] |
| `T1059` | Command and Scripting Interpreter | [Reported] December 2024–January 2025; February 2026 | [R5] |
| `T1069` | Permission Groups Discovery | [Reported] October–November 2023 | [R8] |
| `T1078` | Valid Accounts | [Reported] Supply-chain / compromised-account context | [R3][R5] |
| `T1105` | Ingress Tool Transfer | [Reported] July 2024 | [R1] |
| `T1190` | Exploit Public-Facing Application | [Reported] October–November 2023 | [R8] |
| `T1199` | Trusted Relationship | [Reported] December 2024–January 2025; February 2026 | [R3][R5] |
| `T1204` | User Execution | [Reported] December 2023–February 2024; July 2024; December 2024–January 2025; February 2026 | [R1][R5][R9] |
| `T1485` | Data Destruction | [Reported] October–November 2023; May 2024; July 2024; June 2025; December 2024–January 2025; February 2026 | [R1][R2][R5][R8] |
| `T1490` | Inhibit System Recovery | [Reported] October–November 2023; May 2024; February 2026 | [R2][R5][R8] |
| `T1491` | Defacement | [Reported] December 2023–February 2024 | [R9] |
| `T1505.003` | Server Software Component: Web Shell | [Reported] October–November 2023 | [R8] |
| `T1561` | Disk Structure Wipe | [Reported] October–November 2023; May 2024; July 2024 | [R1][R2][R8] |
| `T1566` | Phishing | [Reported] December 2023–February 2024; July 2024; February 2026 | [R1][R5][R9] |
| `T1567.002` | Exfiltration to Cloud Storage | [Reported] July 2024; July 2025 | [R1][R23d][R23f] |
| `T1585.001` | Establish Accounts: Social Media Accounts | [Reported] December 2023; August 2024 | [R1][R9][R10][R12] |
| `T1591` | Gather Victim Org Information | [Reported] March–June 2024; July 2025 | [R9][R23d][R23f] |

> *This table is a consolidated normalization from public reporting. Evidence label per entry matches the label assigned in the originating timeline phase.*

---

## Detection and Response Priorities

1. **Phishing resilience for current-event lures**
   - Block newly observed lure themes quickly.
   - Increase SOC scrutiny during major geopolitical/technology events.

2. **Supplier/partner trust controls**
   - Enforce zero-trust assumptions for partner-originated updates/messages.
   - Add verification workflows for urgent "security update" requests.
   - Prioritize supply-chain exposure mapping for panic-button/PA vendors (Maagar-Tec and functional analogs), including emergency access workflows and delegated admin paths.
   - Monitor for `.msi` downloads from commercial file-sharing services (Storj, Mega) in combination with supplier-context email lures.

3. **Wiper-impact preparedness**
   - Keep offline immutable backups.
   - Test restoration regularly under time constraints.
   - Monitor for mass overwrite/deletion behavior and suspicious service/driver installation.

4. **Influence-aware incident handling**
   - Separate breach validation from social-media claims.
   - Prepare communications playbooks for "claim before proof" scenarios.
   - Apply claim-scope deflation: actor volume assertions are frequently overstated (see Bennett incident secondary coverage citing KELA analysis).

5. **Egress and API controls**
   - Inspect unusual outbound API traffic from endpoints/servers.
   - Alert on unexpected outbound traffic to messaging-platform infrastructure and commercial file-sharing services.

---

## Detection Engineering Pack (SOC-Ready)

1. **Current-event lure + archive/installer chain**
   - **Data sources:** secure email gateway, M365/Google mail logs, endpoint process tree.
   - **Logic:** event-themed message → user opens archive/PDF → execution of uncommon installer (`.zip`/NSIS/`.msi`) from user temp/download path.
   - **FP notes:** internal IT broadcasts during genuine global outages.
   - **Triage:** validate sender trust history, attachment lineage, first-seen prevalence.
   - **Response:** quarantine artifact, isolate host, search enterprise-wide for same hash/filename.

2. **Unusual `.msi` execution from supplier/business context or commercial file share**
   - **Data sources:** EDR process telemetry, email metadata, identity logs, proxy/egress logs.
   - **Logic:** `.msi` launched from mail attachment path combined with sender-account anomaly (new geolocation/device/time pattern), OR `.msi` download from Mega (`mega.nz`, `mega.io`) or Storj (`storjshare.io`) immediately preceding installer execution.
   - **FP notes:** approved software rollouts.
   - **Triage:** verify change ticket and deployment source.
   - **Response:** block hash, suspend suspicious sender account, enforce recipient-side detonation flow.

3. **Potential destructive pre-impact sequence**
   - **Data sources:** endpoint command-line telemetry.
   - **Logic:** command combinations such as `vssadmin Delete Shadows`, `bcdedit /set ... recoveryenabled No`, `bootstatuspolicy ignoreallfailures`.
   - **FP notes:** rare but possible admin recovery operations.
   - **Triage:** identify initiator account/process ancestry.
   - **Response:** isolate host, revoke active credentials, snapshot volatile evidence.

4. **Driver/service pattern consistent with raw-disk tooling**
   - **Data sources:** Windows service creation logs, driver-load events.
   - **Logic:** creation/loading behavior consistent with `rwdsk.sys`, `RawDisk3`, and related destructive chain context.
   - **FP notes:** low expected baseline in standard enterprise fleets.
   - **Triage:** confirm signer metadata and prevalence.
   - **Response:** contain endpoint cluster and trigger destructive-impact playbook.

5. **Mass file overwrite/deletion burst**
   - **Data sources:** EDR file telemetry, filesystem events.
   - **Logic:** abnormal high-rate writes/renames/deletions across many directories after suspicious installer/script execution.
   - **FP notes:** backup agents, bulk migration jobs.
   - **Triage:** correlate with signed maintenance windows.
   - **Response:** network isolate and preserve forensic timeline.

6. **Security-process kill-list behavior**
   - **Data sources:** process termination logs.
   - **Logic:** repeated termination attempts targeting AV/EDR process names in short interval.
   - **FP notes:** endpoint security upgrades/removals by IT.
   - **Triage:** verify admin actor and approved maintenance.
   - **Response:** host isolation and credential reset for initiating context.

7. **Telegram/API egress anomaly from enterprise assets**
   - **Data sources:** proxy logs, firewall egress, DNS logs.
   - **Logic:** new outbound patterns to Telegram/web API endpoints from non-messaging servers/endpoints immediately post execution.
   - **FP notes:** legitimate user messaging traffic.
   - **Triage:** map destination to host role and recent process ancestry.
   - **Response:** temporary egress containment + targeted packet/log retention.

8. **Channel-claim vs telemetry mismatch alert**
   - **Data sources:** threat intel monitoring + SIEM.
   - **Logic:** actor claim names an organization/system but no matching local compromise indicators appear in expected window.
   - **FP notes:** delayed telemetry ingestion.
   - **Triage:** verify collection health and time sync.
   - **Response:** classify as unverified claim, continue focused hunting. Note: actor claim volumes are frequently overstated; mismatch between claim scope and local evidence is expected and should not itself be treated as confirmation.

9. **Emergency communication workflow anomaly**
   - **Data sources:** OT/system admin logs, telecom/provider logs.
   - **Logic:** out-of-schedule siren/PA activation paired with suspicious access/session events.
   - **FP notes:** drills and planned tests.
   - **Triage:** confirm authorized schedule and operator identity.
   - **Response:** fail-safe fallback, credential rotation, incident bridge with facility/security teams.

10. **High-profile account compromise proxy detection (endpoint-first)**
    - **Data sources:** endpoint telemetry (process/file/network), browser credential/session events, enterprise proxy logs, identity provider signals.
    - **Logic:** suspicious token/session artifacts or credential export behavior from endpoint context associated with high-profile users (for example, unexpected Telegram Desktop local database access/copy, abnormal browser cookie/session theft patterns, non-messaging processes initiating Telegram API/domain connections).
    - **FP notes:** legitimate client upgrades, profile migration, approved forensic collection.
    - **Triage:** validate process ancestry, signer reputation, first-seen prevalence, and user-confirmed activity timeline.
    - **Response:** session revocation, credential reset, token invalidation, endpoint isolation if theft patterns are present. Note: actor-claimed chat volume is not a reliable scope proxy without forensic validation.

11. **IIS ASPX webshell deployment anomaly**
    - **Data sources:** IIS logs, web-server file integrity monitoring, EDR file/process events.
    - **Logic:** new/modified `.aspx` files in unusual web directories (for example, `/scripts/`, `/images/`) combined with webshell-like child process behavior (for example, `w3wp.exe` spawning `cmd.exe`/`powershell.exe`).
    - **FP notes:** legitimate web application updates and admin uploads.
    - **Triage:** compare against deployment baseline and signed release artifacts.
    - **Response:** isolate web node, preserve web root + logs, hunt for lateral movement from web tier.

12. **Exchange mailbox collection spike**
    - **Data sources:** Exchange audit logs, PowerShell logs, identity logs.
    - **Logic:** anomalous burst of mailbox-search/cmdlet activity (for example, `New-MailboxSearch`, `Get-Recipient`) from unusual admin context.
    - **FP notes:** planned compliance/eDiscovery operations.
    - **Triage:** verify requester, ticket, scope, and time window.
    - **Response:** suspend suspicious session, rotate credentials, initiate data-access impact scoping.

---

## Wiper First 30 Minutes (Defensive Mini-Playbook)
1. Declare destructive-activity severity and open incident command.
2. Isolate impacted hosts/subnets; block east-west movement where feasible.
3. Disable suspicious privileged accounts/tokens used in preceding 24 hours.
4. Preserve volatile artifacts (process tree, command-line, loaded drivers, active connections).
5. Freeze risky automated actions (software deployment jobs, admin scripts) pending validation.
6. Validate backup integrity and launch clean-room restore decision path.
7. Trigger communications guardrails: separate verified impact from public claims; do not accept actor claim volumes at face value.
8. Begin enterprise-wide sweep for known destructive command and artifact patterns.

---

<a id="table-4-controls-mapping-nist-csf-lite"></a>
## Controls Mapping (NIST CSF-Lite)

| Risk | Control | Owner | SLA | Measure |
|---|---|---|---|---|
| Lure-based initial access | Advanced mail filtering + attachment detonation + user reporting loop | SecOps + IT | 7 days tuning for new lure wave | Phishing click rate trend + detonation coverage % |
| Supplier-channel abuse | Trusted-sender verification and high-risk attachment policy for partner mail; block `.msi` from commercial file-sharing services (Mega, Storj) absent change ticket | IT + Security Engineering | 14 days | % partner mail with enhanced verification and policy enforcement |
| Wiper/destructive impact | Immutable offline backups + rapid isolation workflow | Infrastructure + SOC | 30 days for test cycle | Restore test success rate + mean time to isolate |
| Claim-driven reputational pressure | Evidence-gated external communications workflow; deflate actor claim volumes until forensically validated | Comms + Legal + IR Lead | Immediate activation per incident | Time from claim to evidence status memo |
| High-profile account compromise | Mandatory strong MFA + anomalous session response runbook | IAM + Executive IT | 14 days | % protected accounts with enforced strong MFA + anomalous session closure time |

---

## Comprehensive IOC Compendium (Public Reporting)

> Use this IOC set as a **correlation and triage baseline**, not as standalone attribution proof.
> Lineage IOCs (MOIS/Void Manticore context) **do not** independently prove Handala attribution; validate with current telemetry before blocking. [R1][R2][R5][R8]
>
> **IOC tagging model (evidence-based):**
> - `evidence_tag`: `hard` (cryptographic/sample-level), `near-hard` (campaign-specific but reusable), `soft` (contextual/behavioral), `benign-context` (legitimate service seen in chain).
> - `freshness_tag`: `stable_tracking` (long-lived for tracking), `active_monitor` (monitor continuously), `volatile`, `maybe_expired` (infrastructure likely rotated), `durable_pattern` (behavioral pattern).

**IOC Table Navigation**
- [Table 5: Network IOCs (IP/CIDR)](#table-5-network-iocs-ipcidr)
- [Table 6: URL and Infrastructure IOCs](#table-6-url-and-infrastructure-iocs)
- [Table 7: Common/Benign Services Used in Chain](#table-7-commonbenign-services-used-in-chain)
- [Table 8: Actor Channel and Messaging IOCs](#table-8-actor-channel-and-messaging-iocs)
- [Table 9: Core Delivery/Impact Artifacts](#table-9-core-deliveryimpact-artifacts)
- [Table 10: Wiper and Destructive Lineage Artifacts](#table-10-wiper-and-destructive-lineage-artifacts)
- [Table 11: Hash IOCs (SHA256)](#table-11-hash-iocs-sha256)
- [Table 12: Hash IOCs (MD5)](#table-12-hash-iocs-md5)

<a id="table-5-network-iocs-ipcidr"></a>
### Network IOCs (IP/CIDR)
- **Type:** Near-hard IOC
- **Scope:** MOIS-lineage / Void-Manticore-linked infrastructure context
- **Shelf life:** Medium (revalidate periodically against passive DNS and ASN movement)
- **Action:** Hunt + conditional block (after environment impact validation)

| Indicator | evidence_tag | freshness_tag | Action profile | Reference |
|---|---|---|---|---|
| `64.176.169.22` | `near-hard` | `maybe_expired` | Hunt; conditional block after local validation | [R2] |
| `64.176.172.235` | `near-hard` | `maybe_expired` | Hunt; conditional block after local validation | [R2] |
| `64.176.172.165` | `near-hard` | `maybe_expired` | Hunt; conditional block after local validation | [R2] |
| `64.176.173.77` | `near-hard` | `maybe_expired` | Hunt; conditional block after local validation | [R2] |
| `64.176.172.101` | `near-hard` | `maybe_expired` | Hunt; conditional block after local validation | [R2] |
| `64.176.172.0/24` (reported range context) | `near-hard` | `maybe_expired` | Hunt; conditional block after local validation | [R2] |

<a id="table-6-url-and-infrastructure-iocs"></a>
### URL and Infrastructure IOCs
- **Type:** Mixed (Near-hard + benign-but-used-in-chain references)
- **Shelf life:** Short to medium
- **Action:** Delivery paths: monitor + temporary block + detonation/hunt. Benign/commercial references: hunt-only / behavioral correlation.

| Indicator | evidence_tag | freshness_tag | Action profile | Reference |
|---|---|---|---|---|
| `hxxps://link-target[.]net/jfby32` | `near-hard` | `maybe_expired` | Monitor + detonation + temporary block in campaign window | [R1] |
| `hxxps://storjshare[.]io/s/jv4ftpt67w5zw2b2wqj4v4zffviq/...update.zip` | `near-hard` | `maybe_expired` | Monitor + detonation + temporary block in campaign window | [R1] |
| `mega[.]nz` / `mega[.]io` | `benign-context` | `active_monitor` | Hunt-only in supplier-lure + `.msi` execution context | [R5] |

<a id="table-7-commonbenign-services-used-in-chain"></a>
### Common/Benign Services Used in Chain (Never Blocklist Alone)
- **Purpose:** prevent accidental block-list poisoning by automation that ingests IOC tables without context.
- **Handling rule:** correlation-only (`behavior + timing + process ancestry`), never standalone block indicators.

| Service | evidence_tag | freshness_tag | Contextual use | Reference |
|---|---|---|---|---|
| `hxxps://www[.]icanhazip[.]com` | `benign-context` | `stable_tracking` | Use only for behavior correlation; never block alone | [R1] |
| `hxxps://www[.]microsoft[.]com` | `benign-context` | `stable_tracking` | Use only for behavior correlation; never block alone | [R1] |

<a id="table-8-actor-channel-and-messaging-iocs"></a>
### Actor Channel and Messaging IOCs
- **Type:** Soft IOC
- **Shelf life:** Short
- **Action:** Monitor + correlate (hunt-only, not attribution proof by itself)

| Indicator | evidence_tag | freshness_tag | Action profile | Reference |
|---|---|---|---|---|
| `https://t.me/HANDALA_RSS` (primary monitored channel) | `soft` | `volatile` | Monitor + timeline correlation only | [R10] |
| `https://t.me/s/handala_backup_357` (backup monitored stream) | `soft` | `volatile` | Monitor + timeline correlation only | [R18] |
| `@Handala_Backup` (X/Twitter backup, post-August 2024 ban) | `soft` | `volatile` | Monitor + timeline correlation only | [R12] |
| `UploadDataToTelegram` (project identifier in malware logic) | `near-hard` | `durable_pattern` | Hunt in malware/project strings + process ancestry | [R1] |

### Volatile Messaging/Bot IOCs (Historical Pivot Only)
- **Type:** Soft to Near-hard (volatile identifiers)
- **Shelf life:** Very short
- **Action:** Historical pivot/hunt only; do not rely on long-term blocking.

| Indicator | evidence_tag | freshness_tag | Action profile | Reference |
|---|---|---|---|---|
| `7613761286:<redacted>` (Telegram bot token structure) | `soft` | `volatile` | Historical pivot only; do not block on token alone | [R1] |
| `6503756114` (Telegram chat ID) | `near-hard` | `volatile` | Pivot with correlated process/network evidence | [R1] |

### File, Service, and Artifact IOCs
- **Type:** Mixed (Hard + Near-hard)
- **Shelf life:** Medium
- **Action:** Hunt + block where validated; keep lineage tagging in SIEM

**Core delivery/impact artifacts:**
<a id="table-9-core-deliveryimpact-artifacts"></a>

| Artifact | evidence_tag | freshness_tag | Action profile | Reference |
|---|---|---|---|---|
| `update.zip` | `near-hard` | `maybe_expired` | Hunt + detonation + quarantine if re-observed | [R1] |
| `CrowdStrike.exe` | `near-hard` | `maybe_expired` | Hunt + detonation + quarantine if re-observed | [R1] |
| `OpenFileFinder.dll` | `near-hard` | `maybe_expired` | Hunt + detonation + quarantine if re-observed | [R1] |
| `Champion.pif` | `near-hard` | `maybe_expired` | Hunt + detonation + quarantine if re-observed | [R1] |
| `Careol.zip` *(variant spelling as appearing in Trellix report text)* | `near-hard` | `maybe_expired` | Hunt + detonation + quarantine if re-observed | [R1] |
| `Carrol.zip` *(alternate spelling observed in same report; treat as same artifact, possible OCR/transcription variant)* | `near-hard` | `maybe_expired` | Hunt + detonation + quarantine if re-observed | [R1] |
| `Carrol.cmd` | `near-hard` | `maybe_expired` | Hunt + process-lineage correlation | [R1] |
| `Ukraine` (wiper stage artifact name) | `near-hard` | `maybe_expired` | Hunt + process-lineage correlation | [R1] |
| `Phase3.ps1` | `near-hard` | `maybe_expired` | Hunt + script block telemetry correlation | [R1] |

**Wiper and destructive lineage artifacts:**
<a id="table-10-wiper-and-destructive-lineage-artifacts"></a>

| Artifact | evidence_tag | freshness_tag | Action profile | Reference |
|---|---|---|---|---|
| `cl.exe` | `near-hard` | `durable_pattern` | Hunt with hash + service/driver correlation | [R2][R8] |
| `rwdsk.sys` | `near-hard` | `durable_pattern` | Hunt with hash + driver-load correlation | [R2][R8] |
| `GoXML.exe` | `near-hard` | `durable_pattern` | Hunt + sandbox + lineage mapping | [R8] |
| `do.zip` / `Do.exe` | `near-hard` | `maybe_expired` | Hunt + detonation + process-lineage | [R2] |
| `RawDisk3` (service label) | `near-hard` | `durable_pattern` | Service/driver analytics + response playbook trigger | [R2] |
| `reGeorge` (webshell family) | `near-hard` | `durable_pattern` | Web-tier hunt + child-process analytics | [R2] |
| `error4.aspx`, `ClientBin.aspx`, `pickers.aspx` | `near-hard` | `durable_pattern` | Web root diff + IIS/EDR correlation | [R8] |
| `mellona.exe`, `disable_defender.exe` | `near-hard` | `durable_pattern` | Hunt + AV-kill/defense-evasion correlation | [R8] |

<a id="table-11-hash-iocs-sha256"></a>
### Hash IOCs (SHA256)
- **Type:** Hard IOC
- **Shelf life:** Long for sample tracking; medium for blocking efficacy
- **Action:** Block + retro-hunt + sandbox triage
- All hashes normalized to lowercase.

| Hash | Context | evidence_tag | freshness_tag | Reference |
|---|---|---|---|---|
| `6eb7dbf27a25639c7f11c05fd88ea2a301e0ca93d3c3bdee1eb5917fc60a56ff` | CRM-linked malicious `.msi` | `hard` | `stable_tracking` | [R5] |
| `e1204ebbd8f15dbf5f2e41dddc5337e3182fc4daf75b05acc948b8b965480ca0` | `cl.exe` | `hard` | `stable_tracking` | [R8] |
| `3c9dc8ada56adf9cebfc501a2d3946680dcb0534a137e2e27a7fcb5994cd9de6` | `rwdsk.sys` | `hard` | `stable_tracking` | [R8] |
| `d0c03d40772cd468325bbc522402f7b737f18b8f37a89bacc5c8a00c2b87bfc6` | Lineage | `hard` | `stable_tracking` | [R2] |
| `deeaf85b2725289d5fc262b4f60dda0c68ae42d8d46d0dc19b9253b451aea25a` | Lineage | `hard` | `stable_tracking` | [R2] |
| `87f0a902d6b2e2ae3647f10ea214d19db9bd117837264ae15d622b5314ff03a5` | Lineage | `hard` | `stable_tracking` | [R2] |
| `85fa58cc8c4560adb955ba0ae9b9d6cab2c381d10dbd42a0bceb8b62a92b7636` | Lineage | `hard` | `stable_tracking` | [R2] |
| `74d8d60e900f931526a911b7157511377c0a298af986d42d373f51aac4f362f6` | Lineage | `hard` | `stable_tracking` | [R2] |
| `cc77e8ab73b577de1924e2f7a93bcfd852b3c96c6546229bc8b80bf3fd7bf24e` | Lineage | `hard` | `stable_tracking` | [R2] |
| `40417eb9ca90af12129f7bcf6e7b2f250f4919f1c5ea59d2f4fc9c96c7f819e3` | Check Point YARA metadata | `hard` | `stable_tracking` | [R2] |

<a id="table-12-hash-iocs-md5"></a>
### Hash IOCs (MD5)
- **Type:** Hard IOC (legacy hash format)
- **Shelf life:** Medium
- **Action:** Hunt + correlation (avoid MD5-only blocking decisions)

| Hash | Context | evidence_tag | freshness_tag | Reference |
|---|---|---|---|---|
| `2bf14f4d28ea8e80f227873de0a4f367` | Campaign | `hard` | `stable_tracking` | [R1] |
| `7b1602dcf39d2f564008e3abbb2f2f6a` | Campaign | `hard` | `stable_tracking` | [R1] |
| `57fbfeb55f8332f6413f31bb310ed7f9` | Campaign | `hard` | `stable_tracking` | [R1] |
| `1476f9f4f13db0a7179fd4dc0825765d` | Campaign | `hard` | `stable_tracking` | [R1] |
| `81e123351eb80e605ad73268a5653ff3` | Lineage | `hard` | `stable_tracking` | [R8] |
| `a9fa6cfdba41c57d8094545e9b56db36` | Lineage | `hard` | `stable_tracking` | [R8] |
| `8f766dea3afd410ebcd5df5994a3c571` | Lineage | `hard` | `stable_tracking` | [R8] |
| `7b71764236f244ae971742ee1bc6b098` | `cl.exe` | `hard` | `stable_tracking` | [R8] |
| `bbe983dba3bf319621b447618548b740` | `GoXML.exe` | `hard` | `stable_tracking` | [R8] |
| `8f6e7653807ebb57ecc549cef991d505` | `rwdsk.sys` | `hard` | `stable_tracking` | [R8] |
| `78562ba0069d4235f28efd01e3f32a82` | Lineage | `hard` | `stable_tracking` | [R8] |
| `60afb1e62ac61424a542b8c7b4d2cf01` | Lineage | `hard` | `stable_tracking` | [R8] |

### Command-Line and Behavioral IOCs
- **Type:** Soft to Near-hard (behavioral)
- **Shelf life:** Medium to long
- **Action:** Detection/hunting priority; do not use alone for attribution

| Indicator / Pattern | evidence_tag | freshness_tag | Action profile | Reference |
|---|---|---|---|---|
| `vssadmin Delete Shadows /all /quiet` | `soft` | `durable_pattern` | High-priority detection + destructive playbook trigger | [R2] |
| `bcdedit /set {default} recoveryenabled No` | `soft` | `durable_pattern` | High-priority detection + destructive playbook trigger | [R2] |
| `bcdedit /set {default} bootstatuspolicy ignoreallfailures` | `soft` | `durable_pattern` | High-priority detection + destructive playbook trigger | [R2] |
| `ping 4.2.2.4 -n 5 > Nul` (execution-timing/flow control pattern) | `soft` | `durable_pattern` | Correlate with installer/script ancestry | [R1] |
| Wiper invocation argument pattern: `confirmdeletefiles` | `near-hard` | `durable_pattern` | Hunt + command-line correlation | [R1] |
| Security-process kill-list examples: `wrsa.exe`, `msmpeng.exe`, `ccsvchst.exe`, `tmccsf.exe`, `aswidsagent.exe`, `avp.exe`, `savservice.exe`, `fssm32.exe`, `coreServiceShell.exe`, `V3Svc.exe`, `V3LITE.EXE`, `V3Main.exe` | `soft` | `durable_pattern` | Correlate with kill-burst + anti-recovery behavior | [R1] |
| Exchange mailbox collection cmdlets: `New-MailboxSearch`, `Get-Recipient` | `near-hard` | `durable_pattern` | Hunt in Exchange/PowerShell audit logs | [R8] |

### Defender Usage Notes
- Prioritize **multi-signal correlation**: (`IOC hit` + `behavior` + `campaign context`) instead of one-indicator decisions.
- Treat channel/claim-only indicators as **soft IOCs** until telemetry confirms compromise.
- Revalidate all network indicators against current blocklists and passive-DNS before production blocking.
- Actor claim volumes are frequently overstated relative to confirmed data scope; do not use claimed exfiltration size as a proxy for confirmed impact.

---

## Overall Statistics, Common Patterns, and Cross-Group Correlation

### Quantitative Snapshot

| Metric | Value | Basis |
|---|---:|---|
| Timeline activity phases | 17 | Expanded timeline in this report (includes June 2025, July 2025, October 2025 phases). **Phase definition:** a distinct reporting-defined campaign window or incident cluster with unique TTP/impact narrative. |
| Phases with explicit destructive/wiper malware behavior | 6 | October–November 2023, May 2024, July 2024, June 2025, December 2024–January 2025, February 2026 [R1][R2][R5][R8] |
| Phases with disruptive non-wiper confirmed operational impact | 1 | January 2025 emergency siren/PA workflow abuse incident. Note: Handala also claimed to have wiped Maagar-Tec systems post-incident; this wiper claim is unverified and not counted in the destructive/wiper phase total above. [R4][R13][R17] |
| Phases with explicit phishing/lure delivery | 5 | Early campaigns, CrowdStrike lure, CRM-linked phishing waves [R1][R5][R9][R14] |
| Phases with clear trusted-relationship/supply-chain abuse | 2 | ReutOne/CRM-linked operations [R3][R5] |
| Phases with public claim/influence amplification | 16 | Claim + channel amplification pattern appears across all post-brand phases (December 2023–March 2026) [R9][R10][R12][R16] |
| Network & Infrastructure indicators | 11 | 5 IPs + 1 CIDR + 5 URL/infra entries in IOC compendium (including Mega) |
| File hash entries | 22 | IOC compendium entries: 10 SHA256 + 12 MD5 |
| Vendor/source convergence on cluster identity | 5+ | Check Point [R5], CrowdStrike [R23c], Microsoft [R19], Sophos [R11], Recorded Future [R23e] |

### Common Operational Patterns
1. [Assessed] **Access → impact → narrative cycle is persistent.** Handala-linked operations repeatedly progress from initial compromise into destructive or leak action, then immediately into public claim/disinformation pressure. [R1][R2][R5][R9]
2. [Assessed] **Tradecraft is operationally effective but technically pragmatic.** Public reporting points to phishing, social engineering, webshell lineage, known destructive utilities, and commercial file-sharing infrastructure (Storj, Mega) rather than dependency on novel 0-days in every campaign. [R1][R5][R8][R9]
3. [Assessed] **Influence operations are not a side effect; they are part of the attack design.** Telegram and mirror channels function as force multipliers for reputational and psychological damage. Actor claim volumes are frequently overstated. [R9][R10][R12][R16][R23i][R23j]
4. [Assessed] **Supplier/partner pathways are a recurring risk amplifier.** Compromised trusted senders and CRM-linked channels are repeatedly highlighted in 2025 reporting. [R3][R5]
5. [Assessed] **Attribution is strongest at cluster/workflow level.** Multiple independent primary sources (Check Point, CrowdStrike, Microsoft, Sophos, Recorded Future) converge on strong cluster-level identity between the Handala Hack persona and MOIS-linked Void Manticore / BANISHED KITTEN / Storm-0842 cluster. [R2][R5][R11][R19][R23c][R23d][R23e]
6. [Assessed] **Communications gap ≠ operational halt.** The silence of Handala's own public channels from approximately February 9 to July 2025 did not prevent cluster operations; wiper activity (June 2025) and hack-and-leak operations (July 2025) continued under vendor cluster attribution. [R5][R23a][R23b][R23d][R23f]

### Other Groups Using Similar Tools/Workflows
> [Assessed] This section provides lineage/overlap context only and is not used for Handala incident-level attribution.

| Shared element | Handala-linked context | Other groups/personas with same element | Assessment |
|---|---|---|---|
| **`cl.exe` + `rwdsk.sys` (RawDisk3) destructive utility** | Included in Handala lineage IOC package and destructive TTP baseline [R2][R8] | Used in Albania government destructive operations attributed to Iranian state actors; mapped in Microsoft/CISA reporting [R7][R8][R19] | **High overlap (tool + procedure), attribution-nonunique** |
| **BiBi wiper family and partition-wipe logic** | Israel-focused destructive operations in Handala/Void context [R2][R19] | Void Manticore/Karma operations; linked multi-theater with Homeland Justice ecosystem [R2][R19] | **High overlap (family + model), attribution-nonunique** |
| **Access-handoff model (access actor → destructive actor)** | Observed in Israel-focused operations tied to Handala/Void activity [R2][R19] | Storm-0861 (Scarred Manticore) to Storm-0842 (Void Manticore) in both Albania and Israel reporting [R2][R19] | **High overlap (workflow), attribution-nonunique** |
| **CVE-2019-0604 SharePoint + webshell persistence lineage** | Lineage context from MOIS-linked pre-brand operations (October–November 2023). Not assessed as a dominant current vector for post-2023 Handala incidents. Full context in the October–November 2023 timeline phase. [R8] | Albania operations and related MOIS-linked actor workflows [R7][R8][R19] | **Moderate-high overlap (lineage TTP), attribution-nonunique** |
| **Commercial file-sharing for payload delivery** | Storj (July 2024), Mega (December 2024–January 2025) [R1][R5] | Broadly used across multiple Iran-nexus and other threat actors; not cluster-unique | **Low specificity, delivery-method-only overlap** |

### Hash/IP Correlation Matrix (Handala Context vs Other Clusters)

| IOC | Handala-side context | Observed overlap with other groups/personas | Correlation note |
|---|---|---|---|
| `3c9dc8ada56adf9cebfc501a2d3946680dcb0534a137e2e27a7fcb5994cd9de6` (`rwdsk.sys` SHA256) | Pre-brand and destructive lineage package in this report [R8] | CISA Albania advisory and Microsoft Albania reporting context [R7][R8] | High historical overlap in MOIS-linked destructive stack |
| `e1204ebbd8f15dbf5f2e41dddc5337e3182fc4daf75b05acc948b8b965480ca0` (`cl.exe` SHA256) | Lineage IOC and destructive utility chain [R8] | Same destructive chain in Albania operation reporting [R7][R8][R19] | High overlap at tool level |
| `7b71764236f244ae971742ee1bc6b098` (`cl.exe` MD5) | Lineage IOC package [R8] | Same file family documented in Albania advisory [R8] | High overlap at artifact level |
| `8f6e7653807ebb57ecc549cef991d505` (`rwdsk.sys` MD5) | Lineage IOC package [R8] | Same driver artifact in Albania advisory [R8] | High overlap at artifact level |
| `bbe983dba3bf319621b447618548b740` (`GoXML.exe` MD5) | Lineage encryptor/wiper ecosystem [R8] | Same destructive campaign family in Albania ecosystem reporting [R7][R8] | Medium-High overlap (campaign family) |
| `64.176.169.22`, `64.176.172.101`, `64.176.172.165`, `64.176.172.235`, `64.176.173.77` | Void/Handala-related infrastructure set [R2] | Reported in Void Manticore destructive activity tied to Storm-0842 naming [R2][R11] | High cluster linkage; public cross-group reuse outside this cluster is not well established |
| `6eb7dbf27a25639c7f11c05fd88ea2a301e0ca93d3c3bdee1eb5917fc60a56ff` | CRM-linked malicious `.msi` campaign (2025 retrospective) [R5] | No high-confidence public non-Handala reuse in cited sources | Currently a campaign-specific high-priority hash |

> Footnote: Overlap ≠ exclusivity; do not use alone for attribution.
>
> [Assessed] For Handala/Void Manticore attribution, infrastructure intersections (IP/CIDR reuse with temporal/campaign alignment) are weighted more heavily than commodity tool overlap (`cl.exe`, `rwdsk.sys`), which has lower uniqueness across Iran-nexus operations. [R2][R5][R11][R19][R23c][R23d][R23e]

---

## VirusTotal Spot-Check (Quota-Limited)

VT enrichment in this report is a scoped sample snapshot run on March 5, 2026 (**UTC**; local report timezone **Asia/Jerusalem**). Results are included for prioritization only and do not represent full-corpus enrichment coverage.

- **Processed in this snapshot:** 20 hash IOCs
- **Resolved with detections (M+S > 0):** 8/20
- **Not found (`404`):** 11/20

> **Analyst note on 404 results:** A VT "not found" result may indicate: (a) the hash was never submitted to VT; (b) the hash value contains a transcription error from a secondary source; or (c) the sample was submitted under a private/restricted visibility setting. Do not interpret "not found" as absence of malicious activity. For hashes sourced from secondary reporting rather than primary technical advisories, re-derive from original artifacts before concluding the hash is invalid.

- **Unresolved in this snapshot:** 1/20

**Highest-signal hashes from this spot-check:**

| Hash | M+S |
|---|---:|
| `bbe983dba3bf319621b447618548b740` | 59 |
| `7b71764236f244ae971742ee1bc6b098` | 58 |
| `74d8d60e900f931526a911b7157511377c0a298af986d42d373f51aac4f362f6` | 54 |
| `60afb1e62ac61424a542b8c7b4d2cf01` | 52 |
| `3c9dc8ada56adf9cebfc501a2d3946680dcb0534a137e2e27a7fcb5994cd9de6` | 46 |
| `8f6e7653807ebb57ecc549cef991d505` | 46 |
| `6eb7dbf27a25639c7f11c05fd88ea2a301e0ca93d3c3bdee1eb5917fc60a56ff` | 36 |
| `85fa58cc8c4560adb955ba0ae9b9d6cab2c381d10dbd42a0bceb8b62a92b7636` | 31 |

> Analyst caveat: treat these scores as **priority hints**. Execute full-corpus enrichment in a dedicated run window (or higher-capacity tier) for complete two-layer relationship mapping.
> Raw spot-check artifact for reproducibility: `vt_hash_spotcheck_2026-03-05.json`.

---

## Confidence and Gaps

### Confidence
- **High:** Handala has conducted repeated disruptive, destructive, and influence-oriented campaigns against Israeli targets across at least six confirmed wiper-phase events and multiple hack-and-leak operations.
- **High (cluster level):** Multiple independent primary sources (Check Point, CrowdStrike, Sophos, Microsoft, Recorded Future) directly link the Handala Hack persona to the Void Manticore / BANISHED KITTEN / Storm-0842 MOIS-aligned cluster.
- **Medium-High:** Individual incident attribution for post-February 2025 activity — attributions are researcher/vendor cluster-level and do not represent actor self-claims.
- **Low:** Specific operational claims posted by actor channels without independent forensic corroboration. Per methodology: claim-led, single-source, no independent technical corroboration; confidence floor is "Low."

### Gaps
- Public reporting remains uneven on confirmed victim impact in several high-profile claims.
- Multi-actor overlap in the same theater complicates precise operation-level attribution.
- **Post-February 2025 communications gap:** Handala's own public channels went silent after approximately February 9, 2025, before resuming in approximately July 2025. Activity attributed to Handala in the interim (June 2025 wiper) and subsequent phases represents researcher/vendor cluster-level attribution (Void Manticore / BANISHED KITTEN) rather than actor self-claims. Consumers should distinguish between cluster-level attribution by researchers and actor self-claimed operations when assessing post-February 2025 incidents. [R23a][R23b][R23d]
- **Operational interpretation of the gap:** current evidence supports a working hypothesis of pause/reduction in influence-channel output rather than pause in intrusion capability. The June 2025 wiper event during the channel-silence window supports continuity of intrusion operations despite communications disruption or tradecraft shift. [R5][R23a][R23b][R23d]
- **Actor claim-volume reliability:** Secondary reporting citing KELA analysis of the December 2025 Bennett incident demonstrated that the actor materially overstated data scope (claimed 1,900 chats; fewer than 40 contained real messages). This pattern likely applies across other claim-volume assertions in the dataset. [R23i][R23j]
- **June 2025 wiper artifacts:** Campaign-specific artifact details for the June 2025 wiper event have not been publicly released by Check Point at evidence cutoff. [R5]

---

## Practical Defensive Actions (Next 30 Days)
1. Run a focused supplier-risk review for CRM/IT service dependencies.
   - Mandatory add-on: perform vendor-of-vendor discovery for emergency communication chains and explicitly flag Maagar-Tec (and equivalent panic-button/PA providers) across subsidiaries and third parties.
2. Add emergency controls for unsigned or unusual `.msi` execution, including downloads from commercial file-sharing services (Mega, Storj).
3. Deploy and test a wiper-specific IR playbook.
4. Expand monitoring for destructive pre-encryption behavior.
5. Train comms + legal + SOC on claim-driven influence operations; establish a claim-scope deflation process before any public statement.

---

## Escalation Readiness (Iran–Israel–US 2026): SOC / CISO / Blue Team / TI-TH

> *For full detection logic and control SLAs, see Detection Engineering Pack and Controls Mapping sections.*

| Role | Top 3 Actions | Timeline |
|---|---|---|
| **SOC** | (1) Promote to high-severity and auto-case any occurrence of `vssadmin Delete Shadows /all /quiet`, `bcdedit /set {default} recoveryenabled No`, or mass file overwrite/rename/delete bursts post installer execution. (2) Route all actor-channel claim events to a dedicated `CLAIM/OSINT` queue; require local telemetry corroboration before escalating to incident status; treat claim volumes as unverified by default. (3) Enable one-click host isolation for the initiating context — prioritize containment over attribution closure when destructive indicators are present. | 0–72 hours |
| **CISO / Incident Command** | (1) Activate evidence-gated external communications: pre-approve holding language with Legal/Comms; no public statement may assert confirmed breach until forensic scoping is complete — and no statement should repeat actor-claimed data volumes without independent validation. (2) Enforce out-of-band verification + signed artifact requirement for all partner/supplier "urgent update" requests; prohibit patches delivered as email attachments or from commercial file shares (Mega, Storj) without a verified change ticket. (3) Validate backup integrity and initiate accelerated restore drill if destructive indicators appear. | 0–72 hours |
| **Blue Team / Detection Engineering** | (1) Add `.msi` execution controls restricting launch from user-writable paths (Downloads, Temp, email attachment directories, commercial file-share download directories); enforce allow-list for signed/managed installers. (2) Implement multi-signal correlation chains: `archive/PDF → installer → script/LOLBins → egress` — do not rely on single-IOC blocking. (3) Add driver-load and service-creation visibility rules for raw-disk/destructive tooling patterns (`rwdsk.sys`, `RawDisk3`, related service names). | 7–30 days |
| **TI / Threat Hunting** | (1) Maintain a ±48h claim-vs-telemetry timeline view around actor-channel posts; treat all actor claim volumes as unverified by default — secondary coverage citing KELA indicates routine overstatement of data scope. (2) Run periodic hunts across four pattern families: installer chains and suspicious `.msi` execution (especially from Mega/Storj); destructive precursor commands; post-execution egress to web services/messaging APIs; webshell anomalies on IIS/Exchange/SharePoint tiers. (3) Do not convert actor-channel claims into confirmed incidents without local telemetry — treat all channel output as collection leads and early-warning signal only. | Continuous |

---

## Appendix B: Volatile Indicators (Rotate Quickly)

- Telegram bot token observed in malware workflow: `7613761286:<redacted>` [R1]
- Telegram chat ID observed in malware workflow: `6503756114` [R1]

> **Handling guidance:** These indicators are volatile and may be expired or reassigned at time of reading. **Publication risk:** publishing live bot tokens in open-distribution reports can enable third parties to probe or interact with the associated bot infrastructure, and may alert operators to detection, triggering faster rotation. If this report is distributed beyond TLP:WHITE scope, consider redacting the token and retaining only the chat ID and a structural description. Use for short-window hunting and historical pivoting only; do not use for long-term blocking.

---

## References

- **[R1]** Trellix, *Handala's Wiper Targets Israel*. Published: July 26, 2024. Accessed: March 5, 2026.
  https://www.trellix.com/en-gb/blogs/research/handalas-wiper-targets-israel/

- **[R2]** Check Point Research, *Bad Karma, No Justice: Void Manticore Destructive Activities in Israel*. Published: May 20, 2024. Accessed: March 5, 2026.
  https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/

- **[R3]** Check Point Research, *6th January – Threat Intelligence Report*. Published: January 6, 2025. Accessed: March 5, 2026.
  https://research.checkpoint.com/2025/6th-january-threat-intelligence-report/

- **[R4]** Check Point Research, *3rd February – Threat Intelligence Report*. Published: February 3, 2025. Accessed: March 5, 2026.
  https://research.checkpoint.com/2025/3rd-february-threat-intelligence-report/

- **[R5]** Check Point Research, *2025: The Untold Stories of Check Point Research*. Published: February 23, 2026. Accessed: March 5, 2026.
  https://research.checkpoint.com/2026/2025-the-untold-stories-of-check-point-research/

- **[R6]** Unit 42, *Threat Brief: March 2026 Escalation of Cyber Risk Related to Iran*. Published: March 2, 2026. Accessed: March 5, 2026.
  https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/

- **[R7]** Microsoft Security Blog, *Microsoft investigates Iranian attacks against the Albanian government*. Published: September 8, 2022. Accessed: March 5, 2026.
  https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/

- **[R8]** CISA/FBI, *AA22-264A Iranian State Actors Conduct Cyber Operations Against the Government of Albania*. Published: September 21, 2022. Accessed: March 5, 2026.
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a

- **[R9]** Cyberint, *Handala Hack: What We Know About the Rising Threat Actor*. First published: July 16, 2024; updated: February 20, 2025. Accessed: March 5, 2026.
  https://cyberint.com/blog/threat-intelligence/handala-hack-what-we-know-about-the-rising-threat-actor/

- **[R10]** Telegram channel (monitoring lead). Accessed: March 5, 2026. Note: Volatile source; content can change; use as monitoring lead only.
  https://t.me/HANDALA_RSS

- **[R11]** Sophos Threat Profiles, *COBALT MYSTIQUE* (alias crosswalk context). Accessed: March 5, 2026.
  https://www.sophos.com/en-us/threat-profiles/cobalt-mystique
  > *Note: COBALT MYSTIQUE is used here as a public alias-crosswalk anchor in relation to Void Manticore (Check Point naming) and Storm-0842 (Microsoft naming).*

- **[R12]** The Record, *Handala's X account banned; backup channel activity continued*. Published: August 21, 2024. Accessed: March 5, 2026.
  https://therecord.media/handala-x-account-banned-twitter-palestine-iran

- **[R13]** The Record, *Hackers hijack sirens in Israeli kindergartens*. Published: January 27, 2025. Accessed: March 5, 2026.
  https://therecord.media/hackers-hijack-sirens-iran-israel

- **[R14]** BleepingComputer, *Fake CrowdStrike fixes target companies with malware/data wipers*. Published: July 21, 2024. Accessed: March 5, 2026.
  https://www.bleepingcomputer.com/news/security/fake-crowdstrike-fixes-target-companies-with-malware-data-wipers/

- **[R15]** The Wall Street Journal, *Iran-linked cyberattack reporting involving former Israeli PM*. Accessed: March 5, 2026. Note: paywalled.
  https://www.wsj.com/world/middle-east/iran-hacks-former-israeli-prime-minister-in-new-tehran-linked-cyberattack-f1a959ca
  > *Editorial note:* Paywalled; used as contextual reference for the February 2025 leak/pressure operations phase. Specific claim supported: reporting on personal-data and weapons-holder data exposure themes attributed to Iran-linked actors. No unique technical artifacts or IOCs are sourced exclusively from this reference.

- **[R16]** International Institute for Counter-Terrorism (ICT), *Bibi Gate: Handala Hack Team - A Mask for Iranian Psychological Warfare*. Published: December 31, 2025. Accessed: March 5, 2026.
  https://ict.org.il/bibi-gate-handala-hack-team-a-mask-for-iranian-psychological-warfare/
  https://ict.org.il/wp-content/uploads/2025/12/Download.pdf

- **[R17]** Times of Israel, reporting on Iranian hackers broadcasting sirens in kindergartens. Published: January 26, 2025. Accessed: March 5, 2026.
  https://www.timesofisrael.com/iranian-hackers-broadcast-rocket-sirens-odes-to-terrorism-in-some-20-kindergartens/

- **[R18]** Telegram backup stream (monitoring lead). Accessed: March 5, 2026. Note: Volatile source; content can change; use as monitoring lead only.
  https://t.me/s/handala_backup_357

- **[R19]** Microsoft Security Insider, *Iran surges cyber-enabled influence operations in support of Hamas*. Published: February 26, 2024. Accessed: March 5, 2026.
  https://www.microsoft.com/en-us/security/security-insider/threat-landscape/iran-surges-cyber-enabled-influence-operations-in-support-of-hamas/

- **[R20]** ODNI/FBI/CISA, *Joint ODNI, FBI, and CISA Statement on Iranian Election Influence Efforts*. Published: August 19, 2024. Accessed: March 5, 2026.
  https://www.dni.gov/index.php/newsroom/press-releases/press-releases-2024/3981-joint-odni-fbi-and-cisa-statement-on-iranian-election-influence-efforts

- **[R21]** JNS, *Iranians claim they hacked former Israeli PM Bennett's phone*. Published: (publication date not available; accessed March 5, 2026).
  https://www.jns.org/iranians-claim-they-hacked-former-israeli-pm-bennetts-phone/

- **[R22]** Israel Hayom, *Handala hackers: Iranian cyber attacks on Israeli officials*. Published: December 28, 2025. Accessed: March 5, 2026.
  https://www.israelhayom.com/2025/12/28/handala-hackers-iranian-cyber-attacks-israel-officials/

- **[R23a]** OP Innovate, *Unpacking Handala*. Published: February 18, 2025. Accessed: March 5, 2026.  
  https://op-c.net/blog/unpacking-handala/
- **[R23b]** OP Innovate, *Did OP Innovate Disrupt Handala Cyber Threat?* Published: February 28, 2025. Accessed: March 5, 2026.  
  https://op-c.net/blog/did-op-innovate-disrupt-handala-cyber-threat/
- **[R23c]** CrowdStrike, *BANISHED KITTEN* adversary profile. Accessed: March 5, 2026.  
  https://www.crowdstrike.com/en-us/adversaries/banished-kitten/
- **[R23d]** Global Affairs Canada (RRM Canada), *Backgrounder: Iran-linked hacker group doxes journalists and amplifies leaked information through AI chatbots*. Published: September 12, 2025. Accessed: March 5, 2026.  
  https://www.international.gc.ca/transparency-transparence/rapid-response-mechanism-mecanisme-reponse-rapide/iran-hack-piratage-iranien.aspx?lang=eng
- **[R23e]** Recorded Future News, *The Retaliation Window: How State and Non-state Actors Could Exploit Escalation in the Middle East*. Published: September 10, 2025. Accessed: March 5, 2026.  
  https://www.recordedfuture.com/blog/retaliation-window-middle-east-escalation
- **[R23f]** Iran International, reporting on Handala/BANISHED KITTEN operation against journalists (Persian-language source cited by RRM Canada). Published: July 8, 2025. Accessed: March 5, 2026.  
  https://www.iranintl.com/202507086458
- **[R23g]** ICNA (Iran Cyber News Agency), reporting on Handala claim targeting Suvarnabhumi Airport systems (claim-tracking/OSINT context, not forensic confirmation). Published: October 2, 2025. Accessed: March 5, 2026.  
  https://irancybernews.org/en/handala-hacking-group-exposes-confidential-access-to-suvarnabhumi-airport/
- **[R23h]** The Jerusalem Post, reporting on Handala claim targeting Clalit systems. Published: February 25, 2026. Accessed: March 5, 2026.  
  https://www.jpost.com/israel-news/article-887911/
- **[R23i]** eSecurity Planet, *Handala Leak Shows Telegram Account Risk, Not iPhone Hacks*. Published: January 29, 2026. Accessed: March 5, 2026.  
  https://www.esecurityplanet.com/threats/handala-leak-shows-telegram-account-risk-not-iphone-hacks/
- **[R23j]** CyberPress, *Telegram Account Compromise Used by Handala Hackers Against Israeli Officials*. Published: January 2, 2026. Accessed: March 5, 2026.  
  https://cyberpress.org/telegram-account-compromise/
  > *Evidence handling note:* No direct public URL to a standalone KELA primary technical write-up for the Bennett/Braverman scope finding was located at evidence cutoff. KELA-dependent statements in this report are therefore treated as secondary-reported (`Reported`), not `Observed`.

---

> **Editorial note — References with unconfirmed publication dates:** One reference used in this report lacks a confirmed publication date: [R21] (JNS, date not available in public metadata). Claims sourced from this reference carry uncertain temporal anchoring and should be treated as accessed-date-only.

---

## Editorial Change Log

- **Fix 1:** Added `[Reported]`/`[Assessed]` labels to the narrative bullets in the TTP synthesis section.
- **Fix 2:** Added the requested editorial warning immediately after all in-text `[R11]` citations.
- **Fix 3:** Added analyst guidance clarifying analytical interpretation of VT `404` hash results.
- **Fix 4:** Replaced Appendix B handling guidance with the expanded operational-risk warning for published bot tokens.
- **Fix 5:** Added a formal definition of **Partially corroborated** to the methodology section.
- **Fix 6:** Replaced the ATT&CK bullet list with a consolidated technique table covering timeline-mentioned techniques.
- **Fix 7:** Condensed Escalation Readiness to a role-keyed checklist table with cross-reference to detection/control sections.
- **Fix 8:** Updated publication-date handling for references `[R9]`, `[R16]`, and `[R21]` per instruction.
- **Fix 9:** Downgraded claim-led confidence statement from **Low to Medium** to **Low** with methodology rationale.
- **Fix 10:** Added the specified caveat warning under January 2025 reported TTPs.
- **Fix 11:** Downgraded Key Judgment 6 confidence to **Medium** and added the bounded-confidence evidence note.
- **Fix 12:** Normalized artifact naming guidance for `Careol.zip`/`Carrol.zip`; SHA256 casing normalized to lowercase.
- **Fix 13:** Added a specific usage note clarifying what the paywalled `[R15]` source supports.
- **Fix 14:** Replaced later `CVE-2019-0604` contextual repetitions with the requested cross-reference framing.
- **Fix 1 (v2) — RETRACTED:** The [R11] editorial warning inserted in v2 was based on a factual error. COBALT MYSTIQUE is the correct Secureworks profile for the Void Manticore / Storm-0842 cluster. The warning has been removed and replaced with a clarifying alignment note in the References section.
- **Fix 2 (v2):** Added missing `T1078` (Valid Accounts) row to ATT&CK consolidated mapping table.
- **Fix 3 (v2):** Moved [R16]/[R21] temporal anchoring note to a clearly separated block after the final reference entry.
- **Fix 4 (v2):** Reformatted [R15] usage note as an inline editorial blockquote within the reference entry.
- **Fix 5 (v2):** Restored technical specificity to Escalation Readiness table; reintroduced concrete commands, controls, and hunt patterns per role.
- **Fix 6 (v2):** Fixed CVE-2019-0604 self-referencing assessed statement; updated Cross-Group Correlation table to use forward-reference framing.
- **Fix 1 (v3):** Retracted the incorrect [R11] COBALT MYSTIQUE editorial warning. Replaced with alignment note confirming correct URL.
- **Fix 2 (v3):** Corrected Quantitative Snapshot — recategorized January 2025 incident and added unverified wiper claim note for Maagar-Tec.
- **Fix 3 (v3):** Added Maagar-Tec as identified technical access vector for January 2025 incident. Added vendor-pivot hunting note.
- **Fix 4 (v3):** Disambiguated August 2024 channel migration narrative — separated X backup (`@Handala_Backup`) from Telegram infrastructure as distinct platform assets.
- **Fix 1 (v4):** Upgraded attribution framing — Void Manticore / Handala Hack direct CPR equivalence statement added to Alias Crosswalk. Key Judgment 5 confidence upgraded from Medium to Medium-High.
- **Fix 2 (v4):** Added June 2025 Handala Hack wiper phase to Activity Timeline from Check Point [R5]. Renamed phase header. Added T1485 TTP, narrative bullet, IOC note. Quantitative Snapshot wiper-phase count updated from 5 to 6.
- **Fix 3 (v4):** Added Mega file share as CRM-campaign `.msi` delivery platform. Updated narrative bullet, IOC/Hunting Leads, and URL/Infrastructure IOC Compendium. Noted distinction from Storj (July 2024).
- **Fix 4 (v4):** Added post-February 2025 communications gap note. Added assessed caveats to Claims subsections of June–October 2025, December 2025, and March 2026 phases.
- **Fix 1 (v5 — final):** Added BANISHED KITTEN (CrowdStrike) and Dune (Recorded Future) to Alias/Cluster Crosswalk. Updated Executive Summary and Key Judgment 5 to reflect five-vendor convergence. Added composite convergence reference set (later split into atomic entries in v6).
- **Fix 2 (v5 — final):** Added July 2025 (Iran International hack-and-leak) and October 2025 (Suvarnabhumi Airport claim) as new timeline phases. Updated targeting and victimology sections. Updated timeline count to 17 phases.
- **Fix 3 (v5 — final):** Added February 2026 Clalit healthcare campaign claim to February 2026 timeline phase. Updated victimology.
- **Fix 4 (v5 — final):** Added KELA Bennett/Braverman analysis (claim-volume overstatement: <40 real messages vs claimed 1,900 chats) to November–December 2025 phase, Confirmed vs Claimed Matrix, Detection Engineering Pack rule 10, Gaps section, and Escalation Readiness TI row.
- **Fix 5 (v5 — final):** Added post-February 2025 operational gap note to timeline header, Gaps section, and February 2025 phase. Clarified gap = channel silence, not operational halt. Added June–July 2025 resumption context.
- **Fix 6 (v5 — final):** Added commercial file-sharing delivery infrastructure (Storj, Mega) to Executive Summary, TTP section, Detection Engineering Pack rule 2, Controls Mapping, and Escalation Readiness. Added Storj delivery label to July 2024 phase IOC/Hunting Leads. Added commercial file-sharing row to Cross-Group Correlation overlap table.
- **Fix 7 (v5 — final):** Added Medium-High confidence tier to Confidence ladder. Updated Key Judgment 3 and Key Judgment 5 accordingly.
- **Fix 8 (v5 — publication hardening):** Added explicit text-based link-analysis chain between Handala persona and Void Manticore / Storm-0842 / COBALT MYSTIQUE / BANISHED KITTEN / Dune aliases, with infrastructure-overlap anchor indicators for clearer executive attribution visualization.
- **Fix 9 (v5 — publication hardening):** Strengthened lineage caveat by explicitly weighting infrastructure intersections above commodity tool overlap in attribution reasoning.
- **Fix 10 (v5 — publication hardening):** Reworked Detection Engineering Rule 10 from platform-session-log dependency to endpoint-first compromise-proxy detection model, improving operational applicability for typical SOC telemetry access.
- **Fix 11 (v5 — publication hardening):** Split benign chain services (`icanhazip`, `microsoft.com`) into a dedicated "Common/Benign Services Used in Chain" section with explicit never-blocklist guidance to reduce accidental FP-driven blocking.
- **Fix 12 (v5 — publication hardening):** Elevated Maagar-Tec supply-chain relevance in practical actions and detection priorities; added vendor-of-vendor review emphasis for emergency communication providers.
- **Fix 13 (v5 — publication hardening):** Replaced the prior `R23` placeholder with concrete public URLs (OP Innovate, CrowdStrike, RRM Canada, Recorded Future, Iran International, ICNA, Jerusalem Post, secondary KELA-citing coverage) and removed "insert URLs before final publication" note.
- **Fix 14 (v5 — publication hardening):** Re-labeled KELA-dependent Bennett/Braverman scope statements as secondary-reported evidence (`Reported`) pending a publicly accessible direct KELA primary write-up.
- **Fix 15 (v6 — publication hardening):** Replaced `[R11]` alias-crosswalk source with public Sophos COBALT MYSTIQUE threat profile; updated in-text Secureworks wording accordingly.
- **Fix 16 (v6 — publication hardening):** Split composite convergence reference into atomic entries `[R23a]`–`[R23j]` and re-mapped in-text citations to source-specific references.
- **Fix 17 (v6 — publication hardening):** Redacted Telegram bot token in Appendix B for open-distribution safety (`7613761286:<redacted>`).
- **Fix 18 (v6 — publication hardening):** Normalized source-date metadata where public dates are available (`[R9]` first published/updated; `[R16]` published date).
- **Fix 19 (v6 — publication hardening):** Added methodological guardrails: explicit rule-of-use for `Partially corroborated` and phase-definition sentence in Quantitative Snapshot.
- **Fix 20 (v6 — navigation hardening):** Converted top-level Table of Contents to clickable links; added dedicated table-navigation blocks and explicit anchor IDs for Table 4–12 (`Controls Mapping` and IOC table set) to improve in-document navigation in long-form review workflows.
