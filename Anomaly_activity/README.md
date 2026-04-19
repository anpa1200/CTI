# Malicious Activity as a Statistical Signal: A Detection Engineering Analysis of Anomaly-Based Detection

**The hypothesis examined: that suspicious and malicious activity produces measurable deviations from normal behaviour, and that many forms of attack can be detected by targeting those deviations.**

By [Andrey Pautov](https://medium.com/@1200km) — April 2026

---

## Table of Contents

1. [The Hypothesis — Scope and Definitions](#1-the-hypothesis--scope-and-definitions)
2. [Taxonomy of Anomaly Types](#2-taxonomy-of-anomaly-types)
3. [Mapping Anomalies to the ATT&CK Lifecycle](#3-mapping-anomalies-to-the-attck-lifecycle)
4. [Evidence Register: Real-World Cases](#4-evidence-register-real-world-cases)
5. [Where Anomaly Detection Works and Where It Fails](#5-where-anomaly-detection-works-and-where-it-fails)
6. [How Attackers Suppress Anomaly Visibility](#6-how-attackers-suppress-anomaly-visibility)
7. [Telemetry Requirements](#7-telemetry-requirements)
8. [Detection Engineering Patterns](#8-detection-engineering-patterns)
9. [Implementation Guidance for SOC and Detection Teams](#9-implementation-guidance-for-soc-and-detection-teams)
10. [Conclusion](#10-conclusion)
11. [References](#11-references)

---

## 1. The Hypothesis — Scope and Definitions

The claim that malicious activity creates detectable anomaly patterns is one of the foundational premises of modern security operations. It is the theoretical basis for UEBA platforms, ML-based SIEM analytics, network traffic analysis tools, and a substantial portion of contemporary detection engineering practice.

The hypothesis is **substantially true, but bounded**. It holds reliably in some attack phases and for some categories of malicious action. It fails, partially or completely, for others. The failure modes are not random — they are structurally determined by attacker technique, environment diversity, telemetry quality, and the mathematical properties of anomaly detection itself.

This article examines the hypothesis rigorously: what it means, where the evidence supports it, where it breaks down, and what detection engineers can practically do with it.

### 1.1 Definitions

**Anomaly.** NIST SP 800-94 defines anomaly-based intrusion detection as the comparison of normal activity profiles against observed events to identify significant deviations [1]. In operational terms, an anomaly is a measurable deviation from one or more baselines: an entity baseline (this user, this host), a peer baseline (users in this role, hosts in this class), a temporal baseline (activity at this time of day), a relationship model (who normally talks to whom), or an event-sequence model (what normally follows what).

**Point anomaly.** A single data instance that is anomalous relative to the rest of the data (Chandola et al., 2009) [2]. Example: a workstation that has never communicated with an external IP suddenly opening a connection to a foreign ASN.

**Contextual anomaly.** An instance that is anomalous only in a specific context — not globally unusual, but unusual given its circumstances [2]. Example: a privileged administrator executing `ntdsutil` is contextually anomalous when the host is a developer workstation but routine on a backup domain controller.

**Collective anomaly.** A collection of related instances that is anomalous together, even if each individual instance is not [2]. Example: no single DNS query to avsvmcloud[.]com subdomains in the SUNBURST campaign was inherently suspicious; the pattern of encoded victim-specific subdomains with delayed resolution created the collective anomaly [3].

**Malicious-behaviour correlation.** The analytical step that links an observed anomaly to an attacker goal, technique, or intrusion stage. An anomaly is not a verdict — it is evidence. A detection becomes operationally useful when the anomaly is correlated with asset context, identity state, companion telemetry, or known adversary tradecraft.

### 1.2 The Central Tension

The core challenge is mathematical. In a typical enterprise environment, the ratio of malicious events to benign events approaches zero. Even a detection system with 99% precision will produce thousands of false positives per day if it processes millions of benign events. This is the **base-rate fallacy** applied to security operations, and NIST SP 800-94 identified it explicitly in 2007: "complex environments are difficult to model accurately, and benign deviations can trigger large numbers of false positives" [1].

The implication is not that anomaly detection is useless. It is that anomaly detection only produces operational value when it is *specific enough* — meaning the baseline is tight, the signal is stable, and the anomaly is sufficiently rare in legitimate traffic. Where those conditions hold, anomaly-based detection is powerful. Where they do not, false positive rates undermine analyst confidence and erode the programme's utility.

---

## 2. Taxonomy of Anomaly Types

The following taxonomy combines the classical framework from Chandola et al. [2] with operational anomaly categories documented by NIST [1], Microsoft MSTIC [4][5][6], Mandiant [7][8][9], CISA/NSA [10][11], and the Australian Cyber Security Centre [12]. Each type has distinct mathematical properties, telemetry requirements, and failure modes.

| Anomaly Type | Definition | Typical Telemetry | Detection Approach | Signal Stability | False Positive Risk |
|---|---|---|---|---|---|
| **Volumetric** | Unusual absolute volume of data, events, or operations relative to entity or service baseline | NetFlow, firewall egress, DNS, file/object access, email, cloud audit | Thresholding + percentile + rolling baseline (Z-score, IQR) | High for exfiltration and ransomware; lower for shared infrastructure | Medium |
| **Frequency / Rate** | Unusual rate of repeated events within a time window | Auth logs, API logs, process start logs, DNS | Count-by-entity over rolling window; Poisson distribution models | High when concentrated; weak when distributed across IPs or tenants | Medium |
| **Temporal** | Activity at unusual times of day, week, or relative to business cycles | Auth logs, SaaS audit, admin actions, EDR | Working-hours baseline; time-series decomposition; seasonality models | Medium; highly context-dependent (shift work, global operations) | Medium–High |
| **Peer-Group** | An entity differs materially from its peer cohort (same role, department, host class) | Identity logs, HR data, endpoint inventory, SaaS access | Clustering (K-Means, TF-IDF cohort analysis), peer distribution percentiles | Medium–High when peer groups are cleanly defined | Medium |
| **Sequence** | Events occur in an unusual order relative to normal operational paths | Process trees, Kerberos authentication chains, API call sequences, session logs | Finite-state models, Markov chains, LSTM/Transformer-based sequence modelling | High for mature server roles; lower for developer environments | Medium |
| **Graph / Relationship** | Unexpected edges, bridges, or paths in identity, network, or resource graphs | Active Directory, IAM, SaaS permissions, NetFlow, cloud resource graph | Graph analytics, community detection, link-prediction scoring | High for privilege changes; moderate for network paths | Medium |
| **Geographic / ASN** | Access from new, implausible, or inconsistent locations or network providers | IdP logs, VPN, SaaS, cloud console | Geo-baseline + impossible-travel logic + ASN peer history | Medium alone; substantially stronger with enrichment | High if used alone |
| **Identity / Access** | Unusual authentication properties, factor changes, app consents, or token behaviour | IdP, MFA logs, Entra/Okta, cloud audit, OAuth logs | Risk detections, peer-baseline comparison, rare-event scoring | High with complete IdP telemetry | Medium |
| **Rare Process / Service** | Execution of a binary or service with low prevalence on that host or host class | EDR, Sysmon Event ID 1, Linux auditd, software inventory | Prevalence scoring, allowlist comparison, digital signature analysis | High on stable server roles; lower on developer workstations | Low–Medium |
| **Parent-Child Execution** | A parent process spawning children it rarely or never should | EDR, Sysmon Event ID 1, auditd | Process lineage rules + rarity modelling by parent process name | High on tightly managed servers | Low–Medium |
| **Data Movement** | Unusual read/write/copy/export/sync behaviour relative to entity or data-class baseline | DLP, file access logs, object storage audit, SaaS export logs, cloud storage | Volume + destination + object-type + peer baseline | High when export paths are fully instrumented | Medium |
| **Protocol / Application Usage** | Misuse of ports, protocols, or application features for non-standard purposes | Proxy logs, DNS, NetFlow, SaaS/IdP API logs | Rare-protocol analytics, entropy analysis, user-agent baseline | Medium–High | Medium |
| **Multi-Event Correlation** | Several individually weak signals combine into an anomalous chain against the same entity | SIEM / XDR across all sources | Correlation rules, graph/session stitching, entity risk scoring | Very high when tuned | Low–Medium |

---

## 3. Mapping Anomalies to the ATT&CK Lifecycle

Anomaly detection effectiveness is not uniform across the MITRE ATT&CK kill chain. The core reason is structural: anomaly detection is most useful when an attacker must create *measurable change* in the environment. It is least useful when the attacker can remain inside accepted identity, protocol, and administrative norms.

### 3.1 ATT&CK Stage Analysis

**Initial Access — Poor.**
Phishing and credential reuse produce weak anomaly signals locally. A login with valid credentials from a known country is not anomalous. Geographic or ASN anomalies (access from a new country, a residential proxy, a Tor exit node) are detectable but carry high false positive rates unless enriched with device, browser, and peer-group context. Midnight Blizzard's 2024 password spray campaign against Microsoft used low-volume attempts from residential proxies deliberately sized to avoid triggering per-tenant thresholds — from any single tenant's perspective, the spray was effectively invisible to local anomaly logic [4]. [Documented]

**Execution — Moderate to Strong.**
Rare parent-child execution chains and rare process execution on servers are among the most stable and actionable anomaly signals. `w3wp.exe` spawning `cmd.exe`, or `UMWorkerProcess.exe` writing files to disk, represents a parent-child anomaly that is both unusual and strongly correlated with post-exploitation activity. In the HAFNIUM Exchange exploitation campaign (CVE-2021-26855), these parent-child anomalies were among the primary detection opportunities documented by Microsoft and Mandiant [5][7]. [Documented]

The limitation at this stage is living-off-the-land (LOTL) technique: an attacker executing `PowerShell.exe` or `wmic.exe` through an already-unusual sequence does create sequence anomalies, but only when command-line logging is enabled and the command-line features are included in the baseline. CrowdStrike's 2025 Global Threat Report documented that 79% of intrusions in 2024 were malware-free, relying on legitimate tools and credentials — a figure that has risen steadily from 40% in 2019 [13]. [Documented]

**Persistence — Moderate.**
New scheduled tasks, service installations, registry run-key additions, or OAuth application registrations that deviate from an entity's baseline are detectable through rare-event and state-change anomaly logic. Microsoft MSTIC documented the Storm-1283 case in which a compromised user created a new OAuth application that then deployed Azure virtual machines for cryptomining — a control-plane anomaly combining unusual app registration with unusual compute creation [6]. [Documented]

MFA reset abuse — documented in UNC3944 operations — is a high-quality persistence signal when combined with the follow-on sign-in: MFA factor change for a privileged user, followed by an unfamiliar sign-in, followed by new OAuth application consent, is a collectively anomalous sequence even if each event looks individually explainable [8]. [Documented]

**Privilege Escalation — Moderate.**
Privilege escalation events (new users added to privileged groups, role grants, token elevation) are detectable through identity and access anomaly logic. The signal quality depends heavily on the cleanness of the baseline — in environments with frequent legitimate privilege changes, the noise level is high. The Dragonfly/Energetic Bear campaigns documented manipulation of administrator group membership on dormant accounts, which creates a clear peer-group and temporal anomaly [Inferred from Microsoft Sentinel documentation].

**Defense Evasion — Weak.**
This is structurally the hardest stage for anomaly detection. Defense evasion by definition targets the attacker's anomaly footprint. Attackers disable security agents, clear logs, rename executables, and use in-process techniques that avoid child-process anomalies. Microsoft notes that malicious IIS modules executing inside `w3wp.exe` avoid child-process detection entirely [5]. NIST SP 800-94 documented the "negative anomaly" problem: absence of expected telemetry (an endpoint that stops generating logs) is anomalous but is rarely modelled [1].

**Credential Access — High.**
Password spraying and brute-force attacks generate clear frequency and rate anomalies. The ACSC's Active Directory guidance provides explicit detection logic: a spike in Event ID 4625 (failed logon) across many accounts within a short window, particularly from a single IP or subnet, is a stable and actionable pattern [12]. [Documented]

The limitation is distribution: Midnight Blizzard's residential proxy infrastructure spread failures across thousands of IP addresses, rendering per-IP rate limiting ineffective. Detection at this point requires cross-tenant or provider-level view, which individual SOC teams typically do not have [4]. [Documented]

**Lateral Movement — Moderate to High.**
Lateral movement is where graph analytics provide the most distinctive value. A "low-probability edge" — a connection between two internal hosts that have no documented communication history — is a structurally strong anomaly. In the Akira ransomware campaign using AdaptixC2 (2025), lateral movement via SMB and named pipes was visible through Sysmon Event IDs 17 and 18 on endpoint telemetry, showing anomalous internal named-pipe connections between the beachhead system and high-value servers [Documented, per active countermeasures IR reporting]. [Documented]

RDP-based lateral movement in the same campaign showed clear peer-group anomalies in Active Directory Event ID 4624 logs: the source/destination host pair had no prior authentication relationship. The limitation is legitimate IT administration — helpdesk and system administrator RDP sessions generate substantial noise in this detection category.

**Command and Control — High.**
Beaconing is a fundamental temporal and frequency anomaly in human-centric network traffic. Human-generated network activity is stochastic and variable; automated C2 beaconing is periodic and mechanically consistent. The SUNBURST campaign attempted to defeat this with variable timing (jitter) and dormancy of 12–14 days before first contact [3]. Even so, the encoded DNS subdomains — victim-specific base32 strings under `avsvmcloud[.]com` — created a high-entropy subdomain anomaly detectable through DNS analytics [3]. [Documented]

The AdaptixC2 case (2025) demonstrated a multi-phase beaconing strategy with interval shifts from 4 seconds to 30 to 60 seconds — a multi-modal temporal distribution visible in connection interval histograms that simple threshold detection misses but frequency-distribution analysis catches. [Documented]

**Exfiltration — Very High.**
This is the most reliably detectable stage through anomaly logic. Mass data movement to external destinations is mathematically distinct from routine office traffic in most environments. The consistent use of Rclone by ransomware operators (documented in LockBit campaigns throughout 2023–2024, appearing in approximately 57% of ransomware exfiltration incidents per DFIR Report data) produces a dual anomaly: rare process execution of `rclone.exe` by SYSTEM or a service account, combined with volumetric outbound transfer to cloud storage endpoints (mega.nz, Google Drive). [Documented]

Mandiant's M-Trends 2025 documented APT41 using SQLULDR2 for database export and PINEGROVE for exfiltration to OneDrive — a data movement anomaly detectable through database audit logs combined with cloud storage egress monitoring [9]. [Documented]

The limitation at this stage is SaaS-native exfiltration: when data is exported via built-in SaaS functionality (SharePoint bulk download, Google Takeout, Salesforce report export), the network path may be entirely invisible to traditional firewall and NetFlow monitoring. Mandiant's SaaS intrusion reporting on UNC3944 is explicit that traditional network monitoring was ineffective for detecting Airbyte/Fivetran-based synchronisation to attacker-controlled cloud storage [8]. [Documented]

**Impact — Very High.**
Ransomware encryption creates a catastrophic outlier: sudden, high-velocity mass file renaming and modification across a file server is one of the strongest volumetric anomalies observable in enterprise telemetry. Shadow copy deletion via `vssadmin.exe` or `wmic` is a rare-process anomaly on user workstations and a critical signal. Black Basta campaigns consistently showed this pattern in DFIR data. [Documented]

### 3.2 Summary Table

| ATT&CK Stage | Anomaly Utility | Primary Anomaly Type | Key Limitation |
|---|---|---|---|
| Initial Access | Poor–Moderate | Geographic, rate | Valid credentials, residential proxies, distributed timing |
| Execution | Moderate–Strong | Parent-child, rare process | LOTL techniques, fileless execution, in-process abuse |
| Persistence | Moderate | Identity/access, state-change | High noise from legitimate admin; requires enrichment |
| Privilege Escalation | Moderate | Identity/access, rare event | Legitimate privilege changes create noise |
| Defense Evasion | Weak | Negative anomaly (absence) | Evasion targets the detection surface itself |
| Credential Access | High (when concentrated) | Frequency/rate | Distributed spray defeats per-tenant thresholds |
| Lateral Movement | Moderate–High | Graph/relationship, peer-group | Legitimate admin traffic overlap |
| Command and Control | High | Temporal, protocol, DNS entropy | Jitter, dormancy, protocol masquerading |
| Collection / Exfiltration | Very High | Volumetric, data movement | SaaS-native exfil bypasses network visibility |
| Impact | Very High | Volumetric, rare process | Usually detected after damage begins |

---

## 4. Evidence Register: Real-World Cases

The table below separates three evidentiary tiers. **[Documented]** means the source explicitly described the anomalous behaviour or a detection based on it. **[Inferred]** means the source documented tradecraft from which a defensible anomaly opportunity can be derived. **[Speculative]** means the detection opportunity is plausible but not corroborated by a primary source.

| Year | Incident / Actor | Primary Source | Activity Observed | Evidence Tier | Anomaly Pattern | Detection Opportunity | Key Limitation |
|---|---|---|---|---|---|---|---|
| 2020 | SUNBURST / UNC2452 | Mandiant [3] | DGA-encoded DNS subdomains under avsvmcloud[.]com; 12–14 day dormancy; HTTP C2 masquerading as Orion telemetry | [Documented] | High-entropy DNS subdomains; temporal anomaly (dormancy then periodic callback); rare external IP relative to Orion traffic | DNS entropy analytics; domain rarity scoring; proxy timing analysis | High-sophistication obfuscation; some traffic resembled legitimate Orion polling |
| 2021 | HAFNIUM / Exchange ProxyLogon | Microsoft MSTIC, Mandiant [5][7] | `UMWorkerProcess.exe` and `w3wp.exe` writing ASPX files; `w3wp.exe` spawning `cmd.exe`; China Chopper webshell execution | [Documented] | Parent-child execution anomaly; rare file write by web worker process; rare URI access | Sysmon/EDR process lineage; IIS ASPX write monitoring; rare-URI analytics | Advanced IIS modules can execute in-process, avoiding child-process anomaly |
| 2023 | Storm-0558 | Microsoft MSTIC [4] | Forged MSA tokens used to access Exchange Online / OWA; anomalous mailbox access reported by customer | [Documented] | Unusual app/protocol access path; identity anomaly (token issuer deviation) | Mailbox audit; sign-in anomalies; OWA/EWS usage baselines | If audit telemetry is absent, token-based access looks identical to legitimate access |
| 2023 | UNC3944 / Scattered Spider | Mandiant [8] | Help-desk vishing for MFA resets; MFA fatigue attacks; SIM swaps; new VM creation; SaaS reconnaissance; Airbyte/Fivetran exfiltration | [Documented] | MFA lifecycle anomalies; unusual VM creation; SaaS export volume; multiple remote admin tools | Identity control-plane monitoring; cloud audit; SaaS audit logs | SaaS-native exfiltration invisible to traditional network monitoring |
| 2023 | Storm-1283 / OAuth cryptomining | Microsoft MSTIC [6] | Compromised user created OAuth app; app deployed Azure VMs for cryptomining; GPU usage spike | [Documented] | Control-plane anomaly (app creation + VM creation by unusual principal); resource usage spike | Cloud audit; app-ownership monitoring; role-grant tracking | Requires cloud identity telemetry of sufficient granularity |
| 2023–2024 | Midnight Blizzard / Cozy Bear | Microsoft MSTIC [4] | Low-volume password spray from residential proxies; malicious OAuth apps; EWS collection; 10× volume increase in Feb 2024 | [Documented] | Weak per-tenant rate anomaly; unfamiliar sign-in properties; app abuse; cross-tenant spray pattern | Provider-level auth analytics; OAuth/app auditing; EWS usage review | Single-tenant anomaly logic cannot see distributed spray across proxies |
| 2024 | Volt Typhoon | CISA/NSA/FBI [10][11] | Valid-account use; LOLBins (`ntdsutil`, `netsh portproxy`, `wevtutil`); SOHO proxy infrastructure; multi-year persistence in critical infrastructure | [Documented] | Unusual command lines on unexpected hosts; sign-in from SOHO IPs; rare network configuration changes | Windows 4688 with command lines; PowerShell/WMI deep logging; edge device telemetry | Substantial legitimate admin overlap; CISA advisory explicitly warns against treating findings as malicious without corroboration |
| 2024 | LockBit / Rclone exfiltration | The DFIR Report [Inferred from IR pattern] | `rclone.exe` executed by SYSTEM/service account; large outbound transfer to mega.nz or cloud storage | [Documented pattern across multiple incidents] | Rare process execution + volumetric outbound anomaly | EDR rare-process; egress volume to cloud storage categories | Legitimate IT use of rclone creates false positives without contextual enrichment |
| 2024 | APT41 data theft | Mandiant M-Trends 2025 [9] | SQLULDR2 database export; PINEGROVE exfiltration to OneDrive | [Documented] | Data movement anomaly; rare database export tool; unusual cloud destination | Database audit; egress analytics; cloud storage/object logs | Large legitimate business data transfers can produce similar signals |
| 2024–2025 | DPRK IT workers / UNC5267 | Mandiant [9] | Geographic/device mismatch; multiple remote admin tools; Astrill VPN; multiple personas; laptop farms | [Documented] | Peer-group, geographic, device, and remote-admin-tool anomalies | HR + endpoint + shipping + IdP telemetry fusion | Requires non-traditional enterprise data and cross-team collaboration |
| 2025 | Akira / AdaptixC2 | Active Countermeasures IR [Referenced in Gemini research] | Multi-phase C2 beaconing (4s → 30s → 60s intervals); Firefox 20.0 User-Agent; lateral movement via SMB and named pipes | [Documented] | Multi-modal temporal anomaly; rare User-Agent signature; anomalous internal named-pipe connections | Connection-interval histogram analysis; User-Agent rarity; Sysmon Event ID 17/18 | Requires long-duration netflow collection to confirm beacon pattern |

---

## 5. Where Anomaly Detection Works and Where It Fails

### 5.1 Conditions for Strong Performance

Anomaly detection is most effective when **all four** of the following conditions are true:

1. **The baseline is stable.** Server roles with limited administrative variance, identity control planes with clean audit trails, and network paths with bounded legitimate destinations all provide tight baselines that make anomalies statistically distinct.

2. **The attack creates measurable state change.** Any action that creates a new entity, modifies a relationship, changes a rate, or moves a volume of data tends to produce a detectable signal. New VM creation, bulk file export, mass authentication failures, and web-worker process spawning all satisfy this condition.

3. **The telemetry is complete.** Parent-child execution anomalies require command-line process creation logging. SaaS exfiltration requires SaaS audit logs. Beaconing detection requires netflow or proxy log with byte counts and timing. Wherever telemetry is absent, the anomaly is invisible by definition.

4. **The anomaly is rare in legitimate traffic.** `w3wp.exe` spawning `cmd.exe` is rare on a well-managed IIS server. An MFA factor reset followed by an unfamiliar sign-in is rare for most users. Rarity is the primary driver of precision.

### 5.2 Conditions for Weak Performance

Anomaly detection degrades predictably under these conditions:

**High environmental diversity.** Environments with many legitimate administrative actions, global user populations, and frequent change windows have noisy baselines. A bulk data download is anomalous for a finance analyst and normal for a data engineering team. Without role-based peer groups and asset classification, anomaly thresholds are set too loosely to produce actionable signals.

**Valid-account intrusions.** When an attacker uses legitimately obtained credentials — through phishing, credential stuffing, or purchase from initial access brokers — the identity anomaly may be minimal or absent. Volt Typhoon's use of valid administrative accounts meant that the identity layer produced no anomaly signal at all; the only detectable deviations were in command-line arguments and network path [10][11]. [Documented]

**Living-off-the-land technique.** CrowdStrike's 2025 report documenting 79% malware-free intrusions [13] reflects a systematic attacker response to EDR-based detection: replace custom malware with native OS tools whose execution is expected in any managed environment. PowerShell, WMI, certutil, and net.exe all have high baseline prevalence. The anomaly signal is not in the tool itself but in the combination of tool + command + context + sequence — which requires richer modelling than simple process-name allowlisting.

**SaaS-native exfiltration.** When data moves via built-in SaaS features — SharePoint download, Salesforce export, Google Workspace sync — the exfiltration path may never traverse a device or network perimeter the defender controls. Mandiant's UNC3944 reporting explicitly documents that traditional monitoring was ineffective for detecting Airbyte/Fivetran-based exfiltration [8]. [Documented]

**Distributed low-and-slow attacks.** Password spray campaigns distributed across residential proxy infrastructure, as documented in the Midnight Blizzard case, defeat per-IP and per-tenant rate anomalies. The attack is visible at a provider or global level but invisible to a tenant-local SOC. This is a structural limitation of anomaly detection that is not solvable through better tuning — it requires a different architectural solution (provider-native risk detections, cross-tenant intelligence sharing).

**Baseline contamination and concept drift.** NIST SP 800-94 documented that "malicious activity can be incorporated into a normal profile" [1] — if an attacker establishes persistence quietly and operates slowly over weeks or months, the anomaly system learns the attacker's behaviour as normal. Modern research labels this *concept drift* [14][15]: as both legitimate and malicious behaviour evolve, static baselines degrade without continuous retraining and the retraining itself introduces risk that slow-changing malicious behaviour gets absorbed.

---

## 6. How Attackers Suppress Anomaly Visibility

Advanced threat actors apply systematic techniques to reduce their anomaly footprint. These are not ad-hoc measures — they reflect deliberate tradecraft evolution in response to increasing SOC and EDR maturity.

### 6.1 Distribute Activity

Midnight Blizzard's password spray used residential proxy infrastructure to distribute authentication attempts across thousands of IP addresses, ensuring no single IP, subnet, or source country exceeded per-tenant alert thresholds [4]. The attacker also targeted legacy, non-production test accounts without MFA — an environment where authentication anomalies are expected and alerting thresholds are typically set higher. [Documented]

Distribution is equally applicable to exfiltration: instead of one large transfer, split the data into many small transfers over many days, each indistinguishable from routine document access.

### 6.2 Use Native Tools and Valid Credentials

Volt Typhoon's CISA advisory describes systematic use of LOLBins (`ntdsutil`, `wevtutil`, `netsh portproxy`, PowerShell) to minimise malware presence and reduce the rarity of executed processes [10]. The attacker's chosen tool is the same tool a legitimate administrator would use; the anomaly, if it exists at all, is in the command-line arguments or network destination — but only if command-line logging is enabled. [Documented]

### 6.3 Exploit Logging Gaps

CISA and NSA guidance on Volt Typhoon explicitly states that default Windows logging configurations are insufficient — process creation logging with command-line arguments, WMI event logging, and deep PowerShell logging are not enabled by default and must be explicitly configured [10][11]. Actors aware of this can operate within the gap between what is audited and what is collected.

Actors may also actively delete telemetry. Event log clearing (`wevtutil cl`) creates a "negative anomaly" — absence of expected telemetry — but this is rarely modelled by anomaly detection systems and often surfaces only when a manual log review is performed after an incident.

### 6.4 Mimic Business Rhythm

Microsoft's Storm-0558 report included activity heatmaps showing that the threat actor operated primarily during business hours consistent with expected working patterns [4]. Temporal anomaly detection — which flags off-hours activity — is defeated by attackers who deliberately synchronise their operations with legitimate working schedules.

### 6.5 Stay In-Process

Microsoft's Exchange exploitation reporting notes that malicious IIS modules can execute entirely within the `w3wp.exe` process space, bypassing child-process spawning entirely [5]. In-memory execution techniques similarly avoid file-creation and process-creation events that endpoint anomaly detection relies on. The anomaly surface shrinks to behavioural indicators within a single process — which requires agent-based memory scanning or API-level telemetry to detect. [Documented]

### 6.6 Use Dormancy and Jitter

SUNBURST remained dormant for 12–14 days after initial installation before contacting C2 infrastructure — a deliberate delay designed to increase the temporal distance between installation and operational use, reducing the probability that any alert triggered during installation would be associated with subsequent C2 activity [3]. When beaconing commenced, variable timing (jitter) was used to defeat simple periodicity detection. [Documented]

CrowdStrike 2025 documented the fastest observed intrusion breakout time of 51 seconds — the other extreme [13]. Speed is itself an evasion strategy: a threat actor who achieves objectives before detection engineering can respond avoids the entire anomaly detection surface.

---

## 7. Telemetry Requirements

The quality of an anomaly detection programme is entirely bounded by the quality of its telemetry. An anomaly model consuming incomplete, unnormalised, or stale data produces results that reflect the data's limitations, not the environment's reality.

### 7.1 Critical Telemetry Sources by Domain

**Endpoint: EDR, Sysmon, Windows 4688, Linux auditd.**
The most important source for execution-layer anomalies. Required fields: `ProcessName`, `ParentProcessName`, `CommandLine`, `User`, `Hashes`, `IntegrityLevel`. CISA and NSA specifically recommend enabling process creation logging with full command-line arguments — without this, 4688 events provide process name but not the arguments that distinguish `PowerShell.exe -enc <encoded>` from `PowerShell.exe Get-Help` [11].

Sysmon Event IDs of particular value: ID 1 (process creation), ID 3 (network connection), ID 7 (image load), ID 11 (file create), ID 17–18 (named pipe create/connect). ID 17 and 18 are specifically useful for detecting lateral movement via named pipes, as documented in the AdaptixC2 case.

**Identity: IdP logs, Active Directory, Entra, Okta.**
Required fields: `UserPrincipalName`, `SourceIP`, `ASN`, `ISP`, `CountryCode`, `DeviceId`, `AuthMethod`, `ResultCode`, `TokenIssuerId`. Microsoft Entra's risk detection documentation is explicit that "unfamiliar sign-in properties" detections require history — the detection compares current sign-in attributes against an account's historical IP, ASN, location, device, browser, and tenant subnet baseline. New accounts and long-inactive accounts require longer learning periods before risk scoring is reliable [6].

**Network: NetFlow, Zeek, proxy, firewall, DNS.**
Required fields for C2 detection: `SrcIP`, `DstIP`, `DstPort`, `BytesSent`, `BytesReceived`, `Duration`, `ConnectionCount`, `Timing`. For DNS: `QueryName`, `ResponseCode`, `ResponseIP`, `QNAME length`, `Shannon entropy of subdomain`. DNS logs are indispensable for detecting tunneling and DGA-like behaviour; a Shannon entropy threshold of approximately 4.5 on subdomain strings is a documented heuristic for identifying encoded or high-entropy subdomains consistent with tunneling tools such as dnscat2 or iodine. [Inferred from academic research and vendor implementation documentation]

**Cloud: AWS CloudTrail, Azure Activity Logs, GCP Audit Logs.**
Required events: compute creation, IAM role grants, secret/key creation, app registrations, storage bucket policy changes. The Storm-1283 cryptomining case turned entirely on cloud audit logs capturing VM creation by an OAuth application — without those logs, the activity would have been invisible until the cloud bill arrived [6].

**SaaS: Microsoft 365 Unified Audit Log, Google Workspace Admin audit, Salesforce Event Log Files.**
Required events: file access, bulk download, export operations, OAuth app authorisations, inbox rule creation, sharing link generation, admin action changes. Mandiant's UNC3944 reporting is unambiguous: without SaaS audit logs, defenders may not discover the intrusion until the extortion note arrives [8].

### 7.2 Common Telemetry Failures

- **Parser drift.** Changes in product logging format or schema silently degrade anomaly models without changing the underlying environment. A field rename or timestamp format change can cause an anomaly model to treat all subsequent events as outliers.
- **Incomplete coverage.** Default Windows logging does not include command-line arguments. Default IIS logging does not include request bodies. Default SaaS configurations often do not enable advanced audit logging.
- **Log forwarding gaps.** Events generated on endpoints or cloud services may not reach the SIEM due to collector failures, quota exhaustion, or network issues.
- **Normalisation inconsistency.** Events from different sources expressing the same activity in different schemas make cross-source correlation and baseline comparison unreliable.

---

## 8. Detection Engineering Patterns

### 8.1 Four Effective Design Patterns

**Pattern 1: Rarity-in-Role.** Detect an event that is rare for the specific user, host class, or application tier — not rare globally. `ntdsutil` executed anywhere in the enterprise is unusual, but `ntdsutil` executed on a development workstation by a non-admin user is a reliable signal. This pattern requires per-role baselines, not estate-wide baselines.

**Pattern 2: Rate Plus Shape.** Combine counts with timing distribution, source diversity, or sequence features. A hundred failed authentication attempts from one IP is a rate anomaly. A hundred failed attempts against a hundred different accounts from a hundred different IPs within a two-hour window is a rate-plus-shape anomaly that a simple per-IP threshold misses entirely. This is the pattern required to detect distributed password spray.

**Pattern 3: State-Change Anomaly.** Detect rarely occurring control-plane changes that materially alter trust or exposure: new OAuth application registrations with mail or offline-access scopes, new privileged group membership, new VM creation by a service principal, new inbox forwarding rule for a C-level executive. These events may occur infrequently enough that even a simple "alert on first occurrence" logic produces high precision.

**Pattern 4: Hybrid Anomaly Gated by Deterministic Condition.** The most operationally practical pattern. Apply anomaly scoring only after prefiltering on a high-risk object class or path. Example: do not score all app registrations — score only app registrations where the consented scopes include `Mail.ReadWrite` or `Files.ReadWrite.All`. This constraint narrows the baseline problem before the anomaly model runs, substantially improving signal-to-noise ratio.

### 8.2 Statistical Methods

**Z-score / 3-sigma rule.**
For normally-distributed, single-variable baselines. If a host's hourly outbound byte count follows a Gaussian distribution with mean μ and standard deviation σ, a transfer generating a Z-score greater than 4 (four standard deviations above mean) represents a probability of approximately 0.003% under the null hypothesis of normal behaviour. This is a strong starting threshold for volumetric exfiltration detection.

The limitation: network traffic and user behaviour are rarely Gaussian. Bimodal distributions (low-activity weekends, high-activity weekdays) and heavy tails (occasional legitimate large transfers) cause the simple Z-score to produce high false positive rates. Seasonal decomposition or percentile-based thresholds are more appropriate for non-Gaussian distributions.

**Isolation Forest.**
Effective for high-dimensional behavioural data where each entity (user, host) is characterised by many features simultaneously. The algorithm isolates anomalies by recursively partitioning the feature space; anomalies require fewer splits to isolate because they are distinct from the majority. Critically: StandardScaler or RobustScaler preprocessing is required — unscaled features with different magnitudes cause the algorithm to favour high-magnitude features regardless of their actual anomaly-relevance. The contamination parameter (expected anomaly proportion in training data) requires calibration against environment-specific false positive rates rather than the library default of 0.1. [Documented via scikit-learn production guidance]

**UEBA / Risk Scoring.**
Rather than alerting on individual anomalies, accumulate risk scores across an entity over time. A user who generates a geographic anomaly (+5 risk points), then a rare process execution (+10), then an unusual outbound data volume (+15) reaches a threshold that triggers investigation — even though no single event crossed an alert threshold. This pattern is explicitly documented in Splunk's risk-based alerting model and Microsoft's Sentinel identity analytics.

### 8.3 Detection Logic Examples

**Distributed Password Spray (combined rate + shape):**
```
Count failed auth events (Event ID 4625 or Entra sign-in failures)
Group by: SourceIP, 15-minute window
Alert when:
  - Distinct target accounts > 20 within window, AND
  - Failure rate across entire tenant > 3× 30-day baseline, AND
  - Followed by any successful authentication within 1 hour
Enrich with: ASN category (residential proxy = elevated risk), geo-distance from user's last known location
```

**Parent-Child Execution Anomaly (web server):**
```
Alert when:
  ParentImage in ('w3wp.exe', 'UMWorkerProcess.exe', 'httpd.exe') AND
  ChildImage in ('cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
No baseline required — deterministic logic for this specific lineage
Companion: Alert on file write with ASPX/PHP/JSP extension by same ParentImage
```

**SaaS Bulk Export Anomaly:**
```
Baseline: per-user daily download volume from SharePoint/OneDrive (30-day rolling)
Alert when:
  - User download volume > μ + 4σ for that user's 30-day peer-normalised baseline, AND
  - Session shows unfamiliar sign-in properties (new ASN, new device, or new country), OR
  - Triggered within 24 hours of MFA reset event
Enrich with: data classification of downloaded files, time since last access to that document library
```

**Beaconing / DGA DNS:**
```
Baseline: per-host domain query frequency and subdomain entropy (14-day rolling)
Alert when:
  - FQDN Shannon entropy > 4.5 (subdomain portion), AND
  - Domain age < 30 days, AND
  - No prior query from this host to this domain
OR
  - Connection interval coefficient of variation (CV) < 0.15 for external IP over 6+ connections
    (low CV = high regularity = automated / beaconing behaviour)
Enrich with: JA3/JA3S fingerprint, TLS certificate age, destination IP ASN
```

---

## 9. Implementation Guidance for SOC and Detection Teams

### 9.1 Start Constrained, Not Universal

The most common failure mode in anomaly programme deployment is scope. "Deploy UEBA across the full estate and tune from there" produces an unmanageable false positive volume that burns analyst confidence before any value is realised. Start with the highest-confidence, tightest-baseline domains first:

1. **Domain controllers** — process execution anomalies, command-line rarity, authentication rate anomalies
2. **Identity providers** — MFA lifecycle changes, app consent, unfamiliar sign-in properties
3. **Cloud control planes** — VM creation, IAM role grants, secret creation, storage policy changes
4. **Internet-facing web servers** — parent-child execution, file write, URI rarity
5. **SaaS admin functions** — bulk export, inbox rule changes, OAuth application registrations

Do not expand to generic workstation UEBA until the above domains are producing actionable, tuned results.

### 9.2 Instrument Before Modelling

If process-creation logging with command lines is not enabled, parent-child and LOLBin anomaly detection will produce results of limited value. If SaaS audit logging is not centralised, exfiltration via native SaaS features will remain invisible. Telemetry gaps are not a tuning problem — they are a visibility problem that no amount of model sophistication can compensate for.

CISA and NSA's logging guidance [11] provides explicit minimum configurations for Windows event forwarding, PowerShell logging, WMI event subscription auditing, and Sysmon deployment. This guidance should be the pre-condition for anomaly programme deployment, not an afterthought.

### 9.3 Baseline by Role, Not by Estate

A finance analyst, a domain controller, a Kubernetes cluster API server, and a developer laptop do not share a meaningful behavioural baseline. Applying an estate-wide threshold to all of them produces baselines that are too loose for privileged infrastructure and too tight for dynamic development environments. The correct denominator is the peer group: users by department and seniority, hosts by role and criticality tier, services by function and external exposure.

### 9.4 Correlate Weak Signals into Entity Risk

A single anomaly is rarely sufficient for an investigation. Several correlated anomalies against the same identity, host, or application within a time window are a high-confidence incident lead. The practical implementation:

- **Identity risk accumulation:** MFA reset + unfamiliar sign-in + new OAuth consent + inbox rule creation within 24 hours → high-confidence investigation trigger
- **Endpoint risk accumulation:** Rare process execution + unusual outbound connection + archive file creation in temp directory within a session → high-confidence investigation trigger  
- **Cloud risk accumulation:** Unusual app registration + VM creation by that app + API key creation + egress to new cloud storage endpoint → high-confidence investigation trigger

### 9.5 Maintain Deterministic Rules for Known-Bad Patterns

Anomaly detection is not a replacement for deterministic rules — it is a complement. For well-understood abuse patterns where the semantics are stable and the false-positive rate is acceptably low, deterministic or signature-based rules outperform anomaly scoring:

- `w3wp.exe` spawning `cmd.exe` → deterministic alert (no baseline needed)
- `vssadmin.exe delete shadows` on a workstation → deterministic alert
- Inbox forwarding rule to external domain created outside change window → deterministic alert
- `ntdsutil` executed on a non-domain-controller → deterministic alert with role context

Reserve anomaly modelling for cases where the malicious pattern is not sufficiently distinct to express as a rule — where the *combination* of context, timing, peer comparison, and volume creates the signal rather than any single attribute.

### 9.6 Build Continuous Validation

Anomaly detection quality degrades silently. Sources of degradation include:
- Parser changes that alter field values or event structure
- New software rollouts that expand the process baseline
- New business workflows that change data movement patterns
- Seasonal events that temporarily shift all baselines
- Exception list growth that progressively excludes legitimate signals

Schedule 30-day baseline audits. Track model score distributions over time — a shift in the distribution of anomaly scores often indicates pipeline or baseline degradation rather than a genuine change in threat activity. Use purple-team exercises with known-good simulations (password spray, web-shell execution chains, bulk SaaS export, beaconing with jitter) to validate that detections still trigger as expected.

### 9.7 Treat SaaS and Cloud as First-Class Detection Domains

The architecture of modern enterprise intrusions has shifted. Mandiant's SaaS reporting documents threat actors who achieve full data theft objectives entirely within cloud and SaaS service layers — without ever installing malware, touching an endpoint in the traditional sense, or generating network traffic visible to a perimeter firewall [8]. Detection programmes built primarily on endpoint and network telemetry will have structural blind spots for these intrusions.

Cloud audit logs (CloudTrail, Azure Activity, GCP Audit) and SaaS audit logs (M365 Unified Audit, Google Workspace Admin audit) must be treated as primary telemetry sources, not supplementary ones.

---

## 10. Conclusion

The hypothesis that malicious activity creates detectable anomaly patterns is **substantially true in a bounded and operationally specific sense**. It is not a universal detection principle — it is a property that holds reliably for some attack phases and categories, and fails predictably for others.

The conditions under which anomaly-based detection is most effective are clear from the evidence: the baseline must be tight, the attack must create measurable state change, the telemetry must be complete, and the anomaly must be rare in legitimate traffic. When all four conditions hold, anomaly detection is powerful — particularly at the credential access, command and control, exfiltration, and impact stages.

The conditions under which it fails are equally clear: valid-account intrusions, living-off-the-land technique, SaaS-native exfiltration, distributed low-and-slow attacks, and environments with poor telemetry coverage all represent structural limitations that cannot be resolved through better model tuning.

Advanced threat actors — Volt Typhoon, Midnight Blizzard, UNC3944 — have systematically adapted their tradecraft to suppress anomaly visibility. They use valid credentials, native tools, residential proxies, SaaS-native functions, and carefully managed operational tempo to remain within the statistical "normal" of their target environments. This is not a future threat; it is the current operational reality documented across primary source reporting in 2023–2025.

The practical answer for detection engineering is neither "anomaly detection catches the unknown" nor "anomaly detection is too noisy to matter." It is a layered detection model in which anomaly analytics filter, prioritise, and correlate; deterministic rules confirm known-bad patterns; behavioural detections encode adversary tradecraft; and entity risk scoring accumulates weak signals into actionable cases. Provider-native risk detections (Entra unfamiliar sign-in, Defender for Cloud Apps anomaly scoring) provide cross-tenant visibility that tenant-local analytics cannot replicate.

Anomaly detection is most valuable not as a primary alerting mechanism but as a **signal-generation and investigation-prioritisation layer** — one component in a detection programme that also includes strong telemetry coverage, clean peer-group definitions, well-tuned deterministic rules, and continuous purple-team validation.

---

## 11. References

[1] National Institute of Standards and Technology. *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST Special Publication 800-94. February 2007. https://csrc.nist.gov/pubs/sp/800/94/final

[2] Chandola, V., Banerjee, A., and Kumar, V. "Anomaly Detection: A Survey." *ACM Computing Surveys*, 41(3), Article 15, July 2009. https://dl.acm.org/doi/10.1145/1541880.1541882

[3] Mandiant (FireEye). "SUNBURST Additional Technical Details." December 2020. https://www.mandiant.com/resources/sunburst-additional-technical-details

[4] Microsoft Security Response Center / Microsoft Threat Intelligence. "Midnight Blizzard: Guidance for Responders on Nation-State Attack." January 2024. https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/

[5] Microsoft Security Response Center. "HAFNIUM Targeting Exchange Servers with 0-Day Exploits." March 2021. https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

[6] Microsoft Threat Intelligence. "Storm-1283 and Storm-1286: OAuth Application Abuse." Microsoft Security Blog, 2023.

[7] Mandiant. "Responding to Microsoft Exchange Server Zero-Day Vulnerabilities." March 2021.

[8] Mandiant. "UNC3944 Targets SaaS Applications." Google Cloud Security Blog, 2023. https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications

[9] Mandiant. *M-Trends 2025*. Google Cloud Security, 2025. https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025

[10] CISA, NSA, FBI, and partner agencies. "People's Republic of China State-Sponsored Cyber Actor Living off the Land to Evade Detection." Advisory AA24-038A. February 2024. https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a

[11] CISA and NSA. "Guide to Securing Microsoft Windows 10 and Windows 11 Audit and Monitoring Events." 2024. https://www.cisa.gov/resources-tools/resources/guide-securing-microsoft-windows-10-and-windows-11-audit-and-monitoring-events

[12] Australian Cyber Security Centre. "Detecting and Mitigating Active Directory Compromises." 2023. https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-administration/detecting-and-mitigating-active-directory-compromises

[13] CrowdStrike. *Global Threat Report 2025*. 2025. https://www.crowdstrike.com/en-us/resources/reports/global-threat-report-executive-summary-2025/

[14] Shyaa, M. A. et al. "Evolving Cybersecurity Frontiers: Concept Drift and Feature Dynamics in Intrusion Detection Systems." *IEEE Access*, 2024.

[15] Bagui, S. S. et al. "Model Retraining upon Concept Drift Detection in Network Traffic Big Data." *Electronics*, 2023.
