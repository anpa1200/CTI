# Beyond the Pyramid: Why AI Makes Anomaly Detection the New Foundation of Cybersecurity Monitoring

**How large language models collapsed three layers of the classic framework — and why behavioral baselines are now the only detection that consistently survives.**

By [Andrey Pautov](https://medium.com/@1200km) — April 2026

---

## Table of Contents

1. [The Pyramid of Pain: What It Got Right](#1-the-pyramid-of-pain-what-it-got-right)
2. [What AI Changed — Layer by Layer](#2-what-ai-changed-layer-by-layer)
3. [What Sits Above TTPs Now](#3-what-sits-above-ttps-now)
4. [The Revised Model](#4-the-revised-model)
5. [Anomaly Detection: A Practitioner's Taxonomy](#5-anomaly-detection-a-practitioners-taxonomy)
   - 5.1 [Network Behavior Anomalies](#51-network-behavior-anomalies)
   - 5.2 [User and Entity Behavior Anomalies (UEBA)](#52-user-and-entity-behavior-anomalies-ueba)
   - 5.3 [Process and Application Anomalies](#53-process-and-application-anomalies)
   - 5.4 [Persistence Anomalies](#54-persistence-anomalies)
   - 5.5 [Insider Threat Behavioral Indicators](#55-insider-threat-behavioral-indicators)
   - 5.6 [Fraud and Financial Anomalies](#56-fraud-and-financial-anomalies)
   - 5.7 [AI-Specific Anomalies](#57-ai-specific-anomalies)
6. [Statistical and ML Methods for Anomaly Detection](#6-statistical-and-ml-methods-for-anomaly-detection)
7. [Building an Anomaly Detection Program](#7-building-an-anomaly-detection-program)
8. [Key Sources](#8-key-sources)

---

## 1. The Pyramid of Pain: What It Got Right

David Bianco's Pyramid of Pain (2013) solved a specific problem: it gave detection engineers a rational argument for where to spend their time. Before it, most organizations treated all indicators equally — an IP address on a blocklist received the same operational weight as a documented adversary technique. The pyramid made the cost asymmetry explicit.

The logic was clean: block an attacker's hash, they recompile. Block their IP, they rotate infrastructure. Force them to change their fundamental technique — how they dump credentials, how they establish persistence, how they move laterally — and you've imposed a cost that requires actual operational work to overcome.

```
[TTPs]                ← Most painful to change
[Tools]
[Network/Host Artifacts]
[Domain Names]
[IP Addresses]
[Hash Values]         ← Least painful to change
```

For a decade, this held. Detection engineering investment gradually shifted upward. The security industry built MITRE ATT&CK, Sigma, and detection-as-code pipelines explicitly to operationalize TTP-level detection at scale. The framework was correct for the threat landscape it described.

That landscape has changed materially.

---

## 2. What AI Changed — Layer by Layer

The pyramid's validity depends on one core assumption: that the cost of changing indicators increases as you move up the stack. AI has restructured that cost curve. Not uniformly — and not completely — but enough that three of the six layers now need to be reassessed.

### Hash Values — Worse Than Before

Nothing has changed structurally here. Hashes were always trivial to rotate, and they remain so. If anything, LLM-assisted code generation makes unique-per-target compiled artifacts more accessible, not less. The bottom layer is as fragile as it always was.

### IP Addresses and Domain Names — Roughly the Same

Infrastructure rotation remains low-cost but not zero-cost. Cloud VPS provisioning, bulletproof hosting, residential proxy networks — none of these were invented by AI. Automated infrastructure-as-code for threat actors predates LLMs. These layers remain weak detection surfaces, and that has not materially changed.

### Network and Host Artifacts — Eroding

This is where the first significant shift appears. Network and host artifacts — specific User-Agent strings, registry key names, file paths, mutex names — have historically been low-cost for defenders to detect and moderate-cost for attackers to change. Changing them required modifying the tool, which required a developer.

LLM-assisted code generation removes that friction. An actor who previously needed to spend hours modifying a C2 framework to evade a specific artifact-based detection can now describe the change in natural language and receive working code. Red team research documents functional offensive tool generation in minutes, not hours.

Microsoft's threat intelligence (2024) identified state-sponsored actors across at least 20 countries experimentally using LLMs for specific offensive tasks, including reconnaissance, social engineering content, and code assistance. The capability is in active use, not theoretical.

### Tools Layer — Partially Collapsed

This is the most significant structural change. Bianco's original argument was that forcing an actor to replace their tools was expensive: custom tooling represents development investment, operational familiarity, and institutional knowledge. An actor who loses their preferred tool loses the investment in it.

LLMs do not eliminate this cost entirely, but they substantially compress it for a specific class of tool: purpose-built, single-campaign utilities. A custom credential harvester, a lateral movement script, a data-staging utility — these can now be generated from natural language prompts, used once, and discarded. The hash will never appear in any threat feed. The code will not match any existing signature.

CrowdStrike's 2025 data offers a useful proxy signal: 79% of initial access attacks are now malware-free. This predominantly reflects credential-based intrusion and living-off-the-land techniques — trends that predate LLMs and are not primarily AI-driven. The relevance to tool-layer compression is indirect: actors who achieve initial access via stolen credentials or legitimate remote tools bypass the tools layer entirely, further reducing its detection value regardless of AI assistance. The tools layer is not dead, but it is less of a forcing function than it was.

Academic red team research and vendor reporting from 2024–2025 document the logical endpoint of tool-layer compression: malware that calls an external LLM API at runtime to generate obfuscated payload variants on each execution, producing artifacts that share no static signature with prior runs. No established signature or hash-based control covers a payload that did not exist before it was deployed. This threat model is documented in published offensive security research; confirmed production use by a named, attributed threat actor has not been independently verified in public reporting as of early 2026.

### TTPs — The Critical Case

Here the picture is genuinely complicated, and honest assessment requires separating two distinct threat models.

**AI-assisted human operators:** An actor who uses LLMs as a productivity tool for specific tasks (drafting phishing content, generating code variants, researching targets) still operates with human-defined TTPs. Their fundamental approach — how they gain initial access, how they move laterally, how they establish persistence — reflects deliberate strategic choice. TTP-based detection remains valuable here. The actor's behavior is still patterned; the AI is accelerating execution, not changing the operational method.

**Autonomous AI agents:** An AI agent that selects techniques based on environmental feedback, adapts its approach in response to detection signals, and varies its method across targets is a qualitatively different problem. If the agent can use different privilege escalation techniques for each target — choosing whichever is available given the observed environment — then TTP-level detection for privilege escalation becomes a coverage problem: you need to detect all variants, not a characteristic pattern.

Research into autonomous attack agents (PentestGPT, ReAct-based frameworks) demonstrates that adaptive technique selection is technically feasible. Documented production use by sophisticated threat actors as of early 2026 is credible but not yet extensively documented with public evidence. This is an emerging threat model, not a fully realized one.

MITRE's December 2024 update to *Summiting the Pyramid* acknowledged this directly, introducing Detection Decomposition Diagrams to map observables to behaviors and quantify evasion resistance — an explicit response to the concern that AI-driven behavioral variation was undermining TTP detection reliability.

### The Revised Cost Structure

| Layer | Pre-AI attacker cost to evade | Post-AI attacker cost to evade | Defender detection durability |
|---|---|---|---|
| Hash values | Near-zero | Near-zero | None — was always trivial |
| IP addresses | Low | Low | None |
| Domain names | Low | Low | None |
| Network/host artifacts | Low-medium | Low (LLM-assisted variant generation) | Reduced |
| Tools | Medium-high | Low for single-use tools; still high for complex frameworks | Partially reduced |
| TTPs (human-directed) | High | High | Unchanged — technique change still requires operational rework |
| TTPs (AI-agent-directed) | High | **Low** — agent selects from repertoire when blocked, no rework required | Substantially reduced: detection becomes a coverage problem (all variants) not a pattern problem |

---

## 3. What Sits Above TTPs Now

If TTP-based detection is under pressure from adaptive AI agents, the question is: what is stable? What can an adversary not easily change, even with AI assistance?

**Strategic intent.** An actor's objective — steal credentials, exfiltrate intellectual property, disrupt operations, commit financial fraud — does not change because they switched to AI-assisted tooling. Intent is stable across all variants of the attack. It is also, unfortunately, very difficult to detect directly. You infer it from the pattern of what is accessed, moved, or destroyed — which requires behavioral analysis.

**Operational tempo.** AI-assisted and autonomous attacks can operate at machine speed — but this is not a fixed property. C2 frameworks have offered configurable jitter and sleep timers for many years: an automated agent can be set to pause for a randomized interval of 8–20 minutes between commands, producing inter-event timing indistinguishable from a distracted human analyst. The tempo advantage of AI is scale and availability (24/7, parallel operations across many targets), not necessarily speed. CrowdStrike's 2024 Global Threat Report documented a record adversary breakout time of 2 minutes 7 seconds — a figure that requires significant automation — but an AI-directed campaign optimized for stealth will deliberately operate slowly. Tempo remains a detectable signal when an actor chooses speed over stealth; it fails as a detection control against one that does not.

**Resource acquisition patterns.** Before an attack begins, an actor provisions infrastructure: cloud accounts, VPS instances, domains, API keys. AI does not change how resources are acquired — only what is done with them. Patterns in infrastructure provisioning, cloud account behavior before first use, and API key issuance timing are stable detection surfaces.

**Behavioral baseline deviation.** This is the most actionable entry. Regardless of what technique an actor uses, which tool they deploy, or whether they are human or AI-directed, they are doing something that the compromised entity — a user account, a host, an application, a network segment — has not done before, or is doing at an unusual time, volume, or destination. The anomaly is more durable than lower-pyramid controls — but it is not invincible.

The limit of this durability must be stated explicitly: an AI agent that observes its own behavioral footprint and adapts to remain within the target's established baseline can defeat threshold-based anomaly detection. Slow exfiltration at the 90th percentile of historical outbound volume, lateral movement that mimics peer-group authentication patterns, and working-hours-only operation are not exotic concepts — they are documented in advanced red team tooling and academic research on adversarial UEBA evasion. Against a sophisticated AI agent explicitly designed to profile and operate within normal behavioral envelopes, anomaly detection is a higher bar than signature detection, not an insurmountable one.

This is why anomaly detection has moved from the top of a wish list to the center of a realistic detection program — and why its limits matter as much as its strengths.

---

## 4. The Revised Model

The Pyramid of Pain remains a useful framework for understanding *why* different detection investments have different durability. It does not need to be discarded — it needs to be extended.

A practical revision for the AI age looks like this:

```
══════════════════════════════════ ANALYTICAL CONTEXT (not direct detection signals)
[Strategic Intent / Mission]       ← Inferred from behavioral pattern; not observable directly
[Operational Tempo]               ← Distinguishes human vs. automated actors when not jittered
══════════════════════════════════ BEHAVIORAL DETECTION (direct, durable)
[BEHAVIORAL BASELINE DEVIATION]   ← Most durable direct signal; defeats tool and TTP variation
══════════════════════════════════ AI compression boundary
[TTPs]                             ← Durable for human-directed; low attacker cost for AI agents
[Tools]                            ← Substantially reduced for single-use tooling
[Network/Host Artifacts]           ← Eroding: LLM variant generation lowers attacker cost
[Domain Names]                     ← Unchanged
[IP Addresses]                     ← Unchanged
[Hash Values]                      ← Unchanged (was always fragile)
```

The critical insight: the AI compression boundary sits between the tools layer and the TTP layer. Everything below it is now cheaper for attackers than it was in 2013. Everything above the boundary retains its original cost structure for human-directed attacks — and behavioral baseline deviation sits above all of it because it detects *the gap between what was normal and what is happening now*, regardless of which tool or technique produced that gap.

This durability is real and material, with a caveat that belongs in any honest treatment: it holds against actors who are not explicitly modeling and adapting to the defender's behavioral baseline. Against a sophisticated AI agent designed to operate within normal behavioral envelopes — the adversarial UEBA evasion problem — behavioral detection becomes a cat-and-mouse problem rather than an architectural anchor. This scenario is documented in red team research and not yet prevalent in confirmed production intrusions as of early 2026; it is the direction the threat is moving, not where it has fully arrived.

This does not mean signature-based and TTP-based detection should be abandoned. They catch the majority of less sophisticated actors who are not using AI assistance. But the detection investment that survives the widest range of threat actors — including AI-assisted ones — is behavioral anomaly detection.

---

## 5. Anomaly Detection: A Practitioner's Taxonomy

Anomaly detection is not a single technique — it is a category of detection that spans multiple domains, data sources, and statistical approaches. The following taxonomy covers the full operational range, from network traffic to insider threat to fraud to AI-specific behavioral signals.

---

### 5.1 Network Behavior Anomalies

Network anomalies detect deviation from established traffic patterns. They are particularly valuable because they operate below the application layer — even encrypted traffic has behavioral characteristics that do not require decryption to analyze.

**C2 Beaconing**

Command-and-control beaconing is among the most reliable network anomalies. Malware that phones home on a schedule produces statistical regularity in connection intervals that legitimate traffic does not. Key signals:

- **Periodicity:** Fixed-interval connections (e.g., every 60 seconds ± 2 seconds) with low jitter. Legitimate user-driven traffic is not periodic.
- **Byte volume consistency:** C2 heartbeats transmit small, consistent payloads. High consistency of outbound byte count per connection is anomalous.
- **Destination consistency:** Repeated connections to a single external IP or domain that has no prior relationship with the host.
- **JA3/JA3S fingerprinting:** TLS handshake characteristics that can identify a C2 framework family even when payload content changes. *Caveat: JA3 fingerprint manipulation has been trivially achievable since at least 2020 via Cobalt Strike malleable C2 profiles and open-source randomization libraries; it is a reliable signal for commodity malware, not a durable control against a technically capable actor. JARM (server-side TLS fingerprint) is a complementary and somewhat more robust signal for identifying C2 infrastructure.*

Detection approach: Isolation Forest on (connection interval variance, byte volume variance, unique destination count) per source host over a rolling 24-hour window. The alerting threshold for connection interval regularity must be derived empirically from your environment — characterize the coefficient of variation distribution of legitimate periodic processes (NTP polling, certificate validation, update clients, heartbeat APIs) before setting any threshold. A single value does not transfer across environments; an uncalibrated threshold will drown analysts in false positives from legitimate automation within days of deployment.

**DNS Anomalies**

DNS is both a rich telemetry source and a frequent abuse vector.

- **DNS tunneling:** Unusually long query strings, high query volume to a single domain, high entropy in subdomain labels (encoded data looks random), queries for uncommon record types (TXT, NULL) to the same domain.
- **DGA (Domain Generation Algorithm) domains:** High-entropy domain names, short TTLs, no prior history, NXDOMAIN responses in bulk — an infected host resolving dozens of failed domains per minute is a DGA beacon.
- **Newly registered domains:** First-seen domain in egress traffic, registered within 30 days, with no established reputation. Not malicious alone, but a risk multiplier when combined with other signals.
- **Internal DNS deviation:** A host that suddenly begins resolving internal hostnames it has never queried before may be conducting reconnaissance.

**Lateral Movement**

Lateral movement leaves network traces that deviate from normal host-to-host communication patterns.

- **New peer connections:** Host A connecting to Host B for the first time, particularly if both are workstations (workstations rarely initiate connections to each other in healthy environments).
- **Authentication port scanning pattern:** Sequential connection attempts to SMB (445), RPC (135), WinRM (5985/5986), or RDP (3389) across multiple internal hosts from a single source within a short window.
- **East-west traffic volume spike:** An internal host that suddenly begins generating significantly more internal traffic than its 30-day baseline warrants investigation regardless of what ports are involved.

**Data Exfiltration**

Volume-based exfiltration anomalies are among the most reliable signals available.

- **Outbound byte volume spike:** Total outbound bytes from a host or user in a session exceeding the 99th percentile of their historical baseline.
- **Destination diversity compression:** A host that normally sends data to many destinations (web browsing) suddenly sending large volumes to a single destination is anomalous.
- **Off-hours large transfer:** High-volume outbound transfer occurring between 22:00–05:00 from a host whose baseline shows no such activity.
- **Cloud storage destinations:** First-time upload to a personal cloud storage service (Dropbox, Mega, Google Drive personal) from a corporate endpoint.

---

### 5.2 User and Entity Behavior Anomalies (UEBA)

UEBA establishes per-entity behavioral baselines and alerts on deviation. The entity can be a user account, a service account, a host, or an application. The baseline must be per-entity — a global threshold misses the signal when a normally high-volume user increases further, and fires false positives on normally low-volume accounts doing anything at all.

**Authentication Anomalies**

- **Impossible travel:** Successful authentication from Location A, followed within two hours by authentication from Location B where the physical travel time between A and B exceeds two hours. A geolocation check on sequential successful logins can catch credential compromise even when MFA has been bypassed. *Bypass: residential proxy services and VPN exit nodes in the target's city defeat this control by placing the attacker's apparent location locally. Impossible travel is a high-confidence signal when triggered; its absence does not indicate no compromise.*
- **New device or new location:** First-time successful authentication from a device fingerprint or geographic location not seen in the prior 30-day baseline. Low confidence alone; high confidence when combined with privileged access or sensitive data access.
- **Off-hours authentication:** Authentication occurring in an hour-bucket that has zero or near-zero historical frequency for this account. Service accounts authenticating at 03:00 when their baseline shows activity only between 08:00–18:00 is a classic post-compromise signal.
- **Authentication velocity:** Successful authentications across multiple systems within a short window — an account authenticating to 15 different internal systems within 10 minutes is consistent with lateral movement, not normal user behavior.
- **MFA bypass patterns:** Authentication succeeding with single factor when MFA is normally required, or anomalous MFA fatigue patterns (many push notifications in rapid succession followed by approval).

**Privileged Account Behavior**

Privileged accounts (domain admins, service accounts, cloud IAM roles) have tighter behavioral baselines than regular users and therefore produce higher-confidence anomaly signals.

- **First-time privileged action:** A user account performing a privileged action (group modification, GPO change, shadow copy deletion) that has never appeared in their history.
- **Privilege escalation without change ticket correlation:** Privilege escalation events that do not correspond to an open change management ticket are anomalous in environments that enforce this workflow.
- **Service account interactive logon:** A service account (svc_*, *-sa, *$) authenticating interactively rather than as a service is a significant anomaly — service accounts do not have humans logging in with them.

**Data Access Anomalies**

- **Unusual resource access:** A user accessing a file share, database, or SharePoint site they have never accessed in the prior 90 days, particularly if the content is categorized as sensitive.
- **Bulk access:** A user accessing an unusually high number of distinct files or records within a session — consistent with data staging or exfiltration preparation. Baseline the per-user daily distinct-object-access count and alert on 99th percentile exceedance.
- **Access outside role:** A marketing user accessing engineering source code repositories, or an HR user accessing financial system data, may indicate a compromised account being used for reconnaissance.

---

### 5.3 Process and Application Anomalies

Process-level anomalies detect deviation in how software behaves on endpoints. They are particularly valuable for detecting living-off-the-land techniques, where the tool is a legitimate OS binary.

**Parent-Child Relationship Deviation**

Every process has an expected parent process in a healthy environment. Deviations are high-confidence signals:

- Web server process (`w3wp.exe`, `nginx`, `tomcat`) spawning a command interpreter (`cmd.exe`, `powershell.exe`, `bash`) — web shell execution.
- Office application spawning a network-capable process (`powershell.exe`, `mshta.exe`, `wscript.exe`) — macro or exploit execution.
- System process (`svchost.exe`, `lsass.exe`) spawning an unexpected child — process injection or hollowing.
- Any process spawning from an unusual path (`C:\Users\`, `C:\ProgramData\`, `C:\Windows\Temp\`) — staging or dropper execution.

**API Call Sequence Anomalies**

At the EDR telemetry level, the sequence of system API calls made by a process is a behavioral signature that survives binary changes. Credential dumping tools — regardless of their name, hash, or vendor — must call specific combinations of Windows APIs: `OpenProcess` with memory-read rights on `lsass.exe`, followed by `ReadProcessMemory`. No legitimate administrative tool has this sequence as its normal operation.

**Command-Line Argument Anomalies**

Legitimate use of `powershell.exe` with `-EncodedCommand` and `-ExecutionPolicy Bypass` and `-NonInteractive` simultaneously is rare for normal administration and common for post-exploitation. Building a baseline of normal command-line argument combinations per parent process allows detection of deviation without relying on specific strings.

**Execution from Anomalous Paths**

Executable files running from user-writable paths (`Downloads`, `AppData\Roaming`, `Temp`) are anomalous in environments where software is deployed from managed paths. This detection is noisy without a baseline — many legitimate installers unpack to temp — but filtered to non-installer processes it has high fidelity.

**Cloud and Container Process Anomalies**

Container and Kubernetes environments introduce process anomaly categories that do not map to Windows endpoint detection:

- **DaemonSet abuse:** A DaemonSet scheduled outside of known namespaces or with a container image not in the approved registry is a persistence and lateral movement primitive. DaemonSets run on every node; a malicious one provides access to all cluster hosts simultaneously. Baseline: what DaemonSets exist, in which namespaces, with which images — any new entry warrants immediate review.
- **Sidecar injection into running pods:** Injecting a container into an existing pod at runtime bypasses image admission controls. The behavioral anomaly is a running pod that has more containers than its original spec defined, or a container whose image was not present at pod creation time.
- **Unexpected `kubectl exec` into production pods:** Interactive shell sessions into production pods are rare in disciplined environments. Any `kubectl exec` into a non-debug pod, particularly in production namespaces, from a user account that does not normally perform this action, is a significant anomaly. Most SIEMs do not parse Kubernetes audit logs by default — this detection requires explicit pipeline configuration.
- **Pod security context escalation:** A pod created with `privileged: true`, `hostPID: true`, or `hostNetwork: true` that is not in the pre-approved privileged workload list. These flags provide near-complete access to the underlying node and are not required for normal application workloads.

---

### 5.4 Persistence Anomalies

Persistence mechanisms are a particularly high-value detection category because an actor cannot leave without establishing persistence, and persistence almost always leaves a detectable artifact. The anomaly angle: not whether a persistence mechanism exists, but when it was created, by what process, and whether the creating process has done this before.

**Scheduled Task and Service Anomalies**

- **Creation outside maintenance windows:** Scheduled tasks or services created at 03:00 by a non-administrative process have no legitimate explanation in most environments.
- **Creation by anomalous parent:** A scheduled task created by `powershell.exe` spawned from `winword.exe` is not a backup job.
- **First-time creator:** A user account or host that has never created a scheduled task creating one for the first time — particularly if combined with an off-hours signal.
- **Task pointing to temp path:** Any scheduled task whose executable path is in a user-writable directory is anomalous.

**Registry Run Key Anomalies**

- **New Run key entry:** A new entry in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or the equivalent HKLM key is a persistence signal. Not all Run key entries are malicious — legitimate software uses them — but a first-time entry created by an unexpected process at an anomalous time warrants investigation.
- **Run key pointing to encoded command:** A Run key value containing `powershell -enc` or a path to a temp file is high-confidence malicious persistence.

**C2 Beacon Timing as Persistence Indicator**

An established C2 beacon is a form of active persistence. The network anomaly (§5.1) and the persistence category overlap here: a host that begins periodic outbound connections to a new external destination at a fixed interval, and continues this pattern across multiple days, is maintaining an active C2 channel. The multi-day continuity is the persistence signal.

**Startup Folder and Boot Sector**

- New files in Windows startup folders (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) created by non-administrative processes.
- Boot sector or MBR modification events — rare in legitimate operation, high-confidence when they occur.

---

### 5.5 Insider Threat Behavioral Indicators

Insider threats are among the hardest problems in behavioral detection because the actor has legitimate access and their baseline is by definition the insider's normal behavior. Detection requires multi-dimensional signals that individually are ambiguous but collectively are consistent with preparation for malicious action.

**Pre-Departure Data Staging**

The most well-documented insider threat behavioral pattern: an employee who intends to leave (voluntarily or after receiving notice) and is taking intellectual property with them.

- **Unusual archive creation:** Rapid creation of ZIP, RAR, or 7z archives from document repositories.
- **USB or personal cloud upload:** First-time or higher-than-baseline upload to a personal cloud service or removable media, particularly of files from sensitive repositories.
- **Bulk download from internal systems:** Downloading a significantly higher volume of files from SharePoint, Confluence, or internal file shares than the user's 90-day baseline.
- **After-hours activity spike:** An employee who normally works 09:00–17:00 accessing internal systems late at night in the weeks before their departure date.
- **HR signal correlation:** When HR data indicates resignation, performance review, or disciplinary action, prior-week data access anomalies should be re-evaluated. Mature insider threat programs correlate HR system events with DLP and access log data as a risk multiplier for existing anomaly signals — not as standalone triggers.

**Privileged Insider — System Administrator**

The most dangerous insider is one with legitimate administrative access. Their "normal" behavior includes many privileged actions, making baseline deviation harder to detect.

- **Accessing accounts outside their scope:** A Windows system administrator accessing cloud IAM consoles, financial systems, or HR databases outside their normal operational area.
- **Disabling audit logging:** A sysadmin disabling event log forwarding or modifying SIEM collection configurations without a change ticket is a serious signal.
- **Creating accounts or backdoors:** New user account creation, particularly for accounts with administrative privileges, outside normal provisioning workflows.
- **Accessing terminated employee accounts:** Any authentication or use of a disabled or terminated account's credentials.

**Behavioral Drift**

Long-term behavioral drift is subtler than acute indicators. An employee whose data access pattern gradually expands to include more sensitive repositories over weeks may be conducting slow reconnaissance. Statistical drift detection — measuring how much an entity's behavior has shifted from its 90-day baseline over rolling 30-day windows — catches this where threshold-based rules cannot.

---

### 5.6 Fraud and Financial Anomalies

Financial and fraud anomalies apply to both external attackers who have compromised accounts and insider actors who abuse financial system access. The detection surface is different from endpoint detection: the data is transaction records, API logs, and access patterns from financial systems rather than endpoint telemetry.

**Account Takeover Indicators**

- **Credential use from new device and location:** Successful authentication from an unrecognized device fingerprint combined with a geographic location not seen in the prior 60-day history. On its own, this is a flag. Combined with a subsequent financial transaction, it approaches high confidence.
- **Password reset followed immediately by transaction:** The sequence reset → login → high-value transaction within minutes is a classic account takeover pattern. Legitimate users who reset passwords typically have a re-familiarization period.
- **Session characteristics mismatch:** A user whose historical sessions use a specific browser and OS suddenly authenticating from a different platform (particularly a headless browser or automation fingerprint) suggests credential use by a different actor.

**Transaction Anomalies**

- **New payee or destination account:** First-time transaction to a bank account or wallet address not seen in the prior 90 days, particularly for high-value amounts. New payee + new geography + off-hours = high confidence.
- **Amount pattern break:** A user whose transactions are normally below $5,000 suddenly initiating a $50,000 transfer. Per-user transaction amount distribution deviation, not a global threshold.
- **Velocity increase:** Transactions per hour significantly above the user's historical baseline — consistent with automated fraud tools cycling through compromised accounts.
- **Withdrawal timing:** Financial API withdrawal calls at hours with near-zero historical frequency for this account, at volume exceeding the 95th percentile.

**Business Email Compromise (BEC) Behavioral Signals**

BEC attacks manipulate financial processes through social engineering. The technical detection surface is in email and financial system behavior:

- **Email rule creation:** A new inbox rule that forwards emails matching financial keywords to an external address.
- **Finance workflow deviation:** A payment request processed outside normal approval workflow, or approval by an account that does not normally authorize payments.
- **Urgency-plus-new-payee pattern:** A payment request that is both time-pressured and involves a new payee should trigger additional verification workflow, and the absence of that verification is a process anomaly.

---

### 5.7 AI-Specific Anomalies

AI systems in production environments introduce a new detection surface. As organizations deploy LLM-based applications, AI agents, and copilot tools, these systems become both targets and potential vectors. Anomaly detection for AI-specific threats is an emerging field — methodologies are less mature than the categories above, but the threat surface is real and growing.

**Prompt Injection Patterns**

Prompt injection — the manipulation of an LLM's behavior through crafted inputs — is the dominant AI application vulnerability as of 2025. OWASP's LLM Top 10 (2025 edition) ranks prompt injection as the top risk. This is a categorical risk prioritization based on expert consensus about attack surface exposure, not an empirical production deployment survey; OWASP does not conduct the kind of sampling that would produce a deployment prevalence percentage.

Detection approach:
- **Instruction override patterns:** Input strings containing phrases like "ignore previous instructions," "disregard your system prompt," "you are now," or jailbreak template patterns. A rule engine flagging these in user inputs to LLM endpoints is the baseline.
- **Anomalous output length or structure:** If an LLM's normal outputs are 100–500 tokens and a session produces 5,000-token outputs, something unusual triggered the model. Volume anomaly on response length is a coarse but useful signal.
- **Cross-session instruction leakage:** An LLM agent that begins referencing information from another user's session has been successfully confused by injection.

**Indirect Prompt Injection via Data**

More sophisticated than direct injection: malicious instructions embedded in documents, web pages, or data that an AI agent retrieves and processes. The agent follows instructions embedded in the external content, not the user's original prompt.

Detection approach:
- Monitor AI agent tool call sequences. An agent that reads a document and then immediately calls an unusual tool (sends email, makes API call, accesses external URL) when that sequence is not part of the normal workflow for this document type warrants review.
- Behavioral baseline on what tools an AI agent calls per task type. Deviation from the expected tool sequence is an anomaly signal.

**Automated Attack Tempo**

AI-assisted attacks operate at speeds that human attackers cannot sustain. This is detectable:

- **Sub-second decision cycles:** A sequence of authentication → discovery → lateral movement → data access compressed into seconds rather than minutes. Human attackers read output. Automated agents do not.
- **Consistent inter-action timing:** Human operators have variable latency between commands. Automated agents have near-constant latency. The coefficient of variation on inter-event timing in an active session can distinguish human from automated operation.
- **24/7 activity without temporal pattern:** Human threat actors have working hours (even state-sponsored actors show diurnal patterns in documented campaigns). An intrusion session that runs continuously for 72 hours without any temporal pattern is consistent with automated operation.

**LLM API Abuse**

For organizations that provide LLM API access:
- **Anomalous query rate:** API usage significantly above a tenant's historical baseline, particularly for queries that extract structured data (consistent with automated scraping or reconnaissance).
- **Token consumption spikes:** Bulk token consumption inconsistent with normal usage pattern — an account that normally uses 10,000 tokens/day consuming 500,000 is anomalous.
- **System prompt extraction attempts:** Repeated queries crafted to elicit the system prompt or model configuration — detectable by pattern and by the behavioral clustering of queries that circle the same topic from multiple angles.

**Adversarial UEBA Evasion — The Honest Limit**

Any practitioner deploying behavioral detection should understand the evasion model they are defending against, not just the detection model. A sophisticated AI agent can defeat behavioral anomaly detection through the following approaches, which are documented in red team research and not exotic:

- **Slow exfiltration at sub-threshold rates:** Operating at or below the 90th or 95th percentile of a user's historical outbound volume, distributing exfiltration across multiple sessions over days or weeks. No single session triggers a volumetric threshold.
- **Peer-group mimicry:** An AI agent that can read documentation about the target's organizational structure, normal working hours, and peer-group access patterns can calibrate its behavior to fall within normal ranges for the compromised account's role.
- **Working-hours operation:** Restricting all activity to hours with historical precedent for the compromised account eliminates off-hours signals entirely.
- **Gradual baseline manipulation:** Slowly increasing access volume over weeks, allowing the rolling baseline to incorporate the elevated activity as new normal before the exfiltration threshold is crossed — the adversarial equivalent of the boiling frog.

These evasion techniques require either significant operational sophistication or AI-assisted profiling of the target environment. They are not the dominant attack pattern today. They represent where the threat is moving. Detection engineering that does not account for this trajectory will be caught unprepared when the techniques proliferate.

The practical response is multi-signal detection: volumetric anomaly, timing anomaly, destination novelty, and peer-group deviation measured simultaneously. An actor who defeats one dimension of detection is more likely to fail a correlated multi-signal alert. No single behavioral signal is robust in isolation against an adversary who knows it exists and is adapting against it.

---

## 6. Statistical and ML Methods for Anomaly Detection

Different anomaly types require different statistical approaches. Choosing the wrong method produces either excessive noise (too many false positives) or missed signals (too many false negatives).

| Method | Best for | Limitation |
|---|---|---|
| **Z-score** | Normally distributed metrics (login count, file access count) | Fails on skewed data; outlier-sensitive baseline |
| **Modified Z-score (MAD)** | Skewed distributions with outliers (byte volumes, transaction amounts) | Requires median calculation; less intuitive to tune |
| **Isolation Forest** | Multidimensional anomaly detection (C2 beaconing: periodicity + volume + destination) | Black-box; naïve implementations with minimal feature sets produce false-positive rates that make the system operationally unusable within days of deployment — feature engineering, tuning against environment-specific traffic, and periodic retraining are mandatory, not optional |
| **LSTM / Autoencoder** | Sequential and time-series data (user session sequences, process API call sequences) | Requires significant training data; expensive to maintain |
| **Statistical process control** | Continuous monitoring with control limits (packet rate, authentication rate) | Assumes stable baseline; sensitive to concept drift |
| **Peer group analysis** | Comparing an entity to its behavioral peer group (similar job roles, same subnet) | Requires meaningful peer group definition |

**Practical guidance:**

For most detection engineering teams, the right starting point is not ML — it is per-entity percentile baselines with rolling lookback windows. The pattern:

```
1. For entity E, compute metric M over baseline window (30–90 days)
2. Compute the 95th percentile of M per entity
3. Alert when current M for entity E exceeds their own 95th percentile by factor F
4. Tune F based on observed false-positive rate
```

This is not sophisticated statistics, but it produces per-entity thresholds that adapt to different behavioral scales, which is the most important property of an anomaly detection system. A global threshold treats the analyst who legitimately downloads 10,000 files per day the same as the employee whose normal download count is 50.

Add ML methods for specific high-value detection categories (C2 beaconing, user session sequence modeling) after the percentile baseline system is operational. Building ML models before you have reliable feature pipelines and baseline data is the most common anomaly detection failure mode.

**Feature engineering requirements for ML-based anomaly detection:**

Raw log data from enterprise telemetry pipelines (UDM/Chronicle, Sentinel, Splunk) is not usable as direct Isolation Forest input. Three categories of preparation are mandatory before any model produces trustworthy output:

- **Feature scaling:** Isolation Forest is sensitive to scale differences between features. Connection interval variance (milliseconds) and distinct destination count (integer 1–500) are incomparable without standardization. Apply StandardScaler or RobustScaler (preferred for skewed security metrics) before training. Unscaled features produce trees that partition almost exclusively on the highest-magnitude dimension, reducing the model to a near-univariate detector.

- **Noise and irrelevant feature removal:** Enterprise UDM log records contain dozens of fields; most are irrelevant or redundant for a specific detection problem. Feeding raw multi-field records into an Isolation Forest without dimensionality reduction produces models dominated by noise dimensions. For C2 beaconing detection, feature set should be engineered to roughly: `[interval_cv, bytes_per_conn_cv, unique_ext_dest_count, session_duration, query_type_entropy]`. Fields like `principal.hostname` or `target.process.file.path` are not features — they are identifiers.

- **Contamination rate calibration:** Isolation Forest's `contamination` parameter assumes a fraction of training data is anomalous. In a pre-compromise baseline, contamination is near-zero; in an enterprise log stream sampled broadly, it may be non-negligible. Setting `contamination=auto` without inspecting the assumed anomaly fraction produces unreliable threshold placement. Validate against a labeled holdout set before production deployment.

---

## 7. Building an Anomaly Detection Program

The taxonomy above describes what to detect. The harder operational question is in what order, with what infrastructure, and against what data sources.

**Start with the highest signal-to-noise categories first.**

The following order reflects a practical deployment sequence based on data availability, detection fidelity, and operational impact:

1. **Authentication anomalies** — most organizations already have authentication logs, the data model is well-understood, and impossible travel / off-hours / new-device signals have low false-positive rates once per-entity baselines are established.

2. **Network beaconing** — DNS and NetFlow/firewall logs are widely available. Periodicity detection on connection intervals has high fidelity for C2 identification. This catches commodity malware and more sophisticated actors alike.

3. **Data volume anomalies** — per-user and per-host outbound byte volume against a rolling baseline. This is the most reliable exfiltration signal and catches both external and insider threats.

4. **Privileged account behavior** — service accounts and admin accounts have tight behavioral baselines, so anomalies are high-confidence. Deploy after authentication anomaly detection because the data is often the same pipeline.

5. **Process and parent-child anomalies** — requires EDR telemetry with sufficient coverage. High fidelity when deployed, but requires endpoint agent deployment at scale.

6. **Financial and fraud anomalies** — requires integration with financial system APIs or transaction logs. Narrow detection surface but very high value per alert.

7. **AI-specific anomalies** — requires instrumentation of LLM application endpoints. Immature field; start with rule-based prompt injection detection before attempting behavioral baseline on AI agent tool calls.

**The baseline requirement is non-negotiable — and not free.**

Anomaly detection without a baseline is just threshold-based alerting with extra steps. Every anomaly detection program requires:

- Minimum 30 days of historical data before alerting (90 days for high-variance entities)
- Per-entity baselines, not global thresholds
- Regular baseline refresh (see concept drift below)
- Explicit exclusion of known-bad data from baseline training (if a host was compromised during the baseline period, its anomalous activity becomes the baseline)

The infrastructure implications are often underestimated. A 90-day per-entity behavioral baseline across an enterprise with 50,000 users, 100,000 endpoints, and dozens of SaaS applications generates hundreds of terabytes of normalized telemetry. Platforms like Google SecOps (Chronicle) or Microsoft Sentinel with UEBA modules handle this at the data-plane level — but the query compute cost of recalculating baselines on a rolling window, running entity-resolution to deduplicate identities across systems, and joining behavioral features at query time for correlation alerts is substantial. Organizations that attempt to build per-entity baselines on general-purpose SIEM infrastructure without dedicated analytics infrastructure frequently discover that the baseline queries saturate compute quotas before the detection logic runs. Understand the storage and compute commitment before committing to per-entity baselines at scale.

**Program failure modes — the ones that actually kill anomaly detection deployments:**

*Concept drift.* Legitimate behavior changes over time: a developer who takes on an architect role changes their access patterns; a seasonal business sees volume spikes that look like exfiltration. A baseline computed from January data will fire false positives on normal March behavior if not refreshed. Drift is cumulative — a static baseline degrades continuously. The practical requirement is a rolling baseline window (typically 30–90 days) that advances with time, not a snapshot trained once at deployment. Without automated retraining, the false-positive rate increases monotonically and analysts will begin suppressing detections.

*Baseline poisoning during compromise.* An actor who operates slowly and within normal behavioral ranges during the baseline period trains the system to treat their malicious activity as normal. This is not a theoretical concern — advanced persistent access campaigns that prioritize stealth over speed can achieve exactly this. Mitigations include: establishing baselines before access is granted (for new entities), baselining against peer groups rather than only historical self, and treating the baseline period as itself requiring monitoring rather than assuming it is clean.

*The cold-start problem.* New users, new hosts, new services, and new cloud accounts have no baseline. The common failure is applying global thresholds to new entities — which either misses everything (global threshold too high for a new low-volume account) or fires constantly (global threshold too low for a new high-volume entity). Solutions: peer-group bootstrapping (assign a new account to a behavioral peer group and inherit that group's baseline), mandatory observation periods before sensitive access is permitted, and separate detection rules for new entities that focus on categorical rather than volumetric signals.

*Alert fatigue as a systemic failure.* A detection program that generates more alerts than analysts can triage is not a detection program — it is a suppression factory. Every suppressed rule is a permanent blind spot. The organizational failure mode is measuring success by detection coverage (number of rules deployed) rather than detection quality (percentage of alerts that represent real findings). Per-rule precision tracking and automatic suppression flagging (rules where >90% of alerts are closed as false positive within 7 days) are operational requirements, not enhancements.

**Alert quality over alert volume.**

The failure mode for anomaly detection programs is alert fatigue. An anomaly detection system that generates 500 alerts per day is not useful regardless of how many true positives it contains. Target:

- Per-rule false positive rate below 10% within 60 days of deployment
- Each alert tells the analyst what the normal baseline was, what the current observation is, and by how much it deviated
- Alerts link to historical context: what was this entity doing 30 days ago, and how does that compare?

Without this context in the alert, analysts cannot triage efficiently and will disable or suppress the detection.

**The adversarial ML frontier — model blind spots.**

When defenders use ML to detect anomalies, sophisticated attackers use ML to find the model's blind spots. This is not a hypothetical — it follows directly from the same capability that enables AI-assisted offense. An adversary with access to representative samples of an organization's traffic (via initial reconnaissance, open-source intelligence, or industry baseline data) can train a surrogate model of the defender's detection system and probe it for regions of the feature space that produce no alert.

The practical consequences:

- A behavioral baseline that was trained on clean data and never updated becomes a fixed target. An attacker who knows the model type, training window, and feature set can craft behavior that lies in low-anomaly regions of that model.
- Isolation Forest, LSTM autoencoders, and percentile baselines are all published, well-understood algorithms. The defender's selection of method is not secret. What remains secret is the specific baseline state — which changes as legitimate behavior evolves.
- The asymmetry: defenders retrain on a schedule (weekly, monthly); attackers can probe continuously. A model that is stale by two months has a known attack surface.

Mitigations are operational, not algorithmic: randomize threshold presentation (do not expose alert triggers in any interface that attackers could observe), rotate detection logic rather than maintaining static rulesets, and maintain detection controls that are not ML-based in parallel — because a rule that matches a specific process name or API sequence cannot be evaded by operating in the wrong region of a feature space.

---

## 8. Key Sources

**AI Threat Behavior**
- Microsoft Security, *Staying Ahead of Threat Actors in the Age of AI*, February 2024
- Google Threat Intelligence Group, *AI Threat Actor Tracking*, 2024–2025
- CrowdStrike, *Global Threat Report 2025*
- CISA/NSA/NCSC/ASD, *Joint Guidance: Cybersecurity of AI Systems*, 2024
- OpenAI, *Disrupting malicious uses of AI by state-affiliated threat actors*, February 2024

**Detection Framework**
- David Bianco, *The Pyramid of Pain*, 2013 — [detect-respond.blogspot.com](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- MITRE CTID, *Summiting the Pyramid v3.0*, December 2024 — [ctid.mitre.org](https://ctid.mitre.org/blog/2024/12/16/summiting-the-pyramid-bring-the-pain/)
- MITRE ATT&CK, *Enterprise Matrix v15+* — [attack.mitre.org](https://attack.mitre.org)

**Anomaly Detection Methods**
- OWASP, *LLM AI Security & Governance Checklist 2025* — [genai.owasp.org](https://genai.owasp.org)
- Academic surveys on C2 beaconing detection via periodicity and statistical analysis are published across IEEE S&P, USENIX Security, and NDSS proceedings; no single canonical reference is cited here — practitioners should search for current empirical results before selecting and calibrating detection methods.
- NIST, *Guide to Intrusion Detection and Prevention Systems (IDPS)*, SP 800-94

**UEBA and Behavioral Analytics**
- Exabeam, *UEBA Explainer and Primer* — [exabeam.com](https://www.exabeam.com)
- Gartner, *Market Guide for User and Entity Behavior Analytics*, 2024

---

*Evidence base: public threat intelligence and vendor reporting through April 2026. Detection approaches described are illustrative; all thresholds and baseline parameters require calibration for your specific environment before production deployment.*

*Classification: Open source / Unclassified.*

*For corrections or technical questions: [Medium @1200km](https://medium.com/@1200km)*
