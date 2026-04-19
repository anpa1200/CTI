# Malicious Activity as a Statistical Signal: A Detection Engineering Analysis of Anomaly-Based Detection

**A comprehensive, evidence-based examination of the hypothesis that suspicious and malicious activity produces measurable deviations from normal behaviour — with documented examples from real APT campaigns, specific log sources, security device detection capabilities, and detection engineering patterns.**

By [Andrey Pautov](https://medium.com/@1200km) — April 2026

---

## Table of Contents

1. [The Hypothesis — Scope and Definitions](#1-the-hypothesis--scope-and-definitions)
2. [Taxonomy of Anomaly Types](#2-taxonomy-of-anomaly-types)
3. [Mapping Anomalies to the ATT&CK Lifecycle](#3-mapping-anomalies-to-the-attck-lifecycle)
4. [Evidence Register: Real APT Campaigns and Documented Anomaly Patterns](#4-evidence-register-real-apt-campaigns-and-documented-anomaly-patterns)
   - [SUNBURST / UNC2452 (2020)](#41-sunburst--unc2452-2020)
   - [HAFNIUM / Exchange ProxyLogon (2021)](#42-hafnium--exchange-proxylogon-2021)
   - [Conti Ransomware (2021–2022)](#43-conti-ransomware-20212022)
   - [APT34 / OilRig DNS Tunneling (2018–2024)](#44-apt34--oilrig-dns-tunneling-20182024)
   - [MOVEit / Cl0p Campaign (2023)](#45-moveit--clop-campaign-2023)
   - [Midnight Blizzard / Cozy Bear (2023–2024)](#46-midnight-blizzard--cozy-bear-20232024)
   - [Scattered Spider / UNC3944 (2023)](#47-scattered-spider--unc3944-2023)
   - [Storm-0558 and OAuth Abuse Campaigns (2023)](#48-storm-0558-and-oauth-abuse-campaigns-2023)
   - [Volt Typhoon (2023–2024)](#49-volt-typhoon-20232024)
   - [APT41 / Winnti — MESSAGETAP (2019–2024)](#410-apt41--winnti--messagetap-20192024)
   - [APT28 / Fancy Bear — Impacket Lateral Movement (2022)](#411-apt28--fancy-bear--impacket-lateral-movement-2022)
   - [Lazarus Group / DPRK — 3CX Supply Chain and Cryptocurrency Theft](#412-lazarus-group--dprk--3cx-supply-chain-and-cryptocurrency-theft)
5. [Detection by Log Source and Security Device](#5-detection-by-log-source-and-security-device)
   - [Windows Security Event Log](#51-windows-security-event-log)
   - [Sysmon](#52-sysmon)
   - [EDR Platforms](#53-edr-platforms)
   - [Network Detection and Response](#54-network-detection-and-response)
   - [Identity and Access Management Platforms](#55-identity-and-access-management-platforms)
   - [Cloud Security Services](#56-cloud-security-services)
   - [DNS Security](#57-dns-security)
   - [SaaS Audit Logs](#58-saas-audit-logs)
6. [Credential-Based Attacks: Anomaly Detection Deep Dive](#6-credential-based-attacks-anomaly-detection-deep-dive)
7. [How Attackers Suppress Anomaly Visibility](#7-how-attackers-suppress-anomaly-visibility)
8. [Detection Engineering Patterns and Logic Examples](#8-detection-engineering-patterns-and-logic-examples)
9. [Implementation Guidance for SOC and Detection Teams](#9-implementation-guidance-for-soc-and-detection-teams)
10. [Conclusion](#10-conclusion)
11. [References](#11-references)

---

## 1. The Hypothesis — Scope and Definitions

The claim that malicious activity creates detectable anomaly patterns is one of the foundational premises of modern security operations. It underpins UEBA platforms, ML-based SIEM analytics, network traffic analysis tools, and the majority of behavioural detection engineering practice.

The hypothesis is **substantially true, but bounded**. It holds reliably for specific attack phases and specific categories of malicious action. It fails — predictably and structurally — for others. Understanding *why* it holds and *why* it fails is operationally more valuable than treating it as a universal principle.

### 1.1 Definitions

**Anomaly.** NIST SP 800-94 defines anomaly-based intrusion detection as the comparison of normal activity profiles against observed events to identify significant deviations [1]. In operational terms, an anomaly is a measurable deviation from one or more baselines: an entity baseline (this user, this host), a peer baseline (users in this role, hosts in this class), a temporal baseline (activity at this time of day), a relationship model (who normally talks to whom), or an event-sequence model (what normally follows what).

**Point anomaly.** A single data instance that is anomalous relative to the rest of the data (Chandola et al., 2009) [2]. Example: a workstation that has never generated outbound DNS queries to high-entropy subdomain strings suddenly doing so.

**Contextual anomaly.** An instance that is anomalous only in a specific context — not globally unusual, but unusual given its circumstances [2]. Example: `ntdsutil` executed by a domain administrator is routine on a backup domain controller and highly anomalous on a developer workstation.

**Collective anomaly.** A collection of related instances that is anomalous together, even if each individual instance is not [2]. Example: no single DNS query to `avsvmcloud[.]com` subdomains in the SUNBURST campaign was inherently suspicious — the pattern of encoded victim-specific subdomains with 12–14 day dormancy followed by periodic callback created the collective anomaly [3].

**Malicious-behaviour correlation.** The analytical step that links an observed anomaly to an attacker goal, technique, or intrusion stage. An anomaly is not a verdict — it is evidence. A detection becomes operationally useful when the anomaly is correlated with asset context, identity state, companion telemetry, or known adversary tradecraft.

### 1.2 The Central Tension

The core challenge is mathematical. In a typical enterprise environment, the ratio of malicious events to benign events approaches zero. Even a detection system with 99% precision will produce thousands of false positives daily if it processes millions of benign events. This is the **base-rate fallacy** applied to security operations, and NIST SP 800-94 identified it explicitly in 2007: "complex environments are difficult to model accurately, and benign deviations can trigger large numbers of false positives" [1].

The implication is not that anomaly detection is useless — it is that it only produces operational value when the baseline is *tight enough*, the signal is *stable enough*, and the anomaly is *rare enough* in legitimate traffic. Where those conditions hold, anomaly-based detection is powerful. Where they do not, false positive rates undermine analyst confidence and erode the entire programme.

---

## 2. Taxonomy of Anomaly Types

The following taxonomy combines the classical framework from Chandola et al. [2] with operational categories documented by NIST [1], Microsoft MSTIC [4][5][6], Mandiant [7][8][9], CISA/NSA [10][11], the ACSC [12], and practitioner research. Each type has distinct mathematical properties, telemetry requirements, and failure modes.

| Anomaly Type | Definition | Primary Telemetry | Detection Approach | Signal Stability | FP Risk |
|---|---|---|---|---|---|
| **Volumetric** | Unusual absolute volume of data, events, or operations vs. entity baseline | NetFlow, firewall egress, DNS, file/object access, email, cloud audit | Threshold + percentile + rolling baseline (Z-score, IQR, moving average) | High for exfiltration/impact; lower on shared infra | Medium |
| **Frequency / Rate** | Unusual rate of repeated events within a time window | Auth logs, API logs, process start logs, DNS | Count-by-entity over rolling window; Poisson model | High when concentrated; weak when distributed across IPs/tenants | Medium |
| **Temporal** | Activity at unusual times relative to entity, business cycle, or service baseline | Auth logs, SaaS audit, admin actions, EDR | Working-hours baseline; time-series decomposition; seasonal models | Medium; highly context-dependent | Medium–High |
| **Peer-Group** | Entity differs materially from its peer cohort (same role, department, host class) | Identity logs, HR data, endpoint inventory, SaaS access patterns | Clustering (K-Means, TF-IDF), peer distribution percentiles | Medium–High when peer groups are cleanly defined | Medium |
| **Sequence** | Events occur in an unusual order relative to normal operational paths | Process trees, auth chains, API sequences, session logs | Finite-state models, Markov chains, LSTM, provenance graphs | High for stable server roles; lower for dev environments | Medium |
| **Graph / Relationship** | Unexpected edges, bridges, or paths in identity, network, or resource graphs | Active Directory, IAM, SaaS permissions, NetFlow | Graph analytics, community detection, link-prediction scoring | High for privilege changes; moderate for network paths | Medium |
| **Geographic / ASN** | Access from new, implausible, or inconsistent locations or network providers | IdP logs, VPN, SaaS, cloud console | Geo-baseline + impossible-travel + ASN peer history | Medium alone; substantially stronger with enrichment | High if alone |
| **Identity / Access** | Unusual auth properties, factor changes, app consents, or token behaviour | IdP, MFA, Entra/Okta, cloud audit, OAuth logs | Risk detections, peer-baseline comparison, rare-event scoring | High with complete IdP telemetry | Medium |
| **Rare Process / Service** | Execution of a binary or service with low prevalence on that host or host class | EDR, Sysmon Event ID 1, Linux auditd, software inventory | Prevalence scoring, allowlist comparison, digital signature analysis | High on stable server roles; lower on developer workstations | Low–Medium |
| **Parent-Child Execution** | A parent process spawning children it rarely or never should | EDR, Sysmon Event ID 1, auditd | Process lineage rules + rarity modelling by parent | High on tightly managed servers | Low–Medium |
| **Data Movement** | Unusual read/write/copy/export/sync behaviour vs. entity or data-class baseline | DLP, file access logs, object storage audit, SaaS export logs | Volume + destination + object-type + peer baseline | High when export paths are instrumented | Medium |
| **Protocol / Application Usage** | Misuse of ports, protocols, or application features for non-standard purposes | Proxy logs, DNS, NetFlow, SaaS/IdP API logs | Rare-protocol analytics, entropy analysis, user-agent baseline | Medium–High | Medium |
| **Negative Anomaly (Absence)** | Expected telemetry stops appearing — logs cleared, agent silenced, process absent | SIEM heartbeat monitoring, log volume baselines, EDR health | Volume baseline on log source; absence detection | Medium — requires baseline of "presence" | Medium |
| **State-Change** | Rarely occurring control-plane changes that materially alter trust or exposure | Cloud audit, AD audit, IdP audit, SaaS admin logs | Alert on first-occurrence or infrequent-occurrence events | Very high for privileged objects | Low when scoped tightly |
| **Multi-Event Correlation** | Several individually weak signals combining into an anomalous chain against one entity | SIEM / XDR across all sources | Correlation rules, graph/session stitching, entity risk scoring | Very high when tuned | Low–Medium |

---

## 3. Mapping Anomalies to the ATT&CK Lifecycle

Anomaly detection effectiveness is not uniform across the MITRE ATT&CK kill chain. The core reason is structural: anomaly detection is most useful when an attacker must create *measurable change*. It is least useful when the attacker can remain inside accepted identity, protocol, and administrative norms.

| ATT&CK Stage | Anomaly Utility | Primary Anomaly Types | Key Evidence | Key Limitation |
|---|---|---|---|---|
| Initial Access | Poor–Moderate | Geographic, ASN, rate | Midnight Blizzard residential proxy spray [4] | Valid credentials, residential proxies, distributed timing |
| Execution | Moderate–Strong | Parent-child, rare process, sequence | HAFNIUM `w3wp.exe` → `cmd.exe` [5]; Conti ADFind [13] | LOTL tools, fileless execution, in-process abuse |
| Persistence | Moderate | State-change, identity/access, rare event | Storm-1283 OAuth VM creation [6]; UNC3944 MFA reset [8] | High noise from legitimate admin; needs enrichment |
| Privilege Escalation | Moderate | Rare process, sequence, identity | Kerberoasting Event 4769 RC4 anomaly [14] | Legitimate privilege changes create noise |
| Defense Evasion | Weak | Negative anomaly (absence), rare event | Conti Defender disable; log clearing via `wevtutil` | Evasion targets the detection surface itself |
| Credential Access | High (concentrated) | Frequency/rate, rare process, sequence | Password spray Event 4625 clustering; Kerberoasting; DCSync [14][15] | Distributed spray defeats per-tenant thresholds |
| Discovery | Moderate | Rare process, peer-group, sequence | ADFind/BloodHound execution [13]; LDAP query spikes | Heavy overlap with legitimate admin tooling |
| Lateral Movement | Moderate–High | Graph/relationship, peer-group, sequence | PTH Event 4624 NTLM Null SID [16]; Conti PsExec + ADMIN$ [13] | Legitimate admin RDP/SMB traffic |
| Command and Control | High | Temporal, protocol, DNS entropy, volumetric | SUNBURST DGA DNS [3]; APT34 DNSpionage TXT records [17] | Jitter, dormancy, protocol masquerading |
| Collection / Exfiltration | Very High | Volumetric, data movement, state-change | APT41 SQLULDR2 + PINEGROVE → OneDrive [9]; Rclone campaigns [13] | SaaS-native exfil bypasses network visibility |
| Impact | Very High | Volumetric, rare process, sequence | Shadow copy deletion; mass file encryption; BlackCat `.alphv` extension [18] | Often detected after damage has commenced |

---

## 4. Evidence Register: Real APT Campaigns and Documented Anomaly Patterns

The entries below separate three evidentiary tiers:

- **[Documented]** — the source explicitly described the anomalous behaviour or detection opportunity.
- **[Inferred]** — the source documented tradecraft from which a defensible anomaly opportunity can be derived.
- **[Speculative]** — the detection opportunity is plausible but not corroborated by a primary source.

---

### 4.1 SUNBURST / UNC2452 (2020)

**Source:** Mandiant [3]; Microsoft MSTIC; SolarWinds incident post-mortem.

**Attack summary:** Threat actors (assessed as APT29/Cozy Bear) compromised the SolarWinds Orion software build pipeline, inserting the SUNBURST backdoor into signed Orion updates distributed to approximately 18,000 organisations. Subsequent intrusions at approximately 100 high-value targets used TEARDROP and Cobalt Strike for post-exploitation activity.

**Phase 1 — Supply chain compromise and DGA C2:**

SUNBURST used a domain generation algorithm (DGA) to encode victim-specific data in DNS subdomains of `avsvmcloud[.]com`. The subdomain string was Base32-encoded using a custom alphabet and contained the victim's internal Active Directory domain name and a unique victim ID derived from local host data. For example, a query to `r1q2sqr3r3r3rnr22qs3s3r1.appsync-api.eu-west-1.avsvmcloud[.]com` encodes victim domain information in the subdomain prefix. [Documented]

**Anomaly pattern (DNS):**
- **Shannon entropy of subdomain labels** substantially above normal — typical human-readable subdomains have entropy below 3.5; encoded SUNBURST subdomains had entropy consistently above 4.5. [Documented]
- **Subdomain length anomaly** — subdomain labels exceeded 30 characters, far longer than typical service hostnames.
- **DNS query timing** — after an initial 12–14 day dormancy period (no DNS resolution, only local checks), queries appeared with variable but machine-generated timing. [Documented]
- **No prior resolution history** — the DGA domain had no prior resolution history in enterprise DNS caches, detectable via domain rarity scoring. [Inferred]

**Detection opportunity and log sources:**
- `dns.log` (Zeek/Corelight): `query` field entropy analysis, `qclass_name`, query frequency per FQDN
- Windows DNS debug log: full QNAME capture
- Proxy logs: HTTP requests from Orion service process to external IPs masquerading as legitimate Orion telemetry
- SIEM correlation: alert on DNS queries where `length(subdomain) > 30 AND entropy(subdomain) > 4.5 AND domain_age < 365`

**Phase 2 — TEARDROP dropper and Cobalt Strike C2:**

TEARDROP was a memory-only DLL dropper disguised as a JPEG file (`gracious_truth.jpg`). It used a rolling XOR obfuscation scheme and loaded Cobalt Strike Beacon entirely in memory, with no executable written to disk. Each Cobalt Strike instance was unique per machine (distinct folder names, file names, export functions, C2 domains, HTTP request patterns, and timestamps). [Documented]

**Anomaly pattern (endpoint):**
- **No process-to-disk write of executable content** — fileless execution avoids standard file-creation detections; however, memory-resident PE injection creates Sysmon Event 7 (image load) anomalies if an unsigned PE is loaded into a signed process. [Inferred]
- **Orion service process generating outbound HTTP** to non-SolarWinds infrastructure — the Orion service regularly contacts SolarWinds update servers, providing cover, but the C2 domains were distinct and had no prior resolution history. [Documented]
- **Cobalt Strike process injection** — lateral movement from the Orion service process generated Sysmon Event 8 (CreateRemoteThread) and Event 10 (ProcessAccess) against target processes. [Documented]

**Key limitation:** The dormancy period specifically defeated anomaly detection that required sustained baseline deviation. The actors also used existing Orion communication patterns as cover, making process-network correlation ambiguous.

---

### 4.2 HAFNIUM / Exchange ProxyLogon (2021)

**Source:** Microsoft MSTIC [5]; Mandiant [7]; CISA Advisory AA21-062A.

**Attack summary:** HAFNIUM (attributed to a Chinese state-sponsored actor) exploited four zero-day vulnerabilities in Microsoft Exchange Server (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065) to achieve pre-authentication remote code execution and deploy webshells.

**Phase 1 — ProxyLogon exploitation:**

CVE-2021-26855 is a server-side request forgery (SSRF) vulnerability in the Exchange Client Access Service (CAS). Exploitation generated anomalous HTTP requests from the Exchange frontend to the backend Exchange store with cookie-based authentication bypass. IIS logs showed unusual HTTP POST requests to Exchange OWA/ECP paths from source IPs with no prior access history. [Documented]

**Anomaly pattern (IIS / web logs):**
- **Rare URI requests** — low-volume GET/POST requests to `/ecp/`, `/owa/`, and Exchange management paths from IPs with no prior resolution in access logs.
- **Response size anomaly** — successful SSRF exploitation returned responses inconsistent with the expected size for that endpoint.
- **NSA's web-shell guidance** explicitly documents "rare URI access" and "low-support requests" analytics for this class of exploitation — specifically recommending alert on URIs accessed by fewer than 5 unique source IPs in a 30-day window that return 200 OK to POST requests. [Documented]

**Phase 2 — Webshell installation:**

Post-exploitation, `UMWorkerProcess.exe` and `w3wp.exe` wrote ASPX files to the Exchange web root. The China Chopper webshell (`shell.aspx`, `iis.aspx`, or similar) was the primary implant, with characteristic command-line arguments unchanged since 2013. [Documented]

**Anomaly pattern (endpoint / EDR):**
- **Parent-child execution:** `UMWorkerProcess.exe` → `cmd.exe` and `w3wp.exe` → `cmd.exe` — a parent-child relationship with near-zero legitimate prevalence on Exchange servers. **This is one of the strongest parent-child anomaly signals in Windows enterprise environments.** [Documented]
- **ASPX file write by web worker:** Sysmon Event ID 11 (FileCreate) with `TargetFilename` matching `*.aspx` in IIS web roots, where the `Image` is `w3wp.exe` or `UMWorkerProcess.exe`. [Documented]
- **Windows Security Event ID 4688** (process creation with command-line logging enabled): `ParentImage = w3wp.exe, NewProcessName = cmd.exe`. Provides the same signal without Sysmon, but requires mandatory command-line audit policy.

**Log sources and security devices:**
- IIS log files: W3C format, `cs-uri-stem`, `cs-uri-query`, `c-ip`, `sc-status`, `cs-bytes`, `sc-bytes`
- Sysmon Event IDs: 1 (process creation), 11 (file create), 3 (network connection)
- Windows Security Event: 4688 with `ProcessCommandLine` field enabled
- EDR (CrowdStrike Falcon): IOA fires on Office or web worker processes spawning shell interpreters
- Microsoft Defender for Endpoint: "Suspicious process execution by web server worker process" built-in alert

**Key limitation:** Microsoft noted that advanced actors deployed IIS native modules (DLLs loaded into `w3wp.exe` address space) rather than ASPX webshells in some instances. In-process modules avoid child-process spawning entirely — Sysmon Event 7 (ImageLoad) for unsigned or anomalous DLLs loaded into IIS worker processes is the residual detection surface. [Documented]

---

### 4.3 Conti Ransomware (2021–2022)

**Source:** The DFIR Report [13] — "BazarCall to Conti Ransomware via Trickbot and Cobalt Strike" (August 2021), "BazarLoader to Conti Ransomware in 32 Hours" (September 2021), "CONTInuing the Bazar Ransomware Story" (November 2021).

**Attack summary:** Conti affiliates used BazarLoader/BazarCall (phone-based phishing to malware delivery) or IcedID as initial access vectors, established a Cobalt Strike Beacon beachhead, conducted internal reconnaissance using free tools, moved laterally via SMB/PsExec, and deployed Conti ransomware domain-wide via PsExec batch execution. Full intrusion cycle documented at 32 hours in one case.

**Phase 1 — Initial Access and Beachhead:**

BazarLoader (later BazarCall) was delivered via document macros or direct download following a phone call directing the victim to a website. The initial Cobalt Strike Beacon established C2 over HTTPS to actor-controlled infrastructure. [Documented]

**Phase 2 — Reconnaissance:**

The DFIR Report explicitly documented the following tools executed from the Cobalt Strike Beacon process: [Documented]
- `adfind.exe` — output written to `C:\Windows\Temp\adf\` as `ad_users.txt`, `ad_computers.txt`, `ad_group.txt`, `trustdmp.txt`, `subnets.txt`, `ad_ous.txt`
- BloodHound — executed in-memory via Cobalt Strike (no on-disk binary)
- `nltest /domain_trusts /all_trusts`
- `net group "Domain Admins" /domain`
- `whoami /all`

**Anomaly patterns (reconnaissance phase):**
- **Rare process execution:** `adfind.exe` has near-zero baseline prevalence in most enterprise environments. EDR rare-process scoring fires immediately on any execution. [Documented]
- **File creation in temp directories:** ADFind output files in `C:\Windows\Temp\adf\` — Sysmon Event 11 (FileCreate) with non-standard filenames in system temp paths by a non-system process. [Inferred]
- **In-memory BloodHound:** No file creation anomaly, but network anomaly — BloodHound performs LDAP queries against the domain controller at high volume. **Active Directory Event 1644** (expensive/inefficient LDAP queries, requires explicit enablement) or high volume of LDAP requests from an unexpected host captures this. [Inferred]
- **Parent-child sequence from Cobalt Strike beacon:** All reconnaissance commands run as child processes of the Cobalt Strike beacon process (often injected into a legitimate process like `explorer.exe` or `svchost.exe`). Sequence anomaly: `explorer.exe` → `adfind.exe` or `svchost.exe` → `nltest.exe`. [Documented]

**Phase 3 — Lateral Movement:**

Conti affiliates used SMB lateral movement, dropped the Conti DLL to `ADMIN$` shares, and executed it remotely via PsExec. RDP was proxied through the IcedID process on port 8080. Internal SMB port 445 scanning identified targets. [Documented]

**Anomaly patterns (lateral movement):**
- **Graph anomaly:** New SMB connections (Windows Security Event 4624, Logon Type 3) from the beachhead host to domain controllers and file servers — host pairs with no prior communication history in 90-day NetFlow/auth baselines. [Inferred]
- **ADMIN$ share access:** Event 5140 (A network share object was accessed) with `ShareName = \\*\ADMIN$` from a workstation context. `ADMIN$` share access from non-IT-administrator workstations is anomalous in most environments. [Documented]
- **PsExec service installation:** Sysmon Event 13 or Windows Security Event 7045 (System log — new service installed): `psexesvc` service or services with random names containing characteristic PsExec patterns (binary signed by Microsoft but executed from an unusual path). [Documented]
- **Port 445 scan:** NetFlow/firewall logs showing connection attempts from a single internal host to many internal hosts on TCP 445 within a short window — rate anomaly on internal east-west traffic. [Inferred]

**Phase 4 — Pre-Encryption:**

Within the final hours, Conti deployed Windows Defender disabling commands and then distributed ransomware via PsExec batch files across the entire domain — achieving domain-wide encryption in under 30 minutes in documented cases. [Documented]

**Anomaly patterns (pre-encryption and impact):**
- **Windows Defender disable:** PowerShell `Set-MpPreference -DisableRealtimeMonitoring $true` or registry modification of Defender keys — both create Sysmon Event 13 (Registry value set) anomalies on the Defender configuration keys. Absence of subsequent Defender event logs from the host is a negative anomaly detectable through SIEM heartbeat monitoring. [Documented]
- **VSS shadow copy deletion:** `vssadmin.exe delete shadows /all /quiet` — rare-process execution of `vssadmin.exe` with `delete shadows` in the command line. On workstations, this is effectively never legitimate. Windows Security Event 4688 (with command-line logging) or Sysmon Event 1 captures this. [Documented]
- **Mass file modification:** File server telemetry or DLP showing thousands of file rename/write events per minute as encryption progresses — volumetric anomaly far outside any backup or batch-processing baseline. [Documented]

**Log sources and security devices for Conti detection:**
- **EDR (any):** Rare process execution of ADFind, BloodHound, PsExec service installation
- **Windows Security Event 7045:** New service installed — fires on PsExec deployment
- **Windows Security Event 4624 Logon Type 3:** Lateral movement authentication
- **Windows Security Event 5140:** ADMIN$ share access
- **Windows Security Event 4688 + command-line:** VSS deletion, Defender disable commands
- **Sysmon Event 1, 11, 13:** Process creation, file creation, registry modification
- **NetFlow:** Internal port 445 scan pattern
- **SIEM:** Absence of Windows Defender telemetry (negative anomaly / heartbeat monitoring)

---

### 4.4 APT34 / OilRig DNS Tunneling (2018–2024)

**Source:** Palo Alto Unit 42 [17]; Cisco Talos DNSpionage reports (2018–2019); Check Point Research — "Iran's APT34 Returns with an Updated Arsenal" (2021).

**Attack summary:** APT34 (OilRig, attributed to Iranian state-sponsored actors) has consistently used DNS tunneling as a C2 channel across multiple toolsets including BONDUPDATER, RDAT, and DNSpionage. Data exfiltration and command retrieval are encoded in DNS query subdomain strings or TXT record responses.

**Documented DNS tunneling technique:**

In the BONDUPDATER and DNSpionage campaigns, the attacker's implant queried custom subdomain strings where:
- Exfiltrated data was encoded in the **subdomain label** of a DNS query directed to an attacker-controlled authoritative DNS server.
- **TXT record responses** were used to deliver commands from the attacker to the implant. The implant issued a TXT record query; the authoritative server returned the command encoded in the TXT record response.
- **Subdomain label length** exceeded 30 characters in many documented queries.
- **Query frequency** to a single domain showed regular polling intervals — a temporal anomaly in an environment where DNS query patterns are normally stochastic. [Documented]

**Anomaly patterns (DNS):**

| Signal | Threshold/Pattern | Log Source |
|---|---|---|
| Subdomain Shannon entropy | > 4.0 for subdomain-only portion | DNS server debug log, Zeek dns.log |
| Subdomain label length | > 30 characters | DNS server debug log |
| TXT record query volume | > baseline per domain (TXT queries are rare in most enterprise DNS) | DNS resolver logs |
| DNS query cadence to single FQDN | Coefficient of variation < 0.20 (regular beaconing pattern) | DNS resolver logs + NetFlow |
| Ratio of TXT : A record queries to same domain | > 1.0 (highly anomalous) | DNS resolver logs |
| Domain age | < 30 days with immediate high query volume | DNS logs + external threat intel |

**Log sources and detection tools:**
- **Windows DNS Debug Log:** Requires enabling DNS diagnostic logging on Windows DNS servers. Captures full QNAME, query type, source IP.
- **Zeek/Corelight dns.log:** Fields include `query` (FQDN), `qtype_name` (A/AAAA/TXT/MX), `rcode_name` (response code), `answers` (response data).
- **RITA (Real Intelligence Threat Analytics):** Open-source framework built on Zeek data. RITA's DNS module computes FQDN query frequency, subdomain entropy, and unique subdomain count per registered domain — directly targeting tunneling detection.
- **Infoblox Threat Defense:** Documents specific DNS anomaly scoring for tunneling, DGA, and NXDOMAIN flood patterns with per-query entropy scoring.
- **Cisco Umbrella:** Blocks and logs DNS requests to known malicious domains and provides anomalous DNS query analytics.

**Key limitation:** DNS logging is frequently absent in enterprise environments. Many organisations forward DNS queries without full QNAME capture, making entropy analysis impossible. DNS tunneling is undetectable without complete DNS query logs including the full subdomain string.

---

### 4.5 MOVEit / Cl0p Campaign (2023)

**Source:** CISA Advisory AA23-158A [19]; Rapid7; Mandiant; Akamai research; NCSC-NL.

**Attack summary:** The Cl0p ransomware group (TA505) exploited CVE-2023-34362, a SQL injection vulnerability in MOVEit Transfer's web application, to deploy the LEMURLOOT webshell and exfiltrate data from hundreds of organisations globally. The campaign was notable for opportunistic mass exploitation across thousands of vulnerable systems within a 48-hour window in late May 2023.

**Phase 1 — SQL Injection and Webshell Deployment:**

The SQL injection payload was delivered in HTTP POST requests to MOVEit Transfer's `/guestaccess.aspx` and `/api/v1/token` endpoints. Post-exploitation, LEMURLOOT was written to the MOVEit web root as `human2.aspx` (deliberately mimicking the legitimate `human.aspx` file). [Documented]

**LEMURLOOT webshell evasion design:** The webshell returned HTTP 404 to any request not containing the custom header `X-siLock-Comment` with the correct GUID-format password value. Additional control flow headers `X-siLock-Step1`, `X-siLock-Step2`, `X-siLock-Step3` managed the webshell interaction phases. The webshell also enumerated files, retrieved the MOVEit database configuration file (containing credentials), and created a local user account named `"Health Check Service"`. [Documented]

**Anomaly patterns:**

| Phase | Anomaly Type | Specific Signal | Log Source |
|---|---|---|---|
| SQL injection | Protocol/volumetric | Anomalous POST body content to known MOVEit endpoints | IIS logs (`cs-uri-stem`, POST body if captured) |
| Webshell write | Parent-child / file creation | `w3wp.exe` writing ASPX file to web root | Sysmon Event 11; Windows Security 4663 (object access) |
| Webshell access | Rare URI | `human2.aspx` accessed by external IPs; 404 returned to most | IIS access logs |
| User account creation | State-change / identity | Event 4720 — new account `"Health Check Service"` created | Windows Security Event 4720 |
| Data exfiltration | Volumetric | Large outbound data transfer from MOVEit server to external IP | NetFlow; firewall egress logs |

**Detection specifics:**
- **IIS log pattern:** Filter for POST requests to `/human2.aspx` or `/_human2.aspx` returning HTTP 200. The custom header `X-siLock-Comment` is visible in IIS extended logs if header logging is enabled (non-default).
- **Windows Security Event 4720** (A user account was created): The creation of `"Health Check Service"` account by a web application process is a state-change anomaly with near-zero legitimate prevalence. Alert threshold: Event 4720 where `SubjectUserName` is not a domain administrator or IT service account.
- **Sysmon Event 11** (FileCreate): `TargetFilename` contains `*.aspx` AND `Image` is `w3wp.exe`. This single rule would have caught LEMURLOOT webshell installation without any statistical baseline.
- **YARA detection** (file-based): NCSC-NL published YARA rules targeting the strings `X-siLock-Comment`, `Health Check Service`, and characteristic ASP.NET constructs within the webshell code — applicable to memory scanning and filesystem scans.

---

### 4.6 Midnight Blizzard / Cozy Bear (2023–2024)

**Source:** Microsoft MSTIC [4]; Microsoft Security Blog — "Midnight Blizzard: Guidance for Responders" (January 2024).

**Attack summary:** Midnight Blizzard (APT29/Cozy Bear) conducted a sustained password spray campaign against Microsoft's corporate environment, gained access via a legacy test account without MFA, and exfiltrated email from senior executive and security team mailboxes. Attack volume increased 10-fold in February 2024 compared to January 2024.

**Password spray anomaly patterns:**

The spray used residential proxy infrastructure to distribute authentication attempts across thousands of IP addresses. From any single tenant's local view, the per-IP failure rate was below standard alert thresholds. The aggregate attack was only visible at a provider or cross-tenant level. [Documented]

**Specific detection signals:**
- **Microsoft Entra Identity Protection — "Password spray" risk detection:** Named detection type in Entra ID Protection. Fires when Entra's cross-tenant telemetry detects the distributed spray pattern against multiple accounts within a tenant. This detection requires the provider-level view that tenant-local monitoring cannot replicate. [Documented]
- **"Unfamiliar sign-in properties" risk detection:** When the spray succeeded against the legacy test account, the subsequent successful sign-in from a residential proxy IP exhibited unfamiliar properties across six dimensions: IP address, ASN, location, device, browser, and tenant IP subnet. All six were outside the historical baseline for that account. [Documented]
- **Target account characteristics:** The compromised account was a legacy, non-production test account — meaning it had sparse sign-in history and therefore a weak baseline, and no MFA enforcement. The "thin baseline" problem: accounts with few historical sign-ins generate high-sensitivity anomaly scoring but also high false-positive rates, because any sign-in is "unfamiliar."

**Post-compromise OAuth application abuse:**

After initial access, Midnight Blizzard created malicious OAuth applications and abused existing OAuth grants to access Exchange Web Services (EWS) for email collection. [Documented]

**Anomaly patterns (OAuth phase):**
- **Entra audit: New application registration** with `Mail.ReadWrite` or `Mail.ReadAll` scope — State-change anomaly. Alert on app consent where scope includes `Mail` or `Files.ReadWrite.All`, especially when consented by an account with unfamiliar sign-in properties within the preceding 24 hours.
- **EWS access pattern:** Application accessing EWS endpoints for multiple mailboxes — application-level volumetric anomaly if EWS access baseline is maintained per-application.
- **Targeted accounts:** Microsoft's report confirmed that executive and security team mailboxes were targeted — "peer-group" anomaly if the application accessing those mailboxes was not previously authorised to do so.

**Log sources:**
- Microsoft Entra sign-in logs (`SigninLogs` table in Sentinel)
- Microsoft Entra audit logs (`AuditLogs` — app registration, OAuth consent)
- Microsoft 365 Unified Audit Log: `MailItemsAccessed` operation (E5 license required)
- Microsoft Entra Identity Protection: `RiskySignIns`, `UserRiskEvents` tables

---

### 4.7 Scattered Spider / UNC3944 (2023)

**Source:** Mandiant [8]; CISA Advisory AA23-320A; Scattered Spider MGM/Caesars incident reporting (2023).

**Attack summary:** Scattered Spider (UNC3944) conducted social engineering intrusions against MGM Resorts International and Caesars Entertainment, among others, using help-desk vishing to obtain MFA resets, then exploiting cloud and SaaS environments for persistence and data exfiltration. The group demonstrated deep knowledge of identity platforms (Okta, Entra ID) and SaaS products.

**Phase 1 — Help-Desk Vishing and MFA Reset Abuse:**

Threat actors called IT help desks posing as employees, using pre-obtained PII (from LinkedIn or prior breaches) to bypass identity verification procedures and request MFA factor resets for high-privilege accounts. [Documented]

**Anomaly patterns (identity):**
- **Okta System Log — `user.mfa.factor.update` event:** MFA factor registration or change for a user — particularly a privileged user — outside of a known self-service or IT change window. Correlate with: absence of a preceding help-desk ticket referencing the account, and a sign-in from an unfamiliar IP within 30 minutes of the reset.
- **Okta `user.session.impersonation.initiate`:** If the actor used Okta administrator access to impersonate other users.
- **Entra audit — `Update user` + MFA device registration:** Microsoft documents `Add registered security info` and `Delete registered security info` operations in the audit log. Alert on MFA registration changes for accounts in privileged roles (Global Administrator, Security Administrator, Exchange Administrator).
- **MFA fatigue pattern:** High volume of MFA push notification events (`user.mfa.attempt.not.completed` in Okta, or `UserStrongAuthClientAuthAttemptFailed` in Entra) against a specific account over a short time window — rate anomaly on MFA denial events per account. [Documented]

**Phase 2 — SaaS Reconnaissance and Exfiltration:**

UNC3944 used legitimate cloud sync tools (Airbyte, Fivetran) to exfiltrate data by connecting attacker-controlled destinations to enterprise SaaS platforms. They also used Rclone, WinSCP, and direct cloud storage provider APIs. [Documented]

**Anomaly patterns (exfiltration):**
- **New OAuth application consent** to Salesforce, ServiceNow, or SharePoint by an unusual principal (recently-signed-in account with unfamiliar properties) — state-change anomaly in SaaS app audit logs.
- **Airbyte/Fivetran connector creation:** Cloud sync tool creating a new data connector to an external destination — visible in the SaaS product's audit log but typically not in firewall or EDR telemetry.
- **Azure VM creation by non-standard principal:** UNC3944 created new VMs for persistent access and tool staging — cloud audit (Activity Log in Azure) captures `Microsoft.Compute/virtualMachines/write` events with the initiating principal. Alert on VM creation by OAuth applications or unfamiliar user principals. [Documented]

**Log sources:**
- Okta System Log (full event log via API or SIEM connector)
- Microsoft Entra audit logs
- Microsoft 365 Unified Audit Log — `FileDownloaded`, `FileSyncDownloadedFull`, `SearchQueryPerformed`
- Azure Activity Log — `Microsoft.Compute/virtualMachines/write`
- Salesforce Event Log Files — file download, report export events
- SaaS CASB (Microsoft Defender for Cloud Apps, Netskope): cross-SaaS anomaly correlation

---

### 4.8 Storm-0558 and OAuth Abuse Campaigns (2023)

**Source:** Microsoft MSTIC [6]; Microsoft Security Blog on Storm-1283 and Storm-1286.

**Storm-0558** (attributed to Chinese state actors) used forged Microsoft account (MSA) consumer signing keys to forge authentication tokens for Exchange Online and OWA. The tokens allowed access to customer mailboxes. Detection was initially triggered by a customer reporting anomalous mailbox access, not by automated detection systems. [Documented]

**Anomaly patterns:**
- **Mailbox audit — `MailItemsAccessed` operation** (Microsoft 365 Unified Audit Log): Access to mailboxes by an application not previously authorised for those mailboxes. Requires E5 licensing or Microsoft Purview Audit Premium.
- **Token issuer anomaly** (Microsoft Entra Identity Protection named detection): Fires when the token presented for sign-in is issued by an authority inconsistent with the tenant's expected token issuers. This is the detection type most directly relevant to the Storm-0558 forged-token technique. [Documented]
- **Application protocol anomaly:** OWA/EWS access from an application ID not previously seen accessing those services in that tenant — application-level peer-group anomaly.

**Storm-1283 / Storm-1286** — approximately 17,000 malicious multi-tenant OAuth applications registered across the Microsoft ecosystem, used for phishing mail delivery via the Microsoft Graph API and inbox rule manipulation. [Documented]

**Anomaly patterns:**
- **App registration spike:** Volume of new application registrations in a tenant above historical baseline — frequency anomaly on `Add application` audit events.
- **Suspicious OAuth scopes:** App consent where scope includes `Mail.Send`, `Mail.ReadWrite`, `Contacts.ReadWrite`, or `offline_access` — state-change anomaly targeted to high-risk scope strings.
- **Inbox rule creation:** `New-InboxRule` operation in the Unified Audit Log, particularly rules forwarding to external domains or deleting specific subject-line categories. Deterministic detection: any inbox rule forwarding to an external domain not on the corporate approved-destinations list.
- **High-volume Graph API mail send:** An application sending significantly more mail messages than its baseline — volumetric anomaly on Graph API mail send operations.

---

### 4.9 Volt Typhoon (2023–2024)

**Source:** CISA/NSA/FBI Advisory AA24-038A [10]; Microsoft MSTIC [4]; NCSC and Five Eyes joint advisory.

**Attack summary:** Volt Typhoon (attributed to Chinese state-sponsored actors) maintained persistent, stealthy access to US critical infrastructure sectors including communications, energy, transportation systems, and water/wastewater — documented with multi-year dwell time in some environments. Their defining characteristic is systematic LOLBin usage and deliberate suppression of anomaly visibility.

**Documented TTPs and detection opportunities:**

| TTP | Specific Action | Anomaly Signal | Log Source | Limitation |
|---|---|---|---|---|
| Credential access | `ntdsutil "ac i ntds" ifm "create full C:\Temp\ntds" q q` | Contextual anomaly: `ntdsutil` with IFM arguments on a non-DC host | Event 4688 with command-line; Sysmon Event 1 | Legitimate DC backup operations use identical commands |
| Network tunneling | `netsh portproxy add v4tov4 listenport=X listenaddress=Y connectport=Z connectaddress=W` | Contextual anomaly: `netsh portproxy` configuration on workstation or server | Event 4688; Sysmon Event 1; network configuration audit | Legitimate VPN or WSL2 configurations use portproxy |
| Log clearing | `wevtutil cl System` / `wevtutil cl Security` | Negative anomaly: absence of Security/System log events after a gap; Event 1102 (audit log cleared) | Windows Security Event 1102 (Security log cleared) | Legitimate admin maintenance may clear logs |
| Lateral movement | Valid credentials via authenticated protocols (RDP, WMI) | Graph anomaly: new host-to-host connection; peer-group anomaly: identity accessing hosts outside normal scope | Event 4624; NetFlow | Significant legitimate admin overlap |
| SOHO proxy use | Sign-ins from residential ISPs or SOHO router IP ranges | Geographic/ASN anomaly: unfamiliar ISP or ASN for the signing account | IdP sign-in logs | Consumer ISP churn creates false positives |
| Living-off-the-land discovery | `wmic os get`, `ipconfig /all`, `net localgroup administrators`, PowerShell `Get-ADDomain` | Sequence anomaly: chain of discovery commands in rapid succession | Event 4688; PowerShell 4104 | Identical commands used in legitimate scripts |

**CISA advisory explicitly states** that many of the behavioural findings associated with Volt Typhoon can also occur in legitimate administrative operations and should not be treated as malicious without corroboration [10]. [Documented]

**Windows Security Event 1102** (The audit log was cleared) is specifically recommended by NSA as a high-priority alert — legitimate administrative log clearing is rare and typically documented in change management systems. Any Event 1102 without a corresponding change management ticket should trigger investigation. [Documented]

**Log sources:**
- Windows Security Event Log: 4688 (process creation + command line), 1102 (log cleared), 4624 (authentication)
- PowerShell logging: Event 4103 (module logging), 4104 (script block logging) — must be explicitly enabled
- Windows Management Instrumentation: Event 5857, 5858, 5860, 5861 (WMI activity/operation) — enabled via "Audit WMI Activity"
- NetFlow/firewall: Unusual east-west traffic between hosts with no prior communication history
- Entra ID / IdP: Sign-in logs with ASN/ISP enrichment

---

### 4.10 APT41 / Winnti — MESSAGETAP (2019–2024)

**Source:** Mandiant [7]; Palo Alto Unit 42; M-Trends 2025 [9].

**MESSAGETAP** was a 64-bit ELF malware deployed on Linux-based SMSC (Short Message Service Centre) servers at telecommunications providers, targeting SMS intercept capabilities for intelligence collection. [Documented]

**Technical behaviour:**
- Loaded `libpcap` to perform raw packet capture on the network interface
- Read configuration files (`keyword_parm.txt`, `parm.txt`) every 30 seconds to refresh target IMSI/MSISDN lists and keyword filters
- Parsed Ethernet/IP/TCP layers to extract and filter SMS messages matching configured criteria
- Saved matching messages to disk for later exfiltration

**Anomaly patterns:**
- **Unusual process with `libpcap` linkage** on a telecom server: A process loaded `libpcap` (raw packet capture library) in an environment where packet capture is not operationally expected. On Linux, detection via `/proc/*/maps` or `lsof` output showing `libpcap.so` loaded into an unusual process. [Documented]
- **Unexpected file read pattern:** Regular (every 30 seconds) read of configuration files from non-standard paths — detectable via Linux auditd with `auditctl -w /path/to/keyword_parm.txt -p r` syscall auditing. [Inferred]
- **Disk writes of network-captured data:** A process writing to disk files from data received on the network interface — correlation of `recvfrom()`/`read()` syscall activity followed by `write()` syscalls to disk files in auditd telemetry. [Inferred]
- **Process not matching expected software inventory:** MESSAGETAP masqueraded as a legitimate-looking process but would not match the known-good software baseline for the SMSC system. Rare-process/service detection applies if an inventory baseline is maintained. [Documented]

**In M-Trends 2025**, APT41 was documented using SQLULDR2 (a legitimate Oracle database export utility) and PINEGROVE (a custom exfiltration tool) to export sensitive data to OneDrive. The SQLULDR2 execution is a rare-process anomaly on most systems; the outbound data transfer to OneDrive is a data-movement anomaly if a cloud storage destination baseline is maintained. [Documented]

---

### 4.11 APT28 / Fancy Bear — Impacket Lateral Movement (2022)

**Source:** CISA Advisory AA22-277A [20] — "Impacket and Exfiltration Tool Used to Steal Sensitive Information from Defense Industrial Base Organization."

**Attack summary:** Russian state-sponsored actors (associated with APT28/Sandworm activity) used the Impacket Python framework for lateral movement and credential extraction in a defense industrial base network over a sustained period.

**Specific Impacket tools documented:**
- **`wmiexec.py`:** Executes commands remotely via WMI — generates Windows Security Event 4624 (Logon Type 3) and creates a WMI job that spawns `cmd.exe` as a child of `WmiPrvSE.exe`. The parent-child chain `WmiPrvSE.exe` → `cmd.exe` is a documented high-fidelity indicator. [Documented]
- **`secretsdump.py`:** Performs DCSync (mimics AD replication) to extract NTLM hashes and Kerberos keys — generates Windows Security Event 4662 with DS-Replication-Get-Changes GUID from a non-DC source host. [Documented]
- **CovalentStealer:** A custom exfiltration tool that staged data to actor-controlled cloud storage. [Documented]

**Anomaly patterns:**

`WmiPrvSE.exe` spawning `cmd.exe`:
- **Sysmon Event 1:** `ParentImage = C:\Windows\System32\wbem\WmiPrvSE.exe`, `Image = cmd.exe`
- **Windows Security 4688:** `ParentProcessName = WmiPrvSE.exe`, `NewProcessName = cmd.exe`
- This parent-child relationship indicates remote WMI code execution and has low legitimate prevalence outside of specific system management configurations.

DCSync via Impacket (`secretsdump.py`):
- **Windows Security Event 4662:** Object access with DS-Replication-Get-Changes GUIDs from a non-DC host (see Section 6 for full field specification)
- **Network anomaly:** DRSUAPI (Directory Replication Service Remote Protocol) traffic from a workstation or server that is not a domain controller — NetFlow showing traffic on TCP port 135 (RPC endpoint mapper) and dynamically assigned high ports from non-DC hosts to domain controllers

**Log sources:**
- Windows Security Event 4624, 4688, 4662
- Sysmon Event 1 (process creation), Event 3 (network connection — RPC to DC)
- WMI Event Log: `Microsoft-Windows-WMI-Activity/Operational` — Event 5857, 5860 (WMI query activity)

---

### 4.12 Lazarus Group / DPRK — 3CX Supply Chain and Cryptocurrency Theft

**Source:** Mandiant; CrowdStrike; CISA advisory on DPRK IT workers; Kaspersky.

**3CX Supply Chain Attack (2023):**

Lazarus Group compromised the 3CX Desktop App update distribution mechanism (a supply chain attack similar to SUNBURST) — the trojanised application was signed with 3CX's legitimate certificate and distributed to approximately 600,000 organisations. The payload performed staged download of additional malware after a dormancy period. [Documented]

**Anomaly patterns:**
- **Trusted application performing unusual network behaviour:** The 3CX softphone application (`3CXDesktopApp.exe`) is expected to make outbound connections to 3CX servers. Connections to non-3CX infrastructure (actor-controlled GitHub repositories for payload retrieval, then actor-controlled C2) represented a network-destination anomaly for a known-trusted application. [Documented]
- **Signed binary with anomalous behaviour:** Detection platforms (CrowdStrike Falcon, MDE) flagged the trojanised 3CX application based on behavioural IOAs — the signed binary performed memory allocation and injection operations inconsistent with a legitimate softphone application. [Documented]
- **YARA / threat intelligence:** CrowdStrike and SentinelOne published detections within hours based on the binary's behavioural characteristics even before signature databases were updated, demonstrating the value of IOA/behavioural detection over signature-only approaches.

**DPRK Cryptocurrency Theft Operations (2023–2024):**

Lazarus subgroup BlueNoroff targeted cryptocurrency exchanges and DeFi protocols. Documented techniques included:
- **Malicious ISO files** delivered via spearphishing — ISO execution created unexpected processes in Windows sandbox environments (Event 4688, unusual parent process `explorer.exe` → `cmd.exe` from ISO-mounted context).
- **In-memory execution (MISTPEN, LPEClient):** Fileless malware stages load entirely in memory. Detection relies on Sysmon Event 8 (CreateRemoteThread), Event 10 (ProcessAccess), and behavioural EDR analysis of API call sequences.
- **Access to private keys and wallet data:** EDR/DLP monitoring for access to `wallet.dat` files, `.pem` private key files, or browser credential stores — file access anomaly for high-value data objects.

---

## 5. Detection by Log Source and Security Device

### 5.1 Windows Security Event Log

The Windows Security Event Log is the primary audit trail for Windows identity, authentication, and process activity. Effective anomaly detection requires enabling advanced audit policies beyond Windows defaults.

**Critical Event IDs for anomaly detection:**

| Event ID | Log | Description | Audit Policy Required | Anomaly Relevance |
|---|---|---|---|---|
| 4624 | Security | Successful logon | Account Logon → Credential Validation | PTH detection (Logon Type 3 + NtLmSsP + Null SID); lateral movement graph |
| 4625 | Security | Failed logon | Account Logon → Credential Validation | Password spray (rate + volume across accounts) |
| 4648 | Security | Logon with explicit credentials (RunAs) | Account Logon → Credential Validation | Lateral movement indicator — attacker using alternate creds |
| 4662 | Security | Operation performed on directory object | DS Access → Directory Service Access + SACL on domain NC | DCSync detection (replication GUIDs from non-DC source) |
| 4672 | Security | Special privileges assigned to new logon | Privilege Use → Sensitive Privilege Use | Privilege escalation — new session with `SeDebugPrivilege`, `SeTcbPrivilege` |
| 4688 | Security | Process created | Detailed Tracking → Process Creation + command-line GPO | LOTL detection, credential tool execution, post-exploitation commands |
| 4697 | Security | Service installed in the system | System → Security System Extension | Malicious service installation (companion to 7045 in System log) |
| 4698 | Security | Scheduled task created | Object Access → Other Object Access Events | Persistence via scheduled tasks |
| 4720 | Security | User account created | Account Management → User Account Management | New account creation (LEMURLOOT "Health Check Service"; attacker backdoor accounts) |
| 4728/4732/4756 | Security | Member added to privileged group | Account Management → Security Group Management | Persistence via group membership; detect adds to Domain Admins, Enterprise Admins, local Administrators |
| 4769 | Security | Kerberos service ticket request | Account Logon → Kerberos Service Ticket Operations | Kerberoasting (Encryption Type 0x17 = RC4 from modern environment) |
| 4776 | Security | DC credential validation (NTLM) | Account Logon → Credential Validation | NTLM authentication to DC — baseline and alert on spikes |
| 5140 | Security | Network share accessed | Object Access → File Share | ADMIN$ access from non-admin workstations (PsExec lateral movement) |
| 7045 | System | New service installed | (System log — always on) | PsExec service deployment; malicious service persistence |
| 1102 | Security | Audit log cleared | (Cannot be disabled) | Log clearing for defense evasion — high-priority alert |

**Non-default audit policies required to enable these events:**
- `Process Creation (4688)` with command-line: Requires both audit policy and the Group Policy setting "Include command line in process creation events"
- `Directory Service Access (4662)`: Requires both audit policy and SACL configuration on Active Directory objects
- `Kerberos Service Ticket Operations (4769)`: Enabled in AD DS environments but requires review to confirm it is generating data
- `File Share (5140)`: Not enabled by default; requires Object Access → File Share audit

### 5.2 Sysmon

Sysmon (System Monitor) provides endpoint telemetry beyond what the native Windows Security log offers, with particular value for process execution chains, network connections, and driver/image loads.

**High-value Sysmon Event IDs for anomaly detection:**

| Event ID | Description | Key Fields | Anomaly Use Case |
|---|---|---|---|
| 1 | Process Create | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes`, `IntegrityLevel` | Parent-child anomalies; rare process; LOTL command-line |
| 3 | Network Connection | `Image`, `DestinationIp`, `DestinationPort`, `Protocol`, `Initiated` | Process-network anomaly; C2 from unusual process |
| 6 | Driver Load | `ImageLoaded`, `Hashes`, `Signed`, `Signature` | BYOVD detection (Bring Your Own Vulnerable Driver); unsigned driver load |
| 7 | Image Load | `Image`, `ImageLoaded`, `Signed`, `SignatureStatus` | Unsigned DLL injection; TEARDROP-style in-memory loader |
| 8 | CreateRemoteThread | `SourceImage`, `TargetImage`, `StartAddress`, `StartModule` | Cross-process injection (non-parent processes injecting into targets) |
| 10 | ProcessAccess | `SourceImage`, `TargetImage`, `GrantedAccess` | LSASS access for credential dumping (access mask `0x1010` = Mimikatz sekurlsa; `0x0820` = injection); Kerberos ticket access |
| 11 | FileCreate | `Image`, `TargetFilename` | Webshell writes (ASPX from `w3wp.exe`); dropper writing payloads to disk |
| 12/13 | Registry Add/Set | `EventType`, `TargetObject`, `Details` | Run-key persistence; Defender configuration modification; COM hijacking |
| 17/18 | Pipe Created/Connected | `PipeName`, `Image` | Named pipe lateral movement (Cobalt Strike default pipe names like `\MSSE-*-server`) |
| 22 | DNS Query | `Image`, `QueryName`, `QueryResults` | Process-level DNS resolution — process not normally making external DNS queries |
| 25 | ProcessTampering | `Image`, `Type` | Process hollowing; herpaderping; transacted file-based evasion |

**Critical Sysmon configuration notes:**
- Sysmon Event 10 (ProcessAccess) with `TargetImage = lsass.exe` generates extreme volume in default configurations — **must** be filtered to specific GrantedAccess masks to avoid overwhelming the SIEM. Recommended filter: `GrantedAccess in (0x1010, 0x1410, 0x0820)` — these masks are characteristic of credential dumping tools.
- Sysmon Event 8 (CreateRemoteThread) also generates noise from legitimate inter-process communication. Filter by: `SourceImage != TargetImage AND StartModule = "Unknown"` to target injection of shellcode from unregistered memory regions.
- Named pipe names for Cobalt Strike default configuration include `\MSSE-*-server`, `\postex_*`, `\status_*` — these are known IOCs and can be detected deterministically via Event 17/18.

### 5.3 EDR Platforms

**CrowdStrike Falcon**

CrowdStrike Falcon's detection engine uses Event Stream Processing (ESP) — a stateful correlation engine processing over 1,000 sensor event types in sequential chains. IOAs (Indicators of Attack) are the primary detection unit: behavioural chains rather than individual events.

Documented Falcon IOA detection categories and examples [21]:

| Detection Category | Behavioural Chain Detected | Example |
|---|---|---|
| Credential Theft | Non-standard process accessing LSASS memory (`OpenProcess` targeting `lsass.exe` from injected module) + attempt to retrieve credentials | Mimikatz sekurlsa running in a reflectively injected PowerShell module |
| Process Injection | Legitimate process receiving injected code + code performing unusual actions (network connection, credential access) | Word.exe injected with shellcode → network connection to external IP |
| Ransomware Behaviour | Mass file rename/encryption operations + VSS deletion + Defender disable | Conti/BlackCat pre-encryption chain |
| Defence Evasion | Security product process termination + log clearing + driver manipulation | Attacker killing EDR agent before lateral movement |
| Lateral Movement | Credential usage + remote process creation + ADMIN$ access chain | Cobalt Strike `jump psexec_psh` lateral movement |

Falcon's AI-powered IOA (introduced 2023) uses cloud-native ML trained on CrowdStrike Security Cloud telemetry to dynamically generate IOA patterns beyond human-authored rules, providing coverage for novel attack variations. [Documented]

**Microsoft Defender for Endpoint (MDE)**

MDE's behaviour monitoring engine performs continuous behavioural telemetry collection and generates alerts in the "Alerts" queue when behavioural chains match documented attack patterns. Key built-in anomaly-adjacent alert categories:

- "Suspicious process execution by web server worker process" — fires on `w3wp.exe` → `cmd.exe` (HAFNIUM pattern)
- "Suspicious credential theft activity" — fires on LSASS access patterns consistent with Mimikatz
- "Suspicious scheduled task creation" — fires on scheduled tasks created by uncommon parent processes
- "Suspicious remote process execution" — fires on WMI/PsExec-style remote command execution
- "Possible attempt to access Primary Refresh Token (PRT)" — Premium Entra ID Protection detection for token theft attempts (requires MDE + Entra integration)

MDE integrates with Microsoft Entra Identity Protection, Sentinel, and Microsoft 365 Defender to create multi-domain incident correlation. [Documented]

### 5.4 Network Detection and Response

**Zeek / Corelight**

Zeek (formerly Bro) is an open-source network analysis framework that generates structured, semantically rich log files from packet captures. Corelight provides enterprise Zeek deployment with additional detection packages.

Key Zeek log files for anomaly detection:

| Log File | Key Fields | Anomaly Use Case |
|---|---|---|
| `dns.log` | `query`, `qtype_name`, `rcode_name`, `answers`, `qclass_name`, `TTL` | DNS tunneling (entropy, query length, TXT record ratio); DGA; C2 |
| `conn.log` | `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts` | Beaconing (regular intervals); volumetric anomaly; port scan; data exfil |
| `http.log` | `host`, `uri`, `user_agent`, `method`, `status_code`, `request_body_len`, `response_body_len` | Rare URI; anomalous User-Agent (Firefox 20.0 in AdaptixC2); C2 over HTTP |
| `ssl.log` | `server_name`, `issuer`, `subject`, `validation_status`, `cipher`, `curve`, `ja3`, `ja3s` | JA3/JA3S fingerprinting for C2 tooling; invalid certificate chains |
| `files.log` | `mime_type`, `filename`, `md5`, `sha256`, `source`, `tx_hosts`, `rx_hosts` | File transfer of unexpected types; malware download |
| `kerberos.log` | `request_type`, `client`, `service`, `error_msg`, `forwardable`, `renewable`, `cipher` | Kerberoasting (cipher = `RC4`); pass-the-ticket; ticket anomalies |
| `smb_files.log` | `action`, `path`, `name`, `size`, `times.modified` | ADMIN$ write (lateral movement); ransomware file modification pattern |

**RITA (Real Intelligence Threat Analytics)** — Open-source framework built on Zeek output. Specific detection modules:
- **Beaconing:** Analyses `conn.log` connection interval consistency using the skew/madm (median absolute deviation of median) algorithm to distinguish machine-generated periodic connections from stochastic human traffic.
- **DNS tunneling:** Analyses `dns.log` subdomain entropy, query length, FQDN uniqueness, and bytes in/out ratio.
- **Long connections:** Flags connections with duration > configurable threshold (e.g., 1 hour) that may represent persistent C2 or data staging.

**Vectra AI**

Vectra AI's Cognito platform baselines per-host network behaviour using ML models (150+ detection models) and detects deviations across four attack phases (C2, lateral movement, reconnaissance, exfiltration). Key documented detection capabilities [22]:

- **Command and Control:** Intermittent beaconing, domain fronting, C2 over encrypted enterprise protocols (LDAPS, encrypted SMB), external remote access anomalies
- **Lateral Movement:** Workstation accessing file servers outside established communication graph; authentication attempts to systems not in baseline; RDP at anomalous hours; SMB lateral movement from unexpected source hosts
- **Reconnaissance:** Internal host scanning; unusual LDAP query volumes from unexpected sources; abnormal DNS query patterns
- **Exfiltration:** Abnormal data transfer volumes to external destinations, even over HTTPS (volumetric, not content-based)

Vectra operates entirely on network metadata — no packet decryption required — making it effective for environments where payload inspection is impractical. [Documented]

### 5.5 Identity and Access Management Platforms

**Microsoft Entra Identity Protection — Named Risk Detection Types**

Microsoft Entra Identity Protection provides the following named detection types, each representing a documented anomaly model [4]:

**Sign-in Risk Detections:**

| Detection Name | Premium/Non-Premium | Real-time or Offline | What It Detects |
|---|---|---|---|
| Unfamiliar sign-in properties | Premium | Real-time | Deviation from historical IP, ASN, location, device, browser, tenant subnet |
| Anonymous IP address | Non-premium | Real-time | Sign-in from Tor exit node or known anonymiser proxy |
| Atypical travel | Premium | Offline | Two sign-ins from geographically distant locations within an impossible travel window |
| Impossible travel | Premium | Offline (Defender for Cloud Apps) | Similar to atypical travel, cross-service correlation |
| Malicious IP address | Premium | Offline | Sign-in from IP associated with confirmed attack activity |
| Password spray | Premium | Real-time or offline | Distributed spray pattern detected across the tenant |
| Verified threat actor IP | Premium | Real-time | Sign-in from IP infrastructure associated with known threat actor groups |
| Anomalous Token | Premium | Real-time or offline | Token characteristics inconsistent with expected issuer, lifetime, or properties |
| Token issuer anomaly | Premium | Real-time or offline | Token issued by an unexpected authority (relevant to forged-token attacks like Storm-0558) |
| Suspicious inbox manipulation rules | Premium | Offline | Inbox rules forwarding to external domains or deleting specific message categories |
| Suspicious inbox forwarding | Premium | Offline | New external email forwarding configuration |
| Mass access to sensitive files | Premium | Offline | Access to volume of files above baseline for user/session |
| New country | Premium | Offline | First-ever sign-in from a particular country for that account |
| Suspicious browser | Premium | Offline | Browser and OS combination inconsistent with account's historical profile |

**User Risk Detections:**

| Detection Name | What It Detects |
|---|---|
| Leaked credentials | NTLM hash or plaintext credential found in breach dumps, paste sites, or dark web forums |
| Attacker in the Middle (AiTM) | Reverse-proxy phishing attack stealing session tokens (requires M365 E5) |
| Suspicious API traffic | Anomalous Microsoft Graph API / directory enumeration activity |
| Possible PRT access | Attempt to access the Primary Refresh Token (requires MDE integration) |
| Anomalous user activity | Composite UEBA-style deviation across multiple dimensions |
| User reported suspicious activity | User denied an MFA push request (MFA fatigue pattern) |

**Okta System Log High-Value Events:**

| Okta Event Type | Anomaly Relevance |
|---|---|
| `user.mfa.factor.update` | MFA factor change — alert for privileged accounts outside change windows |
| `user.mfa.factor.deactivate` | MFA factor removal — high-sensitivity alert |
| `user.session.impersonation.initiate` | Administrator impersonating another user |
| `user.account.privilege.grant` | Privilege assignment — alert for unexpected escalation |
| `policy.evaluate_sign_on` | Sign-on policy evaluation — enriched with device, network, behaviour context |
| `security.threat.detected` | Okta ThreatInsight detection — IP-based threat intelligence correlation |
| `application.user_membership.add` | User added to an application — state-change alert for sensitive apps |
| `user.authentication.auth_via_mfa` with outcome `FAILURE` | MFA denial — rate anomaly for MFA fatigue detection |
| `user.authentication.sso` | SSO authentication — baseline for unusual application access |

### 5.6 Cloud Security Services

**AWS GuardDuty**

GuardDuty's ML-based anomaly detection evaluates all API calls against a per-user, per-entity baseline tracking: who made the request, from what location/IP, to what API. Key finding types by attack stage [23]:

| Attack Stage | GuardDuty Finding Type | Description |
|---|---|---|
| Discovery | `Discovery:IAMUser/AnomalousBehavior` | Unusual IAM discovery API calls (`GetRolePolicy`, `ListAccessKeys`, `DescribeInstances`) |
| Credential Access | `CredentialAccess:IAMUser/AnomalousBehavior` | `GetPasswordData`, `GetSecretValue`, `BatchGetSecretValue`, `GenerateDbAuthToken` from unusual source |
| Defense Evasion | `DefenseEvasion:IAMUser/AnomalousBehavior` | `DeleteFlowLogs`, `DisableAlarmActions`, `StopLogging` — security logging or alerting disabled |
| Exfiltration | `Exfiltration:IAMUser/AnomalousBehavior` | `PutBucketReplication` (S3 data copy to external bucket), `CreateSnapshot`, `RestoreDBInstanceFromDBSnapshot` |
| Persistence | `Persistence:IAMUser/AnomalousBehavior` | Unusual IAM role assumption, new access key creation, unusual cross-account access |

GuardDuty also provides network-based findings (VPC Flow Log analysis): `Backdoor:EC2/C&CActivity.B`, `Recon:EC2/PortProbeUnprotectedPort`, `UnauthorizedAccess:EC2/SSHBruteForce`. [Documented]

**Microsoft Sentinel — Built-in Anomaly Rules**

Sentinel provides ML-based anomaly rules that establish per-entity baselines and score deviations. Key characteristics [24]:
- Anomaly rules run on a learning period (typically 2–4 weeks) before producing results
- Results appear in the `Anomalies` table alongside other SIEM data
- MITRE ATT&CK technique mapping is included in built-in templates
- Anomaly rules cannot be edited directly — duplicate and customise

Key Sentinel anomaly analytics templates:
- `UEBA Anomalous Activity` — detects deviations from entity behaviour baselines across Azure AD, Office 365, and Azure Activity logs
- `Azure Activity Unusual operations` — detects unusual resource creation/deletion/modification patterns
- `Anomalous login to Microsoft Entra ID` — detects sign-in property deviations
- `Uncommon processes observed in last 24 hours` — process rarity on monitored endpoints

### 5.7 DNS Security

DNS telemetry is indispensable for C2 and tunneling detection. Key log sources and detection capabilities:

| Tool | Detection Capability | Specific Anomaly Signals |
|---|---|---|
| **Windows DNS Debug Log** | Full QNAME capture (enabled explicitly) | Entropy analysis, subdomain length, query type distribution per domain |
| **Zeek dns.log** | Structured DNS telemetry from network capture | Same as above, plus timing, response size, and answer analysis |
| **RITA** | Automated DNS tunneling detection | Subdomain entropy, bytes in/out ratio, unique subdomain count per base domain |
| **Infoblox Threat Defense** | Managed DNS with anomaly scoring | Per-query entropy scoring, DGA detection, NXDOMAIN flood detection, RPZ blocking |
| **Cisco Umbrella** | Cloud DNS resolver with global threat intel | Domain risk scoring, DNS category blocking, anomalous query pattern alerting |
| **Palo Alto DNS Security** | ML-based DNS anomaly in NGFW | DGA classification, DNS tunneling (query entropy, length), C2 domain detection |

**Shannon Entropy for DNS Anomaly Detection:**

Shannon entropy measures information content/randomness of a string. Human-readable DNS subdomains (e.g., `mail`, `api`, `login`) have entropy typically below 3.0. Encoded data in DNS tunneling produces entropy consistently above 4.0. The formula:

```
H = -Σ p(x) * log₂(p(x))
```

Where `p(x)` is the probability of each character in the string. A threshold of **4.0–4.5** on the subdomain-only portion of a DNS query provides effective discrimination between encoded payloads and legitimate subdomains in most enterprise environments. Calibration against environment-specific DNS traffic is required to set the threshold without excessive false positives.

### 5.8 SaaS Audit Logs

SaaS audit logs are the primary — and often only — telemetry source for detecting intrusions that occur entirely within cloud service layers.

**Microsoft 365 Unified Audit Log — Key Operations for Anomaly Detection:**

| Operation | Category | Anomaly Relevance |
|---|---|---|
| `MailItemsAccessed` | Exchange | Access to specific mailbox items — requires Purview Audit Premium (E5) |
| `New-InboxRule` | Exchange | Inbox forwarding/deletion rule creation — alert on any external-domain forwarding |
| `Add-MailboxPermission` | Exchange | Mailbox delegation — alert for executive mailboxes |
| `FileDownloaded` | SharePoint/OneDrive | File download events — baseline per-user and alert on volume spikes |
| `FileSyncDownloadedFull` | SharePoint/OneDrive | Full sync download — alert when sync destination is unfamiliar |
| `SearchQueryPerformed` | SharePoint | Search activity — alert for sensitive keyword searches |
| `Add application` | Entra ID | New OAuth app registration — alert for high-risk scopes |
| `Consent to application` | Entra ID | OAuth consent — alert for `Mail.ReadWrite`, `Files.ReadWrite.All` scopes |
| `Set-AdminAuditLogConfig` | Exchange | Audit log configuration change — alert on any disablement |

**Google Workspace Audit Log** — similar categories via the Reports API. Key events for exfiltration detection: `DOWNLOAD` in Drive audit, `CREATE_APPLICATION_SPECIFIC_PASSWORD` in Login audit, `GMAIL_SETTINGS_CHANGE` for forwarding rules.

---

## 6. Credential-Based Attacks: Anomaly Detection Deep Dive

Credential-based attacks are among the most detectable through anomaly logic because they generate structurally distinct patterns in Windows event logs that differ from legitimate Kerberos and NTLM authentication.

### 6.1 Kerberoasting

**What it is:** An attacker with a valid domain user account requests Kerberos service tickets (TGS) for accounts with Service Principal Names (SPNs). The TGS is encrypted with the service account's NTLM hash and can be cracked offline.

**Windows Security Event 4769 — Key Fields for Detection:**

| Field | Legitimate Value | Kerberoasting Value | Significance |
|---|---|---|---|
| `Ticket Encryption Type` | `0x12` (AES-256) or `0x11` (AES-128) | `0x17` (RC4-HMAC) | RC4 requests from modern Windows environments are anomalous — modern systems default to AES |
| `Service Name` | Machine accounts (`*$`) or expected services | Service accounts with SPNs that are high-value targets | Filter: `ServiceName not ending in $` to exclude machine accounts |
| `Account Name` | Service accounts, machines | Regular user account requesting TGS for another service account | The requesting account is a regular user, not a machine |
| `Client Address` | Expected workstation IP | Attacker's workstation | Source IP of the TGS request |
| `Ticket Options` | Various | `0x40800010` is common in Kerberoasting tools | Not definitive alone |

**Detection logic:**
```
EventID = 4769
  AND TicketEncryptionType = 0x17
  AND ServiceName NOT LIKE '%$'
  AND AccountName NOT LIKE '%$'
```
Alert on: single account requesting RC4 TGS for multiple service accounts within a short window (> 5 distinct service accounts in 10 minutes is a strong signal). A single RC4 request may be legitimate legacy compatibility — the volume pattern is the discriminator.

**Prerequisite:** "Audit Kerberos Service Ticket Operations" must be enabled (Success) in Advanced Audit Policy on domain controllers.

### 6.2 DCSync

**What it is:** An attacker with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All permissions (or a compromised domain controller) mimics AD replication to extract password hashes for any domain account, including `krbtgt`. Implemented in Mimikatz (`lsadump::dcsync`) and Impacket (`secretsdump.py`).

**Windows Security Event 4662 — Key Fields:**

| Field | Legitimate Value | DCSync Value | Significance |
|---|---|---|---|
| `SubjectUserName` | A domain controller machine account (`DC01$`) or `NT AUTHORITY\SYSTEM` | A regular user or admin account name (not a machine account) | The core anomaly: non-DC account performing replication |
| `Object Type` | `%{19195a5b-...}` (domainDNS) | Same | Object being accessed |
| `Properties` / Access GUIDs | Normal DC replication | Must include `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes) AND `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All) | Both GUIDs present simultaneously is the definitive signal |

**Required configuration:** Enable "Audit Directory Service Access" (Success) in Advanced Audit Policy → DS Access. Apply a SACL on the domain NC root object granting `SYSTEM` audit for the replication permission GUIDs. This is non-default and must be explicitly configured.

**Detection logic:**
```
EventID = 4662
  AND ObjectType = "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
  AND Properties CONTAINS "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
  AND Properties CONTAINS "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
  AND SubjectUserName NOT LIKE '%$'  -- exclude machine accounts (DCs)
```
Any match of this combined query where `SubjectUserName` is not a machine account is a high-confidence DCSync detection. False positives are extremely rare if the machine-account filter is applied.

### 6.3 Pass-the-Hash

**What it is:** An attacker uses a captured NTLM hash to authenticate to a remote system without knowing the plaintext password. The hash is presented to NTLM authentication, bypassing the need for the cleartext credential.

**Windows Security Event 4624 — PTH Identification Fields:**

| Field | PTH Value | Legitimate Network Logon Value | Significance |
|---|---|---|---|
| `Logon Type` | `3` (Network) | `3` (Network) | Same — not sufficient alone |
| `Logon Process` | `NtLmSsP` | `Kerberos` (for domain accounts) | Legitimate domain logons use Kerberos; PTH forces NTLM |
| `Authentication Package` | `NTLM` | `Kerberos` | Confirms NTLM path |
| `Security ID (SubjectUserSid)` | `S-1-0-0` (NULL SID) | The user's actual SID | NULL SID indicates no prior interactive session — the attacker has only a hash, not a session |
| `Key Length` | `0` | `128` or `256` | Zero-length key is characteristic of PTH |

**Core correlation for PTH detection:**
```
EventID = 4624
  AND LogonType = 3
  AND LogonProcess = NtLmSsP
  AND AuthenticationPackage = NTLM
  AND SubjectUserSid = S-1-0-0
  AND KeyLength = 0
```
**Refinement:** Correlate with absence of a preceding Type 2 (interactive) or Type 10 (remote interactive) logon for the same `TargetUserName` on the same source workstation. Legitimate users authenticate interactively first; PTH attackers have no interactive session. Alert also on: the destination host where Event 4624 is generated — PTH on a domain controller or file server is higher severity than PTH on a workstation.

### 6.4 LSASS Credential Dumping (Sysmon Event 10)

**What it is:** Tools like Mimikatz, ProcDump, or Task Manager dump LSASS memory to extract credential material (NTLM hashes, Kerberos tickets, cleartext passwords from WDigest).

**Sysmon Event 10 — ProcessAccess for LSASS:**

| Field | Malicious Pattern | Notes |
|---|---|---|
| `TargetImage` | `lsass.exe` | Alert only on LSASS as target |
| `GrantedAccess` | `0x1010`, `0x1410`, `0x0820` | `0x1010` = `PROCESS_VM_READ + PROCESS_QUERY_INFORMATION` (Mimikatz sekurlsa); `0x1410` adds `PROCESS_DUP_HANDLE`; `0x0820` = injection mask |
| `SourceImage` | Any process not in expected allowlist | Alert on non-EDR, non-antivirus, non-OS processes accessing LSASS |
| `CallTrace` | Contains `UNKNOWN` (shellcode) or unexpected DLLs | Indicates injected code, not legitimate caller |

**Allowlist management:** The following processes legitimately access LSASS and must be excluded: `MsMpEng.exe` (Windows Defender), `csrss.exe`, `werfault.exe`, `taskmgr.exe` (from admin sessions), EDR agent processes, antivirus processes. Require vendor confirmation for their specific process names.

---

## 7. How Attackers Suppress Anomaly Visibility

Advanced threat actors apply systematic techniques to reduce their anomaly footprint — these are documented TTPs, not hypothetical evasion:

**Distribute the signal.** Midnight Blizzard spread password spray failures across thousands of residential proxy IPs, ensuring no single IP exceeded per-tenant alert thresholds [4]. The same logic applies to data exfiltration — instead of one large transfer, many small transfers over time stay below volumetric thresholds.

**Use valid credentials and legitimate tools.** Volt Typhoon's systematic LOLBin usage means the attacker's executed processes are identical to those a legitimate administrator would run [10]. The anomaly, if it exists, is in command-line argument combinations or network destination — detectable only with full command-line logging and allowlisted-command analysis.

**Stay in-process.** Microsoft documented malicious IIS modules executing within `w3wp.exe` address space, bypassing child-process anomaly detection entirely [5]. SUNBURST's TEARDROP loaded Cobalt Strike entirely in memory without executable writes to disk.

**Exploit logging gaps.** CISA and NSA document that default Windows logging configurations omit command-line arguments, WMI event details, and PowerShell script block content [10][11]. Actors aware of default configurations operate within the gap between what happens and what is recorded.

**Mimic business rhythm.** Microsoft's Storm-0558 activity heatmap showed working hours consistent with the actor's time zone — temporal anomaly detection (off-hours alert) is defeated by actors who deliberately operate during expected business hours [4]. SUNBURST used a 12–14 day dormancy period specifically to separate the installation event from the operational C2 activity in any investigation timeline [3].

**Blend with SaaS-native functionality.** UNC3944's use of Airbyte and Fivetran — legitimate data integration tools — for exfiltration produced no anomaly visible to firewall or EDR monitoring [8]. Detection requires SaaS-native audit telemetry from the specific platforms used.

**Absorb into baseline through slow poisoning.** If an attacker establishes persistence quietly and operates slowly over weeks, UEBA/anomaly systems that retrain on recent data will incorporate the attacker's behaviour into the "normal" model. NIST SP 800-94 documented this as a fundamental weakness: "profiles can be trained to include malicious behaviour if the training window is contaminated" [1].

---

## 8. Detection Engineering Patterns and Logic Examples

### 8.1 Four Core Design Patterns

**Pattern 1: Rarity-in-Role.**
Detect an event that is rare for the specific user, host class, or application tier. The baseline denominator is the peer group, not the estate. ADFind on a developer workstation is rare; `ntdsutil` on a domain controller is expected; `ntdsutil` on a workstation is rare.

**Pattern 2: Rate-Plus-Shape.**
Combine event count with timing distribution, source diversity, or target spread. A hundred authentication failures from one IP is a simple rate anomaly. A hundred failures against a hundred different accounts from a hundred different IPs within two hours — each IP generating only one failure — is a distributed spray detectable only through shape analysis.

**Pattern 3: State-Change Gating.**
Alert on control-plane changes that rarely occur legitimately and materially alter trust or exposure. New OAuth app registration with `Mail.ReadWrite` scope; new user account created by a web server process; new VM created by a service principal; new inbox rule forwarding to external domain. These are "first occurrence" or "infrequent occurrence" events where even a simple threshold of 1 produces acceptable precision.

**Pattern 4: Hybrid Anomaly Gated by Deterministic Condition.**
Apply anomaly scoring only after filtering on a high-risk object class or path. This is the most operationally practical pattern:
- Score app-consent anomalies only when scope includes `Mail.ReadWrite` or `Files.ReadWrite.All`
- Score VM-creation anomalies only when the actor is a service principal or recently-created user
- Score LSASS access anomalies only when `GrantedAccess` matches known malicious masks
- Score parent-child anomalies only when parent is a known web worker or document application

### 8.2 Documented Detection Logic Examples

**Distributed Password Spray (Rate + Shape):**
```kql
// Sentinel / KQL example
SigninLogs
| where TimeGenerated > ago(15m)
| where ResultType != "0"  // failures only
| summarize
    FailedTargetUsers = dcount(UserPrincipalName),
    FailedSourceIPs = dcount(IPAddress),
    FailedCount = count()
  by bin(TimeGenerated, 5m)
| where FailedTargetUsers > 20 AND FailedSourceIPs > 10
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(30m) and ResultType == "0"
  ) on $left.TimeGenerated == $right.bin_TimeGenerated
// Alert: spray followed by successful sign-in
```

**Kerberoasting (Event 4769, RC4 Encryption Type):**
```spl
// Splunk example
index=wineventlog EventCode=4769
  TicketEncryptionType=0x17
  NOT ServiceName="*$"
  NOT AccountName="*$"
| stats count by AccountName, ServiceName, ClientAddress
| where count > 3
// Alert: single account requesting multiple RC4 TGS in window
```

**DCSync (Event 4662, Replication GUIDs from Non-DC):**
```spl
// Splunk example
index=wineventlog EventCode=4662
  ObjectType="%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
  Properties="*1131f6aa*" Properties="*1131f6ad*"
  NOT SubjectUserName="*$"
| table _time, SubjectUserName, SubjectDomainName, IpAddress
// Any result is high-confidence DCSync
```

**Pass-the-Hash (Event 4624 Field Combination):**
```spl
// Splunk example
index=wineventlog EventCode=4624
  LogonType=3
  LogonProcessName=NtLmSsP
  AuthenticationPackageName=NTLM
  SubjectUserSid="S-1-0-0"
  KeyLength=0
  NOT TargetUserName="*$"  // exclude machine accounts
| stats count by TargetUserName, IpAddress
```

**LSASS Access (Sysmon Event 10):**
```spl
// Splunk example
index=sysmon EventCode=10
  TargetImage="*lsass.exe"
  (GrantedAccess=0x1010 OR GrantedAccess=0x1410 OR GrantedAccess=0x0820 OR GrantedAccess=0x1fffff)
  NOT SourceImage IN ("MsMpEng.exe", "csrss.exe", "werfault.exe")
  (CallTrace="*UNKNOWN*" OR NOT SourceImage LIKE "%Windows%")
| table _time, SourceImage, GrantedAccess, CallTrace, Computer
```

**Webshell Parent-Child (w3wp → cmd):**
```kql
// Sentinel / KQL (from DeviceProcessEvents - MDE)
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "UMWorkerProcess.exe", "httpd.exe")
  and FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
// No baseline required — deterministic for this lineage
```

**DNS Tunneling (High-Entropy Subdomains):**
```python
# Python pseudocode for SIEM enrichment or Zeek scripted detection
import math

def shannon_entropy(s):
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())

def is_suspicious_dns(fqdn, query_type):
    parts = fqdn.split('.')
    # Take subdomain portion (everything except registered domain + TLD)
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    entropy = shannon_entropy(subdomain) if subdomain else 0
    return (
        entropy > 4.0 or
        len(subdomain) > 30 or
        query_type in ('TXT', 'NULL', 'MX') and entropy > 3.5
    )
```

**SaaS Bulk Export Anomaly (M365):**
```kql
// Sentinel / KQL
OfficeActivity
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize
    DailyDownloadCount = count(),
    TotalBytes = sum(tolong(OfficeObjectId))  // proxy for volume
  by UserId, bin(TimeGenerated, 1d)
| join kind=inner (
    // User's 30-day baseline
    OfficeActivity
    | where TimeGenerated between(ago(30d)..ago(1d))
    | where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
    | summarize AvgDaily = avg(count()), StdDev = stdev(count())
      by UserId, bin(TimeGenerated, 1d)
    | summarize BaselineAvg = avg(AvgDaily), BaselineStd = avg(StdDev) by UserId
  ) on UserId
| where DailyDownloadCount > BaselineAvg + 4 * BaselineStd
| project TimeGenerated, UserId, DailyDownloadCount, BaselineAvg, ZScore = (DailyDownloadCount - BaselineAvg) / BaselineStd
```

---

## 9. Implementation Guidance for SOC and Detection Teams

### 9.1 Instrument Before Modelling

No anomaly detection programme can compensate for missing telemetry. Before deploying any anomaly model, confirm:

- **Process creation with command lines** (Event 4688 or Sysmon Event 1 with `CommandLine` field) — not enabled by default. Requires Group Policy: `Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events`.
- **Sysmon deployed** with a baseline configuration (SwiftOnSecurity or Olaf Hartong's modular config) covering at minimum Events 1, 3, 7, 8, 10, 11, 13, 17, 22.
- **PowerShell logging** enabled: Module Logging (Event 4103), Script Block Logging (Event 4104), Transcription to a centralised network share.
- **DNS debug logging** on all Windows DNS servers, or Zeek deployed on DNS traffic.
- **SaaS audit logging** enabled and forwarded to SIEM for all production SaaS platforms.
- **Cloud audit logs** (CloudTrail, Azure Activity, GCP Audit) forwarded to SIEM with sufficient retention.
- **IdP logs** (Entra sign-in, Okta System Log) fully ingested with all fields, not sampled.

### 9.2 Start with Constrained, High-Confidence Detections

Sequence for deploying anomaly analytics by confidence and baseline stability:

1. **Domain controllers:** Kerberoasting (Event 4769 + 0x17), DCSync (Event 4662 + GUIDs), LSASS access (Sysmon Event 10)
2. **Identity providers:** MFA lifecycle changes for privileged accounts, unfamiliar sign-in properties, app consent with high-risk scopes
3. **Internet-facing servers:** Web worker parent-child (deterministic), ASPX file write by web worker (deterministic), rare URI analytics
4. **Cloud control planes:** VM creation by unusual principals, IAM role grants, storage policy changes
5. **SaaS export paths:** Bulk download, connected app authorisations, inbox forwarding rules
6. **Network:** DNS entropy analytics, beaconing detection via RITA or NDR platform
7. **Estate-wide UEBA:** Only after above categories are producing tuned results

### 9.3 Baseline by Role, Not by Estate

A finance analyst, Exchange server, Kubernetes API server, and developer laptop share no meaningful behavioural baseline. Applying estate-wide thresholds produces baselines too loose for privileged infrastructure and too tight for dynamic development environments.

Minimum peer group definitions:
- **Users:** by department + seniority tier (executive/manager/IC) + job function (IT admin/developer/finance/HR)
- **Hosts:** by role (domain controller/Exchange server/web server/developer workstation/build server) + network segment + OS version
- **Applications:** by tier (production/staging/dev) + data classification + user base

### 9.4 Accumulate Weak Signals via Entity Risk Scoring

No single anomaly should trigger an investigation ticket. Risk-based alerting accumulates weak signals against the same entity (user, host, application) over time:

**Example composite triggers:**

*Identity attack chain:*
MFA factor reset (+15) → unfamiliar sign-in within 1 hour (+20) → new OAuth app consent with mail scope (+25) → inbox rule creation (+20) = **80 points → investigation**

*Endpoint post-exploitation:*
ADFind execution (+20) → BloodHound LDAP queries (+15) → ADMIN$ access (+15) → new service installation (+20) = **70 points → high-priority investigation**

*Cloud data theft:*
Service principal creating VM (+20) → same principal generating API key (+20) → outbound data transfer above baseline (+15) → new cloud storage destination (+25) = **80 points → investigation**

### 9.5 Validate Continuously with Purple Team Exercises

Anomaly detection requires continuous validation — models degrade silently due to parser drift, schema changes, exception list growth, and concept drift.

Minimum purple-team scenarios to execute quarterly:
- Password spray simulation (Spray tool or manual) against test accounts — verify Event 4625 clustering detection fires
- Kerberoasting against test SPNs — verify Event 4769 RC4 detection fires
- DCSync against lab DC with Event 4662 auditing — verify detection fires and `SubjectUserName` is correctly captured
- Web-shell installation in test IIS environment — verify Sysmon Event 11 and parent-child detection fire
- Bulk SharePoint download from test site — verify volume anomaly detection fires
- DNS tunneling simulation (dnscat2 or iodine in lab) — verify entropy-based detection fires
- Rclone execution in test environment — verify rare-process detection fires

---

## 10. Conclusion

The hypothesis that malicious activity creates detectable anomaly patterns is substantially true but operationally bounded. The evidence from documented real-world campaigns confirms it:

- SUNBURST created collective DNS anomalies (high-entropy encoded subdomains, dormant-then-periodic timing) — detectable with DNS logging and entropy analytics.
- HAFNIUM created unmistakable parent-child execution anomalies (`w3wp.exe` → `cmd.exe`) — detectable with Sysmon or EDR.
- Conti ransomware created a cascade of detectable signals across every attack phase — ADFind rare-process, ADMIN$ share access, PsExec service installation, VSS deletion, mass file encryption — each individually detectable with properly configured Windows audit logging.
- APT34's DNS tunneling created statistical anomalies in query entropy, length, and TXT record usage — detectable with full DNS telemetry and entropy analytics.
- Kerberoasting, DCSync, and Pass-the-Hash each create specific, structured anomalies in Windows authentication event fields that can be detected with deterministic rules requiring no statistical model at all.

The failure modes are equally documented and predictable. Volt Typhoon demonstrated that LOLBin + valid credentials + SOHO proxy infrastructure can suppress almost every anomaly layer below the level of contextual command-line analysis and cross-source entity correlation. Midnight Blizzard demonstrated that distributed spray defeats per-tenant rate limits. UNC3944 demonstrated that SaaS-native exfiltration bypasses network and endpoint monitoring entirely.

The practical conclusion for detection engineering:

1. **Telemetry first** — no model compensates for missing logs. Command-line logging, Sysmon, SaaS audit, and cloud audit are non-negotiable prerequisites.
2. **Deterministic rules for known-bad patterns** — Kerberoasting, DCSync, PTH, webshell parent-child, VSS deletion do not require statistical anomaly models. Configure the event ID, check the field values, alert.
3. **Anomaly logic for stable, high-value signals** — volumetric exfiltration, beaconing periodicity, DNS entropy, bulk SaaS export above entity baseline — these justify proper ML or statistical modelling.
4. **Risk scoring for composite signals** — accumulate weak individual anomalies (temporal, geographic, peer-group) into entity-level risk scores before triggering investigation.
5. **Provider-native detections for cross-tenant visibility** — Entra Identity Protection's "Password spray" and "Unfamiliar sign-in properties" detections provide coverage that tenant-local analytics structurally cannot replicate.
6. **SaaS and cloud as first-class detection domains** — modern intrusions by UNC3944, Midnight Blizzard, and Storm-0558 live entirely in identity and SaaS layers. Network and endpoint monitoring alone will miss them.

The "Anomaly Paradox" — that the technique best suited to catching unknown threats also generates the highest false positive rates — is resolved through hybrid analytics: anomaly logic applied to tightly-scoped, role-normalised, enriched data, gated by deterministic conditions, and correlated into entity risk scores. That is not a theoretical ideal. It is the operational model reflected in CrowdStrike Falcon's IOA design, Sentinel's UEBA analytics, and the detection engineering guidance published by CISA, NSA, Mandiant, and Microsoft MSTIC.

---

## 11. References

[1] National Institute of Standards and Technology. *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST Special Publication 800-94. February 2007. https://csrc.nist.gov/pubs/sp/800/94/final

[2] Chandola, V., Banerjee, A., and Kumar, V. "Anomaly Detection: A Survey." *ACM Computing Surveys*, 41(3), Article 15, July 2009. https://dl.acm.org/doi/10.1145/1541880.1541882

[3] Mandiant (FireEye). "SUNBURST Additional Technical Details." December 2020. https://www.mandiant.com/resources/sunburst-additional-technical-details

[4] Microsoft Security Response Center / Microsoft Threat Intelligence. "Midnight Blizzard: Guidance for Responders on Nation-State Attack." January 2024. https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/

[5] Microsoft Security Response Center. "HAFNIUM Targeting Exchange Servers with 0-Day Exploits." March 2021. https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

[6] Microsoft Threat Intelligence. "Storm-1283 and Related OAuth Application Abuse Campaigns." Microsoft Security Blog, 2023.

[7] Mandiant. "Responding to Microsoft Exchange Server Zero-Day Vulnerabilities." March 2021.

[8] Mandiant. "UNC3944 Targets SaaS Applications." Google Cloud Security Blog, 2023. https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications

[9] Mandiant. *M-Trends 2025*. Google Cloud Security, 2025. https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025

[10] CISA, NSA, FBI, and partner agencies. "People's Republic of China State-Sponsored Cyber Actor Living off the Land to Evade Detection." Advisory AA24-038A. February 2024. https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a

[11] CISA and NSA. "Guide to Securing Microsoft Windows 10 and Windows 11 Audit and Monitoring Events." 2024. https://www.cisa.gov/resources-tools/resources/guide-securing-microsoft-windows-10-and-windows-11-audit-and-monitoring-events

[12] Australian Cyber Security Centre. "Detecting and Mitigating Active Directory Compromises." 2023. https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-administration/detecting-and-mitigating-active-directory-compromises

[13] The DFIR Report. "BazarCall to Conti Ransomware via Trickbot and Cobalt Strike." August 2021. https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/

[14] Metcalf, S. "Detecting Kerberoasting Activity." ADSecurity.org, 2017. https://adsecurity.org/?p=3458

[15] Black Lantern Security. "Detecting DCSync." 2022. https://blog.blacklanternsecurity.com/p/detecting-dcsync

[16] Binary Defense. "Reliably Detecting Pass the Hash Through Event Log Analysis." 2021. https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis

[17] Palo Alto Unit 42. "Behind the Scenes with OilRig (APT34)." 2019.

[18] CISA. "ALPHV Blackcat Ransomware Advisory." Advisory AA23-353A. December 2023. https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a

[19] CISA. "CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability." Advisory AA23-158A. June 2023. https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a

[20] CISA. "Impacket and Exfiltration Tool Used to Steal Sensitive Information from Defense Industrial Base Organization." Advisory AA22-277A. October 2022. https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-277a

[21] CrowdStrike. "Understanding Indicators of Attack: The Power of Event Stream Processing." CrowdStrike Blog, 2023. https://www.crowdstrike.com/en-us/blog/understanding-indicators-attack-ioas-power-event-stream-processing-crowdstrike-falcon/

[22] Vectra AI. *Cognito Platform — AI-Driven Threat Detection and Response*. Product documentation, 2024. https://www.vectra.ai/products/cognito-platform

[23] Amazon Web Services. "GuardDuty Finding Types." AWS Documentation, 2024. https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html

[24] Microsoft. "Work with Anomaly Detection Analytics Rules in Microsoft Sentinel." Microsoft Learn, 2024. https://learn.microsoft.com/en-us/azure/sentinel/work-with-anomaly-rules
