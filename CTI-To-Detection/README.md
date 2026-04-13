# From Threat Intelligence to Detection: A Practitioner's Guide

**Building atomic, collection, correlational, TTP-based, and anomaly detection rules from real adversary behavior.**

By [Andrey Pautov](https://medium.com/@1200km) — April 2026

---

## Table of Contents

1. [Why IOC-Only Detection Fails](#1-why-ioc-only-detection-fails)
2. [The Three APTs: Profiles and Why They Were Chosen](#2-the-three-apts-profiles-and-why-they-were-chosen)
3. [Detection Taxonomy](#3-detection-taxonomy)
4. [Atomic Event Rules](#4-atomic-event-rules)
5. [Collection-Based Rules](#5-collection-based-rules)
6. [Correlational Rules](#6-correlational-rules)
7. [TTP-Based Rules](#7-ttp-based-rules)
8. [Anomaly Detection Rules](#8-anomaly-detection-rules)
9. [The Detection Chain: Layering All Five Tiers](#9-the-detection-chain-layering-all-five-tiers)
10. [Tuning, Validation, and Measurement](#10-tuning-validation-and-measurement)
11. [Key Sources](#11-key-sources)

---

## 1. Why IOC-Only Detection Fails

The most common detection workflow in threat intelligence consumption looks like this: receive a report, extract IPs, domains, and file hashes, push them into your firewall and EDR blocklist, mark the ticket closed. This is useful as far as it goes — blocked infrastructure is blocked infrastructure — but it answers a question no sophisticated adversary actually leaves unanswered.

IP addresses rotate. Domains age out. Hashes are trivially changed with a recompile or packer swap. A threat actor who has been operating for more than a week has almost certainly burned the IOCs that appear in public reports, because those reports describe what was found *after* the fact. By the time an IOC reaches your blocklist, the adversary has likely already moved.

The problem is structural. IOC-based detection operates at the very bottom of the [Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) — the layer where changing indicators costs the attacker almost nothing. Effective detection operates higher up the pyramid: at the level of tools, techniques, and ultimately behavioral patterns that are expensive for an adversary to modify because they are derived from operational necessity, not configuration choices.

This guide builds all five layers of detection from the behavior of three well-documented, sophisticated adversary groups. Each layer answers a different question:

| Layer | Question answered | Adversary cost to evade |
|---|---|---|
| **Atomic** | Did this specific thing happen? | Very low — change the artifact |
| **Collection** | Did this type of thing happen repeatedly? | Low-medium — reduce volume, spread time |
| **Correlational** | Did these different things happen in sequence? | Medium — change toolchain or timing |
| **TTP-based** | Did this technique execute regardless of tool? | High — change core operational method |
| **Anomaly** | Did something deviate from baseline behavior? | Very high — requires understanding your environment |

A detection program that only runs at the top row is noisy and incomplete. One that only runs at the bottom row misses everything that has rotated its indicators. The goal is to run all five layers simultaneously, with increasing alert confidence as you move up.

---

## 2. The Three APTs: Profiles and Why They Were Chosen

Three adversary groups were selected on four criteria: technical sophistication, public reporting depth, operational diversity, and breadth of TTPs that generate useful detection examples across all five layers.

---

### 2.1 APT29 — Midnight Blizzard / Cozy Bear (Russia, SVR)

**Classification:** Russian Foreign Intelligence Service (SVR), active since at least 2008  
**MITRE ATT&CK:** [G0016](https://attack.mitre.org/groups/G0016/)  
**Primary mission:** Long-duration strategic espionage — government, diplomatic, think tank, and technology targets  

**Why chosen:** APT29 is the canonical example of a patient, low-and-slow actor that lives almost entirely off legitimate infrastructure and signed tooling. Their 2019-2020 SolarWinds supply-chain operation (SUNBURST/TEARDROP) remains one of the most technically documented intrusions in open reporting. Their 2023-2024 Microsoft corporate network compromise via OAuth device-code phishing and application impersonation is thoroughly reported by Microsoft MSTIC. They generate rich examples for: supply chain detection, OAuth and SAML abuse, living-off-the-land detection, and long-dwell behavioral anomalies.

**Key campaigns and public reporting:**
- **SUNBURST (SolarWinds):** FireEye/Mandiant Dec 2020, CISA AA20-352A, Microsoft MSTIC Dec 2020
- **NOBELIUM / OAuth abuse:** Microsoft MSTIC Oct 2021, May 2023, Jan 2024
- **Golden SAML:** CyberArk research, Mandiant 2021 follow-up
- **WellMess / WellMail:** UK NCSC Jul 2020 advisory

**Core TTP profile:**
- T1195.002 — Supply chain compromise via software build system
- T1078.004 — Valid cloud accounts (Azure AD, M365)
- T1550.001 — Application access token abuse
- T1556.006 — Modify authentication process (Golden SAML)
- T1059.001 — PowerShell
- T1021.002 — SMB/WMI lateral movement
- T1560.001 — Archive collected data
- T1071.001 — Web protocols for C2 (HTTP/S to legitimate cloud services)

---

### 2.2 APT41 — Double Dragon / Winnti (China, MSS-linked)

**Classification:** China Ministry of State Security contractor/affiliated group, active since at least 2012  
**MITRE ATT&CK:** [G0096](https://attack.mitre.org/groups/G0096/)  
**Primary mission:** Dual — state-directed espionage AND financially motivated cybercrime (ransomware, cryptocurrency theft, virtual goods)  

**Why chosen:** APT41 is the clearest documented case of a single group conducting both state espionage and opportunistic cybercrime. Their toolset is wide, their targeting is broad, and their TTPs are well-documented across multiple vendor reports and U.S. DOJ indictments (2019, 2020). They generate excellent examples of: exploitation chain detection, supply chain DLL hijacking, custom malware staging, living-off-the-land with LOLBins, and multi-phase intrusion correlation.

**Key campaigns and public reporting:**
- **Operation ShadowHammer (ASUS Live Update):** Kaspersky Apr 2019
- **Healthcare/COVID research targeting:** FBI-CISA May 2020
- **Citrix/ManageEngine exploitation wave:** Mandiant 2022-2023
- **DOJ indictments:** Sep 2019 (two defendants), Sep 2020 (five defendants)
- **KEYPLUG / DEADEYE / DUSTPAN malware family:** Mandiant Apr 2022

**Core TTP profile:**
- T1190 — Exploit public-facing application (Citrix, ManageEngine, Log4Shell)
- T1505.003 — Web shell deployment
- T1574.002 — DLL side-loading (very characteristic of this group)
- T1036.005 — Match legitimate name or location (masquerading)
- T1055 — Process injection
- T1003.001 — LSASS memory dump
- T1021.006 — WinRM lateral movement
- T1567.002 — Exfiltration to cloud storage

---

### 2.3 Lazarus Group — HIDDEN COBRA / Diamond Sleet / TraderTraitor (DPRK, RGB)

**Classification:** North Korean Reconnaissance General Bureau (RGB), active since at least 2009  
**MITRE ATT&CK:** [G0032](https://attack.mitre.org/groups/G0032/)  
**Primary mission:** Revenue generation for the DPRK regime (cryptocurrency theft, financial fraud, sanctions evasion) AND targeted espionage (defense, nuclear, aerospace)

**Why chosen:** Lazarus provides the richest set of social-engineering-to-intrusion chain examples and is uniquely documented for financial system targeting. Operation Dream Job (fake LinkedIn recruitment), AppleJeus (trojanized crypto software), and the 3CX supply chain compromise give concrete cases for initial access detection. TraderTraitor is documented extensively by CISA, FBI, and the UN Panel of Experts. They generate excellent examples of: initial access via social engineering, cross-platform malware, BYOVD (bring-your-own-vulnerable-driver), and financial API abuse.

**Key campaigns and public reporting:**
- **Operation AppleJeus:** Kaspersky Aug 2018, CISA Apr 2021 advisory (AA21-048A)
- **Operation Dream Job:** ClearSky Jan 2020, Mandiant 2022 follow-up
- **TraderTraitor (crypto targeting):** CISA/FBI/Treasury Apr 2022, FBI Mar 2023
- **3CX Supply Chain:** Mandiant/CrowdStrike Apr 2023
- **BYOVD (Dell DBUtil / POORTRY):** Mandiant Aug 2022, Microsoft Oct 2022
- **UN Panel of Experts reports:** 2021, 2022, 2023

**Core TTP profile:**
- T1566.002 — Spear-phishing link (LinkedIn, email with weaponized PDF/ZIP)
- T1204.002 — User execution of malicious file
- T1195.002 — Supply chain compromise (3CX, trading software)
- T1014 — Rootkit (BYOVD with POORTRY/WHIPEDOUT)
- T1059.001 / T1059.003 — PowerShell and cmd scripting
- T1041 / T1071.001 — Exfiltration and C2 over HTTPS
- T1657 — Financial theft (cryptocurrency exchange API abuse)
- T1070.004 — File deletion / indicator removal

---

## 3. Detection Taxonomy

Before building rules, it helps to be precise about what each tier detects and what data sources it requires.

### Detection Layer Definitions

**Atomic Event Rules** match a single telemetry event against a known-bad signature. The logic is essentially: `IF event.field == bad_value THEN alert`. No context required, no lookback, no correlation. Fastest to write, fastest to evade.

**Collection-Based Rules** aggregate multiple events of the *same type* over a time window and alert when a threshold is crossed: `IF count(event_type, 10 minutes) > threshold THEN alert`. These detect volume-based techniques like brute force, port scanning, or bulk data staging.

**Correlational Rules** join *different* event types — process creation, network connection, file write, authentication — in a temporal sequence tied to a common entity (host, user, process). They model cause-and-effect chains: the attacker did A, then B, then C. Changing any one link breaks the rule; changing all three breaks the campaign.

**TTP-Based Rules** detect a *technique*, not a specific tool implementing that technique. A TTP-based rule for credential dumping fires whether the actor uses Mimikatz, ProcDump, comsvcs.dll, or a custom tool — because all of them must access LSASS memory in a way that leaves a detectable behavioral footprint, regardless of file hash.

**Anomaly Detection Rules** establish a behavioral baseline per entity (user, host, service account, application) and alert on statistically significant deviations. They require historical data, a meaningful baseline period, and tolerance tuning. They are the hardest to build, the noisiest when poorly tuned, and the hardest for an adversary to evade in a well-baselned environment.

### Required Log Sources by Layer

| Layer | Minimum log sources | Ideal additions |
|---|---|---|
| Atomic | EDR process/file/network events, Firewall/Proxy logs | DNS logs, email gateway, AV telemetry |
| Collection | Authentication logs, network flow, endpoint process logs | DHCP, VPN, cloud audit logs |
| Correlational | All of the above, unified in a SIEM with entity resolution | UEBA, asset inventory |
| TTP-based | Sysmon (Windows), auditd (Linux), EDR with telemetry, cloud API logs | Memory forensics, kernel telemetry |
| Anomaly | Baseline telemetry (30+ days), UEBA or ML platform | Enriched entity context, HR/identity data |

All detection rules in this guide are written in **Sigma** format unless the logic requires a specific platform (noted where used). Sigma is SIEM-agnostic and can be transpiled to Splunk SPL, Microsoft Sentinel KQL, Elastic EQL, and others via `sigma-cli`.

---

## 4. Atomic Event Rules

Atomic rules are the foundation. They are fast, deterministic, and directly traceable to a specific observable from a threat report. The key discipline is: **every atomic rule must cite its source**, have a defined false-positive profile, and be reviewed for continued relevance because indicators age out.

### 4.1 APT29 — SUNBURST DLL Loaded by SolarWinds Process

SUNBURST was delivered as a trojanized update to `SolarWinds.Orion.Core.BusinessLayer.dll`. The backdoor checked for the presence of specific security tools and domains before activating, with a dormancy period of up to two weeks. The most reliable atomic indicator during initial triage was the combination of parent process, DLL path, and subsequent DNS activity.

```yaml
title: SUNBURST Backdoor DLL Load - SolarWinds Orion
id: 4a3f1c2e-8b7d-4e9f-a2c5-1d6e8f3b7a4c
status: stable
description: >
  Detects the loading of the trojanized SolarWinds Orion business layer DLL
  associated with the SUNBURST backdoor (APT29/Midnight Blizzard).
  The legitimate DLL was replaced with a backdoored version during the
  supply chain compromise discovered in December 2020.
references:
  - https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
  - https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
author: Detection Engineering
date: 2020-12-14
modified: 2024-01-01
tags:
  - attack.initial_access
  - attack.t1195.002
  - apt29
  - sunburst
logsource:
  category: image_load
  product: windows
detection:
  selection:
    ImageLoaded|endswith: '\SolarWinds.Orion.Core.BusinessLayer.dll'
    Image|endswith: '\SolarWinds\Orion\SolarWinds.BusinessLayerHost.exe'
  filter_legitimate_hash:
    # Hashes of known-good DLL versions - maintain and update this list
    ImageLoaded|contains: '\SolarWinds\Orion\'
  condition: selection
falsepositives:
  - Legitimate SolarWinds Orion updates — verify DLL hash against known-good
    values from vendor. Alert on any hash NOT in your approved baseline.
level: high
```

**Detection note:** The hash check is intentionally omitted from the core detection logic — instead the rule fires on the parent/child relationship, and your triage workflow should compare the loaded DLL hash against vendor-supplied known-good hashes. This means the rule survives a packer-modified variant.

---

### 4.2 APT41 — Web Shell Creation in IIS Web Root

APT41 consistently deploys web shells immediately after exploiting public-facing applications (Citrix, ManageEngine, Exchange). The shell is written to the web root by the compromised web application process. This is one of the highest-fidelity single-event detections available for this actor.

```yaml
title: Web Shell Created by IIS Worker Process
id: 7b2e4f1a-3c9d-4b8e-f1a7-2e5c8d3b6f9a
status: stable
description: >
  Detects file creation of known web shell extensions in IIS web root paths
  by the IIS worker process (w3wp.exe). APT41 consistently uses this pattern
  immediately after exploiting public-facing applications. This is a high-confidence
  indicator of post-exploitation web shell deployment.
references:
  - https://www.mandiant.com/resources/blog/apt41-us-state-governments
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-277a
author: Detection Engineering
date: 2022-03-15
tags:
  - attack.persistence
  - attack.t1505.003
  - apt41
logsource:
  category: file_event
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\w3wp.exe'
      - '\tomcat.exe'
      - '\java.exe'
  selection_extension:
    TargetFilename|endswith:
      - '.aspx'
      - '.asp'
      - '.ashx'
      - '.asmx'
      - '.php'
      - '.jsp'
      - '.jspx'
  selection_path:
    TargetFilename|contains:
      - '\inetpub\wwwroot\'
      - '\Inetpub\wwwroot\'
      - '\wwwroot\'
  filter_legitimate:
    TargetFilename|contains:
      - '\App_Data\'
      - '\obj\'
  condition: selection_process and selection_extension and selection_path and not filter_legitimate
falsepositives:
  - Application deployments by legitimate CI/CD pipelines using the same process
  - Content management system uploads (if CMS runs under w3wp.exe)
  - Mitigate with change-window allowlisting
level: critical
```

---

### 4.3 Lazarus — Trojanized Installer Executed from User Download Path

Lazarus's AppleJeus and Dream Job operations deliver trojanized installers to targets, typically via spear-phishing or fake LinkedIn job offers. The trojanized application is executed from a user download or temp path and immediately spawns a child process inconsistent with the legitimate application behavior.

```yaml
title: Suspicious Installer Spawning Unexpected Child Process
id: 9c4e2a7f-5d1b-4c8e-b3f6-7a2e9d4c1b8f
status: experimental
description: >
  Detects installer-type executables (MSI, NSIS-style) spawning unexpected
  child processes from user-writable paths. Characteristic of Lazarus Group
  trojanized installer delivery (AppleJeus, Dream Job operations).
  The trojanized installer appears legitimate but spawns a second-stage dropper.
references:
  - https://securelist.com/operation-applejeus/87553/
  - https://www.cisa.gov/sites/default/files/publications/AppleJeus_Report_508.pdf
author: Detection Engineering
date: 2021-05-01
tags:
  - attack.execution
  - attack.t1204.002
  - attack.initial_access
  - attack.t1566.002
  - lazarus
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\msiexec.exe'
      - '\setup.exe'
      - '\install.exe'
      - '\installer.exe'
    ParentCommandLine|contains:
      - '\Users\'
      - '\AppData\Local\Temp\'
      - '\Downloads\'
  selection_suspicious_child:
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
  condition: selection_parent and selection_suspicious_child
falsepositives:
  - Legitimate software installers that invoke PowerShell for post-install config
  - Suppress with signed-installer allowlist (verify Authenticode chain)
level: high
```

---

### 4.4 APT29 — TEARDROP Execution via Encoded Command

TEARDROP was APT29's second-stage memory-only dropper used to load Cobalt Strike Beacons after SUNBURST. It was observed executing via heavily encoded PowerShell commands. The following rule detects the specific encoding pattern combined with a suspicious parent relationship.

```yaml
title: Heavily Encoded PowerShell with Suspicious Parent (TEARDROP Pattern)
id: 2f8a1c4e-6d3b-4f7a-c2e8-5b1d4f8c3e7a
status: stable
description: >
  Detects PowerShell executing with base64-encoded commands and suspicious
  parent processes. Associated with APT29 TEARDROP dropper behavior
  post-SUNBURST compromise. The combination of encoded command, explicit
  bypass flags, and non-standard parent is highly suspicious.
references:
  - https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack/
author: Detection Engineering
date: 2020-12-20
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
  - apt29
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - ' -EncodedCommand '
      - ' -enc '
      - ' -e '
  selection_bypass:
    CommandLine|contains:
      - '-ExecutionPolicy Bypass'
      - '-ep bypass'
      - '-nop'
      - '-NonInteractive'
  selection_suspicious_parent:
    ParentImage|endswith:
      - '\SolarWinds.BusinessLayerHost.exe'
      - '\mmc.exe'
      - '\wbem\WmiPrvSE.exe'
      - '\services.exe'
  condition: selection_powershell and selection_encoded and selection_bypass and selection_suspicious_parent
falsepositives:
  - Legitimate management tools using encoded PowerShell for config tasks
  - Baseline against known-good management automation before deploying
level: high
```

---

## 5. Collection-Based Rules

Collection rules introduce temporal context. Rather than a single event, they watch for a pattern of events of the same type accumulating over a time window. The key design decisions are: what to count, what entity to group by, and what threshold to use.

Thresholds should be derived from your baseline, not invented. If you don't know your normal authentication failure rate, you will either miss attacks or generate constant noise.

### 5.1 APT29 — Spike in OAuth Token Requests from a New IP

APT29's 2023-2024 Microsoft intrusion abused OAuth device-code flow to obtain tokens for Microsoft Graph API access. The pattern involved a single source IP generating many token requests across multiple accounts. A collection rule catches the volume before a correlational rule catches the sequence.

```yaml
title: OAuth Token Request Spike from Single Source IP
id: 1e3c7f9a-4b2d-4e8c-f7a3-9c1e4b7f2d8a
status: stable
description: >
  Detects an unusually high volume of OAuth2 token requests originating from
  a single IP address within a short time window. APT29 used this pattern
  in device-code phishing campaigns targeting M365 and Azure AD tenants.
  Baseline your normal token-request rate before setting thresholds.
references:
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
  - https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/
author: Detection Engineering
date: 2024-01-26
tags:
  - attack.credential_access
  - attack.t1528
  - attack.initial_access
  - attack.t1566
  - apt29
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    ResultType: '0'  # Successful token issuance
    TokenIssuerType: 'AzureAD'
    AuthenticationProtocol: 'deviceCode'
  timeframe: 10m
  condition: selection | count(UserPrincipalName) by IPAddress > 5
falsepositives:
  - Automated provisioning workflows performing device enrollment
  - VPN concentrators appearing as single IP for many users
  - Tune threshold based on 30-day baseline per source IP
level: high

# Splunk equivalent:
# index=azure_signinlogs ResultType=0 AuthenticationProtocol=deviceCode
# | bucket _time span=10m
# | stats dc(UserPrincipalName) as unique_users by _time, IPAddress
# | where unique_users > 5
```

---

### 5.2 APT41 — Repeated Exploitation Attempts Against Same Service

APT41 systematically probes and exploits public-facing services. Their pattern frequently shows multiple exploitation payloads in rapid succession against the same endpoint — testing different bypass variants — before a successful shell. A collection rule on WAF/IDS events or web server error logs catches this preparatory phase.

```yaml
title: Repeated Web Application Exploitation Attempts from Single Source
id: 3d7b2e5a-8f1c-4d9e-a3b7-2f5c8d1e4b7f
status: stable
description: >
  Detects multiple web application exploitation attempt signatures
  (SQL injection, command injection, path traversal, deserialization)
  originating from a single IP against the same target within a short window.
  Characteristic of APT41 pre-exploitation enumeration against Citrix,
  ManageEngine, and Exchange endpoints.
references:
  - https://www.mandiant.com/resources/blog/apt41-initiates-global-intrusion-campaign-using-multiple-exploits
author: Detection Engineering
date: 2022-06-01
tags:
  - attack.initial_access
  - attack.t1190
  - apt41
logsource:
  category: webserver
  product: apache  # adjust for nginx, IIS
detection:
  selection_exploit_pattern:
    sc-status:
      - '400'
      - '403'
      - '404'
      - '500'
    cs-uri-query|contains:
      - '../'
      - '%2e%2e'
      - 'cmd='
      - 'exec('
      - '${jndi:'
      - 'union+select'
      - 'eval('
      - 'Runtime.exec'
  timeframe: 5m
  condition: selection_exploit_pattern | count() by c-ip > 10
falsepositives:
  - Legitimate penetration tests (coordinate with red team schedule)
  - Vulnerability scanners (allowlist known scanner IPs)
level: high
```

---

### 5.3 Lazarus — Bulk File Staging Before Exfiltration

Before exfiltrating cryptocurrency wallet files or financial documents, Lazarus operators stage data by compressing it into archives. A collection rule watching for rapid creation of multiple archive files by a single process catches this staging behavior regardless of the specific archiver used.

```yaml
title: Bulk Archive Creation Suggesting Data Staging
id: 6f2a4c8e-1b9d-4f3a-e8c2-4b7f1d6c9e2a
status: stable
description: >
  Detects rapid creation of multiple archive files (ZIP, 7z, RAR, tar) by
  a single non-standard process. Lazarus Group consistently stages data into
  compressed archives prior to exfiltration. This rule catches the staging
  phase before exfiltration begins.
references:
  - https://www.cisa.gov/sites/default/files/2023-04/aa23-108a_joint_csa_dprk_cryptocurrency_theft_0.pdf
author: Detection Engineering
date: 2023-04-20
tags:
  - attack.collection
  - attack.t1560.001
  - attack.exfiltration
  - lazarus
logsource:
  category: file_event
  product: windows
detection:
  selection_archive:
    TargetFilename|endswith:
      - '.zip'
      - '.7z'
      - '.rar'
      - '.tar'
      - '.tar.gz'
      - '.tgz'
  filter_legitimate_archivers:
    Image|endswith:
      - '\7z.exe'
      - '\WinRAR.exe'
      - '\WinZip.exe'
  timeframe: 3m
  condition: selection_archive and not filter_legitimate_archivers | count(TargetFilename) by Image > 5
falsepositives:
  - Backup software creating many archives rapidly
  - CI/CD build pipelines packaging artifacts
  - Allowlist known backup and build process images
level: medium
```

---

## 6. Correlational Rules

Correlational rules are where detection becomes genuinely difficult for an adversary to evade without restructuring their operation. They require a SIEM capable of joining events across different log sources on a common entity — typically hostname, username, or process ID — within a defined time window.

The discipline here is choosing the right entities for joining and keeping correlation windows tight enough to reduce noise but wide enough to capture the actual technique timing.

### 6.1 APT29 — OAuth Token Grant Followed by Immediate Privileged Graph API Access

The 2024 Midnight Blizzard intrusion into Microsoft's corporate network followed a specific sequence: device-code phishing → token grant → immediate access to Microsoft Graph API for email and file enumeration. The correlation across authentication logs and application activity logs is highly specific.

```yaml
title: OAuth Token Grant Followed by Immediate Microsoft Graph Privileged Access
id: 8a3f1e6c-2d4b-4f8a-c1e3-6f8b3d2e5c7a
status: stable
description: >
  Correlates an OAuth2 token grant via device-code flow with immediate
  subsequent access to privileged Microsoft Graph API endpoints (mail,
  directory, files) from the same IP within a short window.
  This sequence is characteristic of APT29 post-phishing reconnaissance.
  A legitimate user who just authenticated should not immediately enumerate
  directory objects and read mail from an unfamiliar IP.
references:
  - https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/
  - https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
author: Detection Engineering
date: 2024-01-28
tags:
  - attack.credential_access
  - attack.t1528
  - attack.discovery
  - attack.t1087.004
  - apt29
# This rule requires correlation between Azure AD Sign-In Logs
# and Microsoft Graph Activity Logs in Microsoft Sentinel

# KQL implementation (Microsoft Sentinel):
# let TokenGrants = SigninLogs
#     | where AuthenticationProtocol == "deviceCode"
#     | where ResultType == 0
#     | project TokenTime=TimeGenerated, IPAddress, UserPrincipalName, CorrelationId;
# let GraphAccess = MicrosoftGraphActivityLogs
#     | where RequestUri has_any ("/me/messages", "/users", "/me/drive", "/directory")
#     | where ResponseStatusCode between (200 .. 299)
#     | project GraphTime=TimeGenerated, IPAddress, UserPrincipalName=UserId, RequestUri;
# TokenGrants
# | join kind=inner (GraphAccess) on IPAddress, UserPrincipalName
# | where GraphTime between (TokenTime .. (TokenTime + 5m))
# | project TokenTime, GraphTime, IPAddress, UserPrincipalName, RequestUri, CorrelationId

falsepositives:
  - Legitimate users immediately accessing email after OAuth grant on new device
  - Allowlist known corporate IP ranges and managed device identifiers
level: critical
```

---

### 6.2 APT41 — Exploitation → Web Shell → Lateral Movement Chain

APT41's intrusion pattern is highly predictable: exploit a public-facing service, write a web shell, use the web shell to execute discovery commands, then move laterally via WMI or WinRM. Each step leaves traces in different log sources; the correlational rule joins them.

```yaml
title: Web Shell Execution Leading to Network Lateral Movement
id: 4c8e2a1f-7b3d-4c9e-f2a8-1c4e7b3f6d9a
status: stable
description: >
  Correlates three-phase APT41 intrusion pattern:
  Phase 1 - Web shell file created under web server process
  Phase 2 - Discovery commands executed by web application process
  Phase 3 - Lateral movement via WMI or WinRM from the same host
  within a 30-minute window.
  Each phase alone may be ambiguous; the three-phase sequence is
  high-confidence for APT41-style post-exploitation.
references:
  - https://www.mandiant.com/resources/blog/apt41-us-state-governments
  - https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-associates-charged-connection-computer
author: Detection Engineering
date: 2022-09-15
tags:
  - attack.persistence
  - attack.t1505.003
  - attack.discovery
  - attack.t1016
  - attack.lateral_movement
  - attack.t1021.006
  - apt41

# Splunk implementation:
# Phase 1 - Web shell creation
# index=sysmon EventCode=11 Image IN ("*\\w3wp.exe","*\\java.exe")
#   TargetFilename IN ("*.aspx","*.php","*.jsp")
#   | eval phase1_time=_time, host_key=host
#   | table host_key, phase1_time, TargetFilename
#
# Phase 2 - Discovery execution from web process (within 5 min of phase 1)
# index=sysmon EventCode=1
#   ParentImage IN ("*\\w3wp.exe","*\\java.exe")
#   Image IN ("*\\whoami.exe","*\\net.exe","*\\ipconfig.exe","*\\nltest.exe")
#   | eval phase2_time=_time, host_key=host
#
# Phase 3 - WMI/WinRM lateral movement (within 30 min of phase 1)
# index=sysmon EventCode=3
#   Image IN ("*\\wmiprvse.exe","*\\wsmprovhost.exe")
#   DestinationPort IN ("5985","5986","135")
#   NOT DestinationIp IN (cidrMatch("10.0.0.0/8"), cidrMatch("192.168.0.0/16"))
#   | eval phase3_time=_time, host_key=host
#
# Join all three phases on host within 30m window

falsepositives:
  - Legitimate application deployments that write ASPX and then run diagnostics
  - Coordinate with change management to suppress during planned deployments
level: critical
```

---

### 6.3 Lazarus — Spear Phish Execution → Persistence → C2 Beacon

Dream Job and TraderTraitor operations follow a documented sequence: user opens a weaponized document or installer, a dropper establishes persistence (Run key or scheduled task), and then a C2 beacon makes its first outbound connection. The correlational rule joins process creation, registry modification, and network events.

```yaml
title: Suspicious Document Execution Chain to Persistence and C2
id: 7a1e4c2f-9d3b-4e7a-c1f4-2e9c7b3a6f1d
status: experimental
description: >
  Correlates Lazarus Dream Job / TraderTraitor delivery chain:
  Stage 1 - Office or PDF process spawns unexpected child (macro/exploit execution)
  Stage 2 - Child process creates Run key or scheduled task (persistence)
  Stage 3 - A new process beacons to an external IP on non-standard port
  All three stages linked by parent-child process relationship on same host
  within a 15-minute window.
references:
  - https://www.clearskysec.com/operation-dream-job/
  - https://www.cisa.gov/sites/default/files/2023-04/aa23-108a_joint_csa_dprk_cryptocurrency_theft_0.pdf
author: Detection Engineering
date: 2023-05-01
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.persistence
  - attack.t1547.001
  - attack.command_and_control
  - attack.t1071.001
  - lazarus

# EQL (Elastic) implementation:
# sequence with maxspan=15m by host.name
#   [process where process.parent.name in ("WINWORD.EXE","EXCEL.EXE","AcroRd32.exe","msiexec.exe")
#      and process.name in ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")]
#   [registry where registry.path like~ "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
#      and process.name in ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","reg.exe")]
#   [network where network.direction == "egress"
#      and not cidrMatch(destination.ip, "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
#      and destination.port not in (80, 443)]

falsepositives:
  - Macro-enabled Office templates that legitimately modify Run keys (rare)
  - Software installers using Office interop
  - Verify Authenticode chain on the parent process
level: critical
```

---

## 7. TTP-Based Rules

TTP-based detection is the most durable layer. A rule that detects a technique survives tool changes, infrastructure rotation, and even operator changes within a group. The core insight: **every technique has a minimum behavioral footprint that no implementation can fully avoid**, because the footprint is determined by what the technique does to the operating system, not by how it does it.

### 7.1 LSASS Memory Access — Credential Dumping (T1003.001)

All three APTs use credential dumping. APT29 uses Mimikatz variants and custom tooling. APT41 uses ProcDump and comsvcs.dll. Lazarus uses custom LSASS readers. All of them must open a handle to `lsass.exe` with read-memory access rights. The TTP rule catches all variants.

```yaml
title: LSASS Memory Read Access by Non-System Process
id: 5e2c7a3f-1b8d-4e5c-a3f7-8c2e5b1d4a7f
status: stable
description: >
  Detects processes opening a handle to LSASS with memory-read access rights.
  This is the universal footprint of LSASS-based credential dumping regardless
  of the specific tool used — Mimikatz, ProcDump, comsvcs.dll MiniDump,
  custom loaders, or any other implementation must all open this handle.
  Used by APT29, APT41, and Lazarus Group in documented operations.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://www.microsoft.com/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/
author: Detection Engineering
date: 2023-01-10
tags:
  - attack.credential_access
  - attack.t1003.001
  - apt29
  - apt41
  - lazarus
logsource:
  category: process_access
  product: windows
  service: sysmon
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'   # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
      - '0x1410'   # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE
      - '0x143a'   # typical Mimikatz
      - '0x1fffff' # PROCESS_ALL_ACCESS
      - '0x1f3fff' # PROCESS_ALL_ACCESS (older)
  filter_legitimate:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\csrss.exe'
      - '\werfault.exe'
      - '\taskmgr.exe'   # remove if you don't allow task manager
      - '\svchost.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - EDR agents themselves (add your EDR process to filter_legitimate)
  - Windows Error Reporting accessing LSASS during a crash
  - AV scanning LSASS memory (rare but possible)
level: critical
```

---

### 7.2 DLL Side-Loading — Characteristic APT41 Technique (T1574.002)

APT41 is one of the most consistent users of DLL side-loading in documented threat activity. The technique requires a signed legitimate executable loading an unsigned or attacker-controlled DLL from the same directory. The TTP rule detects this regardless of which signed binary is abused.

```yaml
title: Signed Executable Loading Unsigned DLL from Non-Standard Path
id: 2b7f4e1a-6c3d-4b8f-e1a2-7c4b6d3f8e1a
status: stable
description: >
  Detects a signed, legitimate executable loading an unsigned DLL from
  a user-writable or non-standard path. DLL side-loading (T1574.002) is
  a signature technique of APT41 and is used to execute malicious code
  under the cover of a trusted process. This rule does not care which
  binary is abused — it catches the structural pattern.
references:
  - https://www.mandiant.com/resources/blog/apt41-dual-espionage-and-cyber-crime-operation
  - https://attack.mitre.org/techniques/T1574/002/
author: Detection Engineering
date: 2022-07-20
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1574.002
  - apt41
logsource:
  category: image_load
  product: windows
detection:
  selection_signed_binary:
    Signed: 'true'
    SignatureStatus: 'Valid'
  selection_unsigned_dll:
    ImageLoaded|startswith:
      - 'C:\Users\'
      - 'C:\ProgramData\'
      - 'C:\Windows\Temp\'
      - 'C:\Temp\'
    ImageLoaded|endswith: '.dll'
  filter_dll_signed:
    # The loaded DLL itself is signed — not side-loading
    DllSigned: 'true'
  filter_known_paths:
    ImageLoaded|contains:
      - '\AppData\Local\Microsoft\'
      - '\AppData\Local\Google\'
  condition: selection_signed_binary and selection_unsigned_dll and not filter_dll_signed and not filter_known_paths
falsepositives:
  - Legitimate applications that ship with unsigned helper DLLs in user paths
  - Some Python distributions load unsigned DLLs
  - Build a signed DLL allowlist for your environment
level: high
```

---

### 7.3 Bring Your Own Vulnerable Driver — Lazarus POORTRY/WHIPEDOUT (T1014)

Lazarus used a Dell-signed but vulnerable driver (`DBUtil_2_3.sys`, later `POORTRY`) to disable EDR processes from kernel space. The universal footprint: a legitimate-but-vulnerable driver is loaded by a non-OS process, followed shortly by a security tool being terminated. This TTP rule chains the driver load to the subsequent service/process termination.

```yaml
title: Vulnerable Driver Load Followed by Security Tool Termination (BYOVD)
id: 9e3f6a2c-4d1b-4e9f-c2a6-3e8f1b4c7d2e
status: experimental
description: >
  Detects the Bring Your Own Vulnerable Driver (BYOVD) pattern used by
  Lazarus Group: a known-vulnerable or non-standard driver is loaded,
  followed by termination of a security product process. POORTRY and
  WHIPEDOUT were used to kill EDR agents from kernel space.
  This rule requires driver load telemetry (Sysmon Event ID 6) and
  process termination events.
references:
  - https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware
  - https://www.microsoft.com/en-us/security/blog/2022/10/19/hunting-for-kernel-driver-abuse/
  - https://attack.mitre.org/techniques/T1014/
author: Detection Engineering
date: 2022-11-01
tags:
  - attack.defense_evasion
  - attack.t1014
  - attack.t1562.001
  - lazarus
logsource:
  category: driver_load
  product: windows
  service: sysmon

# Part 1: Known vulnerable driver hashes (update regularly from LoLDrivers.io)
detection:
  selection_vuln_driver:
    Hashes|contains:
      # Dell DBUtil
      - 'SHA256=0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5'
      # POORTRY variants (illustrative — maintain updated list)
      - 'SHA256=a4bc07e4f52a4402bde10979e2abb6e4f2462e24a0f02e7a3a5e1c3ae0d4b5f6'
    Signed: 'true'
    SignatureStatus: 'Valid'
  condition: selection_vuln_driver

# Part 2 (correlation): Within 10 minutes, a security product process terminates
# Requires joining with process termination events (Event ID 5/Sysmon 5)
# Target processes to watch:
#   MsMpEng.exe, CSFalconService.exe, CylanceSvc.exe, cb.exe, SentinelAgent.exe

falsepositives:
  - Legitimate use of vulnerable drivers by old software (patch or remove)
  - Maintain LoLDrivers.io blocklist in your driver control policy
level: critical

# Supplementary: Use Windows Defender Application Control (WDAC) or
# Microsoft Vulnerable Driver Blocklist to prevent the load entirely.
```

---

### 7.4 Golden SAML — APT29 Authentication Bypass (T1556.006)

Golden SAML attacks forge SAML assertions to authenticate as any user in federated identity environments. APT29 used this after compromising ADFS signing certificates. The behavioral footprint: a SAML authentication succeeds from an IP and device that have no prior authentication history, with no corresponding MFA event, for a highly privileged account.

```yaml
title: SAML Authentication Without Prior MFA and From New Location
id: 3c9e7a1f-5b4d-4c8e-f9a3-1c7e4b2f5d8a
status: stable
description: >
  Detects potential Golden SAML attacks: a SAML-based authentication
  succeeding for a high-privileged account where:
  - No MFA event was recorded in the session
  - The source IP has no prior authentication history for this user
  - The authentication bypasses Conditional Access policies that should apply
  APT29 used this after exfiltrating ADFS token-signing certificates.
references:
  - https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-services
  - https://www.mandiant.com/resources/blog/detecting-aws-access-key-misuse
author: Detection Engineering
date: 2021-03-01
tags:
  - attack.credential_access
  - attack.t1556.006
  - attack.defense_evasion
  - apt29

# KQL (Microsoft Sentinel):
# SigninLogs
# | where AuthenticationRequirement != "multiFactorAuthentication"
# | where ResourceDisplayName contains "Federation"
# | where ConditionalAccessStatus == "notApplied"
# | where HomeTenantId != ResourceTenantId  // cross-tenant federation sign-in
# | join kind=leftanti (
#     SigninLogs
#     | where TimeGenerated > ago(30d)
#     | summarize PreviousLogins=count() by UserPrincipalName, IPAddress
#     | where PreviousLogins > 0
# ) on UserPrincipalName, IPAddress
# | where UserPrincipalName in (high_priv_accounts)  // maintain this list
# | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location

falsepositives:
  - Legitimate federated sign-ins from new corporate IP ranges
  - Service accounts using certificate-based auth without MFA
  - Review with identity team before deploying
level: critical
```

---

## 8. Anomaly Detection Rules

Anomaly detection moves from "did this specific bad thing happen" to "did this entity behave in a way inconsistent with its established baseline." These rules are the hardest to build, require the most tuning, and produce the most initial noise — but they are also the hardest for a sophisticated adversary to evade in an environment where baselines are maintained.

The prerequisite for every anomaly rule: a meaningful baseline period (minimum 30 days, ideally 90) and a per-entity, not per-environment, baseline. A global threshold on a single metric will catch only the loudest signals.

### 8.1 APT29 — Service Account Accessing Resources at Anomalous Hours

APT29 uses compromised service accounts for long-dwell lateral movement. Service accounts have extremely predictable behavioral patterns — they typically authenticate at the same times, from the same systems, accessing the same resources. Any deviation is high-signal.

```
Anomaly Rule: Service Account Temporal Deviation

Entity: Service account (identified by naming convention, e.g., svc_*, *-sa, *$)
Baseline dimension: Hour-of-day authentication distribution per account
Baseline period: 90 days
Metric: Authentication events per hour
Anomaly condition: Authentication in an hour-bucket with zero or near-zero
                   historical frequency (>3 standard deviations from mean)
                   AND accessing a resource not in the account's access history

Alert payload must include:
  - Account name
  - Source IP
  - Destination resource
  - Time deviation from historical pattern
  - Historical access pattern summary

Implementation note (Splunk MLTK):
  | fit DensityFunction "hour_of_day_auth_count"
      by "ServiceAccountName"
      from base_search
      into model:svc_temporal_model

  | apply model:svc_temporal_model
  | where 'IsOutlier(hour_of_day_auth_count)' = 1

APT29 relevance: Compromised service accounts were used in
  SolarWinds post-compromise for months. The actors authenticated
  outside business hours (UTC+3 working hours observed in several
  Mandiant/CrowdStrike analyses) using accounts that normally only
  authenticated 09:00-17:00 local time.
```

---

### 8.2 APT41 — Vendor Software Loading Anomalous DLL Count

APT41 abuses trusted software by planting DLLs in the application directory. A legitimate application's DLL load profile is highly stable across versions — the same DLLs, from the same paths, in roughly the same order. A sudden expansion in the number or diversity of loaded DLLs from a vendor application is an anomaly that survives hash rotation.

```
Anomaly Rule: Vendor Application DLL Load Profile Deviation

Entity: (Vendor application executable, host)
Baseline dimension:
  - Count of unique DLLs loaded per session
  - Distribution of DLL signing status (% signed by vendor cert)
  - Distribution of DLL load paths (% from application directory)
Baseline period: 60 days
Anomaly conditions (any one triggers):
  - DLL count per session > mean + 2 SD
  - % unsigned DLLs in session > mean + 3 SD
  - Any DLL loaded from a user-writable path that has zero historical
    frequency for this (application, host) pair

Vendor applications to prioritize:
  - Security tools (AV, VPN clients, backup agents)
  - Business applications with wide network access
  - IT management tools (SCCM agents, monitoring agents)

Implementation note:
  Build a rolling 60-day profile per (ImageLoaded parent, host) pair.
  For each new ImageLoad event, compare against the profile.
  Statistical threshold: flag any DLL where frequency in baseline < 1%.

APT41 relevance: KEYPLUG, DEADEYE, and DUSTPAN were all delivered
  via DLL side-loading into legitimate vendor applications.
  The vendor binary was signed and trusted; the sideloaded DLL was not
  in the application's historical load profile.
```

---

### 8.3 Lazarus — Cryptocurrency Process Accessing Financial API Endpoints

TraderTraitor and AppleJeus operations target cryptocurrency exchange employees and software. Once access is gained, operators use the victim's legitimate credentials and applications to interact with exchange APIs. An anomaly rule on the volume, timing, and destination of financial API calls from a user's session can detect this — a user who normally executes 5-10 trades per day suddenly executing hundreds, or doing so at 3AM local time.

```
Anomaly Rule: User Financial API Call Volume and Timing Deviation

Entity: User account (tied to exchange employee or crypto software user)
Baseline dimensions:
  - Daily volume of API calls to trading/withdrawal endpoints
  - Time-of-day distribution of API calls
  - Geographic origin of API calls (IP geolocation)
  - Device fingerprint consistency
Baseline period: 90 days

Anomaly conditions (weighted score; alert at threshold):
  [HIGH weight]   API call volume > mean + 4 SD in any 1-hour window        +40
  [HIGH weight]   Withdrawal API calls from a new geographic location        +40
  [HIGH weight]   API session from an IP with no prior user history          +35
  [MEDIUM weight] API calls at an hour-bucket with <1% historical frequency  +25
  [MEDIUM weight] New device fingerprint in session                          +25
  [LOW weight]    Multiple API key rotations in same session                 +15

Alert at score >= 60.

Implementation note:
  This style of rule is best implemented in a UEBA platform or a custom
  risk-scoring layer in your SIEM. Each condition contributes to a
  per-session risk score for the user entity. Threshold breach triggers
  an investigation alert, not a block (initial deployment) or a step-up
  authentication challenge (mature deployment).

Lazarus relevance: TraderTraitor actors use compromised credentials
  to initiate cryptocurrency withdrawals. The behavioral signature is:
  legitimate credentials + new IP/device + high-volume withdrawal
  + unusual time. Each signal alone is ambiguous; combined they are
  high-confidence. The FBI and CISA April 2022 advisory documents
  this pattern across multiple exchange compromises.
```

---

### 8.4 APT29 — Unusual Outbound Data Volume from Service Following Token Grant

APT29 post-compromise typically involves quiet, low-volume data exfiltration over extended periods — often weeks to months. But after a fresh OAuth token is issued, there is frequently a reconnaissance burst: the actor reads mailboxes, enumerates directories, or accesses SharePoint to map the environment. This produces a short-term data volume anomaly from the Microsoft Graph or Exchange APIs that is detectable against a per-account baseline.

```
Anomaly Rule: Post-Authentication Data Volume Burst from Cloud Service

Entity: User account (in cloud identity system)
Trigger event: OAuth2 token grant (any flow)
Measurement window: 60 minutes following token grant
Baseline dimension: Bytes retrieved from cloud service APIs per session,
                    per user, rolling 90-day distribution
Anomaly condition: Post-grant data retrieval volume > 95th percentile
                   of historical post-grant sessions for this user
                   AND source IP has zero or low (<5) prior session history

Alert enrichment to include:
  - Volume of data retrieved (bytes)
  - API endpoints accessed (Graph /me/messages, /drive, /users)
  - Number of distinct objects accessed
  - IP geolocation and ASN
  - Comparison to user's historical session volume

Implementation note (Microsoft Sentinel):
  Join SigninLogs (token grant) with MicrosoftGraphActivityLogs
  (subsequent API calls) on CorrelationId or UserId within a 1-hour window.
  Aggregate ResponseBytes by UserId for the session.
  Compare against a rolling 90-day per-user percentile model.

APT29 relevance: Documented in Microsoft's January 2024 disclosure.
  Actors performed bulk mailbox enumeration and email reading
  immediately after token issuance. The data volume in the first
  30 minutes of a compromised session was multiple orders of magnitude
  above the same user's historical baseline.
```

---

## 9. The Detection Chain: Layering All Five Tiers

Detection rules should not be evaluated in isolation. A single alert at any tier is an investigation trigger, not a confirmed incident. The value of layering is that correlation across tiers dramatically increases confidence and reduces analyst fatigue.

The following chain illustrates how all five tiers interact for an APT29-style compromise:

```
[ATOMIC]         SolarWinds process loads DLL with non-baseline hash
                 → LOW confidence incident ticket opened
                 ↓
[COLLECTION]     OAuth device-code token grants spike from same IP (>5 users/10min)
                 → MEDIUM confidence — escalated to Tier 2
                 ↓
[CORRELATIONAL]  Token grant → immediate Graph API enumeration (mail + directory)
                 → HIGH confidence — escalated to Tier 3
                 ↓
[TTP-BASED]      Golden SAML assertion observed for privileged account,
                 no MFA, new IP, bypassed Conditional Access
                 → CRITICAL — incident declared, response initiated
                 ↓
[ANOMALY]        Service account accessing resources at 03:00 local time,
                 3 SD above historical pattern, source IP in new ASN
                 → Confirms lateral movement phase, expands blast radius
```

At each tier, the analyst answers a different question:

- **Atomic:** Is this artifact present on this host?
- **Collection:** Is this behavior occurring at an unusual rate?
- **Correlational:** Is this sequence of actions connected to a common actor?
- **TTP:** Is this technique executing, regardless of tool?
- **Anomaly:** Is this entity behaving consistently with its established history?

### Alert Weighting Model

A practical approach to managing alert volume across all five tiers is a per-incident risk score. Rather than treating each rule as a binary alert, assign a base score and let the score accumulate:

| Tier | Base alert score | Escalation threshold |
|---|---|---|
| Atomic (hash/IP/domain IOC) | 10 | >50 triggers Tier 2 review |
| Atomic (behavioral pattern) | 25 | |
| Collection | 30 | |
| Correlational (2-event) | 40 | |
| Correlational (3+ event) | 60 | >75 triggers immediate Tier 3 |
| TTP-based | 70 | |
| Anomaly (single dimension) | 35 | |
| Anomaly (multi-dimension scored) | 65 | >90 triggers incident declaration |

Multiple simultaneous rule fires on the same entity within a time window should be multiplicatively weighted, not additively: an atomic IOC hit plus a TTP rule fire plus an anomaly alert on the same user, same hour, is almost certainly a real incident.

---

## 10. Tuning, Validation, and Measurement

### 10.1 Tuning Philosophy

The failure mode for atomic and collection rules is high false positive rate, leading to alert fatigue and rule bypass. The failure mode for TTP-based and anomaly rules is insufficient telemetry, leading to missed detections.

Tune in this order:
1. **Start with the TTP-based rules.** They generate the fewest alerts but the most actionable ones. Tune the filter lists based on your legitimate software inventory.
2. **Add correlational rules next.** They require joined telemetry, so identify data gaps first. A correlational rule that joins on a log source you don't have will never fire — even if the attack is present.
3. **Add collection rules.** Set thresholds from 30-day baseline data, not from intuition.
4. **Add atomic rules last.** These are cheapest to write and burn fastest. Accept that they will need monthly review.
5. **Deploy anomaly rules in monitor-only mode for the first 60 days.** Document the false positives, tune the entity exclusions, then set alert thresholds.

### 10.2 Validation: Testing Your Detection Coverage

Every rule should be tested before production deployment and periodically thereafter. The minimum validation set for each detection layer:

| Layer | Test method |
|---|---|
| Atomic | Replay captured PCAP or process events with known-bad IOCs in a non-production environment. Use Atomic Red Team for behavioral atomics. |
| Collection | Simulate threshold-crossing events in a test log stream. Verify the time window and grouping key are correct. |
| Correlational | Run a synthetic attack chain in a lab environment. Use Mordor/OTRF datasets for pre-recorded adversary telemetry. |
| TTP-based | Use MITRE ATT&CK Evaluations telemetry, Atomic Red Team tests, or a red team exercise with documented TTPs. |
| Anomaly | Inject a synthetic outlier event that exceeds the threshold. Verify the baseline model is populated and the alert fires correctly. |

Reference datasets for validation:
- **Mordor (OTRF):** [github.com/OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) — pre-recorded APT simulation telemetry
- **Atomic Red Team:** [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) — TTP-level test cases mapped to ATT&CK
- **EVTX-ATTACK-SAMPLES:** [github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — Windows event log samples per technique

### 10.3 Measuring Detection Coverage

Two complementary metrics matter:

**ATT&CK coverage score:** Map each rule you have to one or more ATT&CK technique IDs. Use the ATT&CK Navigator to visualize coverage gaps. A rule that fires on LSASS access covers T1003.001; a rule on web shell creation covers T1505.003. Build a coverage heatmap, prioritize the gaps that match your highest-priority adversary profiles.

**Mean Time to Detect (MTTD) by tier:** Log the time from simulated attack execution to alert generation for each tier. If your TTP-based rule for LSASS access takes 45 minutes to alert because of SIEM ingestion lag, that lag is the detection gap — address it in the data pipeline, not the rule.

**Alert fidelity rate:** Track confirmed true positives as a fraction of total alerts per rule over 30-day rolling windows. A rule below 10% fidelity rate should be tuned or retired. A rule at 100% fidelity over 90 days with zero fires should be tested — it may simply not be covering the technique it claims to cover.

### 10.4 Detection-as-Code Workflow

All rules in this guide are in Sigma format, enabling a detection-as-code pipeline:

```
CTI Report → Extract TTP/IOC → Write Sigma Rule → Code Review → 
Test in Lab (Atomic Red Team / Mordor dataset) → 
Merge to main → sigma-cli convert → Deploy to SIEM →
Monitor fidelity → Review on 30-day cycle
```

Tools for this pipeline:
- **[sigma-cli](https://github.com/SigmaHQ/sigma-cli):** Convert Sigma to Splunk, Sentinel, Elastic, and others
- **[pySigma](https://github.com/SigmaHQ/pySigma):** Python library for programmatic Sigma rule management
- **[Roota](https://github.com/SecurityRiskAdvisors/VECTR):** Rule management and tracking
- **[MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):** Coverage visualization

---

## 11. Key Sources

**APT29 / Midnight Blizzard**
- FireEye/Mandiant, *Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor*, December 2020
- Microsoft MSTIC, *Analyzing Solorigate: the compromised DLL file*, December 2020
- CISA, Advisory AA20-352A — *Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations*, December 2020
- Microsoft Security Response Center, *Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard*, January 2024
- CyberArk Labs, *Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Services*, November 2019

**APT41 / Double Dragon**
- Mandiant, *Double Dragon: APT41, a Dual Espionage and Cyber Crime Operation*, August 2019
- Mandiant, *APT41 and Recent Activity*, August 2022
- U.S. Department of Justice, *Seven International Cyber Defendants, Including "APT41" Associates, Charged*, September 2020
- CISA, Advisory AA22-277A — *Impacket and Exfiltration Tool Used to Steal Sensitive Information from Defense Industrial Base Organization*, October 2022
- Kaspersky GReAT, *Operation ShadowHammer*, April 2019

**Lazarus Group / TraderTraitor**
- Kaspersky GReAT, *Operation AppleJeus: Lazarus hits cryptocurrency exchange*, August 2018
- CISA/FBI/Treasury, *TraderTraitor: North Korean State-Sponsored APT Targets Blockchain Companies*, April 2022
- ClearSky, *Operation Dream Job*, January 2020
- Mandiant, *Lazarus and the Three RATs*, March 2021
- Mandiant, *Staying a Step Ahead: Mitigating the DPRK IT Worker Threat*, June 2022
- FBI, *Flash: Identification of Lazarus Group Cryptocurrency Theft*, March 2023
- CISA, Advisory AA21-048A — *AppleJeus: Analysis of North Korea's Cryptocurrency Malware*, February 2021

**Detection Frameworks and References**
- MITRE ATT&CK, *Enterprise Matrix*, current version — [attack.mitre.org](https://attack.mitre.org)
- MITRE, *Cyber Analytics Repository (CAR)* — [car.mitre.org](https://car.mitre.org)
- David Bianco, *The Pyramid of Pain*, 2013 — [detect-respond.blogspot.com](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- SigmaHQ, *Sigma Rule Repository* — [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- Red Canary, *Atomic Red Team* — [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
- OTRF, *Mordor / Security Datasets* — [github.com/OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)
- LoLDrivers project — [loldrivers.io](https://www.loldrivers.io) — vulnerable/malicious driver reference

---

*Evidence base: public threat intelligence through April 2026. Detection rules are illustrative; all thresholds, filter lists, and entity scopes require tuning for your environment before production deployment.*

*Classification: Open source / Unclassified.*

*For corrections or technical questions: [Medium @1200km](https://medium.com/@1200km)*
