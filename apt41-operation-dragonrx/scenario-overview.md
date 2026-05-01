# Operation DragonRx — APT41 Full Attack Simulation
## Scenario Overview & ATT&CK Kill Chain Mapping

**Author:** Andrey Pautov
**Campaign name:** Operation DragonRx
**Threat actor modeled:** APT41 / Winnti / Double Dragon (BARIUM, Bronze Atlas, Wicked Panda)
**Target sector:** Pharmaceutical / Healthcare
**Motivation modeled:** Dual — IP theft (espionage division) + ransomware (criminal division)
**Article type:** End-to-end attack simulation with lab, detection, and DFIR

---

## Table of Contents

1. [Threat Actor Profile](#1-threat-actor-profile)
2. [Fictional Target Profile](#2-fictional-target-profile)
3. [Scenario Narrative](#3-scenario-narrative)
4. [Full Kill Chain — Phase Summary](#4-full-kill-chain--phase-summary)
5. [ATT&CK Full Mapping Table](#5-attck-full-mapping-table)
6. [Custom Malware: RxPhage](#6-custom-malware-rxphage)
7. [Article Structure Outline](#7-article-structure-outline)

---

## 1. Threat Actor Profile

### APT41 — Who They Are

APT41 (also tracked as: Winnti Group, Double Dragon, BARIUM, Bronze Atlas, Wicked Panda, Earth Baku) is a Chinese state-sponsored threat actor assessed with high confidence to operate under the direction of the Chinese Ministry of State Security (MSS), specifically the Chengdu 404 Network Technology company as a contractor front.

**What makes APT41 unique — the dual mandate:**
- **Espionage track:** Long-term strategic IP theft targeting pharmaceutical, defense, telecom, technology
- **Criminal track:** Financially motivated attacks including ransomware, supply chain compromise for profit, gaming industry fraud

This dual mandate is the core narrative hook of this article. The same operators switch between nation-state tasking and personal financial enrichment — sometimes within the same victim environment.

### Key Real-World Campaigns (for article references)

| Year | Campaign | Technique | Sector |
|------|----------|-----------|--------|
| 2019 | Global intrusion wave | ProxyLogon precursors, supply chain | Telecom, Healthcare |
| 2020 | COVID-19 vaccine IP theft | Spear phishing, VPN exploits | Pharma (Moderna, others) |
| 2021 | Log4Shell exploitation | CVE-2021-44228 within hours of disclosure | Government, Finance |
| 2021 | OPSEC failure / DOJ indictment | 5 MSS officers charged (Zhang Haoran et al.) | — |
| 2022–2024 | KEYPLUG/BRONZE STARLIGHT | KEYPLUG backdoor, Cobalt Strike | Multiple |
| 2024 | Earth Baku resurgence | Custom loaders, IIS backdoors | APAC, EU |

### Core TTPs Referenced in This Simulation

- Initial access via exploiting public-facing applications (CVE-2021-44228 Log4Shell)
- Webshell deployment (China Chopper pattern)
- PlugX / ShadowPad custom backdoor family
- DLL sideloading persistence (signed binary + malicious DLL)
- Credential dumping (LSASS, NTDS.dit)
- Pass-the-Hash lateral movement
- DNS tunneling / custom C2 protocol exfiltration
- Living-off-the-land on Windows (certutil, mshta, rundll32)

### Public References for Article Citations

- US DOJ Indictment (2020): United States v. Zhang Haoran et al.
- Mandiant APT41 report (2019): "Double Dragon: APT41, a Dual Espionage and Cyber Crime Operation"
- CISA Alert AA21-291A: APT actors targeting US cleared defense contractors
- Secureworks CTR-2021-0015: Bronze Atlas Log4Shell exploitation
- Group-IB: Winnti Group under the Scope
- Recorded Future: TAG-22 (APT41 cluster)

---

## 2. Fictional Target Profile

### NovaTech Pharma — Target Organization

**Company:** NovaTech Pharma Inc.
**Sector:** Mid-size pharmaceutical, 1,200 employees
**Headquarters:** Simulated (fictional US company)
**Crown jewels:** Drug compound research database, Phase III clinical trial data, manufacturing process documentation

### Infrastructure Surface (what APT41 sees)

```
External-facing:
  patient-portal.novatech-pharma.local:8080   ← vulnerable Java app (Log4Shell)
  webmail.novatech-pharma.local               ← Exchange (not exploited in this sim)
  vpn.novatech-pharma.local                   ← Cisco ASA (not exploited in this sim)

Internal network (192.168.10.0/24):
  192.168.10.10   DC01.novatech.local         ← Windows Server 2019 Domain Controller
  192.168.10.20   FS01.novatech.local         ← File Server (crown jewel data)
  192.168.10.50   WS01.novatech.local         ← Windows 10 Workstation (scientist)
  192.168.10.100  WEB01.novatech-pharma.local ← Spring Boot app, log4j-core 2.14.1 (entry point)

Attacker-controlled (simulated external):
  10.0.0.5        KALI                        ← Attacker machine (Kali Linux)
  10.0.0.10       C2                          ← Sliver C2 server
  10.0.0.20       JNDI                        ← JNDI exploit server (Log4Shell delivery)
```

### Attack Surface Summary

| Component | Version | Vulnerability | CVE |
|-----------|---------|---------------|-----|
| Apache Log4j (patient portal) | 2.14.1 | JNDI injection RCE | CVE-2021-44228 |
| Spring Boot (embedded Tomcat) | — | Hosts the vulnerable Log4j app | — |
| Windows Server 2019 AD | — | Kerberoasting, DCSync | — |
| Windows 10 workstation | — | LSASS credential theft | — |

---

## 3. Scenario Narrative

### The Setup

APT41's espionage division has been tasked with acquiring NovaTech Pharma's proprietary research on a novel antiviral compound currently in Phase III trials. The drug, if successful, represents a $4B+ market opportunity — making it a strategic intelligence priority.

Simultaneously, APT41's criminal division identifies NovaTech as a ransomware candidate: the company lacks mature security operations, carries cyber insurance, and is deadline-sensitive (a clinical trial delay costs ~$600K/day).

### Timeline of Simulated Events

```
Day 0   — Reconnaissance: passive OSINT + active scanning of external surface
Day 1   — Initial access: Log4Shell exploitation on patient portal (WEB01)
Day 1   — Establish persistence: JSP webshell + cron-based RxPhage beacon
Day 2   — Internal discovery: network scan, AD enumeration from WEB01
Day 3   — Credential access: database config file yields domain creds
Day 3   — Lateral movement: Pass-the-Hash from WEB01 to WS01 (scientist workstation)
Day 4   — Privilege escalation: Kerberoasting → crack service account → DCSync
Day 4   — Crown jewel access: mount FS01 file shares, stage research data
Day 5   — RxPhage deployed to DC01 with DLL sideloading persistence
Day 5   — Exfiltration: HTTPS C2 + DNS tunneling backup channel
Day 6   — (Optional ransomware phase): disable VSS, encrypt non-critical systems
Day 6   — Detection: SOC analyst notices anomalous LDAP queries
Day 7+  — DFIR: memory acquisition, disk imaging, malware analysis, timeline
```

---

## 4. Full Kill Chain — Phase Summary

### Phase 0: Reconnaissance

**Goal:** Map NovaTech's external attack surface without triggering alerts.

**Passive recon:**
- Shodan/Censys search for NovaTech's ASN and IP ranges
- Certificate Transparency logs (crt.sh) for subdomain enumeration
- LinkedIn/OSINT for employee names, job titles, email formats
- BuiltWith/Wappalyzer fingerprint for technology stack

**Active recon (low-noise):**
- Nmap version scan on known web endpoints
- WhatWeb technology fingerprinting
- HTTP header analysis (Server: Apache-Coyote/1.1 → Tomcat)

**Finding:** patient-portal running a Spring Boot app with log4j-core 2.14.1 in the classpath — confirmed via error page stack trace leakage.

---

### Phase 1: Initial Access — Log4Shell (CVE-2021-44228)

**Goal:** Achieve remote code execution on WEB01.

**Mechanism:** The patient portal login endpoint logs the `X-Api-Version` HTTP header using Log4j. A crafted JNDI URI in this header triggers a lookup to attacker-controlled LDAP server, which returns a malicious Java class that executes on the target.

**Key technical steps:**
1. Attacker starts JNDI exploit server (marshalsec or JNDI-Exploit-Kit)
2. Attacker hosts malicious Java payload on HTTP server
3. Crafted HTTP request sent to login endpoint
4. Tomcat JVM fetches attacker LDAP → fetches Java payload → executes
5. Reverse shell lands on attacker netcat listener

---

### Phase 2: Foothold — Webshell + RxPhage Implant

**Goal:** Establish persistent, deniable access independent of the initial exploit.

**Two-layer persistence:**
- **Layer 1:** JSP webshell (`/imgs/cache.jsp`) — fast interactive access, simple
- **Layer 2:** RxPhage beacon — stealthy, survives reboots, encrypted C2

**Why two layers (APT41 doctrine):** Webshells are noisy but fast. Custom implants are slow to deploy but survive detection of the initial webshell. APT41 consistently deploys both.

---

### Phase 3: Discovery

**Goal:** Map internal network, identify high-value targets, find credentials.

**Linux-side discovery (WEB01):**
- Network interface and routing table
- ARP cache for live internal hosts
- Internal port scan (find DC, file server, workstations)
- Search web app config files for hardcoded credentials

**Windows-side discovery (once we have Windows access):**
- `net user /domain`, `net group "Domain Admins" /domain`
- BloodHound / SharpHound for AD attack path mapping
- `systeminfo` fingerprinting on each host

**Critical finding in this scenario:** Tomcat's `context.xml` contains LDAP bind credentials for the Active Directory service account (`svc_ldap / NovaTech2021!`). This shortcircuits Kerberoasting and gives direct domain access.

---

### Phase 4: Credential Access

**Goal:** Obtain high-privilege credentials for domain domination.

**Techniques used:**

1. **Config file credential harvesting** — `context.xml` leak (T1552.001)
2. **Kerberoasting** — request TGS for SPN-registered service accounts, crack offline (T1558.003)
3. **LSASS dump** — via comsvcs.dll LOLBIN on WS01 (T1003.001)
4. **DCSync** — once DA privileges acquired, pull all NTLM hashes (T1003.006)

---

### Phase 5: Lateral Movement

**Goal:** Move from Linux web server → Windows workstation → Domain Controller.

**Pivot chain:**
```
WEB01 (Linux, www-data) 
  → [Pass-the-Hash via Impacket] 
  → WS01 (Windows 10, jsmith) 
  → [Kerberoasting → crack → DA] 
  → DC01 (Windows Server 2019, SYSTEM)
  → [DCSync] 
  → full domain compromise
```

**Tools:** Impacket psexec, CrackMapExec, Rubeus (Kerberoasting), Mimikatz (DCSync)

---

### Phase 6: Collection

**Goal:** Identify and stage crown jewel data (clinical trial research).

**Target data on FS01:**
- `\\FS01\Research\Phase3-Antiviral-Data\` — clinical trial database exports
- `\\FS01\Manufacturing\ProcessDocs\` — proprietary synthesis documentation
- `\\DC01\SYSVOL\` — GPO scripts (bonus: may contain credentials)

**Staging:** compress with 7z using password, split into 50MB chunks for exfil.

---

### Phase 7: Exfiltration

**Goal:** Move data to attacker infrastructure without triggering DLP or IDS.

**Primary channel:** RxPhage HTTPS C2 (blends with normal HTTPS traffic, uses JA3 mimicry)

**Backup channel:** DNS tunneling via dnscat2 (used if HTTPS is blocked; generates high-entropy DNS queries to attacker-controlled domain)

**Exfil volume:** ~2.3 GB of research documents staged and transferred over 6 hours in 50MB chunks.

---

### Phase 8: Persistence — DLL Sideloading on DC01

**Goal:** Establish long-term, hard-to-detect persistence on Domain Controller.

**APT41 signature technique:** DLL sideloading using a legitimate, signed Microsoft or Oracle binary that loads a DLL from its working directory. The malicious DLL (RxPhage loader) is placed in the same path.

**Implementation in simulation:**
- Legitimate binary: `java.exe` (Oracle JRE, digitally signed)
- Malicious DLL: `jvm.dll` (replaced with RxPhage loader)
- Scheduled task: `JavaUpdateService` runs at system boot, SYSTEM context

---

### Phase 9: Optional — Ransomware Phase (Criminal Division)

**Trigger condition:** Assume a second APT41 sub-team decides to monetize access after data exfil.

**Pre-ransomware actions:**
- Disable Windows Defender via Group Policy
- Delete Volume Shadow Copies: `vssadmin delete shadows /all /quiet`
- Stop backup services: `net stop "Backup Exec Agent"`

**Ransomware simulation:** Custom Go encryptor (safe simulation — only encrypts files in `C:\Temp\RansomTest\`) leaves `DRAGONRX_RANSOM.txt` note.

---

### Phase 10: Detection Trigger

**How the SOC notices:**
- Unusual LDAP enumeration queries from WEB01 (Linux, not a typical LDAP client)
- Zeek alert: DNS queries with high entropy subdomains to unknown external domain
- Wazuh alert: Sysmon EID 10 (LSASS process access) on WS01
- Elastic SIEM: DCSsync detected via Windows EID 4662 with "Replication Get Changes All" access

**Realistic detection delay:** 6 days (aligned with industry average dwell time for APT actors ~21 days but compressed for article narrative).

---

## 5. ATT&CK Full Mapping Table

| Phase | ATT&CK ID | Technique Name | Sub-technique | Tool Used | Evidence Artifact |
|-------|-----------|---------------|---------------|-----------|------------------|
| Recon | T1595.002 | Active Scanning: Vulnerability Scanning | — | Nmap, Shodan | External firewall logs |
| Recon | T1592.002 | Gather Victim Host Info: Software | — | WhatWeb, curl | HTTP response headers |
| Recon | T1589.002 | Gather Victim Identity Info: Email | — | theHarvester | — |
| Initial Access | T1190 | Exploit Public-Facing Application | — | Log4Shell PoC | Tomcat access.log, JNDI callback |
| Execution | T1059.004 | Command and Scripting: Unix Shell | — | Bash | Bash history, audit.log |
| Persistence | T1505.003 | Server Software Component: Web Shell | — | JSP webshell | New .jsp file in webroot |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | — | crontab | /var/spool/cron, crontab -l |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | — | schtasks.exe | Windows EID 4698 |
| Persistence | T1574.002 | Hijack Execution Flow: DLL Side-Loading | — | jvm.dll swap | Sysmon EID 7, DLL path analysis |
| Discovery | T1046 | Network Service Discovery | — | Nmap, netcat | Network flow logs |
| Discovery | T1082 | System Information Discovery | — | hostname, uname | Process execution logs |
| Discovery | T1087.002 | Account Discovery: Domain Account | — | net user, ldapsearch | LDAP query logs, EID 4661 |
| Discovery | T1069.002 | Permission Groups Discovery: Domain Groups | — | net group | Windows EID 4799 |
| Discovery | T1018 | Remote System Discovery | — | Nmap, ARP cache | Network logs |
| Discovery | T1482 | Domain Trust Discovery | — | nltest.exe | EID 4661, nltest output |
| Credential Access | T1552.001 | Unsecured Credentials: Files | — | grep, find | File access logs |
| Credential Access | T1558.003 | Steal/Forge Kerberos Tickets: Kerberoasting | — | Rubeus | Windows EID 4769 (RC4 TGS) |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | — | comsvcs.dll, procdump | Sysmon EID 10, LSASS minidump |
| Credential Access | T1003.006 | OS Credential Dumping: DCSync | — | Mimikatz | Windows EID 4662 (DS-Replication) |
| Lateral Movement | T1550.002 | Use Alternate Auth Material: Pass the Hash | — | Impacket psexec | EID 4624 LogonType 3, NTLMv2 |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | — | CrackMapExec | EID 5140, 5145 share access |
| Lateral Movement | T1047 | Windows Management Instrumentation | — | wmic, Impacket wmiexec | EID 4688 wmiprvse.exe child |
| Collection | T1074.001 | Data Staged: Local Data Staging | — | robocopy, xcopy | File system events |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | — | 7-Zip | Process: 7z.exe with -p flag |
| Collection | T1005 | Data from Local System | — | dir, find, robocopy | File read events |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | — | RxPhage HTTPS C2 | Encrypted HTTPS to rare dest |
| Exfiltration | T1048.001 | Exfil Over Alt Protocol: DNS | — | dnscat2 | High-entropy DNS queries |
| C2 | T1071.001 | Application Layer Protocol: Web Protocols | — | RxPhage HTTPS beacon | JA3 hash, HTTP User-Agent |
| C2 | T1132.001 | Data Encoding: Standard Encoding | — | Base64/XOR in RxPhage | Encoded payload in HTTP body |
| C2 | T1573.001 | Encrypted Channel: Symmetric Cryptography | — | XOR config encryption | — |
| C2 | T1008 | Fallback Channels | — | DNS tunnel backup | Low-TTL DNS to attacker domain |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | — | rm, shred | Deleted file artifacts in MFT |
| Defense Evasion | T1027 | Obfuscated Files or Information | — | XOR-encoded RxPhage | Entropy analysis |
| Defense Evasion | T1218.011 | Signed Binary Proxy: Rundll32 | — | comsvcs.dll MiniDump | EID 4688 rundll32 + comsvcs |
| Defense Evasion | T1562.001 | Impair Defenses: Disable/Modify AV | — | Set-MpPreference | EID 4657, MpPreference registry |
| Impact | T1485 | Data Destruction | — | vssadmin delete shadows | EID 524 / VSS deletion |
| Impact | T1486 | Data Encrypted for Impact | — | Go encryptor (sim) | File extension change, ransom note |

---

## 6. Custom Malware: RxPhage

### Overview

**RxPhage** is the custom PlugX-lite RAT designed for this simulation. It is written in Go for cross-platform compilation and contains the following features that mirror real APT41 PlugX/ShadowPad patterns:

| Feature | Implementation | APT41 Parallel |
|---------|---------------|----------------|
| Encrypted config | XOR with rotating key 0x4C | PlugX encrypted config blob |
| HTTPS C2 beacon | Custom HTTP headers, jitter | ShadowPad HTTP protocol |
| DLL sideloading | Loader DLL + legitimate exe | PlugX classic DLL hijack |
| Anti-sandbox | VM artifact check, timing | APT41 widespread use |
| Modular commands | Shell, upload, download, screenshot | PlugX plugin architecture |
| Fallback channel | DNS tunneling (dnscat2 protocol) | APT41 DNS exfil observed |

### Why Go?

Go compiles to a single static binary (no dependency hell), cross-compiles for Windows/Linux, produces binaries with recoverable symbol tables (great for malware analysis walkthrough), and is increasingly used by APT actors (Sliver, Merlin, KEYPLUG-like tools).

### C2 Communication Pattern

```
Beacon: POST /api/v2/telemetry
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Oracle/Java-Update/8.0.361
  X-Client-Id: <UUID derived from hostname+MAC hash>
  X-Session: <Base64(XOR(timestamp))>
  Body: Base64(XOR(JSON beacon data))

Tasking: GET /api/v2/metrics?id=<client_id>&seq=<counter>
  Response: Base64(XOR(JSON task))

Exfil: POST /api/v2/analytics
  Body: Base64(XOR(chunked data, 50KB per chunk))
```

The User-Agent mimics Oracle Java Update traffic — common corporate background noise, rarely blocked or inspected.

---

## 7. Article Structure Outline

```
Title: "Operation DragonRx: Simulating an APT41 Attack End-to-End 
        — From Log4Shell to DFIR and Malware Analysis"

Section 1: Introduction — APT41 and the dual mandate
Section 2: Lab Setup — Deploy the target environment (Docker + Vagrant + Ansible, one `make up`)
Section 3: Reconnaissance — How APT41 maps your perimeter
Section 4: Initial Access — Log4Shell exploitation (live demo)
Section 5: Foothold — Webshell + custom RxPhage beacon deployment
Section 6: Discovery — Mapping the internal network and AD
Section 7: Credential Theft — From config files to DCSync
Section 8: Lateral Movement — Linux to Windows to Domain Admin
Section 9: Collection and Exfiltration — Stealing the crown jewels
Section 10: Persistence — DLL sideloading on the Domain Controller
Section 11: [Optional] The Criminal Turn — Ransomware phase
Section 12: Detection — How a SOC catches this attack
Section 13: DFIR — Full investigation from alert to timeline
Section 14: Malware Analysis — Static and dynamic analysis of RxPhage
Section 15: Conclusions — Lessons and defensive posture
```

---

*Next document: [lab-architecture.md](lab-architecture.md) — full automated deployment guide: Docker Compose + Vagrant + Ansible + Makefile, network topology, Sysmon config, Wazuh rules, and Zeek detection scripts. Deploy with `make up`.*
