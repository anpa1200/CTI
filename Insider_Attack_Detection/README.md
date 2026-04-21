# Detecting Malicious Insider Activity: A Technical Detection Engineering Guide

**April 2026**

> **Epistemic labels used throughout:** [Documented] = a cited source explicitly states this. [Inferred] = derived analytically from documented tradecraft, case facts, or detection engineering practice. Claims without a label have consensus support across the cited literature.

---

## Table of Contents

1. [Why Insider Detection Is Structurally Harder](#1-why-insider-detection-is-structurally-harder)
2. [Insider Threat Taxonomy and Kill Chain](#2-insider-threat-taxonomy-and-kill-chain)
3. [Documented Case Studies](#3-documented-case-studies)
4. [Detection Methods](#4-detection-methods)
   - [4.1 Deterministic Rules](#41-deterministic-rules)
   - [4.2 Behavioural Heuristics](#42-behavioural-heuristics)
   - [4.3 Identity and Privilege Anomalies](#43-identity-and-privilege-anomalies)
   - [4.4 Exfiltration Path Coverage](#44-exfiltration-path-coverage)
   - [4.5 Sabotage Signals](#45-sabotage-signals)
   - [4.6 UEBA and Anomaly Models](#46-ueba-and-anomaly-models)
   - [4.7 Covering-Tracks Detection](#47-covering-tracks-detection)
5. [Detection Priority Matrix](#5-detection-priority-matrix)
6. [Required Telemetry](#6-required-telemetry)
7. [Legal and Privacy Constraints](#7-legal-and-privacy-constraints)
8. [Implementation Guidance](#8-implementation-guidance)
9. [Conclusion and Coverage Gaps](#9-conclusion-and-coverage-gaps)
10. [References](#10-references)

---

## 1. Why Insider Detection Is Structurally Harder

Insider threat detection is structurally harder than external attack detection for a single reason: **the attacker is already authenticated**. There is no perimeter to cross, no credential to steal, no exploit to fire. The insider has a valid account, knows where sensitive data lives, understands what monitoring exists, and can operate at a pace that blends into normal work activity.

External attacker detection relies heavily on the contrast between attacker behaviour and the environment's baseline — unusual protocols, new source IPs, credential anomalies at first login, unexpected tools. The insider *is* the baseline. Their legitimate access is the attack vector.

**Key structural differences from external threats**

- No initial access phase — the insider already has it
- Lateral movement may be entirely absent — the insider reaches their target directly
- Exfiltration channels overlap with legitimate work tools: email, cloud sync, USB, print, SaaS
- The attacker understands operational rhythms and monitoring gaps
- Motivation is often invisible until after the act — financial pressure, grievance, ideology, coercion
- HR and business context (resignation, performance dispute, role change) are often the strongest pre-attack signals, not technical telemetry

**Statistical context**

76% of organisations reported at least one insider incident in 2024, up from 66% in 2019. Organisations experiencing 11–20 insider incidents per year rose from 4% to 21% over the same period [1]. The 2024 Verizon DBIR found internal actors involved in 35% of data breaches [2]. The Ponemon Institute 2025 study found that 62% of organisations now favour user behaviour-based tools for insider detection — a significant shift from pure rule-based approaches [3].

Without behavioural analytics, average dwell time before detection exceeds 9 months [3]. With UEBA deployed and tuned, organisations have reduced this to under 10 days in documented deployments [3]. The operational implication of that gap is severe: in a 9-month dwell window, substantial data exfiltration, prolonged fraud, or prepared sabotage is typically already complete before detection occurs.

**The detection paradox**

The most dangerous insider — technically sophisticated, patient, motivated — is also the one most likely to understand and evade the detection controls in place. The CERT/CMU banking-and-finance study found that 61% of insider incidents were detected by people who were not responsible for security, and only 22% were caught by auditing or monitoring procedures [4]. Logs appeared in 74% of cases where the insider's identity was eventually established — meaning logs are more often used for post-detection attribution than for initial discovery. The cases that get caught are frequently caught by non-technical means: a colleague tip, an accidental IP exposure, an HR flag, or a forensic artefact left during covering-tracks activity.

**Where DLP consistently fails**

DLP fails most consistently when the programme is content-only, threshold-only, or channel-limited. It struggles when:

- The actor copies data to a workstation and then out to removable media in small, sub-threshold chunks
- The exfiltration channel is an approved SaaS workflow (Slack, GitHub, Jira attachments)
- The destination is hidden behind long-lived OAuth tokens or encrypted messaging
- The exfiltration is transformed into print, screenshots, or staged archives rather than raw document transfer
- The encoding is steganographic — legitimate-looking image files carrying hidden payloads

The Desjardins regulatory findings are the most explicit documentation of this failure: over 26 months, an insider's activity was not detected because monitoring was partial, log review was passive, and transfer controls were threshold-based rather than sensitivity-aware [documented — OPC findings]. The Canadian regulator explicitly required that monitoring cover access and transfers below the minimum volume threshold.

**Privileged users versus standard employees**

Detection differs materially by user type. CERT's sabotage research found that most sabotage insiders held technical or privileged roles and that administrator access was common [4]. These users can create persistence, alter logs, destroy backups, or make destructive changes that look like "administration" unless control-plane actions are monitored separately from ordinary admin activity. By contrast, standard employees are more often detected through repository-drain patterns, role-scope deviations, departure-linked volume spikes, and human observation.

---

## 2. Insider Threat Taxonomy and Kill Chain

### 2.1 Threat Categories

The CERT/CMU Division classifies insider threats across three primary types, based on analysis of more than 3,000 documented cases [4]:

**Malicious Insider** — intentional harmful action for personal gain, revenge, ideology, or coercion. Subdivided by goal:

- **Data theft and IP exfiltration** — stealing proprietary information, source code, customer data, trade secrets. The most common category. Frequently correlates with job transition, competitor recruitment, or nation-state tasking.
- **Sabotage** — deliberate destruction or disruption of systems, data, or business processes. Often triggered by termination, disciplinary action, or sustained grievance. Less frequent than IP theft but high-impact per incident.
- **Financial fraud** — manipulation of financial systems, ghost vendors, unauthorised transactions. High prevalence in finance, accounting, and IT admin roles. Often longest dwell time due to low disruption signal.
- **Espionage** — acting as an agent for a foreign government or corporate intelligence interest. Less frequent but highest potential impact. Often indistinguishable from IP theft until a full investigation is underway.

**Negligent Insider** — accidental harm through misuse, misconfiguration, or policy disregard. Not covered in this guide; detection approaches differ significantly.

**Compromised Insider** — a legitimate account taken over by an external attacker. Detection overlaps with insider methods but attacker profile and motivation differ. Distinguished where relevant below.

**Departing Employee** — the 30–90 day window around resignation or termination is consistently the highest-risk period across CERT case data [4]. Behaviour patterns shift: unusual access hours, access to data outside current role, bulk downloads, contact with competitors, and data staging.

### 2.2 The CMU SEI Insider Threat Kill Chain

The CERT Division's kill chain model identifies the following phases [4]. Unlike the external attacker kill chain, phases are not strictly sequential and some may be skipped entirely:

**Phase 1 — Predisposition**
Pre-existing psychological, financial, or ideological factors that create susceptibility. Not technically observable. Requires HR, management, and peer awareness. Security programmes cannot intercept this phase through monitoring alone.

**Phase 2 — Stressor**
A triggering event: termination, demotion, disciplinary action, personal financial crisis, external recruitment offer, ideological radicalisation, or coercion. May leave HR signals (performance reviews, grievance filings) but rarely technical artefacts.

**Phase 3 — Planning**
Identifying what to take, how to take it, and what channels to use. May produce early technical artefacts: reconnaissance queries, access pattern changes, tool downloads, personal device network activity, testing of exfiltration paths during off-hours.

**Phase 4 — Preparation**
Acquiring tools, staging access, testing exfiltration channels, creating alternative access mechanisms. Detection opportunity: rare process execution, new cloud sync client installation, personal email forwarding rule creation, VPN service installation, or access to systems outside normal role scope.

**Phase 5 — Action**
The primary harmful act: bulk copy to removable media or personal cloud, deletion of data or infrastructure, commit of malicious code, submission of fraudulent transactions.

**Phase 6 — Post-incident**
Covering tracks, denying involvement, normalising behaviour. Detection opportunity: log clearing, file timestamp modification, anti-forensic tool execution, destruction of physical media, sudden changes in communication patterns.

**Critical observation:** Most technical detection opportunities are concentrated in phases 3–6. Phases 1–2 require non-technical (HR, management, peer) signals. Programmes that rely solely on technical controls miss the early warning window that CERT's data shows is often present weeks or months before the primary harmful act. CERT's sabotage dataset found that 80% of sabotage cases showed concerning behaviour beforehand that was visible to supervisors, and 71% were ultimately detected by non-security personnel [4].

---

## 3. Documented Case Studies

The following fifteen cases are drawn from DOJ records, regulatory findings, court documents, and CERT case data. Each entry documents: what happened, signals present in retrospect, what was missed, what triggered detection, and the key detection lesson.

---

### 3.1 Chelsea Manning — US Army Intelligence Analyst (2010)

**Category:** Espionage / data exfiltration
**Organisation:** US Army / State Department

Manning downloaded approximately 750,000 classified documents and diplomatic cables from the Secret Internet Protocol Router Network (SIPRNet) over several months using a rewritable CD labelled as a Lady Gaga album. The data was delivered to WikiLeaks and resulted in one of the largest classified data disclosures in US history. [Documented — DoJ charging documents, Congressional testimony]

**Signals present in retrospect:** Anomalous download volume from SIPRNet. Repeated removable media usage on a classified network. Prior reported behavioural concerns including mental health issues and disciplinary incidents that were not escalated to the security team. [Documented]

**What was missed:** No DLP on removable media on SIPRNet. No volume-based anomaly detection on download activity. HR and command-level behavioural signals were not integrated with technical monitoring. A continuous evaluation programme was not active at Manning's unit. [Documented — Congressional hearing findings]

**What triggered detection:** A tip from hacker Adrian Lamo, to whom Manning had disclosed the activity in online chat conversations. Technical controls did not detect the exfiltration. [Documented]

**Key detection lesson:** Without DLP on removable media and volume-based download anomaly detection, physical exfiltration via writable optical or portable media is invisible to technical controls. HR and command signals were available; the missing element was a programme that integrated them with technical monitoring.

---

### 3.2 Edward Snowden — NSA Contractor (2013)

**Category:** Espionage / data exfiltration
**Organisation:** NSA / Booz Allen Hamilton

Snowden, an NSA contractor working as a system administrator, exfiltrated an estimated 1.5 million classified documents from NSA systems, primarily using removable media. He used his sysadmin privileges to access files he had no operational need for, convinced at least one colleague to share their credentials, and used automated scripts to download large document volumes. [Documented — NSA Inspector General report, IC Inspector General findings]

**Signals present in retrospect:** Sysadmin accessing files outside his operational assignment. Credential sharing with colleagues (at least one documented instance). Large-volume automated downloads via scripts. Access to multiple systems beyond normal scope. Insider threat programme not deployed to the Hawaii facility where Snowden worked. [Documented — NSA IG report]

**What was missed:** No continuous monitoring of sysadmin activity. No need-to-know enforcement at the document level. No anomaly detection on credential sharing or atypical access scope for privileged accounts. [Documented — Congressional findings, ODNI]

**What triggered detection:** Not detected before Snowden left the country. Detection occurred via the journalistic publications themselves, not internal controls. [Documented]

**Key detection lesson:** Privileged users (sysadmins, contractors with elevated access) require separate, more rigorous monitoring than standard employees. Access-based need-to-know enforcement and anomaly detection on privileged account activity are prerequisite to any meaningful detection programme for this category.

---

### 3.3 Roger Duronio — UBS Systems Administrator (2002)

**Category:** Sabotage (logic bomb)
**Organisation:** UBS PaineWebber

Duronio, a disgruntled UBS systems administrator who had been denied a bonus he expected, planted a logic bomb on approximately 1,000 UBS servers timed to execute the morning after he resigned. The malicious code deleted files across the environment, causing more than $3 million in damage and taking UBS brokerage operations offline. He also shorted UBS stock expecting the attack to drive the price down. [Documented — DOJ press release, criminal complaint]

**Signals present in retrospect:** Prior disciplinary and grievance history. Unusual scheduling activity on production servers. Scripts placed outside normal change windows. Significant personal financial stake in UBS stock price decline. [Documented — trial record]

**What was missed:** Pre-trigger behavioural monitoring. Admin-action auditing that would have flagged unusual scheduled task or script creation outside a change window. CERT's sabotage dataset notes that 94% of sabotage cases were detected because a system failure or irregularity occurred, 80% showed prior concerning behaviour visible to supervisors, and 71% were detected by non-security personnel [4].

**What triggered detection:** The system failure itself. Forensic attribution followed.

**Key detection lesson:** Logic bombs are detectable before execution through monitoring of scheduled task and script creation activity by non-standard accounts outside change windows. By the time the destructive act fires, detection is too late for prevention. The behavioural pre-cursors — grievance history, unusual admin actions — are the real detection window.

---

### 3.4 Anthony Levandowski — Waymo Engineer (2016)

**Category:** Departing employee / IP theft
**Organisation:** Waymo (Alphabet) → Uber

Levandowski, a senior Waymo self-driving car engineer, downloaded more than 14,000 confidential files totalling approximately 9.7 GB from Waymo's internal systems before resigning, then founded a competing company that was quickly acquired by Uber. He installed special software on his work laptop, connected removable media for roughly eight hours, downloaded files including proprietary LiDAR design data, then reformatted the laptop days before departure. [Documented — Waymo civil complaint, DOJ indictment]

**Signals present in retrospect:** Concentrated repository access across LiDAR and hardware design systems. SD card connection for an extended period. Mass file download in the weeks before resignation. Anti-forensic laptop reformat during the notice window. [Documented — complaint]

**What was missed:** Earlier review of a highly privileged departing senior engineer. Heightened monitoring during the departure window was not triggered. No DLP alert on the 9.7 GB bulk download. [Inferred from documented facts]

**What triggered detection:** An external tip — a supplier email to Uber that exposed design similarity to Waymo technology, prompting Waymo to investigate and file suit. Internal controls did not detect the exfiltration. [Documented]

**Key detection lesson:** The departure window — particularly for senior technical staff with access to crown-jewel IP — requires specifically heightened monitoring. The mass download volume, removable media attachment duration, and subsequent laptop reformatting were all detectable in endpoint and file-server logs. None was acted upon in time.

---

### 3.5 Sudhish Kasaba Ramesh — Cisco Engineer (2018)

**Category:** Sabotage / post-termination access
**Organisation:** Cisco Systems

Ramesh, a former Cisco platform engineer, retained access to Cisco's AWS cloud environment for five months after resignation because his credentials were not revoked on departure. He deployed code from his personal Google Cloud account that deleted 456 virtual machines supporting the Cisco WebEx Teams platform, taking the service offline for approximately two weeks and affecting 16,000 customers. Remediation cost Cisco approximately $1.4 million. [Documented — DOJ press release, criminal complaint]

**Signals present in retrospect:** Post-departure authentication to production AWS environment using credentials that should have been revoked. Access originating from an external Google Cloud account, not a corporate endpoint. Mass deletion of VM resources — 456 VMs in a concentrated burst — visible in CloudTrail logs. [Documented — criminal complaint]

**What was missed:** Access credentials not revoked on resignation. No alerting on post-departure authentication. No real-time alerting on mass resource deletion at that volume in AWS CloudTrail. [Inferred from documented facts]

**What triggered detection:** The service outage itself. CloudTrail logs were available and contained the attribution evidence, but were reviewed forensically after the fact rather than monitored in real time. [Documented]

**Key detection lesson:** Post-termination access is one of the most reliable and actionable deterministic signals available. The CloudTrail evidence was present; the missing element was a real-time alert on both post-departure authentication and bulk VM deletion. A simple rule on `TerminateInstances` exceeding a count threshold would have fired during the attack.

---

### 3.6 Xiaoqing Zheng — GE Engineer (2018)

**Category:** Espionage / IP theft (nation-state adjacent)
**Organisation:** General Electric Aviation

Zheng, a senior GE turbine design engineer, operated for approximately 10 years before arrest, stealing proprietary turbine design files on behalf of Chinese state-affiliated interests. His exfiltration method was steganography: he embedded proprietary GE files inside ordinary-looking image files (including a sunset JPEG and turbine blade images) and emailed them to his personal Hotmail account. [Documented — DOJ indictment, trial record]

**Signals present in retrospect:** Corporate email to personal Hotmail address with attachments. Images with anomalously large file sizes relative to their visual dimensions. Repeated sending pattern to the same external destination over months. No prior legitimate business communication history with those external recipients. [Documented — indictment]

**What was missed:** DLP was not configured to detect steganographic content or anomalous file-size-to-visual-dimension ratios for image attachments. Email to personal consumer domains was not blocked or consistently alerted. The exfiltration channel was available and used undetected for years. [Inferred from documented facts and indictment timeline]

**What triggered detection:** FBI counterintelligence referral, not internal controls. GE's internal systems did not identify the exfiltration. [Documented]

**Key detection lesson:** Standard keyword-based DLP fails entirely against encoded or steganographic exfiltration. Detecting this category requires outbound attachment entropy analysis, file-size-to-content-type anomaly detection, or outbound communication volume baselines by destination domain. Long-term relationships between a corporate email account and a personal webmail domain with consistent attachment sending are detectable as a behavioural pattern even without content inspection.

---

### 3.7 Andrew Skelton — Morrisons Internal Auditor (2014)

**Category:** Disgruntled insider / data exfiltration
**Organisation:** Morrisons (UK supermarket)

Skelton, a Morrisons internal auditor who held a grudge over a disciplinary matter, extracted payroll data for 99,998 Morrisons employees from the PeopleSoft HR system and posted it to a file-sharing site, then mailed it on CD to three newspapers. Morrisons was held vicariously liable by the UK Supreme Court in civil proceedings, resulting in a landmark employer-liability ruling. [Documented — UK Supreme Court judgment, criminal conviction record]

**Signals present in retrospect:** Grievance and disciplinary history. Unusual TOR network access from a corporate laptop. Extraction of a complete employee dataset from PeopleSoft on a specific date. Only a small set of "super users" had access to the full dataset. Subsequent copying to personal removable media. [Documented — judgment]

**What was missed:** Monitoring of privacy-sensitive bulk repository exports. Detection of network-anonymisation tooling (TOR) on corporate devices. Alerting on full-dataset exports by individual user accounts. [Inferred from documented facts]

**What triggered detection:** A newspaper contacted Morrisons before publication. Internal controls did not detect the exfiltration. [Documented]

**Key detection lesson:** Bulk export of an entire sensitive dataset by a single account — particularly one in a privileged data-access role — is a high-signal event. TOR browser access from a corporate device is a strong pre-indicator of intent to evade monitoring and should generate an immediate alert regardless of what data is subsequently accessed.

---

### 3.8 Reyes Daniel Ruiz — Yahoo Software Engineer (2018)

**Category:** Privilege abuse / personal misuse
**Organisation:** Yahoo

Ruiz, a Yahoo software engineer, used his work access to compromise approximately 6,000 user accounts, primarily searching for intimate images and videos. He then used Yahoo credentials to pivot into other cloud accounts belonging to the same users, including iCloud, Facebook, Gmail, and Dropbox. Upon detection, he destroyed the laptop and external hard drive used to store the material. [Documented — DOJ press release, criminal complaint]

**Signals present in retrospect:** Repeated access to user accounts with no business justification. Cross-account pivoting from Yahoo into external third-party services. No service request, ticket, or operational reason associated with the account lookups. [Documented — complaint]

**What was missed:** Role-purpose controls on user data access. Alerting on unusual patterns of individual user account lookups (many accounts, no associated support ticket, non-sequential access). Anti-forensic destruction was a post-detection behaviour, not a pre-detection signal in this case. [Inferred from documented facts]

**What triggered detection:** Employer observation of suspicious account activity. [Documented]

**Key detection lesson:** Privileged access to user data requires both purpose-binding controls (access must be linked to a service ticket) and anomaly detection on access patterns (volume per user, breadth of accounts accessed, absence of operational correlation). The cross-account pivoting into external services should have been detectable as an access velocity and scope anomaly.

---

### 3.9 Nickolas Sharp — Ubiquiti Developer (2020–2021)

**Category:** Data theft / extortion / insider posing as external attacker
**Organisation:** Ubiquiti Networks

Sharp, a senior developer with cloud admin access, cloned hundreds of GitHub repositories and exfiltrated large volumes of data from Ubiquiti's AWS infrastructure using his own credentials. He then posed as an anonymous external attacker, sent a ransom demand for approximately $2 million in Bitcoin, and simultaneously acted as a "whistleblower" to journalists, claiming the breach was more severe than disclosed — while publicly working on Ubiquiti's internal incident response team. He was sentenced to 6 years in prison. [Documented — DOJ press release, criminal complaint]

**Signals present in retrospect:** AWS CloudTrail recorded the exfiltration and mass repository cloning under Sharp's own credentials. A commercial VPN (Surfshark) was used to mask the source IP during most activity. The ransom demand was sent from an anonymous channel shortly after the data theft. [Documented — criminal complaint]

**What triggered detection:** During a home internet outage, Sharp's VPN connection dropped while he continued working. His residential IP address was logged in AWS CloudTrail for a brief unmasked window, linking the activity to his home address. [Documented — DOJ press release]

**Key detection lesson:** CloudTrail logs contained the full evidence trail. The insider was not detected by monitoring but by an operational security error on his own part. This case illustrates both the forensic value of CloudTrail — even when the actor is using VPN — and the weakness of IP-based attribution. Mass repository cloning and large-scale AWS data access under an admin identity should trigger a real-time alert regardless of source IP.

---

### 3.10 Volodymyr Kvashuk — Microsoft Software Engineer (2018–2019)

**Category:** Financial fraud
**Organisation:** Microsoft

Kvashuk, a Microsoft software engineer with access to the company's test environment, stole approximately $10 million in digital gift cards by abusing his production test access to generate and redeem them. He used coworkers' credentials to mask his activity, routed proceeds through Bitcoin mixing services, and claimed the Bitcoin as a "gift from his family" on a home mortgage application. [Documented — Ninth Circuit appeal record, DOJ press release]

**Signals present in retrospect:** Test-account misuse for production financial operations. Unusual gift-card generation and redemption velocity. Identity anomalies — activity appearing under coworkers' credentials. Bitcoin monetisation of a significant USD volume. [Documented]

**What was missed:** Separation of duties between test access and production financial workflows. Monitoring of gift-card generation and redemption rate anomalies. Identity correlation to detect activity inconsistent with the nominal account owner's pattern. [Inferred from documented facts]

**What triggered detection:** Microsoft detected unusual gift-card redemption activity internally and referred the matter to law enforcement. [Documented]

**Key detection lesson:** Financial fraud by a technical insider exploiting production-adjacent test access is a separation-of-duties problem first and a monitoring problem second. Test accounts with production financial capabilities represent a structural control gap. Anomalous redemption velocity and cross-account identity inconsistency are the detectable signals.

---

### 3.11 Desjardins Credit Union — Employee Data Theft (2017–2019)

**Category:** Data exfiltration / downstream fraud
**Organisation:** Desjardins Group (Canada)

Over at least 26 months, a malicious employee copied sensitive personal information — names, addresses, birth dates, social insurance numbers, email addresses, and financial information — from a marketing shared drive to a work computer and then to USB keys. The data was then shared with criminal organisations for downstream fraud. Approximately 4.2 million individuals were affected. The Office of the Privacy Commissioner of Canada found that Desjardins' controls were insufficient on multiple dimensions. [Documented — OPC findings, Desjardins regulatory response]

**Signals present in retrospect:** Unauthorised access to a marketing shared drive containing data beyond the employee's normal scope. Repeated endpoint copies of sensitive data files. Removable media writes over an extended period. Transfers consistently below volume thresholds that might have triggered automated controls. [Documented — OPC findings]

**What was missed:** Active monitoring was absent. DLP deployment was partial. UEBA was not deployed. Transfer controls were threshold-based rather than sensitivity-based — small-volume transfers of highly sensitive data were not flagged. Role-scope controls did not prevent access to data outside the employee's function. [Documented — OPC findings, regulatory requirement list]

**What triggered detection:** The Laval police notified Desjardins during a separate criminal investigation. Internal controls did not detect the activity over 26 months. [Documented]

**Key detection lesson:** This is the most instructive case in the dataset for threshold-based DLP failure. The regulator explicitly required that controls address transfers below the minimum volume threshold. Sensitivity-aware controls — which flag any transfer of regulated personal data regardless of volume — would have changed the detection outcome. UEBA, per the regulator, would have surfaced this as anomalous behaviour relative to the employee's peer group.

---

### 3.12 Tesla — Departing Employee Data Leak (2023)

**Category:** Departing employee / data exfiltration
**Organisation:** Tesla

Two former Tesla employees leaked approximately 100 GB of confidential data — including personal data of 75,000+ current and former employees, customer financial information, and production secrets — to the German newspaper Handelsblatt. In a separate earlier incident (2018–2019), an employee made unauthorised changes to Tesla's manufacturing operating system using false usernames and exported sensitive production data to third parties. [Documented — Handelsblatt, Tesla legal filings, Infosecurity Magazine]

**Signals present in retrospect (2023 case):** Large-scale data export by departing employees. Data included HR records and production data outside the employees' own functional scope. Export volume of 100 GB is a high-signal event in any access log. [Documented]

**What triggered detection (2023 case):** Handelsblatt contacted Tesla before publication. Tesla's internal investigation identified the former employees as the source via access logs. [Documented]

**Key detection lesson:** The 30–90 day window before departure is the highest-risk period in the CERT dataset. CERT data shows that approximately 70% of last-confirmed IP-theft events in studied cases occurred within 60 days before departure [4]. Volume monitoring on data exports should be specifically heightened during this window, and access to data outside the employee's current role scope should generate alerts regardless of departure status.

---

### 3.13 Twitter — Saudi Arabia State-Sponsored Insider Espionage (2015)

**Category:** Insider espionage / state-sponsored collusion
**Organisation:** Twitter (now X)

Ahmad Abouammo (a media partnerships manager) and Ali Alzabarah (a site reliability engineer) abused internal Twitter user-information tools to look up private account details — including phone numbers and IP addresses — of Saudi dissidents and government critics, passing the information to Saudi intelligence officials. Alzabarah accessed data on more than 6,000 accounts on behalf of Saudi officials in a single day. Cash, a watch, and a family trip were provided as payments. [Documented — DOJ criminal complaint, appellate record]

**Signals present in retrospect:** High-volume sensitive account lookups with no business justification. Access to accounts belonging to individuals of political significance to a specific foreign government. Unusual communication pattern with individuals linked to a foreign state. [Documented — complaint]

**What was missed:** Just-in-time access controls on the user-information tools. Alerting on high-risk profile access (politically sensitive accounts, journalists, activists). Anomaly detection on lookup volume — accessing 6,000+ accounts in a single day is a high-signal volumetric event regardless of role. [Inferred from documented facts]

**What triggered detection:** Twitter confronted Alzabarah about one suspicious access. He fled the country the following day. The FBI investigation followed. [Documented]

**Key detection lesson:** Access to sensitive categories of data — in this case accounts of political significance — requires purpose-binding and anomaly detection on volume and pattern. A single-day lookup of 6,000+ accounts by one account is detectable through simple count-based alerting. The access tool existed; the alerting on its abuse did not.

---

### 3.14 Capital One — Paige Thompson, Former AWS Contractor (2019)

**Category:** Contractor knowledge exploitation / data exfiltration
**Organisation:** Capital One / Amazon Web Services

Thompson, a former AWS solutions engineer who had worked on contract with Capital One, exploited a misconfigured Web Application Firewall to conduct SSRF attacks against Capital One's AWS metadata service, obtaining temporary credentials that she used to access S3 buckets containing personal data of 106 million customers. While primarily characterised as an external attack, Thompson's specific knowledge of AWS architecture and the WAF misconfiguration came directly from her prior contractor role at Capital One. [Documented — DOJ indictment, Senate Banking Committee testimony]

**What was missed:** The WAF misconfiguration existed for months and was never detected. AWS CloudTrail contained evidence of the SSRF-based access pattern but no alerting was configured for it. Detection came via a GitHub post by Thompson herself. [Documented]

**Key detection lesson:** Contractors represent a distinct insider threat category — they frequently have privileged technical access, reduced oversight compared to employees, and retain institutional knowledge (including knowledge of misconfigurations) after their engagement ends. Knowledge of internal architecture is a risk that persists after technical access is revoked. Post-engagement monitoring of contractor knowledge assets is a gap in most programmes.

---

### 3.15 CERT Financial Fraud Operational Patterns

**Category:** Financial fraud
**Source:** CERT/CMU Common Sense Guide, 7th Edition [4]

The CERT database documents recurring fraud patterns across thousands of cases. Common patterns in the financial sector include:

- Accounts payable employees creating ghost vendors with personal bank account numbers
- Same employee creating and approving transactions (segregation of duties violation)
- Payment detail modification for legitimate vendors (real vendor, insider's bank account)
- Transactions structured just below approval thresholds to avoid review
- Activity concentrated outside business hours or during holiday and audit periods
- Ghost employees on payroll with direct deposits to insider-controlled accounts

CERT's banking-and-finance study found that in 61% of cases, the insider was detected by non-security personnel, 22% were detected by audit or monitoring, and logs were used for attribution in 74% of cases where the insider's identity was established. [Documented — CERT/CMU]

**Key detection lesson:** Financial fraud detection is primarily a business process control problem (segregation of duties, dual approval, payment integrity verification) rather than a network or endpoint security problem. SIEM-based detection requires integration with ERP audit logs — SAP, Oracle, Workday — and transaction metadata, not just authentication logs.

---

## 4. Detection Methods

The detection logic below is written as defender-operable guidance. Where logic is directly supported by a documented case or research finding, it is cited. Where the correlation is an engineering synthesis rather than a quoted rule from a primary source, it is marked **[Inferred]**. Windows Event IDs are the most common implementation anchors; they should be validated in your environment as audit policy settings, log forwarding, and SACLs vary significantly. Microsoft 365 and SaaS audit operation names vary by licence tier, tenant configuration, and product version.

---

### 4.1 Deterministic Rules

Deterministic rules fire on specific artefact patterns with near-zero legitimate prevalence in a properly configured environment. These should be deployed first — they require the least tuning, produce the fewest false positives, and represent the highest signal-to-noise detection available for the insider threat problem. None requires a baseline period.

---

**Post-termination access attempts**

What it catches: Any authentication or resource access by an account belonging to a terminated employee, resigned employee, or contractor whose engagement has ended.

Log source: IdP sign-in logs (Entra ID, Okta, ADFS); VPN authentication logs; AWS CloudTrail `ConsoleLogin` and `AssumeRole`; Active Directory Event 4624 / 4625 on domain controllers.

Detection logic: Maintain a terminated-accounts list fed from the HR system; alert on any successful or failed authentication attempt by an account on that list. Successful authentication after termination should be treated as an incident until disproven. [Inferred — operationalisation of documented case pattern]

False positives: Service accounts shared with departed users (mitigated by proper offboarding and individual service account ownership); accounts not yet fully deprovisioned due to HR-feed processing lag.

Real case: Cisco/Ramesh — post-departure AWS credential used 5 months after resignation to delete 456 VMs. CloudTrail logs contained the evidence; no real-time alert existed. [Documented]

Prerequisite: HR system integration with identity management; accounts disabled or deleted within a defined SLA (recommend: same business day as departure).

---

**Audit log deletion or disablement**

What it catches: Attacker covering tracks by clearing Windows Event Logs, disabling cloud logging, or stopping log forwarding agents.

Log source: Windows Security Event 1102 (Security log cleared); Windows System Event 104 (System log cleared); AWS CloudTrail `StopLogging`, `DeleteTrail`, `UpdateTrail` (disabling); Azure Monitor workspace deletion or diagnostic settings deletion; Okta / Entra audit log disablement API calls; SIEM ingestion health monitoring for unexpected log source silence.

Detection logic: Alert on any occurrence of Event 1102 or Event 104 outside a documented change window. Alert on any `StopLogging`, `DeleteTrail`, or equivalent cloud API call — these have near-zero legitimate ad-hoc prevalence on production infrastructure. Alert on SIEM ingestion gaps for any critical log source exceeding 15 minutes during active work hours. [Inferred — event ID anchors; near-zero prevalence is a community consensus position]

False positives: System reimaging, approved maintenance. Mitigated by requiring change ticket correlation.

Real cases: Waymo case — laptop reformatted days before departure. Yahoo case — Ruiz destroyed his computer and hard drive after detection. UBS case — Duronio attempted to conceal evidence post-execution. In all three cases, log-destruction or anti-forensic activity followed the primary harmful act. [Documented — case records]

---

**Email forwarding rule to external address**

What it catches: Employee creating an inbox rule to forward all or selected email to a personal external account — a common pre-departure intelligence gathering technique, or a means of sustained low-friction exfiltration.

Log source: Exchange / Microsoft 365 Unified Audit Log (UAL) operation `New-InboxRule` where `ForwardTo` or `RedirectTo` contains an external domain; `Set-Mailbox` with `ForwardingAddress` or `ForwardingSmtpAddress` set to external domain.

Detection logic: Alert on any `New-InboxRule` or `Set-Mailbox` forwarding action where the destination domain is not a corporate domain. Scope to rules created by non-IT accounts. Review any rule created during a departure notification window immediately. [Inferred — operationalisation]

False positives: Legitimate delegated email routing (should be IT-managed, not user-created). Alert volume is typically very low in organisations with enforced acceptable use policies.

Real case: Common pattern in CERT database cases preceding departure; documented in M-Trends reporting as a pre-exfiltration persistence technique. [Documented — CERT 7th ed., Mandiant M-Trends]

---

**Bulk file copy to removable media**

What it catches: USB drive, SD card, or external hard disk used to stage files for physical exfiltration — the Manning, Levandowski, Desjardins, and Snowden method.

Log source: Windows Security Event 4663 (object access with audit entry on sensitive directories) correlated with removable volume path; DLP endpoint agent removable media events (device attach + file write); Sysmon Event 11 (FileCreate) where target is a removable volume; Windows Event 6416 (new removable storage device recognised).

Detection logic: Alert on any file write to a removable volume by a non-IT account; heighten priority when: (a) source files are from monitored sensitive paths, (b) write volume exceeds a threshold (e.g., >50 files per session), or (c) the user is in a departure window flagged by HR. [Inferred — composite rule]

False positives: Legitimate removable media use (IT imaging, authorised backup). Mitigate with a device control policy that blocks unauthorised USB by default; the alert then fires only on authorised devices with unusual volumes.

Real cases: Manning — CD-RW used on SIPRNet with no DLP on removable media. Levandowski — SD card attached for ~8 hours during the departure window. Desjardins — USB keys used repeatedly over 26 months. Snowden — USB drives used to exfiltrate NSA documents. [Documented — case records]

---

**Compression of sensitive directories**

What it catches: Data staging — the attacker archiving files prior to exfiltration. Compression is almost always present when data is being prepared for movement, not when it is being worked with.

Log source: Sysmon Event 1 / Windows Security Event 4688 with command-line logging enabled: `7z.exe`, `winrar.exe`, `7za.exe`, `zip.exe`, `Compress-Archive` (PowerShell) with source arguments pointing to sensitive directories. DLP on archive creation targeting sensitive paths.

Detection logic: Alert when a known archiving utility is executed by a user account where the source path argument includes sensitive directories (HR, Finance, Legal, source code repositories, IP-classified paths). Correlate with subsequent network upload or removable media write within the same session for higher confidence. [Inferred]

False positives: Legitimate backup processes; developer zip operations. Mitigate by scoping to user workstations rather than backup server agents, and by excluding directories owned by IT automation service accounts.

Real cases: Levandowski case staging; Desjardins shared-drive-to-endpoint-to-USB pipeline. Compression was present in multiple CERT case studies as an intermediate staging step. [Documented — CERT 7th ed.]

---

**Large SharePoint or repository download**

What it catches: "Repository drain" — large-scale file download from corporate document stores, SharePoint sites, or source code repositories, common in departing employee exfiltration.

Log source: Microsoft 365 UAL operations `FileDownloaded`, `FileSyncDownloadedFull`, `FolderDownloaded`; OneDrive sync client logs; GitHub repository clone events via audit log; GitLab clone API events; Confluence space export audit.

Detection logic: Alert when a user's daily download event count from SharePoint or OneDrive exceeds their 30-day rolling average by a configurable threshold (suggest Z-score > 3 as a starting point). Separately, alert on any bulk download exceeding a fixed high threshold (e.g., >500 files in a single session) by a non-IT account. [Inferred — specific thresholds are environment-dependent]

False positives: Legal discovery, project migrations, disaster-recovery testing. Mitigate by requiring change tickets for large-scale data movement.

Real case: Tesla (2023) — former employees exfiltrated approximately 100 GB; volume was detectable in access logs post-incident. Desjardins — shared drive access and download pattern was the primary exfiltration path. [Documented — Tesla legal filings, OPC findings]

---

**Screenshot and screen capture tool execution on sensitive hosts**

What it catches: Screen capture of data that cannot be exfiltrated via file copy — e.g., an employee on a DLP-locked terminal who photographs or screenshots the screen to capture data without triggering file-movement controls.

Log source: Sysmon Event 1 / Event 4688 with command-line: `SnippingTool.exe`, `ScreenSketch.exe`, `ShareX.exe`, `OBS Studio`, `Greenshot`, `PicPick`, `Lightshot`, `PSR.exe` (Problem Steps Recorder); DLP screenshot intercept module where available.

Detection logic: Alert on first-ever execution of known screen capture tools by a user on hosts classified as handling sensitive data. Alert on repeated or high-frequency screen capture tool execution during repository access sessions. [Inferred]

False positives: Legitimate support documentation, training material creation. Mitigate with allowlist for expected tools on designated support workstations.

---

**Print-volume spikes**

What it catches: Policy evasion by converting digital data into paper, bypassing all network and file-movement controls.

Log source: Windows PrintService Operational log Event 307 (document printed — includes user, printer, document name, page count, job size); DLP print channel monitoring; print server audit logs.

Detection logic: Alert when a user's daily page count from sensitive application sources (HR systems, financial platforms, source control) exceeds their 90-day rolling average by a configurable multiple. Alert on printing of documents matching DLP classification labels. Alert on printing outside normal shift hours. [Inferred]

False positives: Board packs, finance close, annual reports, audit packages. Calibrate per business cycle.

Note: Public insider prosecutions in the documented case set skew toward digital exfiltration channels; the print vector is under-represented in prosecution records, which is itself a warning about detection coverage rather than evidence of low prevalence. [Inferred]

---

### 4.2 Behavioural Heuristics

Behavioural heuristics require a baseline period (typically 30–90 days) and produce more false positives than deterministic rules. They catch the "authorised but abnormal" pattern that deterministic rules cannot reach. Tune thresholds against your environment before enabling automated alerting.

---

**After-hours access**

What it catches: Activity outside the user's established working-hours baseline — commonly associated with covert action, planning phases, or covering tracks when the insider wants fewer witnesses.

Log source: IdP sign-in logs with timestamps; file server access logs; SaaS audit logs with timestamps; EDR process execution timestamps; badge-access records (correlate with digital access where possible).

Detection logic: Establish a per-user working-hours baseline using a rolling 30–90 day window. Alert when activity occurs at times more than two standard deviations outside the user's normal distribution, **weighted by the sensitivity of the resources being accessed**. Time-of-day alone is a weak signal; it must be combined with resource sensitivity, volume, or other contextual signals to be actionable. [Inferred]

False positives: International travel, time zone changes, on-call rotations, global team members. Mitigate by correlating with HR calendar (travel schedules, shift assignments, on-call rosters).

Note: Sophisticated insiders specifically operate within their own normal hours to evade temporal detection. After-hours alerting has higher value for reactive and opportunistic insiders than for planned, sophisticated campaigns. [Inferred — confirmed by Mandiant MSTIC analysis of threat actor temporal patterns]

---

**Access outside role scope**

What it catches: An employee accessing data, systems, or applications that their peer cohort (same role, department, seniority) never or rarely accesses — indicative of data collection beyond legitimate work needs.

Log source: File server access logs (Event 4663 with SACL); SharePoint site audit logs; DLP classification-based access logs; CRM and ticketing system audit logs (Salesforce, ServiceNow); ERP audit logs; database access logs.

Detection logic: Build access frequency profiles per resource path per role group. Alert when a user's accessed resource set diverges materially from their peer group. Use percentile ranking (e.g., this resource is accessed by 0% of peers in the same role this month) as the scoring basis rather than absolute volume. Combine with access novelty: first-time access to a resource scores higher. [Inferred]

False positives: Cross-functional project assignments, temporary role expansions. Mitigate with a project-exception workflow that creates a documented baseline exception for a defined period.

Real cases: Snowden — sysadmin accessing files outside his operational assignment. Yahoo/Ruiz — user account access with no associated support ticket or business purpose. Twitter/Saudi Arabia — account lookups on politically sensitive profiles with no operational context. [Documented — case records]

---

**Peer-group deviation**

What it catches: Users who remain within authorised systems but behave in ways that differ materially from colleagues in the same role — catching the "authorised but anomalous" pattern that role-scope rules miss because the specific resources accessed are within formal entitlements.

Log source: Identity metadata (department, team, title, project assignments, device class); application access logs; file and email activity; web proxy and SaaS usage telemetry.

Detection logic: Cluster users by role, department, and seniority. Compute a deviation score comparing individual behaviour against the cluster centroid across dimensions including: resource access diversity, data volume, application mix, time-of-day distribution, and external communication volume. Alert when deviation score exceeds a threshold that would place the user in the top 1–2% of their peer group. [Inferred — technique grounded in documented UEBA research]

Research support: Peer-group metadata-informed LSTM models demonstrated improved performance over individual or manually engineered feature baselines in academic insider threat detection work, specifically addressing cold-start and overfitting problems that arise from individual user baselining [referenced in openai research — peer-group LSTM study].

False positives: Heterogeneous peer groups, stale role metadata. Mitigate by maintaining clean HR data feeds and reviewing cluster composition quarterly.

Real case: Desjardins — a peer-group model would have scored the employee's shared-drive access and USB activity as diverging materially from normal marketing department behaviour across the 26-month exfiltration period. [Inferred from documented facts and OPC findings]

---

**Data staging pattern (composite)**

What it catches: The full kill-chain behaviour of collection followed by archiving followed by external transfer or removable media write — a sequence that is the fingerprint of most major data exfiltration incidents in the case set.

Log source: Process creation logs (archive tool execution); file creation and rename logs; repository read logs; DLP events; removable media events; network/SaaS egress logs.

Detection logic: Within a configurable time window (suggest: 2 hours for high-sensitivity paths, 24 hours for broad detection), look for the sequence: (1) access to sensitive file paths, followed by (2) archive utility execution with sensitive source path argument, followed by (3) file write to removable media OR upload to personal cloud OR email to external address. Require at least two of the three post-access steps for alerting. [Inferred — operationalisation of documented staging pattern]

False positives: Legitimate packaging and handoff workflows. Mitigate by scoping step (1) to monitored sensitive path classes.

Real cases: Levandowski — concentrated repository access followed by SD card attachment for 8 hours. Desjardins — shared-drive to endpoint to USB pipeline operating over months. Manning — SIPRNet download followed by CD-RW write. [Documented — case records]

---

**Departing employee volume spike**

What it catches: The "take the files with me" behaviour that CERT data shows is present in approximately 70% of documented IP theft cases within 60 days before departure [4].

Log source: HR departure date flag (fed to SIEM in real time); file download count and byte volume; email attachment sends; DLP events; removable media events; first-time repository access events.

Detection logic: When the HR system flags an employee's resignation or departure date: (a) automatically enrol them in a departure watchlist, (b) reduce anomaly thresholds to their baseline by 50% for the duration of the notice period, (c) alert on any combination of: volume increase >2× 90-day average, first-time access to data outside current role, archive creation on sensitive paths, or upload to personal cloud destination. [Inferred — composite rule operationalising CERT departure-window finding]

False positives: Legitimate handover documentation, portfolio preparation. Require manager approval for large data transfers during offboarding.

Real cases: Levandowski (Waymo) — departure window data staging; Tesla 2023 — 100 GB export by departing employees; Zheng (GE) — exfiltration concentrated around employment transition. [Documented — case records]

---

**Access velocity anomaly**

What it catches: Users accessing hundreds or thousands of unique files in a short period — staging behaviour that is physically impossible at normal reading or working speed.

Log source: File server audit Event 4663; SharePoint `FileDownloaded` and `FileAccessed` events; DLP classification access events.

Detection logic: Alert when a user's unique file access count in any rolling 60-minute window exceeds a threshold that is inconsistent with normal human workflow — suggest starting at >200 unique files per hour for knowledge workers, calibrated per role (a sysadmin running backup scripts has a different baseline). Scope to interactive sessions. [Inferred]

False positives: Automated processes running under user accounts. Mitigate by filtering on session type (interactive vs. service logon).

---

### 4.3 Identity and Privilege Anomalies

---

**New admin account creation outside change windows**

What it catches: Insider creating backdoor administrative accounts for persistent access, for enabling a collaborating external attacker, or as preparation for sabotage.

Log source: Windows Security Event 4720 (user account created); Events 4728, 4732, 4756 (member added to security-enabled group — domain and local); Azure AD / Entra audit log `Add member to role`; AWS IAM `CreateUser`, `AttachUserPolicy`, `CreateAccessKey`.

Detection logic: Alert on any privileged account creation — account added to Domain Admins, local Administrators, AWS AdministratorAccess role, or equivalent — where the creating account is not a known IT provisioning service account and the event time is outside an approved change window. This has near-zero legitimate prevalence for non-IT accounts. [Inferred — detection logic; near-zero prevalence is community consensus]

False positives: Emergency break-glass procedures (mitigated by pre-approved emergency access workflows with out-of-band notification).

---

**Access to systems with no prior history (graph anomaly)**

What it catches: User authenticating to a host or service they have never accessed before — indicative of lateral movement, credential sharing, or pre-exfiltration reconnaissance of systems the attacker was not previously familiar with.

Log source: Windows Security Event 4624 (Logon Type 3 = network, Type 10 = remote interactive) on target systems; VPN split-tunnel destination logs; cloud resource access logs; PAM session initiation logs.

Detection logic: Maintain a per-user access history graph (user → set of systems authenticated to). Alert on first-ever authentication to a system in a high-sensitivity tier (domain controller, database server, payment processing system, backup infrastructure) when combined with data volume or an active HR risk flag. [Inferred]

False positives: New system deployments, role changes. Mitigate with a 72-hour grace period tied to documented role-change events.

Real cases: Saudi Arabia/Twitter case — account information tools accessed for profiles unrelated to the employees' business functions. Microsoft/Kvashuk — coworkers' credentials used to access systems, creating identity-inconsistency signals. [Documented — case records]

---

**Access during leave or announced departure**

What it catches: An account active during a period when the HR system records the user as on leave, suspended, or terminated.

Log source: IdP sign-in logs correlated with HR calendar exports; leave management system API integration with SIEM.

Detection logic: Alert on any authentication by an account where the HR system records the user as inactive (on leave, suspended, or terminated). Treat as high severity immediately. Requires HR system integration with SIEM or UEBA in near-real-time. [Inferred — operationalisation of documented pattern]

False positives: Near-zero when HR data is accurate and feeds are current. Stale feeds or shared credentials are the main false-positive source.

---

**Access creep detection**

What it catches: Users retaining access from previous roles while accumulating access from current roles — creating an unintended high-privilege combination that exceeds any single role's entitlements.

Log source: IAM / Active Directory group membership audit logs; SaaS application access provisioning logs; periodic entitlement snapshot comparison.

Detection logic: Run weekly comparison of each user's effective permissions against a role-appropriate baseline. Alert when a user's effective access includes resource classes not associated with their current documented role. Flag accounts that have changed roles without a corresponding access review. [Inferred — operationalisation of CERT guidance recommendation]

False positives: Intentional cross-role assignments (mitigated by exception catalogue requiring manager and security sign-off).

Real case: Desjardins — broad shared-drive access and weak role segmentation meant the insider could access data in the banking warehouse that was not required for their marketing function. [Documented — OPC findings]

---

**Lateral movement with valid credentials**

What it catches: An insider (or external attacker using insider credentials) pivoting between systems using legitimate account credentials — the pattern that erases most traditional signature-based detection.

Log source: Windows Security Event 4624 (Type 3 network logon) across multiple target systems; remote execution events (WMI, WinRM, PsExec, SSH); PAM session logs; SMB/RDP access logs.

Detection logic: Correlate a user identity appearing on multiple new hosts in rapid succession (suggest: >3 new hosts in 30 minutes outside a documented maintenance window) especially when paired with admin tool execution or service-control actions on those hosts. [Inferred]

False positives: IT support engineers doing maintenance rounds, automation scripts. Mitigate by scoping to non-automation accounts and correlating with change tickets.

Note: Mandiant M-Trends 2026 explicitly documents a shift toward detecting behavioural anomalies rather than static IOCs because valid-credential and native-tool activity erase traditional signatures. This applies equally to insider movement as to external attacker post-compromise activity. [Documented — Mandiant M-Trends 2026]

---

### 4.4 Exfiltration Path Coverage

A complete insider detection programme must cover all meaningful exfiltration channels. Many organisations deploy email DLP and consider the problem addressed. The case evidence shows most documented exfiltrations used channels other than email as the primary path.

---

**Email to personal domain**

Monitor: Mail gateway or Exchange UAL `MessageSent` events where recipient domain is a consumer provider (gmail.com, hotmail.com, yahoo.com, icloud.com, protonmail.com) and the message contains attachments above a size threshold or matches a DLP classification policy. Separately monitor for `MessageSent` volume spikes to any external domain.

Key signal: Sensitive attachment to personal domain; volume spike; combination with departure flag.

Primary limitation: Encrypted attachments evade content inspection; steganography in image files evades classification. GE/Zheng operated this channel for approximately 10 years. [Documented] Content-based DLP cannot detect either evasion method. Behavioural controls (volume, domain, attachment frequency) remain effective.

---

**USB and removable media**

Monitor: Windows Events 4663 (file write on sensitive paths) and 6416 (new device recognised); DLP endpoint agent; Sysmon Event 11 on removable volume paths.

Key signal: File count and bytes written to removable volume in session; correlation with sensitive source paths; user departure status.

Primary limitation: Physical exfiltration (photographing a screen or printed document) produces no digital artefact. This is a coverage gap that no standard technical control addresses. Manning exfiltrated on writable optical media with no DLP present. [Documented]

---

**Personal cloud sync (Dropbox, Google Drive, personal OneDrive, iCloud Drive)**

Monitor: CASB or web proxy category "Personal Cloud Storage" with user identity attribution; endpoint DLP sync-client process network connections; DNS/proxy logs for known personal cloud storage domains.

Key signal: User uploading to a personal cloud storage URL from a corporate device or managed network.

Primary limitation: HTTPS inspection required for URL-level visibility; a personal mobile device used as a hotspot bypasses corporate proxy entirely. [Inferred]

---

**SaaS upload (Slack, GitHub, Jira, Confluence, Notion)**

Monitor: SaaS audit logs for file upload and attachment operations; CASB file upload events; proxy logs for file POST operations to SaaS destinations; GitHub personal access token creation and repository clone events; OAuth grant events for new application authorisations.

Key signal: Volume of uploaded content per user per SaaS platform deviating from peer baseline; new OAuth grant to an unrecognised application; long-lived PAT creation outside normal developer workflow.

Primary limitation: SaaS platforms that generate no native audit log for file operations; obfuscated or encoded content in uploads; abuse of existing approved integrations. M-Trends 2026 documents large-scale theft via long-lived OAuth tokens, hard-coded API keys, and compromised third-party SaaS vendor integrations — making token and integration abuse a mainstream exfiltration path. [Documented — Mandiant M-Trends 2026]

---

**Printing**

Monitor: Windows PrintService Operational log Event 307 (document printed, includes user, printer, document name, page count, job size); DLP print channel monitor; network print server audit logs.

Key signal: Page count spike from sensitive applications; printing outside shift hours; printing to unmanaged or network printers not associated with the user's normal location.

Primary limitation: DLP print monitoring requires an endpoint agent; network printing to remote printers may not be fully captured. Hardware-level capture (photographing the printed output) produces no technical artefact. [Inferred]

---

**Screen capture and screenshot tools**

Monitor: Process execution of known screen capture tools (see §4.1); clipboard operation monitoring where feasible; DLP screen-capture intercept modules.

Primary limitation: Hardware-level capture — a personal phone aimed at the monitor — produces no digital artefact and cannot be detected by technical controls. [Inferred] This is the exfiltration channel with the least technical detection coverage and the most underrepresentation in prosecution records.

---

**Covert channels and low-and-slow exfiltration**

Monitor: DNS resolver logs for high-entropy subdomain labels (DNS tunneling indicators); Zeek dns.log for TXT query volume and unusual query length distributions; proxy logs for unusual beacon cadence to low-reputation or newly registered domains; firewall logs for ICMP anomalies.

Key signal: Consistent, low-volume, periodic outbound connections to the same external destination correlated with prior sensitive data access; subdomain entropy anomalies in DNS; data access preceding each outbound connection in a causal sequence.

Primary limitation: Sophisticated implementations with low-entropy encoding (as documented in the SUNBURST C2 channel) can evade entropy-based detection. [Documented — Mandiant SUNBURST analysis] The Desjardins case illustrates the threshold problem: transfers consistently below volume thresholds were undetected for 26 months. The fix is to monitor the *correlation between data access and subsequent transfer* rather than relying on transfer volume alone. [Documented — OPC findings]

---

### 4.5 Sabotage Signals

Sabotage detection requires monitoring of control-plane actions — the administrative operations that create, modify, or destroy infrastructure — separately from normal data access monitoring. Standard file-access and email monitoring does not cover this threat category.

---

**Mass deletion event**

What it catches: Sudden bulk deletion of virtual machines, repository contents, cloud storage objects, database records, mailboxes, or file server directories.

Log source: AWS CloudTrail `TerminateInstances`, `DeleteBucket`, `DeleteObject` at bulk scale; Azure Activity Log `Microsoft.Compute/virtualMachines/delete`; File server audit Event 4660 (object deleted) correlated with Event 4663 at high volume; database audit log `DROP TABLE` / `DELETE` without WHERE clause; backup system console deletion events.

Detection logic: Alert when a delete operation count from a single user identity exceeds a threshold within a defined time window — suggest: >50 infrastructure objects in 10 minutes for cloud; >500 files in 10 minutes for file servers. Calibrate per role (backup admins and automation have higher legitimate baselines). [Inferred — thresholds are environment-dependent]

Real case: Cisco/Ramesh — 456 VMs deleted in a concentrated burst that was visible in CloudTrail logs but not monitored in real time. [Documented]

---

**Backup deletion and recovery-denial activity**

What it catches: Deletion of backup objects, disabling of backup policies, deletion of shadow copies, or tampering with backup agents — designed to eliminate recovery options before or after a destructive act.

Log source: Backup system admin logs; AWS `DeleteBackup`, `DisassociateRecoveryPoint`, `DeleteRecoveryPoint`; Azure Backup vault deletion events; Sysmon Event 1 with command-line `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set recoveryenabled no`; Windows Event Log Service stop events.

Detection logic: Alert on any backup deletion or backup service disablement outside a documented change window. Backup deletion by a non-backup-admin account should be treated as a critical-priority event immediately. [Inferred]

Note: M-Trends 2026 documents a systemic shift in adversary targeting toward backup infrastructure, identity services, and virtualisation management planes. An insider with admin access to these systems represents the highest-severity sabotage risk in the taxonomy. [Documented — Mandiant M-Trends 2026]

---

**Logic bomb artefacts**

What it catches: Delayed destructive code planted in scheduled tasks, WMI subscriptions, cron jobs, or CI/CD pipelines, timed to execute on a specific trigger or date.

Log source: Sysmon Event 12 (Registry key created/modified under persistence paths); Sysmon Event 13 (Registry value set for persistence); Windows Security Event 4698 (scheduled task created); `Microsoft-Windows-WMI-Activity/Operational` Event 5861 (new permanent WMI subscription created); Linux auditd `crontab` modification events; source-control commit audit for script changes to deployment paths.

Detection logic: Alert on any new scheduled task, WMI subscription, or cron job created by a non-IT user account or created outside a documented change window. Correlate with the account's departure status or HR risk flag. Alert on any WMI subscription whose consumer executes a script or binary from a user-writeable path. [Inferred]

False positives: Legitimate automation (mitigated by scoping to non-service-account, non-IT identities).

Real case: UBS/Duronio — logic bomb planted on approximately 1,000 servers by a disgruntled sysadmin. CERT data shows 94% of sabotage cases were detected only after system failure; the detection opportunity is in the pre-execution phase via scheduled task and persistence monitoring. [Documented — CERT 7th ed., DOJ records]

---

**CI/CD pipeline tampering**

What it catches: An insider modifying build, release, or deployment pipeline configurations to insert malicious code, create backdoors, alter signing, or disable security gates.

Log source: Source-control audit logs (GitHub, GitLab, Bitbucket) for commit author, branch, changed files; GitHub Actions / GitLab CI pipeline definition change events; branch protection rule modification events; secrets management access logs; deployment approval bypass events.

Detection logic: Alert on direct commits to a protected branch (main, production, release) by accounts that normally work on feature branches. Alert on changes to workflow files (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`) by non-pipeline-owner accounts. Alert on pipeline configuration changes outside approved change windows. [Inferred]

False positives: Emergency hotfixes (mitigated by requiring an emergency change ticket and out-of-band secondary approval).

Note: Public insider prosecutions under-report this path, but the risk is consistent with CERT's focus on privileged technical insiders (DevOps, SRE, platform engineers) and Mandiant's documentation of control-plane abuse as a primary adversary technique. [Inferred — risk extrapolation from documented patterns]

---

**Configuration changes outside change windows**

What it catches: Sabotage preparation, stealth privilege expansion, firewall rule modification to enable exfiltration paths, or backdoor configuration changes disguised as routine administration.

Log source: CMDB and change calendar integration; infrastructure-as-code repository commit audit; Active Directory audit for GPO changes; firewall and network device change logs (syslog); cloud security group / NaCL modification events.

Detection logic: Alert when a privileged user modifies production configuration — firewall rules, GPO, IAM policies, network ACLs, DNS records — without an associated open change ticket or outside approved change windows. Correlate with the account's HR status and recent anomaly score. [Inferred]

False positives: Emergency response (mitigated by requiring documented emergency procedures with out-of-band supervisor approval).

---

### 4.6 UEBA and Anomaly Models

UEBA (User and Entity Behaviour Analytics) addresses the "authorised but anomalous" problem that deterministic rules cannot reach. The value of UEBA is not in replacing deterministic rules but in providing a corroborating risk layer that reduces false-positive rates by requiring multiple weak signals to converge before generating an analyst alert.

---

**Entity risk scoring**

This is the most practical bridge between deterministic rules and full machine-learning UEBA. It aggregates multiple weak signals into a per-user risk score over a rolling time window.

Implementation: Each signal contributes a weighted point value; the composite score triggers an analyst queue entry at a threshold — not an immediate automated response. Example signal weights (illustrative and environment-dependent):

- After-hours access to sensitive resources: +5
- First-time access to a high-sensitivity system: +10
- Removable media write from sensitive path: +15
- Archive creation on sensitive directory: +10
- Email forwarding rule to external domain: +25
- HR departure flag active: +20
- Peer-group deviation score in top 5%: +10
- SharePoint download volume >3× baseline: +15
- Log clearing event: +40 (immediate escalation)

Score decay: halve scores that are more than 7 days old without reinforcement. A user's score should reflect current risk trajectory, not historical events. [Inferred — general UEBA design principle]

Platforms that implement this commercially: Microsoft Purview Insider Risk Management, Exabeam, Securonix, Varonis Data Security Platform, Splunk UBA.

Limitation: Risk scores require a baseline period (typically 30 days). New employees and transferred employees have no baseline and generate cold-start false positives. HR integration to provide role context is essential — scores without role context produce too many false positives to be operationally useful.

Regulatory validation: The OPC findings in the Desjardins case explicitly named SIEM and UEBA as active-surveillance tools that would have generated alerts on behaviour such as large downloads by atypical users. The regulator required their deployment as a remediation measure. [Documented — OPC remediation order]

---

**Peer-group clustering**

Clustered peer groups allow anomaly scoring to be calibrated to realistic "normal" for each role, rather than the whole organisation. A marketing employee and a sysadmin are both outliers against an organisation-wide baseline even when behaving normally.

Implementation: Cluster users by department, job title, team, seniority band, and access tier using K-Means or DBSCAN on access and activity feature vectors. Compute a deviation score for each user relative to their cluster centroid. Alert on users in the top 1–2% of their cluster by deviation score, combined with an HR risk or departure flag.

Research support: Peer-group metadata-informed LSTM models showed improved performance over individual or hand-crafted feature baselines in academic work, specifically addressing the cold-start and overfitting problems that arise from individual user baselining. [Referenced — academic LSTM peer-group study]

---

**Sequence anomaly models**

Sequence models detect ordered action chains that rules miss — the specific temporal pattern of: authenticate → access new system → read sensitive files → create archive → exfiltrate.

Implementation: Model expected action sequences per role class using Markov chains (lower complexity, easier to tune) or LSTM neural networks (higher recall, requires more training data). Flag sequences that deviate from the learned model for the role class. Focus on: the transition from data access to archiving to external transfer as a three-step sequence, since each step individually may be benign. [Inferred — operationalisation of documented UEBA research approach]

Research support: Transformer-based sequential modelling with uncertainty-aware clustering showed improved false-positive performance and stronger recall on insider threat benchmark datasets compared to earlier models, while researchers acknowledged that CERT benchmark data is synthetic and real-world performance requires validation on actual corporate telemetry. [Referenced in research materials]

---

**Graph analytics on access patterns**

Graph models represent users, systems, data repositories, and accounts as nodes, with access events as edges. Anomalous behaviour appears as new edges connecting a user node to parts of the graph they have never touched before.

Implementation: Build a time-series access graph. Track first-occurrence timestamps for each user-to-resource edge. Apply community detection (Louvain or Girvan-Newman) to identify clusters of resources that are accessed together as part of normal workflows. Alert when a user accesses a resource outside their community, especially when that resource is in a high-sensitivity tier. [Inferred — operationalisation of graph-based insider detection research approach]

Research support: Graph neural network-based frameworks for insider threat detection argued that GNN-style organisational modelling can surface hidden patterns in access behaviour that are invisible to individual-user or peer-group models. [Referenced in research materials]

Value: Catches the access-creep and lateral resource movement patterns that volume-based detection misses entirely, because these patterns may involve very few file accesses — just to new, previously unaccessed, sensitive locations.

---

### 4.7 Covering-Tracks Detection

Covering-tracks activity typically occurs in Phase 6 of the kill chain — after the primary harmful act. Detecting it provides a second detection opportunity for cases that eluded earlier controls, and the forensic trail preserved before covering-tracks activity completes is often what enables prosecution. In multiple cases in this dataset, the absence of preserved logs was a material factor in investigation difficulty.

---

**Windows Event log clearing**

Windows Security Event 1102 (Security log cleared) and Windows System Event 104 (System log cleared).

Alert on any occurrence. There is no legitimate automated process that clears the Windows Security Event Log outside a documented decommission or gold-image rebuild. Treat every occurrence as high priority until documented otherwise.

Extend to: cloud logging disablement (AWS `StopLogging`, `DeleteTrail`; Azure Diagnostic Settings deletion; GCP audit log sink deletion); SIEM forwarding agent stops (alert on any log source going silent for >15 minutes during work hours).

---

**Anti-forensic tool execution**

Sysmon Event 1 / Event 4688 command-line: `sdelete.exe`, `cipher.exe /w`, `BleachBit.exe`, `CCleaner.exe` (portable), `Eraser.exe`, `secure-delete` (Linux), `shred` (Linux) on endpoints that also accessed sensitive repositories.

Alert on any execution of known anti-forensic secure-deletion tools. Maintain a small allowlist of IT-approved secure deletion tools used in defined IT processes (e.g., decommission workflows).

Real cases: Yahoo/Ruiz — computer and hard drive destroyed after employer detected suspicious activity. Levandowski — laptop reformatted during notice period. Twitter/Saudi Arabia — one defendant fabricated invoices and obstructed investigation after confrontation. [Documented — case records]

---

**PowerShell history deletion**

Sysmon Event 11 (file delete) or file-write audit on `%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`; `Clear-History` command in PowerShell Operational log (Event 4104 with script block logging enabled); deletion of PSReadLine history file via Explorer or command line.

Alert on deletion of the PowerShell history file or execution of `Clear-History`, especially within a 30-minute window of sensitive operations or admin tool execution. This control matters most for privileged users who can cause significant damage with native PowerShell cmdlets alone.

---

**File timestamp manipulation (timestomping)**

Sysmon Event 2 (file creation time changed) — fires when a process modifies a file's MACB timestamps (Modified, Accessed, Changed, Born) to differ from the actual file system change time recorded in the USN journal.

Alert on any Sysmon Event 2 occurrence on files in sensitive directories (HR, Finance, Legal, source code, admin scripts) or on archive files. Cross-reference with USN journal entries where available for forensic confirmation.

False positives: Backup restore operations that preserve original timestamps; some legitimate deployment tools. Low overall volume makes this an operationally manageable alert.

---

**Linux audit trail manipulation**

auditd configuration changes (`auditctl -e 0` disabling auditing); deletion or truncation of `/var/log/audit/audit.log`, `/var/log/auth.log`, `/var/log/secure`; unexpected drop in log file size on any Linux host handling sensitive data.

Alert on any audit configuration change that reduces logging scope. Alert on unexpected size reduction of active log files. Forward auditd logs to SIEM via a separate pipeline that the host's root account cannot write to or modify — if audit logs exist only on the local host, a privileged insider can destroy the evidence trail.

---

## 5. Detection Priority Matrix

Ratings account for implementation effort (licensing, configuration, integration complexity), detection coverage against the insider threat categories documented in §3, and false-positive rate under realistic conditions.

---

**Tier 1 — Deploy immediately (Low effort, High signal, Very low FP rate)**

These controls require minimal configuration, rely on events that are already generated by default or with minor audit policy changes, and produce very few false positives. ROI is highest here.

- **Post-termination access alerting** — Requires HR feed to IdP (typically via SCIM). Catches departing employee and sabotage categories. FP rate: near-zero when HR data is accurate. Evidence: Cisco/Ramesh case.
- **Audit log clearing alerting** — Events 1102 / 104 are already generated; just forward and alert. Catches covering-tracks phase across all categories. FP rate: very low.
- **Email forwarding rule to external domain** — M365 UAL already logs this. Catches pre-departure exfiltration. FP rate: low.
- **New privileged account creation** — AD Events 4720/4728/4756 already generated. Catches backdoor creation and sabotage prep. FP rate: low.
- **Backup deletion outside change window** — Cloud and backup system logs already generated. Catches sabotage preparation. FP rate: low.

---

**Tier 2 — Deploy second (Medium effort, High value)**

These controls require moderate configuration, baseline setup, or endpoint agent deployment.

- **Departing employee composite rule** — Requires HR departure date integration with SIEM. Catches pre-departure data theft. FP rate: low when HR data is accurate. CERT supports this as the single most reliable pre-departure signal pattern.
- **Mass deletion alerting** — Requires cloud and file audit policy; threshold calibration. Catches sabotage. FP rate: low after calibration.
- **Bulk repository download anomaly** — Requires M365 UAL + per-user baseline. Catches pre-departure exfiltration. FP rate: medium initially, improves with tuning.
- **USB/removable media DLP** — Requires endpoint DLP agent deployment. Catches physical exfiltration. FP rate: low with device control policy.
- **After-hours access with sensitive resource correlation** — Requires IdP + HR calendar integration. Catches opportunistic and unsophisticated insiders. FP rate: medium without HR calendar context.
- **Logic bomb artefact detection** — Sysmon Events 4698 / 5861. Catches pre-sabotage preparation. FP rate: low with proper scope to non-IT accounts.

---

**Tier 3 — Deploy third (Medium–High effort, High analytical value)**

These controls require baseline periods, role taxonomy, or integration with HR metadata.

- **Access outside role scope** — Requires role taxonomy and access baseline (30+ days). Catches all categories. FP rate: medium; improves with accurate role data.
- **Peer-group deviation scoring** — Requires role cluster definition and feature engineering. Catches the "authorised but anomalous" pattern. FP rate: medium during tuning phase.
- **Entity risk scoring (UEBA)** — Requires 30-day baseline and ongoing tuning. Catches all categories through signal aggregation. FP rate: low when HR and role context are integrated. Desjardins regulator required this.
- **CI/CD pipeline tampering detection** — Requires source-control audit integration. Catches technical insider sabotage. FP rate: low.
- **Data staging sequence detection** — Requires correlation across process, file, and egress telemetry. Catches the pre-exfiltration staging phase. FP rate: medium initially.

---

**Tier 4 — Advanced and mature programme (High effort, High precision)**

- **Graph analytics on access patterns** — Requires graph database and edge-history tracking. Catches access creep and lateral resource movement. FP rate: low when the model matures.
- **Sequence anomaly models (LSTM/transformer)** — Requires labelled training data and model maintenance. Highest recall for stable-role classes (Finance, HR, DBA). FP rate: medium; requires ongoing tuning.
- **DNS tunneling detection** — Requires full QNAME capture at resolver. Catches covert channel exfiltration. FP rate: medium in environments with complex DNS.
- **Steganography detection in outbound email attachments** — Requires specialised content analysis capability. Catches the GE/Zheng exfiltration method. FP rate: low but high implementation complexity.

---

## 6. Required Telemetry

No detection programme can compensate for missing telemetry. The analytics in §4 require the following log sources to be collected, forwarded to SIEM, and retained for the minimum periods shown. Where the log source is absent, the detection category it enables is blind.

**Identity and access (foundation — enables §4.1, §4.3)**

- IdP sign-in logs (Entra ID, Okta, ADFS, Ping): full field set including user UPN, device ID, IP address, ASN, MFA method, session ID, conditional access result. Retention: minimum 1 year.
- Active Directory security audit: Events 4624, 4625, 4720, 4728, 4732, 4756, 4740, 4767, 1102 from all domain controllers. Retention: minimum 1 year.
- HR system integration: current employment status, departure date, role, department, manager, location — fed to SIEM or UEBA in near-real-time (target: within 1 hour of change). This is the single most underinvested integration in most insider threat programmes.

**Endpoint (enables §4.1, §4.2, §4.7)**

- Sysmon deployed with maintained configuration across all endpoints handling sensitive data. Minimum events: 1 (process create with command-line), 2 (file creation time change), 3 (network connection), 7 (image load), 11 (file create), 12/13 (registry create/modify), 17 (pipe create), 22 (DNS query).
- Windows process creation with command-line arguments via GPO (Event 4688 + `Include command line in process creation events` policy).
- DLP endpoint agent: removable media events, sensitive file path access, print operations, screen capture interception.

**Data and SaaS (enables §4.1, §4.4)**

- Microsoft 365 Unified Audit Log: all available operations. Note: `MailItemsAccessed` requires Microsoft Purview Audit (Premium). Retention: minimum 1 year at standard tier; 10 years at premium if budget permits.
- File server object access (Event 4663) with SACLs configured on: HR directories, Finance directories, Legal directories, IP/source code repositories, customer data stores. Scoped SACLs — not all files — reduce log volume to manageable levels.
- CASB or proxy for personal cloud storage and SaaS upload visibility — requires HTTPS inspection for full URL-level fidelity.
- All production SaaS platform audit logs: Salesforce, GitHub, GitLab, Slack, Jira, Confluence, Notion, Workday, ServiceNow. Most are available via API; some require premium licensing.

**Cloud infrastructure (enables §4.1, §4.5)**

- AWS CloudTrail: all regions, all management events, S3 data events on sensitive buckets, Lambda invocation logging on production functions.
- Azure Activity Log and Microsoft Defender for Cloud security alerts.
- GCP Cloud Audit Logs (Admin Activity, Data Access for sensitive projects).
- Cloud configuration change events: security group modifications, IAM policy changes, VPC flow logs (for exfiltration path detection).

**Network (enables §4.4 covert channel detection)**

- Full QNAME DNS resolver logs — Windows DNS debug logging or Zeek dns.log on recursive resolvers. Standard Windows event logs do not include full query names.
- Web proxy logs with full URI, user identity attribution (not just IP), and content-type.

**HR integration (the most underbuilt component in most programmes)**

- Departure dates with minimum 24-hour advance notice to SIEM before the departure date.
- Leave calendar.
- Role change events (moves between departments, promotions, transfers).
- Disciplinary and performance action flags (high sensitivity: requires HR/Legal approval framework in most jurisdictions before integrating with security monitoring).

---

## 7. Legal and Privacy Constraints

Insider threat monitoring operates in legally constrained territory in all major jurisdictions. The following is operational guidance derived from publicly available regulatory and legal sources. It is not legal advice. Obtain qualified legal counsel before deploying employee monitoring programmes.

---

**United States**

The Electronic Communications Privacy Act (ECPA) and Computer Fraud and Abuse Act (CFAA) generally permit employer monitoring of employer-owned systems, networks, and devices.

Employees have a reduced expectation of privacy on corporate devices and networks when: (a) a clear acceptable use policy (AUP) is in place that explicitly notifies employees of monitoring, (b) the monitoring is of work systems for legitimate business purposes, and (c) the policy has been acknowledged in writing by employees. [Documented — ODNI NITTF guidance, ECPA]

The NLRB has issued guidance noting that employer monitoring policies can become unlawful when they are so broad as to chill protected concerted activity (employees' rights to organise and discuss working conditions). [Documented — NLRB guidance]

CERT's Common Sense Guide adds a specific operational boundary: do not monitor privileged communications such as employee communications with doctors or lawyers; do not target protected disclosures or whistleblower activity solely because the employee is reporting misconduct. [Documented — CERT/CMU 7th ed.]

---

**European Union (GDPR)**

Employee monitoring requires a lawful basis under GDPR Article 6 — most commonly legitimate interest (Article 6(1)(f)) or legal obligation, with a balancing test demonstrating the security interest outweighs employee privacy interests.

Monitoring must be: proportionate (limited to what is necessary for the stated security purpose), transparent (employees informed of what is collected and why), purpose-limited (security monitoring data cannot be repurposed for performance management without a separate legal basis), and subject to a Data Protection Impact Assessment (DPIA) under Article 35 when the processing is systematic and high-risk.

Covert monitoring (without employee notification) is permissible in limited circumstances — typically only when there is specific, documented suspicion of criminal activity and disclosure would prejudice an investigation. Blanket covert monitoring is not lawfully supportable under GDPR in most circumstances.

Works council (Betriebsrat in Germany, comité social et économique in France) consultation is required in many EU member states before deploying employee monitoring systems. Failure to consult may invalidate the programme and the evidence it produces. [Documented — GDPR Articles 6, 13, 35; EDPB guidelines]

---

**Australia (Privacy Act 1988)**

The Privacy Act applies to organisations with annual turnover > AUD 3 million and to all Commonwealth government agencies.

The employee records exemption means that personal information in employment records held by private-sector employers for employment-related purposes is exempt from the Privacy Act's requirements. However, monitoring activities that go beyond HR purposes (content monitoring, communications surveillance) may require employee consent or fall under state and territory workplace surveillance laws (notably New South Wales Workplace Surveillance Act 2005, Victoria, Queensland). [Documented — OAIC guidance]

The Australian Privacy Principles (APPs) require transparency about data collection regardless of the employee records exemption for non-HR data. [Documented — OAIC]

The minimum legal floor and the prudent governance floor are not the same thing. Even where monitoring is technically lawful, organisations should use clear notices, narrow purposes, and role-based access to monitoring outputs to maintain the trust relationship with employees and to ensure that any adverse action based on monitoring results is defensible. [Inferred — operational governance guidance]

---

**Practical guidance for all jurisdictions**

- Maintain a current, legally reviewed Acceptable Use Policy that explicitly notifies employees that corporate systems are monitored and describes the scope of monitoring.
- Separate security monitoring data from performance management data — they require different legal bases in most jurisdictions.
- Restrict access to monitoring outputs to a defined team (Security, HR, Legal) under documented need-to-know controls.
- Treat HR-correlated signals (disciplinary flags, performance dispute records) as specially sensitive data requiring explicit HR and Legal approval before integration with security monitoring feeds.
- Document the legal basis for each monitoring activity in a register, with records of the DPIA or equivalent proportionality assessment.
- Ensure human review is in the loop for any adverse employment action based on monitoring results — automated scoring alone is insufficient basis for termination or legal referral in any jurisdiction.
- Log analyst access to monitoring data — the monitoring programme itself must have an audit trail.

---

## 8. Implementation Guidance

The following phased approach prioritises the highest-value, lowest-effort controls first, while building toward a mature multi-layer programme. Do not skip Phase 1 to reach Phase 3 — the foundational telemetry and legal framework that Phase 1 establishes is prerequisite to everything that follows.

---

### Phase 1 — Foundations (Months 1–3)

Target outcome: Minimum viable insider detection programme. Would have provided real-time detection in the Cisco, Yahoo, and Morrisons cases.

1. **HR system integration with IdP**: departure dates, role changes, leave status flowing to SIEM or UEBA within 1 hour of change. This single integration enables more high-value detection rules than any other single action.

2. **Enable and forward to SIEM**: IdP sign-in logs (full field set), Active Directory audit Events 4624 / 4720 / 4728 / 1102, AWS CloudTrail (all management events), Microsoft 365 UAL. If these sources are not already in SIEM, start here.

3. **Implement Tier 1 deterministic rules** from §5: post-termination access, audit log clearing, email forwarding to external domain, new privileged account creation, backup deletion outside change window.

4. **Legal and policy foundation**: review and update Acceptable Use Policy; engage legal counsel for DPIA or jurisdiction-appropriate assessment; document legal basis for each monitoring activity.

5. **Offboarding SLA**: define and enforce a technical offboarding SLA — all accounts disabled and credentials revoked within 4 hours of documented departure. This is the single most high-value procedural control against post-termination sabotage.

---

### Phase 2 — Data Exfiltration Coverage (Months 3–6)

Target outcome: Coverage of the most common insider exfiltration paths. Would have provided detection in the Tesla, Levandowski, and Desjardins cases.

1. **Endpoint DLP deployment**: prioritise removable media monitoring and sensitive file-path access logging. Deploy to all endpoints handling sensitive data before expanding to all corporate devices.

2. **File server SACL configuration**: enable SACLs on sensitive directories (HR, Finance, Legal, IP repositories, customer data); forward Event 4663 to SIEM. Scope carefully — applying SACLs to all files generates unmanageable log volume.

3. **SharePoint and OneDrive download baseline**: build per-user download event count baseline (30-day rolling); deploy count-based anomaly alert.

4. **CASB or proxy personal cloud category**: configure alerting or blocking for personal cloud storage categories with user identity attribution.

5. **Sysmon deployment**: deploy Sysmon with a maintained configuration (SwiftOnSecurity or Florian Roth baseline as starting points) across endpoints if not already present. Prioritise Events 1, 2, 11, 12, 13.

6. **Departing employee composite rule**: triggered by HR departure date flag + volume anomaly + destination change. Start with manual analyst review before automating alerts.

7. **Mass deletion threshold alerting**: configure cloud control-plane deletion monitoring in AWS CloudTrail and Azure Activity Log; set count-based thresholds for file server deletion events.

---

### Phase 3 — Behavioural Analytics (Months 6–12)

Target outcome: "Authorised but anomalous" detection coverage. Addresses the pattern that deterministic rules cannot reach — the Zheng, Snowden, and Twitter cases.

1. **Role-based peer groups**: define user clusters in SIEM or UEBA platform using HR department, job title, and access tier. Validate cluster composition before enabling scoring.

2. **After-hours access detection**: integrate HR calendar data; deploy composite alerting (after-hours + sensitive resource access).

3. **Access outside role scope**: build baseline of role → expected resource paths; deploy deviation alerting with a 30-day sensitivity threshold.

4. **Entity risk scoring**: select 5–8 weighted signals; deploy in read-only observation mode for 30 days before enabling analyst alerts. Tune false-positive rate before expanding signal set.

5. **CI/CD and pipeline tampering**: integrate source-control audit logs; configure direct-to-production-branch commit alerting; add pipeline configuration change monitoring.

6. **Logic bomb artefact alerting**: Sysmon Events 4698, 5861 scoped to non-IT user accounts; correlate with HR departure status.

7. **Analyst playbook**: create a written escalation process for each alert type that explicitly asks: does this signal correspond to a kill-chain phase (grievance indicators, staging, exfiltration, sabotage, concealment)?

---

### Phase 4 — Mature Programme (Year 2+)

Target outcome: Comprehensive coverage across all insider categories including sophisticated, patient actors.

1. **Graph analytics**: deploy authentication and access graph with first-occurrence edge tracking; apply community detection to flag novel access to sensitive resource clusters.

2. **Sequence anomaly models**: for highest-risk role classes (Finance, DBA, sysadmin, cloud engineers), build action sequence models trained on longitudinal audit data.

3. **HR flag integration expansion**: with Legal and HR approval, integrate disciplinary and performance flag data into risk scoring for specifically elevated-risk accounts.

4. **Quarterly purple-team exercises**: simulate all 15 case study scenarios against the detection programme; measure time-to-detect and coverage gaps.

5. **Insider Threat Working Group**: establish a cross-functional group (Security + HR + Legal + IT) with defined escalation procedures, investigation protocols, and case management capability.

6. **Long-retention log storage**: move identity, control-plane, and network-device logs to low-cost long-term storage (minimum 3 years) to support investigations involving long dwell times — the Desjardins case lasted 26 months; the Zheng case lasted approximately 10 years.

---

## 9. Conclusion and Coverage Gaps

### What the evidence shows

**Human detection still leads.** The CERT/CMU banking-and-finance study found that 61% of insider incidents were detected by non-security personnel, and only 22% by auditing or monitoring [4]. Technical controls are more often used for post-detection attribution than as the primary detection trigger. The cases in §3 confirm this pattern: Manning, Levandowski, Morrisons, GE/Zheng, Capital One, and the Saudi-collusion case were all detected by human observation, external tip, or law enforcement — not by internal technical controls. Building a programme that supports and amplifies human observation (HR integration, departure watchlists, manager escalation paths) is as important as the detection engineering itself.

**Deterministic rules deliver the best ROI.** Post-termination access, audit log clearing, email forwarding rules, and privileged account creation are high-signal, low-noise controls that require minimal tuning. They should be the first investment, not deferred in favour of complex UEBA.

**DLP is necessary but routinely insufficient.** The consistent finding across cases is that DLP fails against steganographic encoding (GE/Zheng), physical exfiltration (Manning), slow-and-low transfers below volume thresholds (Desjardins), and channels outside DLP scope (SaaS tokens, personal device hotspot). A DLP-only programme misses the majority of documented exfiltration methods. Sensitivity-aware controls — flagging any transfer of regulated data regardless of volume — are more effective than threshold-only controls.

**Dwell time is the central operational problem.** Without UEBA, average dwell time exceeds 9 months [3]. The Desjardins insider operated for 26 months. Zheng operated for approximately 10 years. The operational lesson is that insider detection programmes must assume long-dwell scenarios, require long-retention logging, and must not rely on volume thresholds that assume bulk exfiltration behaviour.

**Privileged users are the highest-risk category.** Sysadmins, DBAs, DevOps and cloud engineers, and security team members can operate below alert thresholds precisely because they understand the monitoring. Detection for privileged users requires: PAM with session recording, a separate logging pipeline they cannot access or modify, need-to-know enforcement beyond their administrative role, and tighter change-window controls for their administrative actions.

### Coverage gaps — what standard enterprise tooling currently cannot detect

**Steganographic exfiltration** — files hidden in image, audio, or video payloads sent via legitimate email. No standard DLP tool detects this without specialised content analysis configured specifically for statistical anomalies in file payloads relative to their declared MIME type. GE/Zheng operated undetected for approximately 10 years using this method.

**Physical exfiltration** — photographing a monitor with a personal device, removing printed documents, verbally memorising access credentials. No technical detection is possible. Process controls (clear-desk policy, no-photography zones, escorted access to data rooms) are the only mitigations.

**Social engineering of a peer** — the insider obtains sensitive data by convincing a legitimate colleague to send it on their behalf. The insider's account generates no anomalous activity because they never access the data directly. Detection requires monitoring of the colleague's outbound behaviour, not the insider's.

**Very slow, low-volume exfiltration** — one document per week for 18 months stays below every standard volume threshold while accumulating substantial IP over the period. The only effective detection is sensitivity-aware (any transfer of documents from a specific classification tier triggers review) or graph-based (access to a document cluster outside normal role scope).

**Insider with knowledge of the detection system** — a security engineer, SIEM administrator, or detection engineer who understands which rules are deployed and operates specifically below all thresholds and outside all monitoring scopes. Requires a separate, independent monitoring pipeline and a second pair of eyes from outside the security team. This is one of the hardest problems in the category.

**Long-term nation-state planted insiders** — highly trained, patient actors aware of monitoring practices and capable of operating within legitimate behavioural envelopes for extended periods. The GE/Zheng case was resolved by counterintelligence referral, not internal detection. Technical controls alone are insufficient for this threat category; counterintelligence partnership is required.

**Personal devices and personal accounts** — bring-your-own-device environments and personal cloud accounts accessed from outside corporate networks are largely invisible to corporate monitoring. A user who accesses corporate data on a managed device and then transfers it to a personal cloud account via a personal mobile hotspot leaves minimal corporate telemetry.

---

## 10. References

[1] Cybersecurity Insiders. *2024 Insider Threat Report*. 2024. https://www.cybersecurity-insiders.com/portfolio/insider-threat-report/

[2] Verizon. *2024 Data Breach Investigations Report*. 2024. https://www.verizon.com/business/resources/reports/dbir/

[3] Ponemon Institute. *2025 Cost of Insider Risks Global Report*. 2025.

[4] Carnegie Mellon University SEI CERT Division. *Common Sense Guide to Mitigating Insider Threats, Seventh Edition*. 2022. https://sei.cmu.edu/library/common-sense-guide-to-mitigating-insider-threats-seventh-edition/

[5] US Department of Justice. *United States v. Chelsea Manning*. 2010. https://www.federaltimes.com/smr/50-years-federal-times/2015/12/04/manning-snowden-leaks-the-threat-from-within-emerges/

[6] NSA Inspector General / ODNI. *Review of the Unauthorized Disclosures of Former NSA Contractor Edward Snowden*. 2016. https://www.asisonline.org/security-management-magazine/articles/2023/04/insider-threats/after-snowden/

[7] US Department of Justice. *United States v. Sudhish Kasaba Ramesh*. 2020. https://www.justice.gov/usao-ndca/pr/former-cisco-engineer-sentenced-two-years-federal-prison-intentionally-damaging

[8] US Department of Justice. *United States v. Xiaoqing Zheng*. 2019. https://www.justice.gov/d9/press-releases/attachments/2019/04/23/zheng_et_al_indictment_0.pdf

[9] US Department of Justice / The Record. *United States v. Nickolas Sharp (Ubiquiti)*. 2023. https://therecord.media/ubiquiti-nickolas-sharp-guilty-plea-data-extortion

[10] Handelsblatt / Infosecurity Magazine. *Tesla Insider Data Breach, 2023*. https://www.infosecurity-magazine.com/news/tesla-insiders-responsible-for/

[11] US Department of Justice. *United States v. Roger Duronio (UBS Logic Bomb)*. 2006. https://www.justice.gov/archive/usao/nj/Press/files/pdffiles/Duroniosen.pdf

[12] Waymo LLC v. Uber Technologies Inc. *Trade Secret Complaint and Investigation*. 2017. https://www.courthousenews.com/wp-content/uploads/2018/02/waymo-uber.pdf

[13] UK Supreme Court. *Wm Morrison Supermarkets plc v Various Claimants*. 2020. https://www.supremecourt.uk/cases/uksc-2018-0090.html

[14] US Department of Justice. *United States v. Reyes Daniel Ruiz (Yahoo)*. 2019. https://www.justice.gov/usao-ndca/pr/former-yahoo-employee-pleads-guilty-computer-intrusion

[15] US Department of Justice / Ninth Circuit. *United States v. Volodymyr Kvashuk (Microsoft)*. 2020–2022. https://www.justice.gov/usao-wdwa/pr/software-engineer-sentenced-9-years-defrauding-microsoft-10-million

[16] Office of the Privacy Commissioner of Canada. *Investigation into Desjardins Group's compliance with PIPEDA*. 2020. https://www.priv.gc.ca/en/opc-actions-and-decisions/investigations/investigations-into-businesses/2020/pipeda-2020-001/

[17] US Department of Justice. *United States v. Ahmad Abouammo and Ali Alzabarah (Twitter/Saudi Arabia)*. 2019–2022. https://www.justice.gov/usao-ndca/pr/former-twitter-employee-found-guilty-acting-agent-foreign-government

[18] US Department of Justice. *United States v. Paige Thompson (Capital One)*. 2019–2022. https://www.justice.gov/usao-wdwa/pr/former-seattle-tech-worker-convicted-wire-fraud-computer-intrusion

[19] Mandiant / Google Cloud Security. *M-Trends 2026*. 2026. https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025

[20] CISA. *Insider Threat Mitigation Guide*. 2020. https://www.cisa.gov/sites/default/files/publications/fact-sheet-insider-threat-mitigation-program-092018-508.pdf

[21] ODNI National Insider Threat Task Force. *Insider Threat Program Maturity Framework*. 2018. https://www.dni.gov/files/NCSC/documents/nittf/NITTF_Insider_Threat_Program_Maturity_Framework.pdf

[22] European Data Protection Board. GDPR Articles 6, 13, 35. https://gdpr-info.eu/

[23] Office of the Australian Information Commissioner. *Employee Records Exemption*. https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/workplace-privacy/employee-records-exemption

[24] Mandiant. *SUNBURST Backdoor Analysis*. 2020. https://www.mandiant.com/resources/blog/sunburst-additional-technical-details
