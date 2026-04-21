# Deep Research Prompt — Insider Attack Detection

## Research Objective

Produce a comprehensive, evidence-based technical research report on detecting malicious and suspicious activity originating from insider threats — defined as one or more current or former employees, contractors, or privileged users who intentionally abuse legitimate access to cause harm. The report must be grounded in documented incident response cases, published academic research, and vendor threat intelligence, and must cover detection approaches from simple artifact-based indicators to sophisticated anomaly and behavioural models.

---

## Scope and Framing

The research must treat the insider attacker as a **threat actor with legitimate access**, not a perimeter attacker. This is the core detection problem: the insider has valid credentials, knows the environment, understands monitoring gaps, and their activity often looks indistinguishable from normal work. Detection cannot rely on signature-based IOCs for most scenarios.

Cover the following insider threat categories and ensure each has documented real-world cases cited:

1. **Malicious data exfiltration** — employee stealing IP, customer data, source code, trade secrets before resignation or during employment
2. **Sabotage** — deliberate destruction, modification, or disruption of systems, data, or infrastructure
3. **Privilege abuse** — legitimate admin using elevated rights beyond authorised scope (accessing records they have no business need for, creating backdoor accounts, modifying audit configurations)
4. **Financial fraud** — manipulating financial systems, approving unauthorised transactions, creating ghost vendors or accounts
5. **Espionage / nation-state planted insider** — employee acting as agent for a foreign or corporate intelligence interest
6. **Collaboration with external attacker** — insider providing credentials, network access, or intelligence to an external threat actor
7. **Departing employee** — elevated risk window in the 30–90 days before and after resignation/termination

---

## Primary Research Sources to Analyse

Search for and analyse content from the following source categories. Cite specific documents where possible:

**Incident Response Reports:**
- CISA advisories and case studies involving insider threats
- CERT Insider Threat Center (Carnegie Mellon SEI) — Common Sense Guide to Mitigating Insider Threats (all editions), CERT Insider Threat Database case studies
- US-CERT / ICS-CERT cases involving critical infrastructure sabotage
- Verizon Data Breach Investigations Report (DBIR) — insider threat sections across multiple years
- Mandiant / Google Threat Intelligence M-Trends reports — insider threat sections
- CrowdStrike Global Threat Report — insider threat coverage
- Real documented cases: Edward Snowden (NSA), Chelsea Manning (US Army), Tesla/Autopilot code theft (2019), Ubiquiti insider (2021), Cisco WebEx sabotage (2018), GE turbine IP theft, Capital One (Paige Thompson — contractor abuse), CISA insider threat case studies

**Academic Research:**
- Carnegie Mellon SEI CERT insider threat research papers (all available)
- "Detecting Insider Threats" literature — cite specific papers
- UEBA (User and Entity Behaviour Analytics) academic foundations
- Psycholinguistic and behavioural indicator research (pre-attack signal literature)
- Graph-based insider threat detection research
- Time-series anomaly detection applied to insider threats

**Frameworks and Standards:**
- NIST SP 800-53 (insider threat controls)
- NIST SP 800-12 (monitoring)
- MITRE ATT&CK — insider threat techniques mapped to the framework
- CMU SEI Insider Threat Kill Chain model
- CISA Insider Threat Mitigation Guide

**Vendor Threat Intelligence:**
- Microsoft — insider risk documentation (Microsoft Purview Insider Risk Management)
- Splunk UBA / UEBA documentation
- Exabeam, Securonix, Varonis, Forcepoint DLP insider threat research papers

---

## Detection Coverage Required

For each detection category below, provide:
- **What it detects** (specific insider behaviour or artifact)
- **Log source / telemetry required**
- **Specific event IDs, fields, or data points** where applicable
- **Detection logic or analytic approach** (rule, threshold, anomaly model, ML technique)
- **Known limitations and false positive sources**
- **Real-world example** of this detection catching or missing an insider (cite source)

### 1. Simple Artifact-Based Detections (Deterministic Rules)

- Bulk file copy/download to removable media (USB, external drive) — DLP events, endpoint file copy events
- Printing large volumes of sensitive documents — print server logs
- Email forwarding rules to external personal addresses — Exchange/O365 audit log
- Large email attachments sent to personal email domains — DLP, mail gateway
- Cloud sync client syncing sensitive folders to personal cloud accounts (Dropbox, Google Drive, personal OneDrive) — proxy logs, DLP, endpoint
- AirDrop / Bluetooth file transfer from corporate device — endpoint telemetry
- Access to sensitive files outside normal work hours — file server audit logs
- Login from personal device to corporate systems — device compliance, MDM
- Account creation or permission grants to unknown accounts — AD audit, cloud IAM
- Modification or deletion of audit logs — Windows Event 1102, cloud audit log tampering events
- Disabling endpoint security tools — EDR telemetry, registry changes
- Screenshot tools execution on a system with classified or sensitive data classification — process execution logs
- Compression utilities (7z, WinRAR, zip) applied to sensitive directories — process + file audit

### 2. Behavioural Pattern Detections (Heuristic Analytics)

- **After-hours access spike** — user accessing systems, files, or applications significantly outside their established time-of-day baseline
- **Unusual data volume relative to role** — finance user downloading 10× their normal monthly volume in a single session
- **Access to data outside role scope** — HR employee accessing engineering documents; developer accessing customer PII outside their application's data tier
- **Sudden spike in failed access attempts to sensitive resources** — user probing systems they shouldn't need
- **Departing employee data staging** — unusual volume + new destination + compression + removable media, correlated with HR termination flag
- **Peer-group deviation** — user accessing resources that no one else in their department or role ever accesses
- **Search query anomalies** — enterprise search (SharePoint, Confluence, Salesforce) queries containing terms like "confidential", "acquisition", "salary", "IP", "source code" from users without business need
- **Clipboard/copy-paste volume anomaly** (where DLP or CASB captures this) — clipboard exfiltration detection
- **Access velocity** — user accessing 500 unique files in 20 minutes (impossible at normal reading/working speed — staging behaviour)

### 3. Identity and Privilege Anomalies

- Privilege escalation requests that deviate from normal approval workflow
- Service account or shared account usage by an individual (non-standard login)
- Admin account used for non-administrative tasks (browsing, email, personal applications)
- Creation of new admin or service accounts by existing admins outside change windows
- Modification of group membership for high-privilege groups without change ticket
- OAuth application consent grants with excessive scope by non-IT users
- Lateral movement using legitimate credentials to systems outside normal access scope
- Pass-the-Hash or Pass-the-Ticket by a legitimate privileged user (distinguishing insider vs. compromised account)
- Kerberoasting or LDAP enumeration initiated from a workstation associated with a specific user identity

### 4. Data Exfiltration Path Detection

Cover each exfiltration path with specific detection approach:
- **Email** (personal domain, personal webmail via browser)
- **Cloud storage** (personal Dropbox, Google Drive, iCloud — CASB, proxy, DLP)
- **USB / removable media** (DLP endpoint agent, Windows Event 4663, AutoPlay events)
- **Printing** (print spooler logs, DLP)
- **Screenshot / screen recording** (process execution, DLP visual content detection)
- **Personal device on corporate network** (NAC, DHCP anomaly, MDM)
- **SaaS application as exfil channel** (uploading to Slack, Teams, Jira, GitHub personal repos)
- **Covert channel** (DNS tunneling initiated by insider tool, ICMP exfil)
- **Physical** (photographing screens — limited technical detection; physical security correlation)

### 5. Network and System Behaviour

- Internal reconnaissance (LDAP queries, AD enumeration, network scanning from a user workstation)
- Access to systems with no prior connection history (graph anomaly on authentication logs)
- Lateral movement using legitimate credentials but to hosts outside normal work scope
- Remote access (VPN, RDP, SSH) at unusual times or from unusual locations
- Access during leave periods, sick days, or post-termination (requires HR data correlation)
- Installation of remote access tools (TeamViewer, AnyDesk, ngrok, reverse SSH) — process execution, network connection to known RAT infrastructure

### 6. Sabotage Detection

- Mass deletion events (file deletion at scale, database record deletion) — file audit, DB audit
- Database schema modification or backup deletion by non-DBA accounts
- Configuration changes to production systems outside change windows — CMDB comparison, cloud CloudTrail
- Deletion or modification of backup sets — backup system audit logs
- Deployment of logic bomb components (scheduled tasks, WMI subscriptions, cron jobs) created by user accounts
- Infrastructure-as-code tampering in CI/CD pipelines — git commit attribution, pipeline audit
- Code commits that introduce backdoors or destructive logic — SAST, code review anomaly, unusual commit at unusual time

### 7. Cloud and SaaS-Specific Insider Detection

- Mass download from SharePoint/OneDrive/Google Drive relative to user baseline
- Sharing sensitive documents with external (personal) email addresses
- Bulk export of CRM records (Salesforce, HubSpot) — API audit logs
- OAuth app consent to personal applications by privileged users
- Admin console actions (Azure, AWS, GCP) outside normal operations: mass IAM policy changes, disabling logging, creating persistent access keys
- Exfiltration via cloud-native data integration tools (Airbyte, Fivetran, Zapier) — SaaS audit logs
- Tenant-level setting changes that reduce visibility (disabling audit log, relaxing DLP policies)

### 8. UEBA and ML-Based Approaches

- **Entity risk scoring** — how to aggregate weak signals into a per-user risk score over time
- **Peer-group modelling** — clustering users by role/department/behaviour and detecting outliers
- **Sequence modelling** — detecting unusual action sequences (access pattern A→B→C not seen before for this user type)
- **Time-series decomposition** — separating seasonality from genuine behavioural shifts
- **Graph analytics** — detecting new edges in user-resource access graphs that create privilege paths
- **NLP on communication metadata** — sentiment analysis on email/Slack metadata (where legally permissible) as a pre-attack signal — cite CERT research on psycholinguistic indicators
- **Autoencoder-based anomaly detection** — reconstruction error as insider threat signal

### 9. HR and Contextual Signal Correlation

Research the following as detection-enhancing correlators (not standalone detections):
- Resignation submitted → elevated monitoring window
- Performance review dispute, disciplinary action, demotion
- Role change (new access + old access not revoked = "access creep" + insider risk)
- Notice period — access should decrease, not increase
- Post-termination access attempts (this is a hard indicator)
- Contractor / third-party access — reduced oversight, elevated exfil risk
- Working unusual hours correlation with business stress indicators

### 10. Covering-Tracks Detection

- Deletion of browser history, PowerShell history, command history on Linux
- Modification or deletion of Windows Event logs (Event 1102, 104)
- Use of incognito/private browsing on corporate devices (proxy metadata gap)
- Anti-forensic tools execution (eraser, CCleaner, cipher.exe /w) — process execution logs
- Modification of file timestamps (timestomping) — Sysmon Event 2
- Log rotation or log truncation abuse on Linux systems

---

## Output Structure Required

Organise the final research report as follows:

1. **Introduction** — The insider threat problem; why it is structurally different from external attacks; base rate and detection challenge
2. **Insider Threat Taxonomy** — Categories of insider attacker; motivations; CMU SEI kill chain model
3. **Documented Case Studies** — 8–12 real cases with: what happened, what signals were present (in retrospect), what was missed, what eventually triggered detection
4. **Detection Framework** — sections 1–10 above, each with the full coverage requested
5. **Detection Priority Matrix** — by ease of implementation vs. detection coverage (similar structure to the anomaly article's §5.9)
6. **Data Sources and Telemetry Requirements** — what must be collected before any detection can work
7. **Legal and Privacy Constraints** — monitoring limitations by jurisdiction (US, EU GDPR, UK, Australia); what is permissible to log and alert on
8. **Implementation Guidance** — how to build a phased insider threat detection programme
9. **Conclusion** — What the evidence shows about insider threat detectability; key limitations
10. **References** — Full citations for all sources

---

## Quality Requirements

- Every detection claim must be grounded in a cited source (IR report, academic paper, vendor documentation, or documented case) or explicitly labelled as the author's reasoned inference
- Use the same epistemic label system as the anomaly article: **[Documented]** = cited source states this explicitly; **[Inferred]** = derived from documented tradecraft
- Do not conflate insider threat with compromised account (external attacker using stolen credentials) — distinguish clearly where detection logic differs
- Include false positive analysis for every detection category
- Where a detection requires specific licensing, tooling, or configuration that is not universally available, state it explicitly
- Cite CERT/CMU case numbers where available for real cases
- Include coverage gaps — what categories of insider behaviour are currently undetectable with standard enterprise tooling

---

## Specific Questions to Answer

1. What percentage of insider threat cases are detected by technical controls vs. tip from a colleague or manager? (cite DBIR, CERT data)
2. What is the average dwell time for insider threats before detection? How does this compare to external attackers?
3. Which insider threat categories (sabotage vs. theft vs. fraud) have the strongest vs. weakest technical detection surface?
4. What does the research say about the pre-attack behavioural window — how early do behavioural signals appear before the technical act?
5. How does the detection approach differ for privileged users (admins, DBAs, DevOps) vs. non-privileged employees?
6. What are the documented cases where DLP failed to catch insider exfiltration and why?
7. What role does data classification play in making insider threat detection tractable?
