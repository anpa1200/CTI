# Embedded Systems, Hardware, and Firmware Attack Surface CTI

Source-verified CTI research record for the 1200km ecosystem.

## Publication

- Live 1200km page: https://1200km.com/CTI/
- Medium article: https://medium.com/@1200km/comprehensive-cyber-intelligence-research-attacks-against-embedded-systems-hardware-firmware-8a151f8d5f1b
- Published: 2026-07-03
- Version: Final source-verified edition
- Author: Andrey Pautov

## Intelligence Scope

This research covers the combined embedded, hardware, firmware, edge-appliance, and management-plane attack surface:

- Internet-facing VPN, firewall, router, mail-security, and edge appliances
- BMC/IPMI/Redfish management interfaces
- UEFI, Secure Boot, boot-chain trust, and firmware persistence
- CPU microcode, confidential-computing, and silicon-level vulnerabilities
- GPU local-memory leakage and AI workload isolation
- SOHO/IoT router proxy infrastructure
- OT/IoT firmware lifecycle and cyber-physical exposure

## Primary Actor and Campaign Tags

- Volt Typhoon
- KV Botnet
- UAT-4356
- ArcaneDoor
- FIRESTARTER
- UNC3886
- RedPenguin
- UNC5221
- UNC4841
- Sandworm / APT44
- Cyclops Blink
- AcidRain
- Mirai-derived IoT botnets

## Priority CVE and Vulnerability Tags

- CVE-2024-3400
- CVE-2023-46805
- CVE-2024-21887
- CVE-2025-22457
- CVE-2025-20333
- CVE-2025-20362
- CVE-2023-2868
- CVE-2025-68686
- CVE-2022-21894
- CVE-2024-54085
- CVE-2024-36347
- CVE-2024-56161
- CVE-2025-54510
- CVE-2022-40982
- CVE-2023-4969

## ATT&CK and Detection Tags

- T1190 - Exploit Public-Facing Application
- Valid account abuse
- Network device compromise
- Proxy infrastructure
- Command and control relay
- Defense evasion through log disruption
- Firmware persistence
- Boot or logon initialization persistence
- Exfiltration through appliance position
- Credential access from edge and management-plane trust

## Sectors and Asset Tags

- Critical infrastructure
- Government
- Telecommunications
- Energy
- Transportation
- Enterprise edge
- Remote access
- Cloud and virtualization management
- OT/ICS
- IoT and SOHO
- AI/ML workloads

## Operational Use

Use the public page as the reader-friendly report and use this repository record as the Git-backed CTI index entry.
For operational analysis, ingest the article into AdversaryGraph and connect:

- CVE records to affected vendors and products
- CVEs to ATT&CK technique candidates
- Actor and campaign records to observed appliance or firmware tradecraft
- Asset inventory fields to exposed management services, lifecycle status, and firmware version
- Telemetry readiness gaps to validation tasks

## Related Ecosystem Links

- AdversaryGraph: https://1200km.com/adversarygraph/
- AdversaryGraph docs: https://1200km.com/adversarygraph-docs/
- CVE Library: https://1200km.com/adversarygraph-docs/cve-cvss-intelligence/
- Attack Simulation: https://1200km.com/adversarygraph-docs/attack-simulation/
- Live ATT&CK workspace: https://1200km.com/threat-matrix/
- CTI Analyst Field Manual: https://1200km.com/cti-analyst-field-manual/
