# Operation DragonRx — APT41 Full Attack Simulation

**Article project:** End-to-end APT41 simulation with lab, detection, DFIR, and malware analysis.
**Author:** Andrey Pautov
**Target publication:** Medium [@1200km](https://medium.com/@1200km)

---

## Quick Start

```bash
cd apt41-operation-dragonrx/dragonrx-lab/

make up        # deploy full lab (Docker + Vagrant VMs + Ansible provisioning)
make test      # validate all services, AD, and detection stack
make shell     # enter Kali attacker container
make attack    # run automated attack sequence
make status    # show Docker + Vagrant state
make logs      # tail all container logs
make down      # stop lab (preserve data volumes)
make reset     # destroy everything and start clean
```

**Kibana SIEM:** http://localhost:5601  
**Sliver C2:** `docker exec -it dragonrx_c2 sliver`

---

## Document Index

| Document | Contents |
|----------|----------|
| [scenario-overview.md](scenario-overview.md) | Threat actor profile, fictional target, narrative, full ATT&CK mapping (25 techniques), article structure outline |
| [lab-architecture.md](lab-architecture.md) | Full deployment guide: Docker Compose + Vagrant + Ansible + Makefile; network topology, Vagrantfile, Ansible roles, Sysmon config, Wazuh rules, Zeek scripts |
| [attack-playbook.md](attack-playbook.md) | Phase-by-phase commands: recon → Log4Shell → webshell → discovery → Kerberoasting → LSASS dump → DCSync → lateral movement → exfil → DLL sideloading → cleanup |
| [rxphage-malware.md](rxphage-malware.md) | PlugX-lite Go RAT design: XOR config, HTTPS C2, DLL sideloading loader, anti-analysis, static/dynamic analysis walkthrough, YARA rule, IOCs |
| [malware-analysis-guide.md](malware-analysis-guide.md) | Full malware analysis guide for every DragonRx artifact: RxPhage ELF/PE, JVM sideloading loader, JSP webshell, JNDI class, Sliver beacon, DNS tunnel, and lab encryptor |
| [detection-guide.md](detection-guide.md) | Zeek signatures, Wazuh XML rules (100110–100170), Elastic KQL/EQL correlation rules, Suricata IDS rules, threat hunting queries — mapped to every attack phase |
| [dfir-playbook.md](dfir-playbook.md) | IR triage, memory acquisition, Volatility3 (Linux + Windows), disk forensics, Plaso timeline, network forensics, attribution, eradication checklist |

---

## Lab File Reference

```
dragonrx-lab/
├── Makefile                          # make up / test / attack / down / reset
├── Vagrantfile                       # DC01, FS01, WS01 Windows VMs
├── docker-compose.yml                # 8 Linux containers
├── ansible/
│   ├── playbooks/deploy.yml          # full provisioning playbook
│   ├── playbooks/test.yml            # automated validation
│   └── roles/                        # dc01, fs01, ws01, sysmon, wazuh_agent
├── siem/
│   ├── wazuh/rules/dragonrx_rules.xml   # custom detection rules (8 rules)
│   ├── zeek/local.zeek                   # Log4Shell + DNS tunnel detection
│   └── sysmon/sysmonconfig.xml           # Sysmon EID 1,3,7,10,11,22 config
└── scripts/
    ├── deploy.sh                     # ★ one-script full deployment (replaces 'make up')
    ├── setup_routing.sh              # bridge Docker ↔ VirtualBox on 192.168.10.0/24
    └── fix_vboxdrv.sh                # rebuild VBoxDRV kernel module if needed
```

---

## Scenario Summary

**Threat actor:** APT41 / Winnti / Double Dragon (Chinese MSS, dual espionage + crime mandate)
**Campaign name:** Operation DragonRx
**Target:** NovaTech Pharma (fictional mid-size pharmaceutical company)
**Goal:** Steal Phase III clinical trial data (espionage) + ransomware option (criminal division)

**Kill chain:**
```
Recon → Log4Shell (CVE-2021-44228) → JSP webshell + RxPhage beacon
→ Internal discovery → LDAP credential harvest (container env vars / config files)
→ Kerberoasting → LSASS dump → DCSync → Lateral movement (Linux→Windows→DA)
→ Crown jewel collection (FS01 Research + Manufacturing shares)
→ HTTPS + DNS tunnel exfil (2.31 GB)
→ DLL sideloading persistence on DC → [Optional: ransomware phase]
→ Detection by SOC (Day 6) → Full DFIR investigation
```

**Lab stack:**
- **Docker:** Kali (attacker), Sliver C2, JNDI exploit server, WEB01/Log4Shell target, Wazuh, Elasticsearch, Kibana, Zeek
- **Vagrant/VirtualBox:** DC01 (Windows Server 2019, AD DS), FS01 (Windows Server 2019, file server), WS01 (Windows 10, workstation)
- **Ansible:** Automated AD setup, user accounts, SPNs, Sysmon, Wazuh agents, crown jewel data
- **Networks:** `attacker_net` 10.0.0.0/24 (Docker) | `target_net` 192.168.10.0/24 (Docker + VirtualBox bridged)

**Custom malware:** RxPhage — Go-based PlugX-lite RAT (XOR config, HTTPS C2, DLL sideloading, anti-sandbox)

---

## Article Sections → Document Mapping

| Article Section | Source Document |
|----------------|----------------|
| §1 APT41 who they are | scenario-overview.md §1 |
| §2 Lab setup | lab-architecture.md |
| §3 Reconnaissance | attack-playbook.md Phase 0 |
| §4 Log4Shell exploitation | attack-playbook.md Phase 1 |
| §5 Webshell + RxPhage | attack-playbook.md Phase 2 |
| §6 Discovery and AD enum | attack-playbook.md Phase 3 |
| §7 Credential theft | attack-playbook.md Phase 4 |
| §8 Lateral movement | attack-playbook.md Phase 5 |
| §9 Collection and exfil | attack-playbook.md Phase 6-7 |
| §10 Persistence | attack-playbook.md Phase 8 |
| §11 Ransomware (optional) | attack-playbook.md Phase 9 |
| §12 Detection | detection-guide.md |
| §13 DFIR | dfir-playbook.md |
| §14 Malware analysis | rxphage-malware.md §9-10 |
| §15 Conclusions | scenario-overview.md §4 ATT&CK table |

---

## ATT&CK Coverage Summary (25 Techniques)

Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command & Control, Impact — all phases covered.

Full mapping table: [scenario-overview.md → Section 5](scenario-overview.md#5-attck-full-mapping-table)
