# IOC Tables — Sandworm / APT44 (Seashell Blizzard)

Extracted from the [CTI Research report](cti-research-sandworm-apt44-with-nav.pdf) for correlation and triage. **Do not use as standalone attribution proof.** Validate with current telemetry before blocking. Network IOCs from incident reporting are volatile — do not use as permanent blocklist entries without revalidation.

**Evidence cutoff:** March 2026 · **Sources:** [CERT Polska / R23](https://www.cert.pl/en/posts/2025/12/dynowiper/), CISA, Mandiant, ESET, NCSC, Google TAG

---

## Network IOCs (IP) — December 2025 Poland incident chain

| Indicator | Context | Evidence | Freshness | Action |
|-----------|---------|----------|-----------|--------|
| 185.200.177.10 | VPN/M365 logins in incident chain | near-hard | maybe_expired | Hunt; short-term block only after validation |
| 195.26.87.225 | Renewables-sector login source | near-hard | maybe_expired | Hunt; short-term block only after validation |
| 146.190.211.75 | FortiGate management abuse | near-hard | maybe_expired | Hunt; short-term block only after validation |
| 128.140.34.155 | FortiGate management abuse | near-hard | maybe_expired | Hunt; short-term block only after validation |
| 95.85.114.66 | C2 / tool retrieval infrastructure | near-hard | maybe_expired | Hunt; short-term block only after validation |
| 95.85.114.74 | C2 / tool retrieval infrastructure | near-hard | maybe_expired | Hunt; short-term block only after validation |
| 31.172.71.5 | Compromised server in incident chain | near-hard | maybe_expired | Hunt; short-term block only after validation |
| 31.172.71.5:50443/tcp | Operational port | near-hard | maybe_expired | Egress/ingress correlation |
| 31.172.71.5:8008/tcp | Operational port | near-hard | maybe_expired | Egress/ingress correlation |
| 31.172.71.5:44445/tcp | Operational port | near-hard | maybe_expired | Egress/ingress correlation |

---

## Domain / Infrastructure IOCs

| Indicator | Context | Evidence | Action |
|-----------|---------|----------|--------|
| esetsmart[.]com | ESET-impersonation phishing | soft / volatile | Alert + block in phishing controls |
| esetscanner[.]com | ESET-impersonation phishing | soft / volatile | Alert + block in phishing controls |
| esetremover[.]com | ESET-impersonation phishing | soft / volatile | Alert + block in phishing controls |
| solntsepek[.]com | Persona-linked (AcidPour context) | soft / volatile | Hunt + block |
| totalcmd[.]net | Masquerading software distribution | near-hard / maybe_expired | Block + detonation |
| updater-file[.]xyz | Malware/tool delivery | near-hard / maybe_expired | Block + detonation |

---

## File / Artifact IOCs (names)

| Indicator | Context | Action |
|-----------|---------|--------|
| dynacom_update.ps1 | DynoWiper distribution | Hunt + script block logging |
| exp1.ps1 | DynoWiper distribution | Hunt + script block logging |
| dynacom_update.exe | DynoWiper | Hunt + detonation + quarantine |
| Source.exe | DynoWiper | Hunt + detonation + quarantine |
| schtask.exe | DynoWiper (masqueraded) | Hunt with hash + process lineage |
| KB284726.ps1 | LazyWiper | Hunt + script block logging |
| scilc.exe | OT MicroSCADA; misuse = destructive | OT alert; non-maintenance args |
| 108_100.exe | Industroyer2 | Hunt + detonation |
| zrada.exe | ArguePatch (Industroyer2) | Hunt + detonation |
| link.ps1 | GPO/script enumeration | Hunt in GPO/SYSVOL |
| sc.sh, wobf.sh, wsol.sh | ORCSHRED, AWFULSHRED, SOLOSHRED | Hunt in OT/Linux |

---

## Hash IOCs — SHA-256

| Hash | File / context | Evidence | Action |
|------|----------------|----------|--------|
| 8759e79cf3341406564635f3f08b2f333b0547c444735dba54ea6fce8539cf15 | dynacom_update.ps1 (DynoWiper) | hard / stable | Block + hunt |
| f4e9a3ddb83c53f5b7717af737ab0885abd2f1b89b2c676d3441a793f65ffaee | exp1.ps1 (DynoWiper) | hard / stable | Block + hunt |
| 65099f306d27c8bcdd7ba3062c012d2471812ec5e06678096394b238210f0f7c | Source.exe (DynoWiper) | hard / stable | Block + hunt |
| 835b0d87ed2d49899ab6f9479cddb8b4e03f5aeb2365c50a51f9088dcede68d5 | dynacom_update.exe (DynoWiper) | hard / stable | Block + hunt |
| 60c70cdcb1e998bffed2e6e7298e1ab6bb3d90df04e437486c04e77c411cae4b | schtask.exe (DynoWiper) | hard / stable | Block + hunt |
| d1389a1ff652f8ca5576f10e9fa2bf8e8398699ddfc87ddd3e26adb201242160 | schtask.exe (DynoWiper variant) | hard / stable | Block + hunt |
| 033cb31c081ff4292f82e528f5cb78a503816462daba8cc18a6c4531009602c2 | KB284726.ps1 (LazyWiper) | hard / stable | Block + hunt |
| 68192ca0fde951d973eb41a07814f402f2b46e610889224bd54583d8a332a464 | Probable DynoWiper distribution script | near-hard / stable | Hunt |
| ba89f7ca1fdbd7f8ce5f081f393af6e95f7de473e3d6376f42f11ad58f0f75fb | dynacom_update.exe (CERT Polska set) | hard / stable | Block + hunt |
| dc54d7f820f6f699ab5a976eb95d112f54b3dddde3f0097fc7322549753f7209 | explorer.exe (CERT Polska set) | hard / stable | Block + hunt |
| 50df5734dd0c6c5983c21278f119527f9fdf6ef1d7e808a29754ebc5253e9a86 | Cyclops Blink cpd sample 1 | hard / stable | Block + hunt |
| c082a9117294fa4880d75a2625cf80f63c8bb159b54a7151553969541ac35862 | Cyclops Blink cpd sample 2 | hard / stable | Block + hunt |
| 5866e1fa5e262ade874c4b869d57870a88e6a8f9d5b9c61bd5d6a323e763e021 | Infamous Chisel killer | hard / stable | Block + hunt |
| 2d19e015412ef8f8f7932b1ad18a5992d802b5ac62e59344f3aea2e00e0804ad | Infamous Chisel blob | hard / stable | Block + hunt |
| 5c5323bd17fd857a0e77be4e637841dad5c4367a72ac0a64cc054f78f530ba37 | ndbr_armv7l (Infamous Chisel) | hard / stable | Block + hunt |
| 3cf2de421c64f57c173400b2c50bbd9e59c58b778eba2eb56482f0c54636dd29 | ndbr_i686 (Infamous Chisel) | hard / stable | Block + hunt |
| 338f8b447c95ba1c3d8d730016f0847585a7840c0a71d5054eb51cc612f13853 | db (Infamous Chisel multi-call) | hard / stable | Block + hunt |
| 33a2be6638be67ba9117e0ac7bad26b12adbcdf6f8556c4dc2ff3033a8cdf14f | td (Infamous Chisel Tor) | hard / stable | Block + hunt |
| 140accb18ba9569b43b92da244929bc009c890916dd703794daf83034e349359 | tcpdump component (Infamous Chisel) | hard / stable | Block + hunt |

---

## Hash IOCs — SHA-1 (Industroyer2 chain)

| Hash | File / context | Evidence | Action |
|------|----------------|----------|--------|
| fd9c17c35a68fc505235e20c6e50c622aed8dea0 | 108_100.exe (Industroyer2) | hard / stable | Block + hunt |
| 6fa04992c0624c7aa3ca80da6a30e6de91226a16 | zrada.exe (ArguePatch) | hard / stable | Block + hunt |
| 9ce1491ce69809f92ae1fe8d4c0783bd1d11fbe7 | pa.pay (TailJump) | near-hard / stable | Hunt |
| 0090cb4de31d2d3bca55fd4a36859921b5fc5dae | link.ps1 (GPO enumeration) | near-hard / stable | Hunt |
| d27d0b9bb57b2bab881e0efb97c740b7e81405df | sc.sh (ORCSHRED) | hard / stable | Block + hunt |
| 3cdbc19bc4f12d8d00b81380f7a2504d08074c15 | wobf.sh (AWFULSHRED) | hard / stable | Block + hunt |
| 8fc7646fa14667d07e3110fe754f61a78cfde6bc | wsol.sh (SOLOSHRED) | hard / stable | Block + hunt |

---

## Behavioral / Procedure IOCs (high priority)

| Indicator | Context | Action |
|-----------|---------|--------|
| scilc.exe -do ... (OT SCIL script) | MicroSCADA misuse; destructive | OT alert + incident bridge |
| GPO + scheduled task wiper from DC | Domain-wide destructive rollout | Containment + disable malicious GPO |
| Default Domain Policy tampering (Files.xml, ScheduledTasks.xml) | Wiper deployment | Policy integrity check + rollback |
| .pcap / tcpdump on appliance outside maintenance | Credential interception | Egress + forensic retention |
| Credential replay from edge IP to M365/cloud | Credential harvest | Lock account + isolate |
| LSASS + NTDS.dit/SAM/SYSTEM extraction | Identity-tier escalation | High-severity IR |
| Kerberos ticket abuse (Diamond Ticket) | KDC abuse | KDC analytics + containment |
| Wiper logic: small vs large files at high velocity | Destructive pattern | Destructive playbook trigger |

---

## Behavioral / Procedure IOCs (medium–high)

| Indicator | Context | Action |
|-----------|---------|--------|
| Set-PSReadLineOption -HistorySaveStyle SaveNothing | PowerShell anti-forensics | Alert on admin hosts |
| [kworker:0/1] from user-space executable path | Linux process masquerade | EDR/analytics |
| Factory reset / config wipe of edge during attack | Anti-forensics | Escalation + snapshot |
| Slack webhook exfiltration of script output | Data exfil | Webhook egress alert |
| db.sqlite (or equivalent) accessed by unexpected process | WaveSign-type | Detection + hunt |

---

## Defender usage notes

- **Network IOCs:** Short validity window; use for retrospective correlation and short-term triage only. Revalidate before blocking.
- **Behavioral indicators** have longer useful life than IP/hash; prioritize GPO abuse, credential dumping, and OT command misuse in detection engineering.
- Prioritize multi-signal correlation over single-IOC hits. Maintain separate confidence for cluster vs incident attribution.
