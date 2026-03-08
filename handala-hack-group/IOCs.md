# IOC Tables — Handala Hack Group (Void Manticore)

Extracted from the [CTI Research report](cti-research-handala-hack-group-with-nav.pdf) for correlation and triage. **Do not use as standalone attribution proof.** Validate with current telemetry before blocking. Lineage IOCs (MOIS/Void Manticore context) do not independently prove Handala attribution.

**Evidence cutoff:** March 5, 2026 · **Sources:** [R1](https://www.trellix.com/en-gb/blogs/research/handalas-wiper-targets-israel/), [R2](https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/), [R5](https://research.checkpoint.com/2026/2025-the-untold-stories-of-check-point-research/), [R8](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a)

---

## Network IOCs (IP/CIDR)

| Indicator | Evidence | Freshness | Action |
|-----------|----------|-----------|--------|
| 64.176.169.22 | near-hard | maybe_expired | Hunt; conditional block after local validation |
| 64.176.172.235 | near-hard | maybe_expired | Hunt; conditional block after local validation |
| 64.176.172.165 | near-hard | maybe_expired | Hunt; conditional block after local validation |
| 64.176.173.77 | near-hard | maybe_expired | Hunt; conditional block after local validation |
| 64.176.172.101 | near-hard | maybe_expired | Hunt; conditional block after local validation |
| 64.176.172.0/24 | near-hard (range context) | maybe_expired | Hunt; conditional block after local validation |

---

## URL / Infrastructure IOCs

| Indicator | Evidence | Notes |
|-----------|----------|--------|
| hxxps://link-target[.]net/jfby32 | near-hard | Monitor + detonation; temporary block in campaign window |
| hxxps://storjshare[.]io/s/jv4ftpt67w5zw2b2wqj4v4zffviq/...update.zip | near-hard | Payload path; monitor + detonation |
| mega[.]nz / mega[.]io | benign-context | Hunt-only in supplier-lure + .msi context; **never block in isolation** |
| hxxps://www[.]icanhazip[.]com | benign-context | Behavior correlation only; **never block in isolation** |
| hxxps://www[.]microsoft[.]com | benign-context | Behavior correlation only; **never block in isolation** |

---

## Actor Channel / Messaging (Soft IOCs)

| Indicator | Use |
|-----------|-----|
| https://t.me/HANDALA_RSS | Monitor + timeline correlation only |
| https://t.me/s/handala_backup_357 | Monitor + timeline correlation only |
| @Handala_Backup (X/Twitter) | Monitor + timeline correlation only |

---

## File, Service, and Artifact IOCs

| Type | Indicator | Evidence | Action |
|------|-----------|----------|--------|
| Core delivery/impact | update.zip | near-hard | Hunt + detonation + quarantine |
| | CrowdStrike.exe | near-hard | Hunt + detonation + quarantine |
| | OpenFileFinder.dll | near-hard | Hunt + detonation + quarantine |
| | Champion.pif | near-hard | Hunt + detonation + quarantine |
| | Careol.zip / Carrol.zip | near-hard | Hunt + detonation + quarantine |
| | Carrol.cmd | near-hard | Hunt + process-lineage correlation |
| | Phase3.ps1 | near-hard | Hunt + script block telemetry |
| | UploadDataToTelegram (project ID) | near-hard | Hunt in malware strings + process ancestry |
| Wiper/destructive | cl.exe | near-hard | Hunt with hash + service/driver correlation |
| | rwdsk.sys | near-hard | Hunt with hash + driver-load correlation |
| | GoXML.exe | near-hard | Hunt + sandbox + lineage mapping |
| | do.zip / Do.exe | near-hard | Hunt + detonation + process-lineage |
| | RawDisk3 (service) | near-hard | Service/driver analytics + playbook trigger |
| | error4.aspx, ClientBin.aspx, pickers.aspx | near-hard | Web root diff + IIS/EDR correlation |
| | mellona.exe, disable_defender.exe | near-hard | Hunt + AV-kill/defense-evasion correlation |

---

## Hash IOCs (SHA-256)

| Hash | Context |
|------|---------|
| 6eb7dbf27a25639c7f11c05fd88ea2a301e0ca93d3c3bdee1eb5917fc60a56ff | CRM-linked malicious .msi |
| e1204ebbd8f15dbf5f2e41dddc5337e3182fc4daf75b05acc948b8b965480ca0 | cl.exe |
| 3c9dc8ada56adf9cebfc501a2d3946680dcb0534a137e2e27a7fcb5994cd9de6 | rwdsk.sys |
| d0c03d40772cd468325bbc522402f7b737f18b8f37a89bacc5c8a00c2b87bfc6 | Lineage |
| deeaf85b2725289d5fc262b4f60dda0c68ae42d8d46d0dc19b9253b451aea25a | Lineage |
| 87f0a902d6b2e2ae3647f10ea214d19db9bd117837264ae15d622b5314ff03a5 | Lineage |
| 85fa58cc8c4560adb955ba0ae9b9d6cab2c381d10dbd42a0bceb8b62a92b7636 | Lineage |
| 74d8d60e900f931526a911b7157511377c0a298af986d42d373f51aac4f362f6 | Lineage |
| cc77e8ab73b577de1924e2f7a93bcfd852b3c96c6546229bc8b80bf3fd7bf24e | Lineage |
| 40417eb9ca90af12129f7bcf6e7b2f250f4919f1c5ea59d2f4fc9c96c7f819e3 | Check Point YARA metadata |

---

## Hash IOCs (MD5, legacy)

| Hash | Context |
|------|---------|
| 2bf14f4d28ea8e80f227873de0a4f367 | Campaign |
| 7b1602dcf39d2f564008e3abbb2f2f6a | Campaign |
| 57fbfeb55f8332f6413f31bb310ed7f9 | Campaign |
| 1476f9f4f13db0a7179fd4dc0825765d | Campaign |
| 81e123351eb80e605ad73268a5653ff3 | Lineage |
| a9fa6cfdba41c57d8094545e9b56db36 | Lineage |
| 8f766dea3afd410ebcd5df5994a3c571 | Lineage |
| 7b71764236f244ae971742ee1bc6b098 | cl.exe |
| bbe983dba3bf319621b447618548b740 | GoXML.exe |
| 8f6e7653807ebb57ecc549cef991d505 | rwdsk.sys |
| 78562ba0069d4235f28efd01e3f32a82 | Lineage |
| 60afb1e62ac61424a542b8c7b4d2cf01 | Lineage |

---

## Command-Line / Behavioral IOCs

| Indicator | Use |
|-----------|-----|
| vssadmin Delete Shadows /all /quiet | High-priority detection + destructive playbook trigger |
| bcdedit /set {default} recoveryenabled No | High-priority detection + destructive playbook trigger |
| bcdedit /set {default} bootstatuspolicy ignoreallfailures | High-priority detection + destructive playbook trigger |
| ping 4.2.2.4 -n 5 > Nul | Correlate with installer/script ancestry |
| Wiper argument: confirmdeletefiles | Hunt + command-line correlation |
| Security-process kill-list | wrsa.exe, msmpeng.exe, ccsvchst.exe, tmccsf.exe, aswidsagent.exe, avp.exe, savservice.exe, fssm32.exe, coreServiceShell.exe, V3Svc.exe, V3LITE.EXE, V3Main.exe — correlate with kill-burst + anti-recovery |
| Exchange cmdlets | New-MailboxSearch, Get-Recipient — hunt in Exchange/PowerShell audit logs |

---

## Defender usage notes

- Revalidate all network indicators against current blocklists and passive DNS before production blocking.
- Treat channel/claim-only indicators as soft IOCs until telemetry confirms compromise.
- Prioritize multi-signal correlation (IOC + behavior + campaign context) over single-indicator decisions.
- Actor claim volumes are frequently overstated; do not use claimed exfiltration size as a proxy for confirmed impact.
