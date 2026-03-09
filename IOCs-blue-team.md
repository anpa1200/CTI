# Blue-Team IOC Tables — Consolidated

Single reference for **Handala (Void Manticore)**, **MuddyWater (Mango Sandstorm)**, and **Sandworm (APT44 / Seashell Blizzard)**. Use for SIEM rules, blocklists, hunt packages, and EDR correlation. Validate against current telemetry before blocking; do not use as sole attribution proof.

**Legend**

| Field | Values |
|-------|--------|
| **Actor** | Handala \| MuddyWater \| Sandworm |
| **Action** | **Block** — add to blocklist where appropriate; **Alert** — generate detection; **Hunt** — retrospective/search; **Monitor** — observe only |
| **Confidence** | hard / near-hard / soft ; stable_tracking / maybe_expired / volatile |

**Source reports:** [handala-hack-group](handala-hack-group/IOCs.md) · [muddywater-seedworm](muddywater-seedworm/IOCs.md) · [sandworm-apt44](sandworm-apt44/IOCs.md)

---

## 1. IP addresses

| Indicator | Actor | Context | Action | Confidence |
|-----------|-------|---------|--------|------------|
| 64.176.169.22 | Handala | Campaign C2/infrastructure | Hunt; conditional block after validation | near-hard / maybe_expired |
| 64.176.172.235 | Handala | Campaign C2/infrastructure | Hunt; conditional block after validation | near-hard / maybe_expired |
| 64.176.172.165 | Handala | Campaign C2/infrastructure | Hunt; conditional block after validation | near-hard / maybe_expired |
| 64.176.173.77 | Handala | Campaign C2/infrastructure | Hunt; conditional block after validation | near-hard / maybe_expired |
| 64.176.172.101 | Handala | Campaign C2/infrastructure | Hunt; conditional block after validation | near-hard / maybe_expired |
| 64.176.172.0/24 | Handala | Range context | Hunt; conditional block after validation | near-hard / maybe_expired |
| 185.200.177.10 | Sandworm | VPN/M365 logins (Dec 2025 Poland) | Hunt; short-term block after validation | near-hard / maybe_expired |
| 195.26.87.225 | Sandworm | Renewables-sector login source | Hunt; short-term block after validation | near-hard / maybe_expired |
| 146.190.211.75 | Sandworm | FortiGate management abuse | Hunt; short-term block after validation | near-hard / maybe_expired |
| 128.140.34.155 | Sandworm | FortiGate management abuse | Hunt; short-term block after validation | near-hard / maybe_expired |
| 95.85.114.66 | Sandworm | C2 / tool retrieval | Hunt; short-term block after validation | near-hard / maybe_expired |
| 95.85.114.74 | Sandworm | C2 / tool retrieval | Hunt; short-term block after validation | near-hard / maybe_expired |
| 31.172.71.5 | Sandworm | Compromised server (Dec 2025 Poland) | Hunt; short-term block after validation | near-hard / maybe_expired |

---

## 2. Domains / URLs (defanged)

| Indicator | Actor | Context | Action | Confidence |
|-----------|-------|---------|--------|------------|
| link-target[.]net | Handala | Payload/lure | Alert + temporary block in campaign window | near-hard |
| storjshare[.]io (path to update.zip) | Handala | Payload delivery | Alert + detonation | near-hard |
| mega[.]nz / mega[.]io | Handala | Benign in isolation; supplier-lure + .msi context | Hunt only; never block alone | soft |
| esetsmart[.]com | Sandworm | ESET-impersonation phishing | Alert + block | soft / volatile |
| esetscanner[.]com | Sandworm | ESET-impersonation phishing | Alert + block | soft / volatile |
| esetremover[.]com | Sandworm | ESET-impersonation phishing | Alert + block | soft / volatile |
| solntsepek[.]com | Sandworm | Persona-linked (AcidPour) | Hunt + block | soft / volatile |
| totalcmd[.]net | Sandworm | Masquerading software distribution | Block + detonation | near-hard / maybe_expired |
| updater-file[.]xyz | Sandworm | Malware/tool delivery | Block + detonation | near-hard / maybe_expired |

---

## 3. SHA-256 hashes

| Hash | Actor | Context | Action | Confidence |
|------|-------|--------|--------|------------|
| 6eb7dbf27a25639c7f11c05fd88ea2a301e0ca93d3c3bdee1eb5917fc60a56ff | Handala | CRM-linked malicious .msi | Block + hunt | near-hard |
| e1204ebbd8f15dbf5f2e41dddc5337e3182fc4daf75b05acc948b8b965480ca0 | Handala | cl.exe | Block + hunt | near-hard |
| 3c9dc8ada56adf9cebfc501a2d3946680dcb0534a137e2e27a7fcb5994cd9de6 | Handala | rwdsk.sys | Block + hunt | near-hard |
| d0c03d40772cd468325bbc522402f7b737f18b8f37a89bacc5c8a00c2b87bfc6 | Handala | Lineage | Hunt | near-hard |
| deeaf85b2725289d5fc262b4f60dda0c68ae42d8d46d0dc19b9253b451aea25a | Handala | Lineage | Hunt | near-hard |
| 87f0a902d6b2e2ae3647f10ea214d19db9bd117837264ae15d622b5314ff03a5 | Handala | Lineage | Hunt | near-hard |
| 85fa58cc8c4560adb955ba0ae9b9d6cab2c381d10dbd42a0bceb8b62a92b7636 | Handala | Lineage | Hunt | near-hard |
| 74d8d60e900f931526a911b7157511377c0a298af986d42d373f51aac4f362f6 | Handala | Lineage | Hunt | near-hard |
| cc77e8ab73b577de1924e2f7a93bcfd852b3c96c6546229bc8b80bf3fd7bf24e | Handala | Lineage | Hunt | near-hard |
| 40417eb9ca90af12129f7bcf6e7b2f250f4919f1c5ea59d2f4fc9c96c7f819e3 | Handala | Check Point YARA metadata | Hunt | near-hard |
| 8759e79cf3341406564635f3f08b2f333b0547c444735dba54ea6fce8539cf15 | Sandworm | dynacom_update.ps1 (DynoWiper) | Block + hunt | hard / stable |
| f4e9a3ddb83c53f5b7717af737ab0885abd2f1b89b2c676d3441a793f65ffaee | Sandworm | exp1.ps1 (DynoWiper) | Block + hunt | hard / stable |
| 65099f306d27c8bcdd7ba3062c012d2471812ec5e06678096394b238210f0f7c | Sandworm | Source.exe (DynoWiper) | Block + hunt | hard / stable |
| 835b0d87ed2d49899ab6f9479cddb8b4e03f5aeb2365c50a51f9088dcede68d5 | Sandworm | dynacom_update.exe (DynoWiper) | Block + hunt | hard / stable |
| 60c70cdcb1e998bffed2e6e7298e1ab6bb3d90df04e437486c04e77c411cae4b | Sandworm | schtask.exe (DynoWiper) | Block + hunt | hard / stable |
| d1389a1ff652f8ca5576f10e9fa2bf8e8398699ddfc87ddd3e26adb201242160 | Sandworm | schtask.exe (DynoWiper variant) | Block + hunt | hard / stable |
| 033cb31c081ff4292f82e528f5cb78a503816462daba8cc18a6c4531009602c2 | Sandworm | KB284726.ps1 (LazyWiper) | Block + hunt | hard / stable |
| 68192ca0fde951d973eb41a07814f402f2b46e610889224bd54583d8a332a464 | Sandworm | DynoWiper distribution script | Hunt | near-hard / stable |
| ba89f7ca1fdbd7f8ce5f081f393af6e95f7de473e3d6376f42f11ad58f0f75fb | Sandworm | dynacom_update.exe (CERT set) | Block + hunt | hard / stable |
| dc54d7f820f6f699ab5a976eb95d112f54b3dddde3f0097fc7322549753f7209 | Sandworm | explorer.exe (CERT set) | Block + hunt | hard / stable |
| 50df5734dd0c6c5983c21278f119527f9fdf6ef1d7e808a29754ebc5253e9a86 | Sandworm | Cyclops Blink cpd sample 1 | Block + hunt | hard / stable |
| c082a9117294fa4880d75a2625cf80f63c8bb159b54a7151553969541ac35862 | Sandworm | Cyclops Blink cpd sample 2 | Block + hunt | hard / stable |
| 5866e1fa5e262ade874c4b869d57870a88e6a8f9d5b9c61bd5d6a323e763e021 | Sandworm | Infamous Chisel killer | Block + hunt | hard / stable |
| 2d19e015412ef8f8f7932b1ad18a5992d802b5ac62e59344f3aea2e00e0804ad | Sandworm | Infamous Chisel blob | Block + hunt | hard / stable |
| 5c5323bd17fd857a0e77be4e637841dad5c4367a72ac0a64cc054f78f530ba37 | Sandworm | ndbr_armv7l (Infamous Chisel) | Block + hunt | hard / stable |
| 3cf2de421c64f57c173400b2c50bbd9e59c58b778eba2eb56482f0c54636dd29 | Sandworm | ndbr_i686 (Infamous Chisel) | Block + hunt | hard / stable |
| 338f8b447c95ba1c3d8d730016f0847585a7840c0a71d5054eb51cc612f13853 | Sandworm | db (Infamous Chisel) | Block + hunt | hard / stable |
| 33a2be6638be67ba9117e0ac7bad26b12adbcdf6f8556c4dc2ff3033a8cdf14f | Sandworm | td Tor (Infamous Chisel) | Block + hunt | hard / stable |
| 140accb18ba9569b43b92da244929bc009c890916dd703794daf83034e349359 | Sandworm | tcpdump (Infamous Chisel) | Block + hunt | hard / stable |

---

## 4. MD5 hashes (Handala only)

| Hash | Actor | Context | Action | Confidence |
|------|-------|--------|--------|------------|
| 2bf14f4d28ea8e80f227873de0a4f367 | Handala | Campaign | Hunt | near-hard |
| 7b1602dcf39d2f564008e3abbb2f2f6a | Handala | Campaign | Hunt | near-hard |
| 57fbfeb55f8332f6413f31bb310ed7f9 | Handala | Campaign | Hunt | near-hard |
| 1476f9f4f13db0a7179fd4dc0825765d | Handala | Campaign | Hunt | near-hard |
| 81e123351eb80e605ad73268a5653ff3 | Handala | Lineage | Hunt | near-hard |
| a9fa6cfdba41c57d8094545e9b56db36 | Handala | Lineage | Hunt | near-hard |
| 8f766dea3afd410ebcd5df5994a3c571 | Handala | Lineage | Hunt | near-hard |
| 7b71764236f244ae971742ee1bc6b098 | Handala | cl.exe | Block + hunt | near-hard |
| bbe983dba3bf319621b447618548b740 | Handala | GoXML.exe | Block + hunt | near-hard |
| 8f6e7653807ebb57ecc549cef991d505 | Handala | rwdsk.sys | Block + hunt | near-hard |
| 78562ba0069d4235f28efd01e3f32a82 | Handala | Lineage | Hunt | near-hard |
| 60afb1e62ac61424a542b8c7b4d2cf01 | Handala | Lineage | Hunt | near-hard |

---

## 4b. SHA-1 hashes (Sandworm — Industroyer2 chain)

| Hash | Actor | Context | Action | Confidence |
|------|-------|--------|--------|------------|
| fd9c17c35a68fc505235e20c6e50c622aed8dea0 | Sandworm | 108_100.exe (Industroyer2) | Block + hunt | hard / stable |
| 6fa04992c0624c7aa3ca80da6a30e6de91226a16 | Sandworm | zrada.exe (ArguePatch) | Block + hunt | hard / stable |
| 9ce1491ce69809f92ae1fe8d4c0783bd1d11fbe7 | Sandworm | pa.pay (TailJump) | Hunt | near-hard / stable |
| 0090cb4de31d2d3bca55fd4a36859921b5fc5dae | Sandworm | link.ps1 (GPO enumeration) | Hunt | near-hard / stable |
| d27d0b9bb57b2bab881e0efb97c740b7e81405df | Sandworm | sc.sh (ORCSHRED) | Block + hunt | hard / stable |
| 3cdbc19bc4f12d8d00b81380f7a2504d08074c15 | Sandworm | wobf.sh (AWFULSHRED) | Block + hunt | hard / stable |
| 8fc7646fa14667d07e3110fe754f61a78cfde6bc | Sandworm | wsol.sh (SOLOSHRED) | Block + hunt | hard / stable |

---

## 5. File / artifact names (hunt & detection)

| Indicator | Actor | Context | Action |
|-----------|-------|---------|--------|
| update.zip | Handala | Core delivery | Block + hunt + quarantine |
| CrowdStrike.exe | Handala | Masqueraded | Block + hunt + quarantine |
| OpenFileFinder.dll | Handala | Delivery | Block + hunt + quarantine |
| Champion.pif | Handala | Delivery | Block + hunt + quarantine |
| Careol.zip / Carrol.zip / Carrol.cmd | Handala | Delivery | Block + hunt |
| Phase3.ps1 | Handala | Script | Hunt + script block logging |
| cl.exe | Handala | Wiper (hash correlate) | Block + hunt |
| rwdsk.sys | Handala | Driver | Block + hunt |
| GoXML.exe | Handala | Wiper | Block + hunt |
| do.zip / Do.exe | Handala | Wiper | Block + hunt |
| RawDisk3 (service) | Handala | Driver/service | Alert + hunt |
| error4.aspx, ClientBin.aspx, pickers.aspx | Handala | Web root | Hunt + IIS/EDR |
| mellona.exe, disable_defender.exe | Handala | AV kill | Alert + hunt |
| PowGoop, Small Sieve, Canopy, Mori, POWERSTATS | MuddyWater | Legacy malware families | Hunt in telemetry |
| BugSleep, MuddyRot, Fooder, MuddyViper | MuddyWater | Modern implants | Hunt + detonation |
| CE-Notes, LP-Notes, Blub, go-socks5 | MuddyWater | Credential/proxy | Hunt |
| GhostFetch, GhostBackDoor, HTTP_VIP, CHAR | MuddyWater | Olalampo set | Hunt + Rust/Deno context |
| Atera, ScreenConnect, Syncro, SimpleHelp, RemoteUtilities | MuddyWater | RMM abuse | Allowlist; alert if unsanctioned |
| dynacom_update.ps1, exp1.ps1 | Sandworm | DynoWiper | Hunt + script logging |
| dynacom_update.exe, Source.exe, schtask.exe | Sandworm | DynoWiper | Block + hunt |
| KB284726.ps1 | Sandworm | LazyWiper | Hunt + script logging |
| scilc.exe | Sandworm | OT MicroSCADA misuse | OT alert; non-maintenance args |
| 108_100.exe, zrada.exe | Sandworm | Industroyer2 | Block + hunt |
| link.ps1, sc.sh, wobf.sh, wsol.sh | Sandworm | GPO/OT scripts | Hunt |

---

## 6. Behavioral / command-line (detection rules)

| Indicator | Actor | Action |
|-----------|-------|--------|
| vssadmin Delete Shadows /all /quiet | Handala | Alert; destructive playbook trigger |
| bcdedit /set {default} recoveryenabled No | Handala | Alert; destructive playbook trigger |
| bcdedit /set {default} bootstatuspolicy ignoreallfailures | Handala | Alert; destructive playbook trigger |
| ping 4.2.2.4 -n 5 > Nul | Handala | Correlate with installer/script ancestry |
| confirmdeletefiles (wiper argument) | Handala | Hunt + CLI correlation |
| Security kill-list: wrsa.exe, msmpeng.exe, ccsvchst.exe, tmccsf.exe, aswidsagent.exe, avp.exe, savservice.exe, fssm32.exe, coreServiceShell.exe, V3Svc.exe, V3LITE.EXE, V3Main.exe | Handala | Alert on kill-burst + anti-recovery |
| New-MailboxSearch, Get-Recipient (Exchange) | Handala | Hunt in Exchange/PowerShell logs |
| powershell.exe / cmd.exe child of RMM agent | MuddyWater | Alert; RMM-to-script chain |
| Office/PDF lure → file-sharing → admin agent | MuddyWater | Alert; campaign pattern |
| Scheduled task updater-like name on non-admin workstation | MuddyWater | Hunt persistence |
| Browser credential store access by unsigned binary | MuddyWater | Alert credential theft |
| Rust/Deno execution where not business-normal | MuddyWater | Hunt (e.g. CHAR) |
| Process injection into legitimate executables | MuddyWater | EDR analytics |
| scilc.exe -do ... (OT SCIL script) | Sandworm | OT alert + incident bridge |
| GPO + scheduled task wiper from DC | Sandworm | Containment + disable malicious GPO |
| Default Domain Policy tampering (Files.xml, ScheduledTasks.xml) | Sandworm | Policy integrity + rollback |
| .pcap / tcpdump on appliance outside maintenance | Sandworm | Egress + forensic retention |
| Credential replay from edge IP to M365/cloud | Sandworm | Lock account + isolate |
| LSASS + NTDS.dit/SAM/SYSTEM extraction | Sandworm | High-severity IR |
| Kerberos Diamond Ticket abuse | Sandworm | KDC analytics + containment |
| Set-PSReadLineOption -HistorySaveStyle SaveNothing | Sandworm | Alert anti-forensics on admin |
| [kworker:0/1] from user-space path (Linux) | Sandworm | EDR process masquerade |
| Factory reset / config wipe of edge during attack | Sandworm | Escalation + snapshot |
| Slack webhook exfil of script output | Sandworm | Webhook egress alert |
| db.sqlite (or equivalent) by unexpected process | Sandworm | WaveSign-type hunt |

---

## 7. Actor channels (monitor only — soft IOCs)

| Indicator | Actor | Use |
|-----------|-------|-----|
| https://t.me/HANDALA_RSS | Handala | Monitor + timeline |
| https://t.me/s/handala_backup_357 | Handala | Monitor + timeline |
| @Handala_Backup (X/Twitter) | Handala | Monitor + timeline |

---

## Usage

- **Block:** Prefer for hard/stable hash and high-confidence domain IOCs; revalidate IPs before long-term block.
- **Alert:** Use for behavioral and CLI patterns; tune to reduce false positives.
- **Hunt:** Use for lineage, soft, and maybe_expired IOCs; combine with time windows and other signals.
- **Monitor:** Use for actor channels and benign-context indicators only.

Revalidate all indicators against current blocklists and passive DNS before production blocking. Prioritize multi-signal correlation over single-IOC decisions.
