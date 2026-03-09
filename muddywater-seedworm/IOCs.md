# IOC Tables — MuddyWater / Seedworm (Mango Sandstorm)

Extracted from the [CTI Research report](cti-research-muddywater-seedworm-with-nav.pdf) for correlation and triage. **Do not use as standalone attribution proof.** Validate with current telemetry before blocking. Network IOCs age rapidly — validate recency before enforcing blocklists.

**Evidence cutoff:** March 7, 2026 · **Core baseline:** [CISA AA22-055A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a)

---

## 1. Network IOCs (IP)

| Indicator | Context | Evidence | Freshness | Action |
|-----------|---------|----------|-----------|--------|
| 18[.]219.14.54 | MuddyWater C2 (May–June 2025; Jerusalem CCTV correlation) | R22 (Amazon Threat Intelligence) | maybe_expired | Hunt; short-term block after validation |
| 194.11.246.101 | processplanet[.]org (Attack #2, Turbid Currents) | Dream Security | 2025-02 | Block + hunt |
| 159.198.36.115 | screenai[.]online C2 (Phoenix backdoor v4) | Dream Security; Group-IB | 2025-08 | Block + hunt |
| 162.0.230.185 | Jerusalem/C2 server (Olalampo) | Group-IB | 2026-01 | Block + hunt |
| 209.74.87.100 | Olalampo payload host (GhostBackDoor/CHAR) | Group-IB | 2026-01 | Block + hunt |
| 143.198.5.41 | Olalampo payload host | Group-IB | 2026-01 | Block + hunt |
| 209.74.87.67 | Olalampo payload host | Group-IB | 2026-01 | Block + hunt |
| 159.198.66.153 | Resolves from nomercys[.]it[.]com (RustyWater) | Protoslabs | 2026-01 | Block + hunt |
| 159.198.68.25 | stratioai[.]org (Cloudflare); CloudSEK appendix | Protoslabs | 2026-01 | Block + hunt |
| 161.35.228.250 | Hosting pivot (RustyWater appendix) | Protoslabs | 2026-01 | Block + hunt |

---

## 2. Domain / URL IOCs (defanged)

| Indicator | Context | Evidence | Action |
|-----------|---------|----------|--------|
| nomercys.it[.]com | RustyWater RAT C2 and favicon host (Jan 2026) | Protoslabs, R19, R20 | Block + hunt |
| codefusiontech[.]org | Olalampo GhostFetch C2 (educational theme); HTTP_VIP; deploys AnyDesk | Group-IB, R21 | Block + hunt |
| netivtech[.]org | LIGHTPHOENIX C2 (Attack #1, Turbid Currents); StealthCache | Dream Security, R13 | Block + hunt |
| processplanet[.]org | Infrastructure co-registered with netivtech (Attack #2) | Dream Security | Block + hunt |
| photosjournalism[.]com | C2 for Attack #3 campaign | Dream Security | Block + hunt |
| screenai[.]online | Shared C2 (Phoenix backdoor v4) | Dream Security; Group-IB | Block + hunt |
| jerusalemsolutions[.]com | Olalampo GhostBackDoor C2 (Israel/Nomads theme) | Group-IB | Block + hunt |
| promoverse[.]org | Olalampo GhostFetch C2 | Group-IB | Block + hunt |
| miniquest[.]org | Olalampo GhostFetch C2 | Group-IB | Block + hunt |
| stratioai[.]org | Supporting C2 (Cloudflare IP) | Protoslabs | Block + hunt |
| bootcamptg[.]org | Supporting C2 (Cloudflare IP) | Protoslabs | Block + hunt |
| api.telegram.org | Telegram Bot API (CHAR, Small Sieve, PYTRIC C2) | R3, R21 | Alert when from atypical processes; do not block globally |

---

## 3. Hash IOCs — SHA-256

| Hash | File / family | Context | Action |
|------|----------------|--------|--------|
| 8674058edfbe636e550109fabb6403827c1bba4ab08833e9692099c96a43497a | POWERSTATS | PowerShell backdoor; credential theft | Block + hunt |
| b154d3fd88767776b1e36113c479ef3487ceda0f6e4fc80cef85ba539a589555 | PowGoop | Loader; Operation Quicksand variant | Block + hunt |
| 94278fa01900fdbfb58d2e373895c045c69c01915edc5349cd6f3e5b7130c472 | BugSleep / MuddyRot | C/C++ backdoor (Check Point, Sekoia) | Block + hunt |
| 5f22f4c4fdb36c4f0ea3248abb00521e39008c1fb4c97e1b4a9c7b9ef0b691c2 | wtsapi.dll (StealthCache) | Advanced backdoor | Block + hunt |
| a2001892410e9f34ff0d02c8bc9e7c53b0bd10da58461e1e9eab26bdbf410c79 | RUSTRIC / RustyWater / Archer RAT | Rust RAT | Block + hunt |
| f38a56b8dc0e8a581999621eef65ef497f0ac0d35e953bd94335926f00e9464f | Cybersecurity.doc | Malicious lure (disguised MSI); RustyWater (MalwareBazaar) | Block + hunt |
| 7523e53c979692f9eecff6ec760ac3df5b47f172114286e570b6bba3b2133f58 | reddit.exe | Rust RAT (RustyWater); Protoslabs | Block + hunt |
| 40dead1e1d83107698ff96bce9ea52236803b15b63fb0002e0b55af71a9b5e05 | Malicious macro DOC | FakeUpdate injector (Oct 2025) | Block + hunt |

---

## 4. Hash IOCs — SHA-1

| Hash | File / family | Context | Action |
|------|----------------|--------|--------|
| 47b70c47beb33e88b4197d6af1b768230e51b067 | Fooder | 64-bit C/C++ loader (ESET) | Block + hunt |
| 6de859a27ccc784689e8748cef536e32780e498a | Phoenix v4 | Backdoor (Oct 2025) | Block + hunt |
| 668dd5b6fb06fe30a98dd59dd802258b45394ccd | Phoenix backdoor | mononoke.exe v4 | Block + hunt |
| 5ec5a2adaa82a983fcc42ed9f720f4e894652bd7 | Phoenix backdoor | mononoke.exe v4 (variant) | Block + hunt |
| 1883db6de22d98ed00f8719b11de5bf1d02fc206b89fedd6dd0df0e8d40c4c56 | Phoenix backdoor | sysProcUpdate.exe variant | Block + hunt |
| 3ac8283916547c50501eed8e7c3a77f0ae8b009c | Phoenix backdoor | sysProcUpdate.exe variant | Block + hunt |
| 76fa8dca768b64aefedd85f7d0a33c2693b94bdb | Phoenix backdoor | sysProcUpdate.exe variant | Block + hunt |
| 3d6f69cc0330b302ddf4701bbc956b8fca683d1c | Phoenix backdoor | sysProcUpdate.exe variant | Block + hunt |
| f4e0f4449dc50e33f846545e57cddc7b8be1c10f | GhostFetch downloader | AnyDesk.exe | Block + hunt |
| 3441306816b7cbce9518f7c4eef47f623035ef0c | GhostFetch | Static EXE payload | Block + hunt |
| 9ca11fcb7c795606f45fb86563f784b73d3cf2f7 | GhostFetch loader | nightbird.exe | Block + hunt |
| 06f3b55f5034dd1d1f0099cd1b24059c0f7ce181 | GhostBackdoor | gdi32upd.dll (service DLL) | Block + hunt |
| 7bd04218541eacee2b7d63382c4bc0426d965bab | HTTP_VIP loader | FMApp.dll | Block + hunt |
| f306f59b9e51585e0fa509a6f75f9486a5f335eb | GhostFetch companion | server.exe | Block + hunt |
| 317a0b202cb5b06292dbf6718d728f44aefa81b8 | GhostFetch companion | client.exe | Block + hunt |
| ea3b90acb0c4e8322ac6c1925ca7f9cd2e184df5 | GhostBackdoor | edesc.dll (server DLL) | Block + hunt |
| 82b07097f7eed9c29f85d3ad0875e4cd98f6c69d | GhostBackdoor | Client payload | Block + hunt |

---

## 5. File / artifact IOCs (names and paths)

| Type | Indicator | Context | Action |
|------|-----------|---------|--------|
| Executable | gram_app.exe | Small Sieve (NSIS installer) | Hunt + detonation |
| DLL | FML.dll | Mori (DNS tunneling backdoor) | Hunt |
| DLL | wtsapi.dll | StealthCache | Hunt + detonation |
| Executable | reddit.exe | RustyWater (Cloudflare icon masquerade); spawned by installer | Hunt + detonation |
| Document | Cybersecurity.doc | Malicious lure (disguised MSI); RustyWater | Hunt + detonation |
| INI/path | CertificationKit.ini | Dropped installer payload path (ProgramData) | Hunt |
| Executable | mononoke.exe | Phoenix backdoor v4 | Hunt + detonation |
| Executable | sysProcUpdate.exe | Phoenix backdoor v4 variant | Hunt + detonation |
| Executable | AnyDesk.exe | GhostFetch downloader (abused) | Hunt when unsanctioned |
| Executable | nightbird.exe | GhostFetch loader | Hunt + detonation |
| DLL | gdi32upd.dll | GhostBackdoor service DLL | Hunt + detonation |
| DLL | FMApp.dll | HTTP_VIP loader | Hunt + detonation |
| Executable | server.exe / client.exe | GhostFetch companion | Hunt + detonation |
| DLL | edesc.dll | GhostBackdoor server DLL | Hunt + detonation |
| Registry | OutlookMicrosift | Small Sieve (intentional typo); Run keys | Hunt |
| Registry/path | \intel\utils\utils.jse | Run-key persistence; hidden script path | Hunt |
| Path | C:\intel\utils\utils.jse | Hidden script (MuddyWater persistence) | Hunt |
| Mutex | DocumentUpdater | BugSleep/MuddyRot | Alert + hunt |
| Mutex | PackageManager | BugSleep/MuddyRot | Alert + hunt |
| Scheduled task | MicrosoftVersionUpdater | Persistence | Alert + hunt |
| Scheduled task | DocumentUpdater | Persistence | Alert + hunt |
| Scheduled task | OutlookMicrosift | Persistence | Alert + hunt |
| Scheduled task | PackageManager | Persistence | Alert + hunt |
| PDB | phoenixV4 | Phoenix v4 lineage | Hunt in PE metadata |
| Path/var | Jacob | Rust library path (CHAR, RUSTRIC); dev env overlap | Hunt in artifacts |
| Doc metadata | DontAsk, Jacob | Olalampo document tags | Hunt |

---

## 6. C2 / URI patterns

| Indicator | Context | Action |
|-----------|---------|--------|
| HTTP(S) to /aq36 | StealthCache | Egress alert + block |
| /register, /iamalive | Phoenix v4 beaconing | Egress alert |
| Telegram bot username | stager_51_bot (CHAR) | Monitor; do not block Telegram globally |
| TCP port 443 (raw) | BugSleep/MuddyRot C2 | Correlate with mutex/injection |

---

## 7. Malware family names (hunt / detection)

### Historical (2017–2022)

| Family | Notes |
|--------|------|
| POWERSTATS | PowerShell backdoor |
| PowGoop | Loader, DLL side-loading |
| Small Sieve | gram_app.exe, Telegram C2 |
| Canopy / Starwhale | VBS/WSF chain |
| Mori | FML.dll, DNS tunneling |

### Modern (2024–2026)

| Family | Notes |
|--------|------|
| Dindoor | JavaScript/TypeScript backdoor; Deno runtime; cert "Amy Cherne"; US/Israel targets (early 2026) |
| Fakeset | Python backdoor; certs "Amy Cherne" & "Donald Gay"; linked Stagecomp/Darkcomp |
| Stagecomp / Darkcomp | Backdoors linked to cert "Donald Gay"; Seedworm/MuddyWater |
| BugSleep / MuddyRot | C/C++ backdoor; mutex DocumentUpdater/PackageManager |
| StealthCache | wtsapi.dll, netivtech[.]org |
| LIGHTPHOENIX | netivtech[.]org C2 (Turbid Currents Attack #1) |
| Fooder | 64-bit loader; Snake-game evasion |
| MuddyViper | C/C++ backdoor; 20 commands; CNG API |
| VAXOne | Masquerades as Veeam/AnyDesk/Xerox/OneDrive |
| CE-Notes | Chrome stealer |
| LP-Notes | Credential stealer (fake Windows Security prompt) |
| Blub | Browser stealer (Chrome/Edge/Firefox/Opera) |
| Phoenix v4 | Oct 2025; NordVPN OPSEC; mononoke.exe, sysProcUpdate.exe |
| PYTRIC | PyInstaller wiper; Telegram C2 (attribution low–medium) |
| RUSTRIC / RustyWater / Archer RAT | Rust RAT; nomercys.it[.]com; reddit.exe |
| GhostFetch | Loader; in-memory GhostBackDoor; AnyDesk.exe, nightbird.exe |
| GhostBackDoor | Advanced backdoor; gdi32upd.dll, edesc.dll |
| HTTP_VIP | Downloader; codefusiontech[.]org; FMApp.dll; deploys AnyDesk |
| CHAR | Rust backdoor; stager_51_bot; SOCKS5 |
| Kalim | Named as invoked by CHAR; limited public analysis |

---

## 8. RMM / remote tool abuse (soft IOCs)

Unsanctioned install or execution in phishing-to-persistence chains → alert and review.

| Software | References | Use |
|----------|------------|-----|
| Atera | R10, R11, R16 | Allowlist; alert if unsanctioned |
| ScreenConnect | R14, R24 | Same |
| SimpleHelp | R11 | Same |
| Syncro | R10, R16 | Same |
| RemoteUtilities | R11, R24 | Same |
| Level, PDQ | R16 | Same |
| AnyDesk | R21 (HTTP_VIP deployment) | Same |

---

## 9. Delivery / infrastructure (file-sharing, lures)

| Indicator | Context | Action |
|-----------|---------|--------|
| info[@]tmcell | Impersonated sender in RustyWater lure (Jan 2026) | Alert on inbound; hunt |
| Egnyte, OneHub, Mega, Dropbox | PDF/Office → link → RMM or payload | Alert on Office/PDF → file-sharing → executable |
| Phishing subject "Cybersecurity Guidelines" | RustyWater (TMCell compromise) | Hunt |
| Compromised TMCell (Altyn Asyr CJSC, Turkmenistan) | RustyWater campaign | Context for egress/delivery |
| Rclone to Wasabi bucket | MuddyWater exfil attempt (reported) | DLP + egress alert |

---

## 10. Behavioral / detection IOCs

| Indicator | Context | Action |
|-----------|---------|--------|
| powershell.exe or cmd.exe child of RMM agent | RMM-to-script chain | High-priority detection |
| VBA WriteHexToFile, UserForm1.TextBox1.Text | Macro pattern (Olalampo) | Alert |
| Four-level nested loop in macro | MuddyWater-specific | Alert |
| Injection into msedge.exe, chrome.exe, opera.exe, anydesk.exe, onedrive.exe, powershell.exe | BugSleep | EDR alert |
| >10 consecutive Sleep calls in first 60s of process | Anti-sandbox (BugSleep, Fooder) | Alert |
| Mutex DocumentUpdater or PackageManager | BugSleep/MuddyRot | Alert |
| Run-key persistence from ProgramData/Downloads/Temp | RustyWater, Phoenix v4 | Alert |
| Access to Chrome Login Data / Local State by non-browser process | CE-Notes, Blub, MuddyViper | Alert |
| Fake Windows Security prompt (LP-Notes, MuddyViper) | Credential theft | Alert |
| Telegram API (api.telegram.org) from atypical process | CHAR, Small Sieve, PYTRIC | Alert |
| Screen resolution / mouse activity checks | GhostFetch sandbox evasion | Hunt |
| Early VEH registration | RustyWater anti-debug | Hunt |
| PyInstaller + backup discovery/deletion | PYTRIC-style wiper | Alert |
| AV icon spoofing (Check Point, SentinelOne) in PE | UNG0801/IconCat | Hunt |
| Rust binaries in non-Rust environments | CHAR, RUSTRIC | Hunt |

---

## 11. CVE exploitation (initial access / escalation)

| CVE | Context | Action |
|-----|---------|--------|
| CVE-2020-1472 (Zerologon) | AA22-055A | Patch + detect |
| CVE-2020-0688 (Microsoft Exchange RCE) | AA22-055A | Patch + detect |
| Recent CVEs on public-facing servers | Olalampo (specifics undisclosed) | Prioritize VPN/public server patching |

---

## 12. IoT / CCTV vector (Amazon R22)

| Indicator | Context | Action |
|-----------|---------|--------|
| Anomalous outbound from DVR/NVR, IP cameras | Jerusalem CCTV correlation | Segment; monitor |
| Unauthorized external connections to CCTV servers | Same | Alert + block |

---

## 13. Digital certificates (soft IOCs)

| Subject / CN | Context | Action |
|--------------|---------|--------|
| Amy Cherne | Dindoor (signed); Fakeset; Stagecomp/Darkcomp lineage | Alert on signed payloads; CRT.sh / cert transparency hunt |
| Donald Gay | Fakeset; Stagecomp, Darkcomp (Seedworm) | Same |

---

## 14. Campaign timeline (major campaigns)

| Date | Event / source |
|------|----------------|
| 2017-05 | First tracked MuddyWater campaigns (FireEye) |
| 2018-01 | Mandiant: PowerStats, macro backdoors |
| 2022-05 | CISA/FBI/MI5 AA22-055A (Iranian APT MuddyWater) |
| 2023-06 | Deep Instinct: PhonyC2; Technion attribution |
| 2024-02 | Symantec/Broadcom: Dindoor, Fakeset (US/Israel) |
| 2024-03 | HarfangLab: Atera-Agent campaign (Israel); YARA |
| 2024-04 | Deep Instinct: DarkBeatC2 |
| 2025-02 | Dream Security "Turbid Currents" (9 attacks, Israel/EU/MENA) |
| 2025-10 | Group-IB: Phoenix v4, FakeUpdate |
| 2026-01 | Protoslabs: RustyWater; Group-IB Operation Olalampo (GhostFetch, GhostBackDoor, CHAR) |
| 2026-03 | Symantec/Carbon Black: Dindoor/Fakeset post Iran–US/Israel conflict |

---

## 15. YARA & Sigma (detection references)

- **YARA:** HarfangLab and others publish rules for MuddyWater tools (e.g. Atera MSI abuse). Example pattern: embedded strings such as `COMPANYID001Q3000009snPyIAIACCOUNTID`, `mrrobertcornish@gmail.comINTEGRATORLOGINCOMPANYID`, and known Atera cert MD5 `0A289978E5898DF40A238EB8A552E8` in MSI 1–4 MB. Refine with IOCs above.
- **Sigma:** Use process-creation rules for encoded PowerShell/HTA (e.g. `vbscript:Close(Execute("CreateObject('` + `powershell` + `-w 1 -exec Bypass` + `\ProgramData\`), or `[Convert]::ToBase64String` / `GetResponse().GetResponseStream()`). Mandiant TTPs; Detection.FYI. For Rust implants, hunt strings such as `reqwest` / `tokio`.

---

## 16. Authoritative IOC sources (full lists)

| Source | Content |
|--------|---------|
| [CISA AA22-055A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a) | IP, domain, hash, YARA; PowGoop, Small Sieve, Canopy, Mori, POWERSTATS |
| [CISA AA24-241A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a) | Iran-based actors, US critical infrastructure |
| [USCYBERCOM/CNMF](https://www.cybercom.mil/Media/News/Article/2897570/iranian-intel-cyber-suite-of-malware-uses-open-source-tools/) | Malware disclosure (R2) |
| [NCSC Small Sieve MAR](https://www.ncsc.gov.uk/files/NCSC-Malware-Analysis-Report-Small-Sieve.pdf) | Small Sieve hashes, gram_app.exe, OutlookMicrosift |
| [NCSC/CISA Joint Advisory](https://www.ncsc.gov.uk/pdfs/news/joint-advisory-observes-muddywater-actors-conducting-cyber-espionage.pdf) | Joint MuddyWater IOCs |
| [ESET MuddyWater Snakes](https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/) | Fooder, MuddyViper, CE-Notes, LP-Notes, Blub |
| [Group-IB Olalampo](https://www.group-ib.com/blog/muddywater-operation-olalampo/) | GhostFetch, GhostBackDoor, HTTP_VIP, CHAR, stager_51_bot |
| [Group-IB Infrastructure](https://www.group-ib.com/blog/muddywater-infrastructure-malware/) | StealthCache, netivtech[.]org, wtsapi.dll |
| [Amazon Threat Intelligence](https://aws.amazon.com/blogs/security/new-amazon-threat-intelligence-findings-nation-state-actors-bridging-cyber-and-kinetic-warfare/) | 18.219.14.54, Jerusalem CCTV correlation |
| [CloudSEK RustyWater](https://www.cloudsek.com/blog/reborn-in-rust-muddywater-evolves-tooling-with-rustywater-implant) | nomercys.it[.]com, reddit.exe, RustyWater hash |
| [Seqrite UNG0801](https://www.seqrite.com/blog/ung0801-tracking-threat-clusters-obsessed-with-av-icon-spoofing-targeting-israel/) | PYTRIC, RUSTRIC |
| [Help Net Security – Iran-linked APT](https://www.helpnetsecurity.com) | Dindoor, Fakeset; certs Amy Cherne, Donald Gay (Stagecomp/Darkcomp) |
| Dream Security (Turbid Currents), Protoslabs (RustyWater), Group-IB (Olalampo) | Domains, IPs, hashes, filenames in tables above |

---

## 17. Recommended SOC triage & prioritisation

- **Block/monitor C2:** Block or sinkhole known C2 domains/IPs (e.g. screenai[.]online, nomercys[.]it[.]com, bootcamptg[.]org, jerusalemsolutions[.]com). Monitor DNS and HTTP(S) to these; use passive DNS and CRT.sh for related certs (Amy Cherne, Donald Gay).
- **Hunt phishing & lures:** Search for malicious filenames (Cybersecurity.doc, reddit.exe, CertificationKit.ini). Check gateways for sender info[@]tmcell. Enforce strict Office macro policy; use DLP for Rclone/Wasabi exfil.
- **Endpoint/YARA:** Deploy YARA (e.g. HarfangLab Atera MSI rules) for MuddyWater binaries and DLLs. Hunt persistence: `HKCU\...\Software\Microsoft\Office\Outlook\Addins\OutlookMicrosift`, Run keys under `\intel\utils\utils.jse`, and `C:\intel\utils\utils.jse`.
- **Network/lateral:** Alert on unsanctioned AnyDesk/PDQ; monitor Telegram Bot API from non-browser processes (CHAR). Egress filter and TLS inspection for encoded MSHTA/PowerShell.
- **Threat intel:** Correlate with MITRE (T1566, T1059, T1071.001, T1547.001, T1003). Use Sigma rules and VT/Hybrid-Analysis for hash and IOC triage. On confirmation, assume broad access; isolate, rebuild, rotate creds, share IOCs with CERTs.

---

## Defender usage notes

- **Network IOCs:** Validate against current blocklists and passive DNS before production blocking; treat as maybe_expired for incident-specific reporting.
- **Hashes:** Prefer SHA-256 for blocking; SHA-1 where only that is published (Fooder, Phoenix v4).
- **Behavioral indicators** have longer useful life than IP/domain; prioritize RMM-to-script, injection, mutexes, and credential-store access.
- **Single-source items** (e.g. Olalampo, StealthCache): use for hunting; do not rely as sole attribution for legal/policy.
- **PYTRIC:** Destructive capability high confidence; MuddyWater attribution low–medium — hunt accordingly.
- Revalidate all indicators with CISA and vendor advisories before enforcement.
