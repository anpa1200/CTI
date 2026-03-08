# IOC Tables — MuddyWater / Seedworm (Mango Sandstorm)

Extracted from the [CTI Research report](cti-research-muddywater-seedworm.html) for correlation and triage. **Do not use as standalone attribution proof.** Validate with current telemetry before blocking. For full network, URL, and hash IOCs use the linked advisories (e.g. [CISA AA22-055A](https://www.cisa.gov/uscert/ncas/alerts/aa22-055a), [AA24-241A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a), and vendor reports).

**Evidence cutoff:** March 7, 2026 · **Core baseline:** [R1](https://www.cisa.gov/uscert/ncas/alerts/aa22-055a)

---

## Network / URL / Hash IOCs (Authoritative Sources)

| Source | Use |
|--------|-----|
| [CISA AA22-055A](https://www.cisa.gov/uscert/ncas/alerts/aa22-055a) | Primary IOC set (IP, domain, hash, YARA) for Iranian gov-sponsored activity including MuddyWater |
| [CISA AA24-241A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a) | Iran-based actors, US critical infrastructure sectors |
| [USCYBERCOM](https://www.cybercom.mil/Media/News/Article/2945592/iranian-government-sponsored-actors-conduct-cyber-operations-against-global-gov/) | Aligned indicators |
| [NCSC Small Sieve MAR](https://www.ncsc.gov.uk/files/NCSC-Malware-Analysis-Report-Small-Sieve.pdf) | Small Sieve hashes and artifacts |
| [CISA CNMF MuddyWater](https://www.cisa.gov/news-events/alerts/2022/01/12/cnmf-identifies-and-discloses-malware-used-iranian-apt-muddywater) | Disclosed malware hashes |
| [ESET Research](https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/) | Fooder/MuddyViper technical IOCs |
| [Group-IB Olalampo](https://www.group-ib.com/blog/muddywater-operation-olalampo/) | GhostFetch, GhostBackDoor, HTTP_VIP, CHAR |

---

## Malware / Tooling Family IOCs (Artifact Names)

### Legacy (2017–2022, advisory-documented)

| Family / artifact | References | Action |
|-------------------|------------|--------|
| PowGoop | R1, R3, R4 | Hunt in long-retention telemetry |
| Small Sieve | R1, R3, R4 | Hunt; see NCSC MAR for hashes |
| Canopy (Starwhale) | R1, R4 | Hunt |
| Mori | R1, R4 | Hunt |
| POWERSTATS | R1, R4 | Hunt |

### Modern (2024–2026 reporting)

| Family / artifact | References | Action |
|-------------------|------------|--------|
| BugSleep / MuddyRot | R12 | Hunt; C/C++ implant, process injection |
| Fooder (loader) | R13, R14 | Hunt + detonation |
| MuddyViper (backdoor) | R13, R14 | Hunt + C2/credential correlation |
| CE-Notes, LP-Notes, Blub | R13 | Credential/reverse-tunnel modules |
| go-socks5 | R13 | Proxy component |
| GhostFetch | R15 | Olalampo downloader |
| GhostBackDoor | R15 | Olalampo backdoor |
| HTTP_VIP | R15 | Olalampo component |
| CHAR (Rust) | R15 | Olalampo backdoor; hunt Rust in unexpected contexts |

---

## RMM / Software Abuse (Soft IOCs)

Unsanctioned installation or execution of these in phishing-to-persistence chains should trigger detection and review.

| Software / product | References | Use |
|--------------------|------------|-----|
| Atera | R10, R11 | Allowlist; alert on unsanctioned install/exec |
| ScreenConnect | R10, R11 | Same |
| Syncro | R10, R11 | Same |
| SimpleHelp | R10, R11 | Same |
| RemoteUtilities | R10, R11 | Same |

---

## Behavioral / Command-Line IOCs

| Indicator | Use |
|-----------|-----|
| `powershell.exe` or `cmd.exe` spawned as child of RMM agent binaries | High-value detection; RMM-to-script chain |
| Office/PDF lure → external file-sharing → administrative agent deployment | Campaign pattern; stack with RMM IOCs |
| Scheduled task creation with updater-like naming on non-admin workstations | Persistence hunt (R13) |
| Browser credential store access by unsigned/unexpected binaries | Credential theft correlation |
| Rust or Deno runtime execution where not business-normal | 2026 hunt heuristic (e.g. CHAR); not deterministic alone |
| Process injection into common legitimate executables | BugSleep/MuddyViper behavior; EDR analytics |
| Staged in-memory execution after loader | Fooder/MuddyViper; memory/script block logging |
| Telegram-assisted C2 or command channeling | Olalampo; network/messaging correlation |

---

## Initial Access & Persistence Patterns

| Pattern | References |
|---------|------------|
| Spearphishing with document/URL lures and embedded links | R1, R10, R24 |
| Abuse of valid credentials and account compromise | R1, R11 |
| Deployment via trusted remote administration after foothold | R10, R11 |
| Scheduled tasks and startup persistence | R13 |
| Service/process masquerading and memory injection | R12, R13 |

---

## Defender usage notes

- Revalidate all indicators against current blocklists and vendor advisories before production blocking.
- Prioritize behavior-first detection (RMM-to-script, credential access, injection) over static family names.
- Full IP/domain/hash lists live in CISA AA22-055A, AA24-241A, and vendor reports; this document summarizes families and behaviors from the CTI report only.
- Treat overlap with other Iranian clusters (e.g. Lyceum) as context for hunting, not proof of single infrastructure in every incident.
