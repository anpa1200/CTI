# CTI — Cyber Threat Intelligence

**Evidence-labeled threat reports, SOC-oriented guidance, and defensive research.**  
Open-source CTI by [Andrey Pautov](https://medium.com/@1200km).

[![Medium](https://img.shields.io/badge/Medium-@1200km-12100E?style=flat&logo=medium)](https://medium.com/@1200km)

---

## What’s in this repo

Structured, citation-linked versions of long-form CTI articles: **PDF** and **HTML** with table of contents, working reference links `[R1]`–`[Rx]`, and original figures. Each report is self-contained in its own directory and can be used for SOC playbooks, hunting, and training.

- **Defender-focused:** Prioritizes actionable guidance, detection ideas, and controls mapping.
- **Evidence-labeled:** Claims are tagged (Observed / Reported / Assessed / Claimed) with source references.
- **Offline-friendly:** PDFs and HTML work without depending on Medium or external links for the body text.

---

## Reports

| Report | Scope | Format |
|--------|--------|--------|
| [**Handala Hack Group**](handala-hack-group/) | Handala Hack Team / Void Manticore. Evidence-labeled assessment and SOC guidance. Dec 2023–Mar 2026. | [PDF](handala-hack-group/cti-research-handala-hack-group-with-nav.pdf) · [HTML](handala-hack-group/cti-research-handala-hack-group.html) · [Medium →](https://medium.com/@1200km/cti-research-handala-hack-group-aka-handala-hack-team-ddbdd294cfb8) |
| [**Sandworm / APT44**](sandworm-apt44/) | GRU GTsST (Sandworm). Evidence-labeled assessment and SOC guidance. 2009–Mar 2026. | [PDF](sandworm-apt44/cti-research-sandworm-apt44-with-nav.pdf) · [HTML](sandworm-apt44/cti-research-sandworm-apt44.html) · [Medium →](https://medium.com/@1200km/cti-research-sandworm-apt44-649332e8af44) |
| [**MuddyWater / Seedworm**](muddywater-seedworm/) | Iranian MOIS-linked MuddyWater cluster. Evidence-labeled assessment and SOC guidance. 2017–Mar 2026. | [PDF](muddywater-seedworm/cti-research-muddywater-seedworm-with-nav.pdf) · [HTML](muddywater-seedworm/cti-research-muddywater-seedworm.html) · [Primary sources →](https://www.cisa.gov/uscert/ncas/alerts/aa22-055a) |
| [**ATT&CK as a Working Tool**](ATT%26CK/) | Practitioner's guide: framework anatomy, 14 tactics, 5 hands-on use cases (mapping, gap analysis, Sigma + ATT&CK, threat hunting, adversary emulation). For CTI analysts, detection engineers, and SOC analysts. Mar 2026. | [PDF](ATT%26CK/ATT%26CK%20as%20a%20Working%20Tool_%20Theory%20and%20Hands-On%20Practical%20Usage%20_%20by%20Andrey%20Pautov%20_%20Mar%2C%202026%20_%20Medium.pdf) · [Medium →](https://medium.com/@1200km) |
| [**Attribution Methodology**](Attribution/) | Practitioner's guide: building and defending threat actor attribution. Evidence types ranked by strength (IOC overlap → TTP consistency → operator mistakes), 5-level attribution spectrum, false flag detection, APT29 worked exercise. For CTI analysts. Mar 2026. | [PDF](Attribution/attribution.pdf) · [Medium →](https://medium.com/@1200km) |
| [**Infrastructure Pivoting**](Infrastructure_pivoting/) | Field manual: expanding a single IOC into a full attacker infrastructure map. 7 pivot types (passive DNS, reverse IP, ASN, TLS certs, subdomains, Shodan/Censys, WHOIS), C2 tracing worked example. Includes `autoWF.py` — automated pivot tool (VirusTotal + SecurityTrails + crt.sh). Mar 2026. | [autoWF.py](Infrastructure_pivoting/autoWF.py) · [Medium →](https://medium.com/@1200km) |

*More reports (malware writeups, tool analysis, IOCs) will be added in separate directories.*

- **Template:** Use **[template/](template/)** to start a new report with the same structure (README, IOCs, outline, optional build scripts).

---

## Repo structure

```
CTI/
├── README.md                 # This file
├── template/                 # Universal research template (see below)
│   ├── README.md             # How to use the template
│   ├── REPORT-README.tpl.md  # Report directory README template
│   ├── IOCs.tpl.md           # IOC document template
│   ├── REPORT-OUTLINE.md     # Section outline for the long-form article
│   └── extract_figures.sh.tpl
├── handala-hack-group/       # One directory per report
│   ├── README.md, IOCs.md
│   ├── *.pdf, *.html
│   └── assets/               # Figures (optional; gitignored)
├── sandworm-apt44/
│   ├── README.md, IOCs.md
│   ├── *.pdf, *.html
│   └── assets/
├── muddywater-seedworm/
│   ├── README.md, IOCs.md
│   ├── *.pdf, *.html
│   └── assets/
├── ATT&CK/                   # Practitioner's guide to MITRE ATT&CK
│   ├── README.md
│   └── *.pdf
├── Attribution/              # Practitioner's guide to attribution methodology
│   ├── README.md
│   └── *.pdf
└── Infrastructure_pivoting/  # Field manual: single IOC → full attacker infrastructure
    ├── README.md
    ├── autoWF.py             # Automated pivot tool (VT + SecurityTrails + crt.sh)
    └── *.pdf
```

- **PDF:** Table of contents, clickable `[R1]`…`[Rx]` to references, original figures where available.
- **HTML:** Same content; good for search, copy-paste, and re-printing to PDF.
- **assets/:** Figures extracted from source; used when (re)building the report.

---

## Author & sources

- **Author:** [Andrey Pautov](https://medium.com/@1200km)  
- **Long-form articles:** [Medium @1200km](https://medium.com/@1200km)  
- Reports here are structured, citation-linked editions of those articles (evidence cutoff and scope noted in each report).

---

## Adding a new report

Use the **[template](template/)** for a consistent structure:

1. Copy files from **`template/`** into a new directory (e.g. `my-actor-name/`).
2. Rename and fill placeholders in `REPORT-README.tpl.md` → save as `README.md`; do the same for `IOCs.tpl.md` → `IOCs.md`.
3. Add your report **PDF** and **HTML** (and `assets/` if you have figures; see template and existing reports for the build workflow).
4. Add a row to the **Reports** table above with links to the report and source.

See **[template/README.md](template/README.md)** for placeholders, naming conventions, and optional build steps.

---

## Disclaimer

- **Use:** Defensive and research only. Not for offensive use.
- **IOCs/samples:** Handle according to your security policy; validate before production use.
- **Attribution:** Views and assessments are the author’s; sources are cited in each report.

---

## License

Per-report. See each report’s README and the original source (e.g. Medium) for terms of use.
