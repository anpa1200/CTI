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

*More reports (malware writeups, tool analysis, IOCs) will be added in separate directories.*

---

## Repo structure

```
CTI/
├── README.md                 # This file
├── handala-hack-group/       # One directory per report
│   ├── README.md             # Report summary + Medium link
│   ├── *.pdf, *.html         # Report with TOC and ref links
│   └── assets/               # Figures
└── sandworm-apt44/
    ├── README.md
    ├── *.pdf, *.html
    ├── assets/
    └── extract_figures.sh    # Optional: pull figures from Medium PDF
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

1. Create a new directory (e.g. `report-name/`).
2. Add a **README.md** (title, scope, link to Medium or primary source).
3. Add report **PDF** and/or **HTML** (and `assets/` if you have figures).
4. Add a row to the **Reports** table above with links to the report and source.

---

## Disclaimer

- **Use:** Defensive and research only. Not for offensive use.
- **IOCs/samples:** Handle according to your security policy; validate before production use.
- **Attribution:** Views and assessments are the author’s; sources are cited in each report.

---

## License

Per-report. See each report’s README and the original source (e.g. Medium) for terms of use.
