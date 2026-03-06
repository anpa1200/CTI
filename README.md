# CTI — Cyber Threat Intelligence Reports

Repository of **threat intelligence reports**, **malware analysis**, and **reverse engineering** notes by [Andrey Pautov](https://medium.com/@1200km).

**Medium:** [@1200km](https://medium.com/@1200km) — long-form CTI articles and research.

---

## Reports

| Report | Description | Medium |
|--------|-------------|--------|
| [**Handala Hack Group**](handala-hack-group/) | Evidence-labeled assessment and SOC guidance (Handala Hack Team / Void Manticore). Dec 2023–Mar 2026. | [Read on Medium →](https://medium.com/@1200km/cti-research-handala-hack-group-aka-handala-hack-team-ddbdd294cfb8) |

*(More reports will be added as separate directories.)*

---

## Structure

- Each report or project lives in its **own directory** (e.g. `handala-hack-group/`).
- A report directory typically includes:
  - **PDF** and/or **HTML** (with TOC and working reference links where applicable)
  - **assets/** (figures, screenshots)
  - **README.md** (scope, sources, how to regenerate if applicable)
- Future content may include: malware writeups, tool reverse engineering, IOC lists, and detection rules — each in a **dedicated directory** with its own README and, where relevant, a link to the Medium (or other) article.

---

## Adding a new report

1. Create a new directory (e.g. `reports/my-threat-name/` or `malware-analysis/sample-name/`).
2. Add a **README.md** with title, scope, link to Medium/article, and file descriptions.
3. Add the report files (PDF, HTML, assets, scripts as needed).
4. Update this README’s **Reports** table with the new entry and link.

---

## Disclaimer

- Reports are for **defensive** and **research** use.
- IOCs and samples (if any) should be handled according to your security policy and environment.
- Opinions and assessments are the author’s; attribution and references are cited in each report.

---

## License

Per-report. See each report’s README and original sources (e.g. Medium) for terms of use.
