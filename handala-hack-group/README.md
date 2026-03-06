# CTI Research: Handala Hack Group (aka Handala Hack Team)

Evidence-labeled threat intelligence assessment and SOC defensive guidance (December 2023–March 2026).

**→ [Read the full article on Medium](https://medium.com/@1200km/cti-research-handala-hack-group-aka-handala-hack-team-ddbdd294cfb8)**

---

## Contents

| File | Description |
|------|-------------|
| **cti-research-handala-hack-group-with-nav.pdf** | Report PDF: table of contents, working reference links [R1]–[R23j], all figures. |
| **cti-research-handala-hack-group.html** | Same report as HTML (TOC, in-text citations → references and URLs). |
| **assets/** | Figures from the report (PNG). |
| **build_html.py** | Script to regenerate HTML from article text (see below). |

## Source

- **Article:** [CTI Research: Handala Hack Group (aka Handala Hack Team)](https://medium.com/@1200km/cti-research-handala-hack-group-aka-handala-hack-team-ddbdd294cfb8)
- **Author:** [Andrey Pautov](https://medium.com/@1200km)
- **Evidence cutoff:** March 5, 2026

## Regenerating HTML/PDF

1. Save the Medium article text to `article_source.txt` in this directory (or set `ARTICLE_PATH` in `build_html.py`).
2. Regenerate HTML:
   ```bash
   python3 build_html.py
   ```
3. Generate PDF (Chrome/Chromium headless):
   ```bash
   google-chrome --headless --disable-gpu --no-pdf-header-footer \
     --print-to-pdf=cti-research-handala-hack-group-with-nav.pdf \
     "file://$(pwd)/cti-research-handala-hack-group.html"
   ```

In-text **[R1]**…**[R23j]** link to the References section; each reference links to the external source URL.
