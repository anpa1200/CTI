# CTI Research: Sandworm / APT44

Evidence-labeled threat intelligence assessment and SOC defensive guidance (2009 — March 2026).

**→ [Read the full article on Medium](https://medium.com/@1200km/cti-research-sandworm-apt44-649332e8af44)**

---

## Contents

| File | Description |
|------|-------------|
| **cti-research-sandworm-apt44-with-nav.pdf** | Report PDF: table of contents, working reference links [R1]–[R30]. |
| **cti-research-sandworm-apt44.html** | Same report as HTML (TOC, in-text citations → references and URLs). |
| **assets/** | Figures (if added; optional). |

## Source

- **Article:** [CTI Research: Sandworm / APT44](https://medium.com/@1200km/cti-research-sandworm-apt44-649332e8af44)
- **Author:** [Andrey Pautov](https://medium.com/@1200km)
- **Evidence cutoff:** March 5, 2026

## Regenerating HTML/PDF

1. Save the Medium article text to `article_source.txt` in this directory (or set `ARTICLE_PATH` in `build_html.py`).
2. Run `python3 build_html.py` to regenerate the HTML.
3. Generate PDF (Chrome/Chromium headless):
   ```bash
   google-chrome --headless --disable-gpu --no-pdf-header-footer \
     --print-to-pdf=cti-research-sandworm-apt44-with-nav.pdf \
     "file://$(pwd)/cti-research-sandworm-apt44.html"
   ```

In-text **[R1]**…**[R30]** link to the References section; each reference links to the external source URL.
