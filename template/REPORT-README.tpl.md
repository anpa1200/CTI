# CTI Research: {{REPORT_TITLE}}

Evidence-labeled threat intelligence assessment and SOC defensive guidance ({{DATE_RANGE}}).

**→ [Read the full article on Medium]({{MEDIUM_URL}})**

---

## Contents

| File | Description |
|------|-------------|
| **cti-research-{{SLUG}}-with-nav.pdf** | Report PDF: table of contents, working reference links [R1]–[Rx], and figures (if extracted). |
| **cti-research-{{SLUG}}.html** | Same report as HTML (TOC, in-text citations → references and URLs). |
| **assets/** | Figures extracted from the Medium article PDF (optional; see below). |
| **extract_figures.sh** | Optional: script to extract figures from a Medium-export PDF into `assets/`. |

### Including original pictures from Medium

Medium’s page cannot be scraped for images automatically. To get the **original figures** into the PDF:

1. **Export the article as PDF from Medium**  
   Open [the article]({{MEDIUM_URL}}) in your browser (logged in if needed) → **Print** (Ctrl+P / Cmd+P) → **Save as PDF**. Save it in this directory (e.g. as `article_medium.pdf`).

2. **Extract figures**  
   Run:
   ```bash
   chmod +x extract_figures.sh
   ./extract_figures.sh article_medium.pdf
   ```

3. **Regenerate HTML and PDF**  
   ```bash
   python3 build_html.py
   google-chrome --headless --disable-gpu --no-pdf-header-footer \
     --print-to-pdf=cti-research-{{SLUG}}-with-nav.pdf \
     "file://$(pwd)/cti-research-{{SLUG}}.html"
   ```

## Source

- **Article:** [CTI Research: {{REPORT_TITLE}}]({{MEDIUM_URL}})
- **Author:** [Andrey Pautov]({{AUTHOR_URL}})
- **Evidence cutoff:** {{EVIDENCE_CUTOFF}}
- *(Optional)* **Core baseline:** [{{PRIMARY_SOURCE}}]({{PRIMARY_SOURCE_URL}}) — delete this line if not used

## Regenerating HTML/PDF

1. Save the Medium article text to `article_source.txt` in this directory (or set `ARTICLE_PATH` in `build_html.py`).
2. Run `python3 build_html.py` to regenerate the HTML.
3. Generate PDF (Chrome/Chromium headless):
   ```bash
   google-chrome --headless --disable-gpu --no-pdf-header-footer \
     --print-to-pdf=cti-research-{{SLUG}}-with-nav.pdf \
     "file://$(pwd)/cti-research-{{SLUG}}.html"
   ```

In-text **[R1]**…**[Rx]** link to the References section; each reference links to the external source URL.
