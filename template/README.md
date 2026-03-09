# CTI Research Template

Universal template for adding a new threat-intelligence report to this repo. Based on the structure used in **Handala**, **MuddyWater**, and **Sandworm** reports.

---

## Quick start

1. **Create a new report directory** and copy the template files (run from repo root; do not copy this `template/README.md` into the report — it stays here):
   ```bash
   mkdir my-report-name
   cp template/REPORT-README.tpl.md template/IOCs.tpl.md template/REPORT-OUTLINE.md my-report-name/
   cp template/extract_figures.sh.tpl my-report-name/extract_figures.sh   # optional
   ```

2. **In the new directory:** rename `REPORT-README.tpl.md` → `README.md` and `IOCs.tpl.md` → `IOCs.md`, then fill all placeholders (see [Placeholders](#placeholders) below).

3. **Add your report files**: HTML, PDF, and optionally `assets/`, `build_html.py`, `extract_figures.sh` (see repo `.gitignore` for what stays local).

4. **Update the root [README.md](../README.md)** Reports table with a row linking to your report.

---

## Template files

| File | Purpose |
|------|---------|
| **REPORT-README.tpl.md** | Report directory README. Copy to `README.md` in your report folder; replace placeholders. |
| **IOCs.tpl.md** | IOC document skeleton. Copy to `IOCs.md`; fill tables from your research. |
| **REPORT-OUTLINE.md** | Suggested section outline for the long-form article (Medium/post). Use when writing the research. |
| **extract_figures.sh.tpl** | Optional: script to extract figures from a Medium-export PDF. Rename to `extract_figures.sh`, set `PDF_PATH`. |

---

## Placeholders

Replace these in the copied files (case-sensitive):

| Placeholder | Example | Description |
|-------------|---------|-------------|
| `{{REPORT_TITLE}}` | Sandworm / APT44 | Full report title (e.g. "Handala Hack Group (aka Handala Hack Team)") |
| `{{SLUG}}` | sandworm-apt44 | Directory and filename slug (lowercase, hyphens) |
| `{{ALIASES}}` | Void Manticore, Handala Hack Team | Short alias list for the actor/group |
| `{{DATE_RANGE}}` | December 2023–March 2026 | Time scope of the assessment |
| `{{EVIDENCE_CUTOFF}}` | March 5, 2026 | Date through which evidence was reviewed |
| `{{MEDIUM_URL}}` | https://medium.com/@1200km/... | Link to the Medium (or primary) article |
| `{{PRIMARY_SOURCE}}` | CISA AA22-055A (optional) | Key advisory or baseline source URL/text |
| `{{AUTHOR_URL}}` | https://medium.com/@1200km | Author profile URL |

**Naming convention for generated files:**
- HTML: `cti-research-{{SLUG}}.html`
- PDF: `cti-research-{{SLUG}}-with-nav.pdf`

---

## Report directory layout (target)

After using the template and adding your content:

```
my-report-name/
├── README.md                    # From REPORT-README.tpl.md
├── IOCs.md                      # From IOCs.tpl.md (filled)
├── cti-research-<slug>.html      # Generated or pasted report
├── cti-research-<slug>-with-nav.pdf
├── assets/                      # Optional; gitignored at repo level
├── article_source.txt           # Optional; gitignored
├── build_html.py                # Optional; gitignored
└── extract_figures.sh            # Optional
```

---

## Build workflow (optional)

If you use the same pipeline as existing reports:

1. Save article text to `article_source.txt` in the report directory.
2. Use or adapt `build_html.py` from another report (set `ARTICLE_PATH`, `OUT_HTML`, `ASSETS_DIR`, `REF_URLS`).
3. Run `python3 build_html.py` → generates HTML with TOC and `[R1]`…`[Rx]` reference links.
4. Export figures: print article to PDF from browser, then run `./extract_figures.sh <your.pdf>` (if using the script).
5. Generate PDF: `google-chrome --headless ... --print-to-pdf=cti-research-<slug>-with-nav.pdf "file://$(pwd)/cti-research-<slug>.html"`

---

## Adding the report to the repo README

In the root **README.md**, add a row to the **Reports** table:

```markdown
| [**Your Report Title**](my-report-name/) | Brief scope. Evidence-labeled assessment and SOC guidance. {{DATE_RANGE}}. | [PDF](my-report-name/cti-research-<slug>-with-nav.pdf) · [HTML](my-report-name/cti-research-<slug>.html) · [Medium →]({{MEDIUM_URL}}) |
```

Then add the new directory to the **Repo structure** section if you want it listed there.
