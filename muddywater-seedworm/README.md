# CTI Research: MuddyWater / Seedworm (Mango Sandstorm)

Evidence-labeled threat intelligence assessment and SOC defensive guidance (2017-March 2026).

---

## Contents

| File | Description |
|------|-------------|
| **cti-research-muddywater-seedworm.html** | Report HTML with TOC and in-text citations linking to references. |
| **cti-research-muddywater-seedworm-with-nav.pdf** | Optional PDF export (generate with Chrome headless). |
| **article_source.txt** | Source text used to generate the HTML. |
| **build_html.py** | Builder script that converts source text into navigation-ready HTML. |
| **assets/** | Optional figures (`fig-000.png`, etc.) if you add image placeholders. |

## Sources

This report is compiled directly from primary advisories and technical vendor publications, with explicit confidence labels for unverified claims.

- Evidence cutoff: March 7, 2026
- Core baseline: [CISA AA22-055A](https://www.cisa.gov/uscert/ncas/alerts/aa22-055a)

## Build

1. Generate HTML:
   ```bash
   python3 build_html.py
   ```
2. Generate PDF:
   ```bash
   google-chrome --headless=new --disable-gpu --no-pdf-header-footer \
     --print-to-pdf=cti-research-muddywater-seedworm-with-nav.pdf \
     "file://$(pwd)/cti-research-muddywater-seedworm.html"
   ```

In-text references `[R1]...[R24]` map to the References section and each external source URL.
