#!/usr/bin/env python3
"""
Build professional HTML/PDF report: Handala Hack Group CTI Research.
- Table of contents with anchor links
- Working reference links: in-text [R1]..[R23j] link to References and to source URLs
- Original figures from assets/ (extracted from source PDF)
- Print-ready, Git-publishable styling
"""

import re
import html
import os

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Set to path of article text file if regenerating HTML from source
ARTICLE_PATH = os.path.join(_SCRIPT_DIR, "article_source.txt")
OUT_HTML = os.path.join(_SCRIPT_DIR, "cti-research-handala-hack-group.html")
ASSETS_DIR = os.path.join(_SCRIPT_DIR, "assets")
SOURCE_URL = "https://medium.com/@1200km/cti-research-handala-hack-group-aka-handala-hack-team-ddbdd294cfb8"

# Reference id -> URL (from References section; R16 has two URLs, we use first)
REF_URLS = {
    "R1": "https://www.trellix.com/en-gb/blogs/research/handalas-wiper-targets-israel/",
    "R2": "https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/",
    "R3": "https://research.checkpoint.com/2025/6th-january-threat-intelligence-report/",
    "R4": "https://research.checkpoint.com/2025/3rd-february-threat-intelligence-report/",
    "R5": "https://research.checkpoint.com/2026/2025-the-untold-stories-of-check-point-research/",
    "R6": "https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/",
    "R7": "https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/",
    "R8": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a",
    "R9": "https://cyberint.com/blog/threat-intelligence/handala-hack-what-we-know-about-the-rising-threat-actor/",
    "R10": "https://t.me/HANDALA_RSS",
    "R11": "https://www.sophos.com/en-us/threat-profiles/cobalt-mystique",
    "R12": "https://therecord.media/handala-x-account-banned-twitter-palestine-iran",
    "R13": "https://therecord.media/hackers-hijack-sirens-iran-israel",
    "R14": "https://www.bleepingcomputer.com/news/security/fake-crowdstrike-fixes-target-companies-with-malware-data-wipers/",
    "R15": "https://www.wsj.com/world/middle-east/iran-hacks-former-israeli-prime-minister-in-new-tehran-linked-cyberattack-f1a959ca",
    "R16": "https://ict.org.il/bibi-gate-handala-hack-team-a-mask-for-iranian-psychological-warfare/",
    "R17": "https://www.timesofisrael.com/iranian-hackers-broadcast-rocket-sirens-odes-to-terrorism-in-some-20-kindergartens/",
    "R18": "https://t.me/s/handala_backup_357",
    "R19": "https://www.microsoft.com/en-us/security/security-insider/threat-landscape/iran-surges-cyber-enabled-influence-operations-in-support-of-hamas/",
    "R20": "https://www.dni.gov/index.php/newsroom/press-releases/press-releases-2024/3981-joint-odni-fbi-and-cisa-statement-on-iranian-election-influence-efforts",
    "R21": "https://www.jns.org/iranians-claim-they-hacked-former-israeli-pm-bennetts-phone/",
    "R22": "https://www.israelhayom.com/2025/12/28/handala-hackers-iranian-cyber-attacks-israel-officials/",
    "R23a": "https://op-c.net/blog/unpacking-handala/",
    "R23b": "https://op-c.net/blog/did-op-innovate-disrupt-handala-cyber-threat/",
    "R23c": "https://www.crowdstrike.com/en-us/adversaries/banished-kitten/",
    "R23d": "https://www.international.gc.ca/transparency-transparence/rapid-response-mechanism-mecanisme-reponse-rapide/iran-hack-piratage-iranien.aspx?lang=eng",
    "R23e": "https://www.recordedfuture.com/blog/retaliation-window-middle-east-escalation",
    "R23f": "https://www.iranintl.com/202507086458",
    "R23g": "https://irancybernews.org/en/handala-hacking-group-exposes-confidential-access-to-suvarnabhumi-airport/",
    "R23h": "https://www.jpost.com/israel-news/article-887911/",
    "R23i": "https://www.esecurityplanet.com/threats/handala-leak-shows-telegram-account-risk-not-iphone-hacks/",
    "R23j": "https://cyberpress.org/telegram-account-compromise/",
}

TOC_TO_ID = [
    ("Report Metadata", "report-metadata"),
    ("Methodology & Evidence Labels", "methodology-evidence-labels"),
    ("Confidence & What Changes Confidence", "confidence-what-changes"),
    ("Executive Summary", "executive-summary"),
    ("Alias / Cluster Crosswalk", "alias-cluster-crosswalk"),
    ("Key Judgments", "key-judgments"),
    ("Activity Timeline (2023–2026)", "activity-timeline"),
    ("Confirmed vs Claimed Matrix", "confirmed-vs-claimed-matrix"),
    ("Public Presence and Information Operations Footprint", "public-presence"),
    ("Targeting and Victimology", "targeting-victimology"),
    ("Tactics, Techniques, and Procedures (Observed/Reported)", "ttps"),
    ("ATT&CK-Oriented Mapping (Analyst View)", "attck-mapping"),
    ("Detection and Response Priorities", "detection-response-priorities"),
    ("Detection Engineering Pack (SOC-Ready)", "detection-engineering-pack"),
    ("Wiper First 30 Minutes (Defensive Mini-Playbook)", "wiper-first-30-minutes"),
    ("Controls Mapping (NIST CSF-Lite)", "controls-mapping"),
    ("Comprehensive IOC Compendium (Public Reporting)", "ioc-compendium"),
    ("Overall Statistics, Common Patterns, and Cross-Group Correlation", "overall-statistics"),
    ("Confidence and Gaps", "confidence-gaps"),
    ("Practical Defensive Actions (Next 30 Days)", "practical-defensive-actions"),
    ("References", "references"),
]


def slug(s: str) -> str:
    s = re.sub(r"[^\w\s\-/]", "", s.strip())
    s = re.sub(r"[\s/]+", "-", s)
    return re.sub(r"-+", "-", s).strip("-").lower() or "section"


def section_id_from_title(title: str) -> str:
    for text, sid in TOC_TO_ID:
        if text in title or title in text:
            return sid
    return slug(title)


def convert_md_links(text: str) -> str:
    def repl(m):
        label, url = m.group(1), m.group(2).replace("&amp;", "&")
        return f'<a href="{html.escape(url)}">{html.escape(label)}</a>'
    return re.sub(r'\[([^\]]+)\]\((https?://[^\)]+)\)', repl, text)


def convert_inline_code(text: str) -> str:
    return re.sub(r'`([^`]+)`', r'<code>\1</code>', text)


def convert_ref_citations(text: str) -> str:
    """Replace [R1], [R2], [R23a] etc. with links to #ref-Rx."""
    # Match [R1], [R2], [R23a], etc. — group captures e.g. R1, R23a
    def repl(m):
        ref_key = m.group(1)  # already "R1", "R23a", etc.
        url = REF_URLS.get(ref_key)
        if url:
            return f'<a href="#ref-{ref_key}" class="ref-cite" title="Reference">{html.escape(m.group(0))}</a>'
        return m.group(0)
    return re.sub(r'\[(R\d+[a-z]?)\]', repl, text)


def process_text(text: str) -> str:
    text = convert_md_links(text)
    text = convert_inline_code(text)
    text = convert_ref_citations(text)
    return text


def main():
    with open(ARTICLE_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    start = next(i for i, line in enumerate(lines) if line.strip().startswith("# CTI Research: Handala Hack Group"))
    end = len(lines)
    for i, line in enumerate(lines):
        if "## Written by Andrey Pautov" in line or (i > 800 and "Help" in line and "Status" in line):
            end = i
            break
    content_lines = lines[start:end]

    body_parts = []
    in_ul = False
    in_ol = False
    image_index = 0
    in_references_section = False
    i = 0

    while i < len(content_lines):
        line = content_lines[i]
        stripped = line.strip()

        # Image placeholder -> embed figure from assets
        if "Press enter or click to view image" in stripped or stripped == "--":
            if "Press enter or click to view image" in stripped:
                image_index += 1
                fig_num = (image_index - 1) % 13  # we have fig-000..fig-012
                fig_path = f"assets/fig-{fig_num:03d}.png"
                if os.path.isfile(os.path.join(os.path.dirname(OUT_HTML), fig_path.replace("/", os.sep))):
                    body_parts.append(f'<figure class="report-fig"><img src="{fig_path}" alt="Figure {image_index}" loading="lazy" /></figure>')
            i += 1
            continue

        # Skip byline clutter and duplicate author line (author is in header)
        if stripped in ("Listen", "Share", "Just now", "35 min read"):
            i += 1
            continue
        if stripped.startswith("[Andrey Pautov](") and "medium.com" in stripped and len(stripped) < 150:
            i += 1
            continue

        # H1
        if stripped.startswith("# ") and not stripped.startswith("## "):
            if in_ul:
                body_parts.append("</ul>")
                in_ul = False
            if in_ol:
                body_parts.append("</ol>")
                in_ol = False
            in_references_section = False
            title = stripped[2:].strip()
            body_parts.append(f'<h1 id="top">{html.escape(title)}</h1>')
            i += 1
            continue

        # H2
        if stripped.startswith("## ") and "Table of Contents" not in stripped:
            if in_ul:
                body_parts.append("</ul>")
                in_ul = False
            if in_ol:
                body_parts.append("</ol>")
                in_ol = False
            title = stripped[3:].strip()
            sid = section_id_from_title(title)
            in_references_section = sid == "references"
            body_parts.append(f'<h2 id="{sid}">{html.escape(title)}</h2>')
            i += 1
            continue

        # Table of Contents
        if "## Table of Contents" in stripped:
            if in_ul:
                body_parts.append("</ul>")
                in_ul = False
            if in_ol:
                body_parts.append("</ol>")
                in_ol = False
            body_parts.append('<h2 id="table-of-contents">Table of Contents</h2>')
            body_parts.append('<nav class="toc" aria-label="Table of contents"><ul>')
            for label, sid in TOC_TO_ID:
                body_parts.append(f'<li><a href="#{sid}">{html.escape(label)}</a></li>')
            body_parts.append("</ul></nav>")
            i += 1
            while i < len(content_lines) and not content_lines[i].strip().startswith("## "):
                i += 1
            continue

        # H3
        if stripped.startswith("### "):
            if in_ul:
                body_parts.append("</ul>")
                in_ul = False
            if in_ol:
                body_parts.append("</ol>")
                in_ol = False
            title = stripped[4:].strip()
            body_parts.append(f'<h3 id="{slug(title)}">{html.escape(title)}</h3>')
            i += 1
            continue

        # List item (References section: add id="ref-R1" etc. and make citation link to URL)
        if stripped.startswith("- "):
            if not in_ul:
                body_parts.append("<ul>")
                in_ul = True
            inner = stripped[2:]
            if in_references_section:
                ref_m = re.match(r'^\[(R\d+[a-z]?)\]\s*', inner)
                if ref_m:
                    # Keep [Rx] as link to URL; id on li for in-text citation jumps
                    ref_key = ref_m.group(1)
                    inner = inner[ref_m.end():]
                    inner = convert_md_links(inner)
                    inner = convert_inline_code(inner)
                    url = REF_URLS.get(ref_key, "#")
                    body_parts.append(f'<li id="ref-{ref_key}"><a href="{html.escape(url)}" class="ref-link">[{ref_key}]</a> {inner}</li>')
                else:
                    inner = process_text(inner)
                    body_parts.append(f"<li>{inner}</li>")
            else:
                inner = process_text(inner)
                body_parts.append(f"<li>{inner}</li>")
            i += 1
            continue

        # Numbered list
        if re.match(r"^\d+\.\s", stripped):
            if in_ul:
                body_parts.append("</ul>")
                in_ul = False
            if not in_ol:
                body_parts.append("<ol>")
                in_ol = True
            inner = re.sub(r"^\d+\.\s", "", stripped)
            body_parts.append(f"<li>{process_text(inner)}</li>")
            i += 1
            continue

        if (in_ul or in_ol) and (not stripped or stripped.startswith("TTPs ") or stripped.startswith("Claims ") or stripped.startswith("IOC/") or stripped == "Observed victim focus in open reporting includes:"):
            if in_ul:
                body_parts.append("</ul>")
                in_ul = False
            if in_ol:
                body_parts.append("</ol>")
                in_ol = False

        if stripped:
            body_parts.append(f"<p>{process_text(stripped)}</p>")
        else:
            body_parts.append("")

        i += 1

    if in_ul:
        body_parts.append("</ul>")
    if in_ol:
        body_parts.append("</ol>")

    body_html = "\n".join(body_parts)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CTI Research: Handala Hack Group (aka Handala Hack Team)</title>
  <meta name="description" content="Evidence-labeled threat intelligence assessment and SOC defensive guidance on Handala Hack Group (Handala Hack Team), December 2023 to March 2026.">
  <meta name="author" content="Andrey Pautov">
  <link rel="canonical" href="{SOURCE_URL}">
  <style>
    :root {{
      font-family: "Georgia", "Times New Roman", serif;
      line-height: 1.6;
      color: #1a1a1a;
      --toc-bg: #f8f9fa;
      --border: #dee2e6;
      --link: #0a5eb2;
      --link-visited: #551a8b;
    }}
    body {{ margin: 0; padding: 0; max-width: 52rem; margin-left: auto; margin-right: auto; padding: 2rem 1.5rem 3rem; }}
    .doc-meta {{
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 0.875rem;
      color: #495057;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }}
    .doc-meta a {{ color: var(--link); }}
    h1 {{
      font-size: 1.75rem;
      font-weight: 700;
      margin-top: 0;
      margin-bottom: 0.5rem;
      border-bottom: 2px solid var(--border);
      padding-bottom: 0.5rem;
    }}
    h2 {{ font-size: 1.35rem; margin-top: 2.5rem; margin-bottom: 0.75rem; scroll-margin-top: 1rem; }}
    h3 {{ font-size: 1.15rem; margin-top: 1.5rem; margin-bottom: 0.5rem; }}
    nav.toc {{
      background: var(--toc-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem 1.5rem;
      margin: 1.5rem 0 2rem;
    }}
    nav.toc ul {{ list-style: none; padding-left: 0; margin: 0; }}
    nav.toc li {{ margin: 0.4rem 0; }}
    nav.toc a {{ color: var(--link); text-decoration: none; }}
    nav.toc a:hover {{ text-decoration: underline; }}
    a {{ color: var(--link); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    a:visited {{ color: var(--link-visited); }}
    a.ref-cite {{ font-weight: 600; }}
    a.ref-link {{ font-weight: 600; }}
    code {{
      font-family: "Consolas", "Monaco", monospace;
      background: #f1f3f4;
      padding: 0.15em 0.4em;
      border-radius: 3px;
      font-size: 0.9em;
    }}
    ul, ol {{ margin: 0.75rem 0 1.25rem 1.5rem; padding-left: 1.5rem; }}
    li {{ margin: 0.35rem 0; }}
    figure.report-fig {{
      margin: 1.5rem 0;
      text-align: center;
    }}
    figure.report-fig img {{ max-width: 100%; height: auto; border: 1px solid var(--border); border-radius: 4px; }}
    .back-top {{ margin-top: 2.5rem; font-size: 0.9rem; color: #6c757d; }}
    @media print {{
      body {{ padding: 1rem; }}
      nav.toc {{ break-inside: avoid; }}
      a.ref-cite {{ color: #0a5eb2; }}
    }}
  </style>
</head>
<body>
  <header class="doc-meta">
    <p>Evidence-Labeled Threat Intelligence Assessment and SOC Defensive Guidance (December 2023–March 2026). Author: <a href="https://medium.com/@1200km">Andrey Pautov</a>. Evidence cutoff: March 5, 2026. <a href="{SOURCE_URL}">Original article (Medium)</a>.</p>
  </header>
  <a id="top"></a>
{body_html}
  <footer class="back-top">
    <a href="#table-of-contents">↑ Table of Contents</a> · <a href="#top">↑ Top</a>
  </footer>
</body>
</html>
"""

    os.makedirs(os.path.dirname(OUT_HTML) or ".", exist_ok=True)
    with open(OUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_doc)
    print("Wrote", OUT_HTML)


if __name__ == "__main__":
    main()
