#!/usr/bin/env python3
"""
Extract text from Medium-saved PDFs and write clean Markdown README files.
Also regenerates HTML and PDF exports via build_article_html.py logic.
"""

import os
import re
import subprocess

REPO = os.path.dirname(os.path.abspath(__file__))

MEDIUM_JUNK = re.compile(
    r'^(Open in app|Search|Write|Member-only story|Sign up|Sign in|Listen|Share|Follow'
    r'|More from.*|Help|Status|About|Careers|Press|Blog|Privacy|Terms|Text to speech'
    r'|Teams|\d+ (Follower|Following)|Get the app|Subscribe|Membership|Related).*$',
    re.IGNORECASE
)


def extract_pdf_text(pdf_path):
    result = subprocess.run(
        ["pdftotext", "-layout", pdf_path, "-"],
        capture_output=True, text=True, timeout=60
    )
    return result.stdout


def clean_text(raw):
    lines = raw.splitlines()
    cleaned = []
    skip_until_title = True

    for line in lines:
        stripped = line.strip()

        # Skip Medium UI junk at top until we hit the real title
        if skip_until_title:
            # The real title is the first substantial non-junk line
            if stripped and not MEDIUM_JUNK.match(stripped) and len(stripped) > 10:
                skip_until_title = False
            else:
                continue

        # Remove obvious Medium UI artifacts throughout
        if MEDIUM_JUNK.match(stripped):
            continue
        if re.match(r'^\d+$', stripped):  # standalone numbers (like counts)
            continue

        cleaned.append(line.rstrip())

    # Remove trailing empty lines at end
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()

    return '\n'.join(cleaned)


def text_to_markdown(text, title, medium_url, author="Andrey Pautov"):
    lines = text.splitlines()
    md_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip the title line if it appears as first non-empty line
        if md_lines == [] and stripped and stripped in title:
            i += 1
            continue

        # Numbered section headings like "1. Introduction: Why..."
        m = re.match(r'^(\d+)\.\s+([A-Z].{5,})', stripped)
        if m and len(stripped) < 120:
            md_lines.append(f'\n## {stripped}')
            i += 1
            continue

        # Sub-headings: Title Case lines that are short and not a list item
        if (stripped and len(stripped) < 80 and stripped[0].isupper()
                and not stripped.endswith('.')
                and not stripped.startswith('·')
                and not stripped.startswith('-')
                and not re.match(r'^[A-Z][a-z].*[,;]$', stripped)
                and re.match(r'^[A-Z][A-Za-z /&:()—-]+$', stripped)):
            md_lines.append(f'\n### {stripped}')
            i += 1
            continue

        # Bullet-like lines starting with · or •
        if stripped.startswith('·') or stripped.startswith('•'):
            md_lines.append('- ' + stripped[1:].strip())
            i += 1
            continue

        # Code-like blocks (indented 4+ spaces or contains backticks/KQL patterns)
        if (re.match(r'^\s{4,}\S', line)
                or re.match(r'^(SELECT|WHERE|FROM|EventID|source|index|sigma|title:|detection:|logsource:)', stripped)):
            if md_lines and md_lines[-1] != '```':
                md_lines.append('```')
            md_lines.append(stripped)
            # peek ahead for more code lines
            while i + 1 < len(lines) and (
                re.match(r'^\s{4,}\S', lines[i + 1])
                or re.match(r'^(SELECT|WHERE|FROM|EventID|AND|OR|\|)', lines[i + 1].strip())
            ):
                i += 1
                md_lines.append(lines[i].strip())
            md_lines.append('```')
            i += 1
            continue

        md_lines.append(stripped if stripped else '')
        i += 1

    # Deduplicate consecutive blank lines
    result = []
    prev_blank = False
    for l in md_lines:
        if l == '':
            if not prev_blank:
                result.append('')
            prev_blank = True
        else:
            result.append(l)
            prev_blank = False

    body = '\n'.join(result).strip()

    header = f"# {title}\n\n"
    if medium_url and medium_url != "https://medium.com/@1200km":
        header += f"By [{author}](https://medium.com/@1200km) · [Published on Medium]({medium_url})\n\n---\n\n"
    else:
        header += f"By [{author}](https://medium.com/@1200km)\n\n---\n\n"

    return header + body


ARTICLES = [
    {
        "pdf":    os.path.join(REPO, "ATT&CK",
                  "ATT&CK as a Working Tool_ Theory and Hands-On Practical Usage _ by Andrey Pautov _ Mar, 2026 _ Medium.pdf"),
        "readme": os.path.join(REPO, "ATT&CK", "README.md"),
        "html":   os.path.join(REPO, "ATT&CK", "attck-as-a-working-tool.html"),
        "out_pdf":os.path.join(REPO, "ATT&CK", "attck-as-a-working-tool.pdf"),
        "title":  "ATT&CK as a Working Tool: Theory and Hands-On Practical Usage",
        "url":    "https://medium.com/@1200km/att-ck-as-a-working-tool-theory-and-hands-on-practical-usage-d63835c9f101",
    },
    {
        "pdf":    os.path.join(REPO, "Infrastructure_pivoting",
                  "Infrastructure Pivoting_ How CTI Analysts Expand From a Single IOC to a Full Attacker Network _ by Andrey Pautov _ Mar, 2026 _ Medium.pdf"),
        "readme": os.path.join(REPO, "Infrastructure_pivoting", "README.md"),
        "html":   os.path.join(REPO, "Infrastructure_pivoting", "infrastructure-pivoting-ioc-to-network.html"),
        "out_pdf":os.path.join(REPO, "Infrastructure_pivoting", "infrastructure-pivoting-ioc-to-network.pdf"),
        "title":  "Infrastructure Pivoting: How CTI Analysts Expand From a Single IOC to a Full Attacker Network",
        "url":    "https://medium.com/@1200km/infrastructure-pivoting-how-cti-analysts-expand-from-a-single-ioc-to-a-full-attacker-network-1295d50ec29c",
    },
    {
        "pdf":    os.path.join(REPO, "Attribution", "attribution.pdf"),
        "readme": os.path.join(REPO, "Attribution", "README.md"),
        "html":   os.path.join(REPO, "Attribution", "attribution-methodology.html"),
        "out_pdf":os.path.join(REPO, "Attribution", "attribution-methodology.pdf"),
        "title":  "Attribution Methodology: How to Build, Defend, and Challenge a Threat Actor Attribution",
        "url":    "https://medium.com/@1200km",
    },
]

# Reuse HTML builder from build_article_html.py
import sys
sys.path.insert(0, REPO)
from build_article_html import md_to_html, build as build_html_pdf


def run():
    for a in ARTICLES:
        name = os.path.basename(os.path.dirname(a["readme"]))
        print(f"\n[{name}]")

        if not os.path.exists(a["pdf"]):
            print(f"  SKIP — PDF not found: {a['pdf']}")
            continue

        raw = extract_pdf_text(a["pdf"])
        cleaned = clean_text(raw)
        md = text_to_markdown(cleaned, a["title"], a["url"])

        with open(a["readme"], "w", encoding="utf-8") as f:
            f.write(md)
        size_kb = len(md) / 1024
        print(f"  README.md → {size_kb:.1f} KB")

        # Regenerate HTML + PDF from the new README
        build_html_pdf(a["readme"], a["html"], a["out_pdf"], a["url"])


if __name__ == "__main__":
    run()
    print("\nDone.")
