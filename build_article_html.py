#!/usr/bin/env python3
"""
Convert Markdown articles to styled HTML + PDF (via Chrome headless).
Usage:  python3 build_article_html.py
"""

import os
import re
import subprocess
import markdown
from markdown.extensions.tables import TableExtension
from markdown.extensions.fenced_code import FencedCodeExtension

REPO = os.path.dirname(os.path.abspath(__file__))

CSS = """
  :root {
    font-family: "Georgia", "Times New Roman", serif;
    line-height: 1.7;
    color: #1a1a1a;
    --toc-bg: #f8f9fa;
    --border: #dee2e6;
    --link: #0a5eb2;
    --link-visited: #551a8b;
    --code-bg: #f1f3f4;
  }
  body { margin: 0; padding: 0; max-width: 52rem; margin-left: auto; margin-right: auto; padding: 2rem 1.5rem 3rem; }
  .doc-meta {
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 0.875rem;
    color: #495057;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border);
  }
  .doc-meta a { color: var(--link); }
  h1 { font-size: 1.75rem; font-weight: 700; margin-top: 0; margin-bottom: 0.5rem; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; }
  h2 { font-size: 1.35rem; margin-top: 2.5rem; margin-bottom: 0.75rem; scroll-margin-top: 1rem; }
  h3 { font-size: 1.15rem; margin-top: 1.75rem; margin-bottom: 0.5rem; }
  h4 { font-size: 1.05rem; margin-top: 1.25rem; margin-bottom: 0.4rem; }
  nav.toc { background: var(--toc-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1rem 1.5rem; margin: 1.5rem 0 2rem; }
  nav.toc ul { list-style: none; padding-left: 0; margin: 0; }
  nav.toc li { margin: 0.4rem 0; }
  nav.toc a { color: var(--link); text-decoration: none; }
  nav.toc a:hover { text-decoration: underline; }
  a { color: var(--link); text-decoration: none; }
  a:hover { text-decoration: underline; }
  a:visited { color: var(--link-visited); }
  code { font-family: "Consolas", "Monaco", monospace; background: var(--code-bg); padding: 0.15em 0.4em; border-radius: 3px; font-size: 0.88em; }
  pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 5px; padding: 1rem 1.2rem; overflow-x: auto; }
  pre code { background: none; padding: 0; font-size: 0.85em; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0 1.5rem; font-size: 0.9em; }
  th { background: #e9ecef; }
  th, td { border: 1px solid var(--border); padding: 0.5rem 0.75rem; text-align: left; }
  tr:nth-child(even) td { background: #f8f9fa; }
  blockquote { border-left: 3px solid var(--border); margin: 1rem 0; padding: 0.5rem 1.2rem; color: #495057; font-style: italic; }
  ul, ol { margin: 0.75rem 0 1.25rem 1.5rem; padding-left: 1.5rem; }
  li { margin: 0.35rem 0; }
  hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }
  p { margin: 0.75rem 0; }
  .back-top { margin-top: 2.5rem; font-size: 0.9rem; color: #6c757d; }
  @media print {
    body { padding: 1rem; }
    nav.toc { break-inside: avoid; }
  }
"""

def slugify(text):
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_-]+', '-', text)
    return text

def extract_title(md_text):
    m = re.search(r'^#\s+(.+)', md_text, re.MULTILINE)
    return m.group(1).strip() if m else "Article"

def md_to_html(md_text, title, medium_url, author="Andrey Pautov"):
    body_html = markdown.markdown(
        md_text,
        extensions=[
            TableExtension(),
            FencedCodeExtension(),
            'toc',
            'nl2br',
            'sane_lists',
        ]
    )
    medium_link = f'<a href="{medium_url}">Published on Medium</a>' if medium_url else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <meta name="author" content="{author}">
  {"<link rel='canonical' href='" + medium_url + "'>" if medium_url else ""}
  <style>{CSS}</style>
</head>
<body>
  <header class="doc-meta">
    <p>Author: <a href="https://medium.com/@1200km">{author}</a>. {medium_link}</p>
  </header>
  {body_html}
  <p class="back-top"><a href="#top">↑ Back to top</a></p>
</body>
</html>"""

def build(md_path, html_path, pdf_path, medium_url):
    with open(md_path, encoding="utf-8") as f:
        md_text = f.read()
    title = extract_title(md_text)
    html = md_to_html(md_text, title, medium_url)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  HTML → {html_path}")
    result = subprocess.run([
        "google-chrome", "--headless", "--disable-gpu",
        "--no-sandbox", "--disable-dev-shm-usage",
        f"--print-to-pdf={pdf_path}",
        "--print-to-pdf-no-header",
        html_path
    ], capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        print(f"  PDF  → {pdf_path}")
    else:
        print(f"  PDF FAILED: {result.stderr[:200]}")

ARTICLES = [
    {
        "md":   os.path.join(REPO, "Anomaly_activity", "README.md"),
        "html": os.path.join(REPO, "Anomaly_activity", "malicious-activity-statistical-signal.html"),
        "pdf":  os.path.join(REPO, "Anomaly_activity", "malicious-activity-statistical-signal.pdf"),
        "url":  "https://medium.com/bugbountywriteup/malicious-activity-as-a-statistical-signal-a-detection-engineering-analysis-of-anomaly-based-90df8b6dea12",
    },
    {
        "md":   os.path.join(REPO, "CTI-To-Detection", "README.md"),
        "html": os.path.join(REPO, "CTI-To-Detection", "cti-to-detection-practitioners-guide.html"),
        "pdf":  os.path.join(REPO, "CTI-To-Detection", "cti-to-detection-practitioners-guide.pdf"),
        "url":  "https://medium.com/bugbountywriteup/from-threat-intelligence-to-detection-a-practitioners-guide-2d930b168426",
    },
    {
        "md":   os.path.join(REPO, "Insider_Attack_Detection", "README.md"),
        "html": os.path.join(REPO, "Insider_Attack_Detection", "detecting-malicious-insider-activity.html"),
        "pdf":  os.path.join(REPO, "Insider_Attack_Detection", "detecting-malicious-insider-activity.pdf"),
        "url":  "https://medium.com/bugbountywriteup/detecting-malicious-insider-activity-a-technical-detection-engineering-guide-3c3b41e95e82",
    },
    {
        "md":   os.path.join(REPO, "Kubernetes", "CTI_Kubernetes_Container_Threat_Research.md"),
        "html": os.path.join(REPO, "Kubernetes", "cti-research-kubernetes-cloud-native.html"),
        "pdf":  os.path.join(REPO, "Kubernetes", "cti-research-kubernetes-cloud-native.pdf"),
        "url":  "https://medium.com/bugbountywriteup/cti-research-kubernetes-cloud-native-threat-landscape-70373d6d7a87",
    },
    {
        "md":   os.path.join(REPO, "AI_PT", "AI_Offensive_Security_Practical_Attacks_Against_LLM_Agents.md"),
        "html": os.path.join(REPO, "AI_PT", "ai-offensive-security-llm-agents.html"),
        "pdf":  os.path.join(REPO, "AI_PT", "ai-offensive-security-llm-agents.pdf"),
        "url":  "",
    },
    {
        "md":   os.path.join(REPO, "AI_Threat_Actors", "README.md"),
        "html": os.path.join(REPO, "AI_Threat_Actors", "ai-in-offensive-operations.html"),
        "pdf":  os.path.join(REPO, "AI_Threat_Actors", "ai-in-offensive-operations.pdf"),
        "url":  "https://medium.com/@1200km/ai-in-offensive-operations-how-threat-actors-use-artificial-intelligence-4eaeeaf029a9",
    },
    {
        "md":   os.path.join(REPO, "Pyramid-of-Pain-AI-Revision", "README.md"),
        "html": os.path.join(REPO, "Pyramid-of-Pain-AI-Revision", "what-ai-assisted-offensive-work-means.html"),
        "pdf":  os.path.join(REPO, "Pyramid-of-Pain-AI-Revision", "what-ai-assisted-offensive-work-means.pdf"),
        "url":  "https://medium.com/system-weakness/what-ai-assisted-offensive-work-actually-means-for-your-detection-program-a-practitioners-9c27a8f40f12",
    },
    {
        "md":   os.path.join(REPO, "ATT&CK", "README.md"),
        "html": os.path.join(REPO, "ATT&CK", "attck-as-a-working-tool.html"),
        "pdf":  os.path.join(REPO, "ATT&CK", "attck-as-a-working-tool.pdf"),
        "url":  "https://medium.com/@1200km/att-ck-as-a-working-tool-theory-and-hands-on-practical-usage-d63835c9f101",
    },
    {
        "md":   os.path.join(REPO, "Infrastructure_pivoting", "README.md"),
        "html": os.path.join(REPO, "Infrastructure_pivoting", "infrastructure-pivoting-ioc-to-network.html"),
        "pdf":  os.path.join(REPO, "Infrastructure_pivoting", "infrastructure-pivoting-ioc-to-network.pdf"),
        "url":  "https://medium.com/@1200km/infrastructure-pivoting-how-cti-analysts-expand-from-a-single-ioc-to-a-full-attacker-network-1295d50ec29c",
    },
    {
        "md":   os.path.join(REPO, "Attribution", "README.md"),
        "html": os.path.join(REPO, "Attribution", "attribution-methodology.html"),
        "pdf":  os.path.join(REPO, "Attribution", "attribution-methodology.pdf"),
        "url":  "https://medium.com/@1200km",
    },
]

if __name__ == "__main__":
    for a in ARTICLES:
        print(f"\n[{os.path.basename(a['md'])}]")
        build(a["md"], a["html"], a["pdf"], a["url"])
    print("\nDone.")
