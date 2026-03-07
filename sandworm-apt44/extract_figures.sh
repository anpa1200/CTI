#!/bin/bash
# Extract figures from a Medium-export PDF of the Sandworm article.
# Usage: ./extract_figures.sh <path-to-medium-export.pdf>
# Example: Open https://medium.com/@1200km/cti-research-sandworm-apt44-649332e8af44
#          in your browser → Print → Save as PDF → save as article_medium.pdf
#          Then: ./extract_figures.sh article_medium.pdf

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <path-to-medium-export.pdf>"
  echo "Example: $0 article_medium.pdf"
  exit 1
fi

PDF="$1"
if [ ! -f "$PDF" ]; then
  echo "Error: File not found: $PDF"
  exit 1
fi

mkdir -p assets
pdfimages -png "$PDF" assets/fig
echo "Extracted $(ls assets/fig-*.png 2>/dev/null | wc -l) figures to assets/"
echo "Next: run python3 build_html.py then regenerate the PDF with Chrome headless."
