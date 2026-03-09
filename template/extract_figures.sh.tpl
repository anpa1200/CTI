#!/usr/bin/env bash
# Extract figures from a Medium-export (or other) PDF into assets/fig-NNN.png.
# Usage: ./extract_figures.sh <path-to-article.pdf>
# Requires: poppler-utils (pdfimages). Install: sudo apt install poppler-utils

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PDF_PATH="${1:-}"
OUT_DIR="${SCRIPT_DIR}/assets"

if [[ -z "$PDF_PATH" || ! -f "$PDF_PATH" ]]; then
  echo "Usage: $0 <path-to-article.pdf>"
  exit 1
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"
pdfimages -png "$PDF_PATH" fig-
echo "Extracted to $OUT_DIR (fig-000.png, fig-001.png, ...)"
