"""Report export helpers: CSV, PDF, and optional redacted HTML paths."""

from __future__ import annotations

import csv
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def export_artifacts_csv(artifacts: list, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["artifact_id", "artifact_type", "value", "source", "confidence", "depth", "discovered_at"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for art in artifacts:
            writer.writerow({k: art.get(k) for k in fields})
    return str(path)


def export_presences_csv(presences: list, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "presence_id", "platform_name", "username", "profile_url",
        "is_verified", "display_name", "follower_count",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in presences:
            writer.writerow({k: row.get(k) for k in fields})
    return str(path)


def generate_pdf_from_html(html_path: str, pdf_path: Optional[str] = None) -> str:
    """Convert an HTML report to PDF via pandoc/xelatex when available."""
    html = Path(html_path)
    if not html.exists():
        raise FileNotFoundError(html_path)
    out = Path(pdf_path) if pdf_path else html.with_suffix(".pdf")
    out.parent.mkdir(parents=True, exist_ok=True)

    pandoc = shutil.which("pandoc")
    if not pandoc:
        raise RuntimeError("PDF export requires pandoc on PATH")

    # Prefer engines that exist locally
    engine = None
    for candidate in ("xelatex", "pdflatex", "lualatex", "wkhtmltopdf", "weasyprint"):
        if shutil.which(candidate):
            engine = candidate
            break

    cmd = [pandoc, str(html), "-o", str(out), "-f", "html"]
    if engine and engine.endswith("latex"):
        cmd.extend(["--pdf-engine", engine])
    elif engine == "wkhtmltopdf":
        cmd.extend(["--pdf-engine", "wkhtmltopdf"])

    # Strip heavy scripts/iframe for PDF readability by using a simplified pass
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0 or not out.exists():
            # Fallback: write a minimal text-ish HTML then convert
            simplified = _simplify_html_for_pdf(html.read_text(encoding="utf-8", errors="ignore"))
            with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as tmp:
                tmp.write(simplified)
                tmp_path = tmp.name
            try:
                result2 = subprocess.run(
                    [pandoc, tmp_path, "-o", str(out), "-f", "html"]
                    + (["--pdf-engine", engine] if engine and engine.endswith("latex") else []),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result2.returncode != 0 or not out.exists():
                    raise RuntimeError(result.stderr or result2.stderr or "pandoc PDF conversion failed")
            finally:
                Path(tmp_path).unlink(missing_ok=True)
    except Exception:
        raise

    logger.info("PDF report saved to %s", out)
    return str(out)


def _simplify_html_for_pdf(html: str) -> str:
    """Drop scripts and iframes that confuse LaTeX PDF engines."""
    import re
    html = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.I | re.S)
    html = re.sub(r"<iframe\b[^>]*>.*?</iframe>", "<p>[Interactive graph omitted in PDF]</p>", html, flags=re.I | re.S)
    return html
