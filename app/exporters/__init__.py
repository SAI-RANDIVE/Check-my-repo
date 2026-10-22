"""Exporters: CycloneDX SBOM/CBOM, SARIF 2.1.0, CSV and PDF."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.engine import ScanReport

FORMATS = {
    "sbom": ("application/vnd.cyclonedx+json", "sbom.cdx.json"),
    "cbom": ("application/vnd.cyclonedx+json", "cbom.cdx.json"),
    "sarif": ("application/sarif+json", "results.sarif"),
    "csv": ("text/csv", "findings.csv"),
    "pdf": ("application/pdf", "report.pdf"),
    "json": ("application/json", "report.json"),
}


def render(report: ScanReport, fmt: str) -> bytes:
    """Render a report in the requested format and return the bytes."""
    if fmt == "sbom":
        from app.exporters.sbom import build_sbom

        return json.dumps(build_sbom(report), indent=2).encode()
    if fmt == "cbom":
        from app.exporters.cbom import build_cbom

        return json.dumps(build_cbom(report), indent=2).encode()
    if fmt == "sarif":
        from app.exporters.sarif import build_sarif

        return json.dumps(build_sarif(report), indent=2).encode()
    if fmt == "csv":
        from app.exporters.csv_export import build_csv

        return build_csv(report).encode("utf-8-sig")
    if fmt == "pdf":
        from app.exporters.pdf import build_pdf

        return build_pdf(report)
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2, default=str).encode()
    raise ValueError(f"unknown export format: {fmt}")


def write(report: ScanReport, fmt: str, path: Path) -> Path:
    """Render and write an export to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render(report, fmt))
    return path
