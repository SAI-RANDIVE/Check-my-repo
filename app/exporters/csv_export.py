"""CSV export of all findings (with spreadsheet formula-injection protection)."""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.engine import ScanReport

COLUMNS = ["priority", "risk_score", "severity", "module", "rule_id", "title", "file", "line", "status", "cwe", "owasp",
           "package", "version", "cves", "cvss", "epss", "epss_percentile", "in_kev", "kev_due_date", "fixed_version",
           "upgrade_command", "tainted", "historical", "commit", "secret_preview", "justification", "fingerprint"]


def _safe(v: Any) -> Any:
    """Neutralise cells that a spreadsheet would treat as a formula (CWE-1236)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def build_csv(report: ScanReport) -> str:
    """Return the findings table as CSV text."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLUMNS)
    for f in report.findings:
        x = f.extra
        row = [f.priority, f.risk_score, f.severity, f.module, f.rule_id, f.title, f.file, f.line or "", f.status,
               f.cwe or "", f.owasp_name or "", x.get("package", ""), x.get("version", ""), " ".join(x.get("cves", [])),
               x.get("cvss_score", ""), x.get("epss", ""), x.get("epss_percentile", ""), x.get("in_kev", ""),
               x.get("kev_due_date", "") or "", x.get("fixed_version", "") or "", x.get("upgrade_command", "") or "",
               f.tainted, x.get("historical", ""), x.get("commit", "") or "", x.get("redacted", ""),
               f.justification or "", f.fingerprint]
        w.writerow([_safe(v) for v in row])
    return buf.getvalue()
