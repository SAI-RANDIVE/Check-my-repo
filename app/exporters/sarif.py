"""SARIF 2.1.0 export, compatible with ``github/codeql-action/upload-sarif``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.config import APP_NAME, APP_VERSION
from app.scanners.base import cwe_url

if TYPE_CHECKING:
    from app.engine import ScanReport

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}
INFO_URI = "https://github.com/"


def build_sarif(report: ScanReport, include_closed: bool = True) -> dict[str, Any]:
    """Return a SARIF 2.1.0 log with one run."""
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for f in report.findings:
        if not include_closed and f.status != "open":
            continue
        if f.rule_id not in index:
            sec = f.extra.get("cvss_score") if f.module == "dependencies" else None
            sec = sec if sec is not None else SECURITY_SEVERITY.get(f.severity, 5.0)
            tags = ["security", f.module]
            if f.cwe:
                tags += [f.cwe, f"external/cwe/{f.cwe.lower()}"]
            help_uri = (f.references[0] if f.references else None) or cwe_url(f.cwe) or INFO_URI
            short = f.title if f.module != "dependencies" else f"{f.rule_id} in {f.extra.get('package')}"
            md = f"**{short}**\n\n{f.description}\n\n**Remediation**\n\n{f.remediation}"
            if f.secure_example:
                md += f"\n\n```\n{f.secure_example}\n```"
            index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id,
                "name": "".join(w.capitalize() for w in f.rule_id.replace("_", "-").split("-")),
                "shortDescription": {"text": short[:250]},
                "fullDescription": {"text": (f.description or short)[:1000]},
                "helpUri": help_uri,
                "help": {"text": f.remediation or short, "markdown": md},
                "defaultConfiguration": {"level": LEVEL.get(f.severity, "warning")},
                "properties": {"tags": tags, "security-severity": f"{float(sec):.1f}",
                               "precision": "high" if f.confidence == "high" else "medium",
                               "problem.severity": "error" if LEVEL.get(f.severity) == "error" else "warning"},
            })
        msg = f.title
        if f.module == "dependencies":
            x = f.extra
            bits = [f"{x.get('package')} {x.get('version')} is affected by {f.rule_id}"]
            if x.get("cvss_score") is not None:
                bits.append(f"CVSS {x['cvss_score']}")
            if x.get("epss") is not None:
                bits.append(f"EPSS {x['epss']:.3f}")
            if x.get("in_kev"):
                bits.append("listed in CISA KEV")
            if x.get("fixed_version"):
                bits.append(f"fixed in {x['fixed_version']}")
            msg = "; ".join(bits) + "."
        elif f.module == "secrets" and f.extra.get("historical"):
            msg += f" Introduced in commit {str(f.extra.get('commit'))[:10]} ({f.extra.get('commit_date')})."
        msg += f" Priority {f.priority}: {f.extra.get('priority_reason', '')}."
        res: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": LEVEL.get(f.severity, "warning"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file or "README.md", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, f.line or 1)},
            }}],
            "partialFingerprints": {"codesentinelFingerprint/v1": f.fingerprint or f.compute_fingerprint()},
            "properties": {"priority": f.priority, "riskScore": f.risk_score, "module": f.module,
                           "tainted": f.tainted},
        }
        if f.status != "open":
            res["suppressions"] = [{"kind": "external" if f.status == "suppressed" else "inSource",
                                    "status": "accepted", "justification": f.justification or f.status}]
        results.append(res)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": APP_NAME, "version": APP_VERSION, "semanticVersion": APP_VERSION,
                                "informationUri": INFO_URI, "rules": rules}},
            "automationDetails": {"id": f"codesentinel/{report.target}/"},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
            "results": results,
            "properties": {"grade": report.gate.grade, "score": report.gate.score, "gatePassed": report.gate.passed,
                           "failOn": report.gate.fail_on},
        }],
    }
