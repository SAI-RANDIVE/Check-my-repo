"""CycloneDX 1.6 JSON software bill of materials with embedded vulnerabilities (VEX-style)."""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING, Any

from app.config import APP_NAME, APP_VERSION

if TYPE_CHECKING:
    from app.engine import ScanReport

SPDX_LIKE = re.compile(r"^[A-Za-z0-9.\-+]+$")
CVSS_METHOD = {"3.1": "CVSSv31", "3.0": "CVSSv3", "4.0": "CVSSv4", "2.0": "CVSSv2"}


def _license(lic: str | None) -> list[dict[str, Any]]:
    if not lic:
        return []
    if " OR " in lic or " AND " in lic or lic.startswith("("):
        return [{"expression": lic}]
    return [{"license": {"id": lic}}] if SPDX_LIKE.match(lic) else [{"license": {"name": lic}}]


def _split_name(ecosystem: str, name: str) -> tuple[str | None, str]:
    if ecosystem == "Maven" and ":" in name:
        g, a = name.split(":", 1)
        return g, a
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        g, a = name.split("/", 1)
        return g, a
    return None, name


def _metadata(report: ScanReport, kind: str) -> dict[str, Any]:
    return {
        "timestamp": report.finished_at,
        "tools": {"components": [{"type": "application", "author": "CodeSentinel", "name": APP_NAME,
                                  "version": APP_VERSION}]},
        "component": {
            "type": "application", "bom-ref": "root-application", "name": report.target,
            **({"version": report.commit_sha[:12]} if report.commit_sha else {}),
            "properties": [p for p in [
                {"name": "codesentinel:source", "value": report.source},
                {"name": "codesentinel:commit", "value": report.commit_sha} if report.commit_sha else None,
                {"name": "codesentinel:bom-kind", "value": kind},
            ] if p],
        },
    }


def build_sbom(report: ScanReport) -> dict[str, Any]:
    """Return a CycloneDX 1.6 SBOM dict for the report's components and dependency vulnerabilities."""
    components = []
    refs = set()
    for c in report.components:
        group, name = _split_name(c.ecosystem, c.name)
        props = [{"name": "codesentinel:ecosystem", "value": c.ecosystem},
                 {"name": "codesentinel:direct", "value": str(c.direct).lower()},
                 {"name": "codesentinel:manifest", "value": c.file}]
        if c.version_inferred:
            props.append({"name": "codesentinel:version_inferred", "value": "true"})
        comp: dict[str, Any] = {"type": "library", "bom-ref": c.purl, "name": name}
        if group:
            comp["group"] = group
        if c.version:
            comp["version"] = c.version
        comp["purl"] = c.purl
        comp["scope"] = c.scope if c.scope in ("required", "optional") else "required"
        lic = _license(c.license)
        if lic:
            comp["licenses"] = lic
        comp["properties"] = props
        components.append(comp)
        refs.add(c.purl)
    dependencies = [{"ref": "root-application", "dependsOn": sorted({c.purl for c in report.components if c.direct})}]
    dependencies += [{"ref": c.purl, "dependsOn": sorted(d for d in set(c.dependencies) if d in refs and d != c.purl)}
                     for c in report.components]
    vulns = []
    for f in report.findings:
        if f.module != "dependencies":
            continue
        x = f.extra
        ratings = []
        if x.get("cvss_score") is not None:
            r: dict[str, Any] = {"source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{x['vuln_ids'][0]}"},
                                 "score": x["cvss_score"], "severity": f.severity if f.severity != "info" else "info",
                                 "method": CVSS_METHOD.get(x.get("cvss_version") or "", "other")}
            if x.get("cvss_vector"):
                r["vector"] = x["cvss_vector"]
            ratings.append(r)
        if x.get("epss") is not None:
            ratings.append({"source": {"name": "FIRST EPSS", "url": "https://www.first.org/epss/"},
                            "score": x["epss"], "method": "other",
                            "justification": f"EPSS probability; percentile {x.get('epss_percentile')}"})
        refs_list = [{"id": a, "source": {"name": "NVD" if a.startswith("CVE-") else "OSV",
                                           "url": (f"https://nvd.nist.gov/vuln/detail/{a}" if a.startswith("CVE-")
                                                   else f"https://osv.dev/vulnerability/{a}")}}
                     for a in sorted(set(x.get("vuln_ids", []) + x.get("cves", []))) if a != f.rule_id]
        v: dict[str, Any] = {
            "bom-ref": f"{f.rule_id}@{x['purl']}",
            "id": f.rule_id,
            "source": {"name": "NVD" if f.rule_id.startswith("CVE-") else "OSV",
                       "url": (f"https://nvd.nist.gov/vuln/detail/{f.rule_id}" if f.rule_id.startswith("CVE-")
                               else f"https://osv.dev/vulnerability/{f.rule_id}")},
            "ratings": ratings,
            "description": f.title,
            "advisories": [{"url": u} for u in f.references[:5]],
            "affects": [{"ref": x["purl"]}],
            "properties": [
                {"name": "codesentinel:priority", "value": f.priority},
                {"name": "codesentinel:risk_score", "value": str(f.risk_score)},
                {"name": "codesentinel:in_cisa_kev", "value": str(bool(x.get("in_kev"))).lower()},
            ],
        }
        if refs_list:
            v["references"] = refs_list
        if f.cwe and f.cwe.startswith("CWE-") and f.cwe[4:].isdigit():
            v["cwes"] = [int(f.cwe[4:])]
        if x.get("upgrade_command"):
            v["recommendation"] = f"Upgrade to {x.get('fixed_version')}: {x['upgrade_command']}"
        if x.get("published"):
            v["published"] = f"{x['published']}T00:00:00Z"
        if x.get("kev_due_date"):
            v["properties"].append({"name": "codesentinel:kev_due_date", "value": x["kev_due_date"]})
        vulns.append(v)
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": _metadata(report, "sbom"),
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": vulns,
    }
