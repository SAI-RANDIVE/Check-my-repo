"""Exporters: CycloneDX SBOM/CBOM, SARIF 2.1.0, CSV and PDF structure."""

from __future__ import annotations

import csv
import io
import json
import re

from app.exporters import render
from app.exporters.cbom import build_cbom
from app.exporters.csv_export import build_csv
from app.exporters.sarif import build_sarif
from app.exporters.sbom import build_sbom
from app.scanners.base import Finding


def test_sbom_structure(offline_reports: dict) -> None:
    r = offline_reports["vulnerable"]
    bom = build_sbom(r)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", bom["serialNumber"])
    assert bom["metadata"]["tools"]["components"][0]["name"] == "CodeSentinel" and bom["metadata"]["timestamp"]
    comps = bom["components"]
    assert len(comps) == len(r.components) > 20
    assert all(c["type"] == "library" and c["purl"].startswith("pkg:") and c["scope"] in ("required", "optional") for c in comps)
    log4j = next(c for c in comps if c["name"] == "log4j-core")
    assert log4j["group"] == "org.apache.logging.log4j" and log4j["version"] == "2.14.1"
    refs = {c["bom-ref"] for c in comps} | {"root-application"}
    for d in bom["dependencies"]:
        assert d["ref"] in refs and set(d["dependsOn"]) <= refs
    assert any(c.get("licenses") for c in comps)


def test_sbom_vulnerability_entries() -> None:
    from app.engine import ScanReport
    from app.scoring import GateResult

    f = Finding(module="dependencies", rule_id="CVE-2023-4863", title="pillow 8.0.0: libwebp", severity="high",
                cwe="CWE-787", references=["https://osv.dev/vulnerability/GHSA-j7hp-h8jx-5ppr"],
                extra={"purl": "pkg:pypi/pillow@8.0.0", "vuln_ids": ["GHSA-j7hp-h8jx-5ppr"], "cves": ["CVE-2023-4863"],
                       "cvss_score": 8.8, "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                       "epss": 0.99, "epss_percentile": 0.999, "in_kev": True, "kev_due_date": "2023-10-04",
                       "fixed_version": "10.0.1", "upgrade_command": 'pip install "pillow>=10.0.1"', "package": "pillow", "version": "8.0.0"})
    rep = ScanReport(target="t", source="s", source_type="path", commit_sha=None, branch=None, started_at="2026-10-22T00:00:00+00:00",
                     finished_at="2026-10-22T00:00:01+00:00", duration_seconds=1, findings=[f], components=[], crypto_assets=[],
                     gate=GateResult(score=0, grade="F", passed=False, fail_on="p0", counts={"P0": 1, "P1": 0, "P2": 0, "P3": 0}))
    v = build_sbom(rep)["vulnerabilities"][0]
    assert v["id"] == "CVE-2023-4863" and v["affects"] == [{"ref": "pkg:pypi/pillow@8.0.0"}]
    assert v["ratings"][0]["method"] == "CVSSv31" and v["ratings"][0]["score"] == 8.8 and v["cwes"] == [787]
    assert {"name": "codesentinel:in_cisa_kev", "value": "true"} in v["properties"]


def test_cbom_structure(offline_reports: dict) -> None:
    cbom = build_cbom(offline_reports["vulnerable"])
    assert cbom["specVersion"] == "1.6"
    comps = cbom["components"]
    assert comps and all(c["type"] == "cryptographic-asset" for c in comps)
    ecb = next(c for c in comps if c["name"].startswith("AES") and "ECB" in c["name"])
    ap = ecb["cryptoProperties"]["algorithmProperties"]
    assert ecb["cryptoProperties"]["assetType"] == "algorithm" and ap["primitive"] == "block-cipher" and ap["mode"] == "ecb"
    assert ecb["evidence"]["occurrences"][0]["location"] == "crypto_utils.py" and ecb["evidence"]["occurrences"][0]["line"]
    rsa = next(c for c in comps if c["name"] == "RSA-1024")
    props = {p["name"]: p["value"] for p in rsa["properties"]}
    assert props["codesentinel:quantum_vulnerable"] == "true" and props["codesentinel:classification"] == "broken"
    assert rsa["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] == "1024"


def test_sarif_structure(offline_reports: dict) -> None:
    sarif = build_sarif(offline_reports["vulnerable"])
    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for r in run["tool"]["driver"]["rules"]:
        assert r["helpUri"].startswith("https://") and "security-severity" in r["properties"]
        float(r["properties"]["security-severity"])
    for res in run["results"]:
        loc = res["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1 and loc["artifactLocation"]["uri"]
        assert res["partialFingerprints"]["codesentinelFingerprint/v1"]
        assert run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
    sqli = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "PY-SQLI")
    assert "external/cwe/cwe-89" in sqli["properties"]["tags"]


def test_csv_has_rows_and_blocks_formula_injection(offline_reports: dict) -> None:
    rows = list(csv.reader(io.StringIO(build_csv(offline_reports["vulnerable"]))))
    assert rows[0][0] == "priority" and len(rows) == len(offline_reports["vulnerable"].findings) + 1
    from app.exporters.csv_export import _safe

    assert _safe("=HYPERLINK(1)") == "'=HYPERLINK(1)" and _safe("ok") == "ok"


def test_pdf_is_multi_page(offline_reports: dict) -> None:
    pdf = render(offline_reports["vulnerable"], "pdf")
    assert pdf[:5] == b"%PDF-" and len(re.findall(rb"/Type /Page[^s]", pdf)) >= 5


def test_json_export_round_trips(offline_reports: dict) -> None:
    from app.engine import ScanReport

    r = offline_reports["vulnerable"]
    data = json.loads(render(r, "json"))
    back = ScanReport.from_dict(data)
    assert len(back.findings) == len(r.findings) and back.gate.grade == r.gate.grade
