"""Module 2b: OSV / EPSS / KEV clients (HTTP mocked with respx), caching, degradation and analysis."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.config import get_settings
from app.scanners.base import Component
from app.scanners.intel import (
    IntelClient,
    MemoryCache,
    build_dependency_findings,
    cvss_from_vuln,
    enrich_async,
    fixed_version,
    upgrade_command,
    version_key,
)

S = get_settings()
LODASH = Component(name="lodash", version="4.17.15", ecosystem="npm", purl="pkg:npm/lodash@4.17.15", file="package-lock.json")
PILLOW = Component(name="pillow", version="8.0.0", ecosystem="PyPI", purl="pkg:pypi/pillow@8.0.0", file="requirements.txt")

GHSA = {
    "id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"], "summary": "Prototype Pollution in lodash",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
    "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.7.0"}, {"fixed": "4.17.19"}]}]}],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
    "references": [{"type": "WEB", "url": "https://github.com/lodash/lodash/issues/4874"}],
}
WEBP = {
    "id": "PYSEC-2023-175", "aliases": ["CVE-2023-4863", "GHSA-j7hp-h8jx-5ppr"], "summary": "libwebp heap overflow",
    "affected": [{"package": {"ecosystem": "PyPI", "name": "pillow"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.0.1"}]}]}],
}
WEBP_GHSA = {**WEBP, "id": "GHSA-j7hp-h8jx-5ppr", "aliases": ["CVE-2023-4863", "PYSEC-2023-175"],
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}]}
KEV = {"catalogVersion": "2026.10.21", "vulnerabilities": [
    {"cveID": "CVE-2023-4863", "dueDate": "2023-10-04", "dateAdded": "2023-09-13", "vulnerabilityName": "libwebp",
     "knownRansomwareCampaignUse": "Unknown", "requiredAction": "Apply updates"}]}


def mock_all(router: respx.MockRouter) -> None:
    router.post(S.osv_querybatch_url).mock(return_value=httpx.Response(200, json={"results": [
        {"vulns": [{"id": "GHSA-p6mc-m468-83gw"}]}, {"vulns": [{"id": "PYSEC-2023-175"}, {"id": "GHSA-j7hp-h8jx-5ppr"}]}]}))
    router.get(S.osv_vuln_url.format(id="GHSA-p6mc-m468-83gw")).mock(return_value=httpx.Response(200, json=GHSA))
    router.get(S.osv_vuln_url.format(id="PYSEC-2023-175")).mock(return_value=httpx.Response(200, json=WEBP))
    router.get(S.osv_vuln_url.format(id="GHSA-j7hp-h8jx-5ppr")).mock(return_value=httpx.Response(200, json=WEBP_GHSA))
    router.get(S.epss_url).mock(return_value=httpx.Response(200, json={"data": [
        {"cve": "CVE-2020-8203", "epss": "0.05213", "percentile": "0.92461", "date": "2026-10-21"},
        {"cve": "CVE-2023-4863", "epss": "0.99979", "percentile": "0.99990", "date": "2026-10-21"}]}))
    router.get(S.kev_url).mock(return_value=httpx.Response(200, json=KEV))


@respx.mock
async def test_full_enrichment_pipeline() -> None:
    mock_all(respx.mock)
    async with IntelClient(cache=MemoryCache()) as client:
        findings, stats = await enrich_async([LODASH, PILLOW], client)
    by = {f.rule_id: f for f in findings}
    assert set(by) == {"CVE-2020-8203", "CVE-2023-4863"}  # PYSEC + GHSA merged by alias
    webp = by["CVE-2023-4863"].extra
    assert webp["in_kev"] and webp["kev_due_date"] == "2023-10-04" and webp["epss"] == pytest.approx(0.99979)
    assert webp["cvss_score"] == pytest.approx(8.8) and webp["fixed_version"] == "10.0.1"
    assert sorted(webp["vuln_ids"]) == ["GHSA-j7hp-h8jx-5ppr", "PYSEC-2023-175"]
    lod = by["CVE-2020-8203"].extra
    assert lod["upgrade_command"] == "npm install lodash@4.17.19" and lod["epss_percentile"] == pytest.approx(0.92461)
    assert stats["kev_hits"] == 1 and stats["epss_populated"] == 2 and not stats["intel_partial_sources"]


@respx.mock
async def test_querybatch_is_cached() -> None:
    route = respx.post(S.osv_querybatch_url).mock(return_value=httpx.Response(200, json={"results": [{}]}))
    cache = MemoryCache()
    async with IntelClient(cache=cache) as client:
        await client.osv_query([LODASH])
        await client.osv_query([LODASH])
    assert route.call_count == 1


@respx.mock
async def test_querybatch_chunks_of_500() -> None:
    comps = [Component(name=f"p{i}", version="1.0.0", ecosystem="npm", purl=f"pkg:npm/p{i}@1.0.0", file="x") for i in range(1001)]
    route = respx.post(S.osv_querybatch_url).mock(side_effect=lambda req: httpx.Response(
        200, json={"results": [{} for _ in __import__("json").loads(req.content)["queries"]]}))
    async with IntelClient(cache=MemoryCache()) as client:
        await client.osv_query(comps)
    assert route.call_count == 3


@respx.mock
async def test_epss_batches_of_100() -> None:
    route = respx.get(S.epss_url).mock(return_value=httpx.Response(200, json={"data": []}))
    async with IntelClient(cache=MemoryCache()) as client:
        await client.epss([f"CVE-2020-{i:04d}" for i in range(250)])
    assert route.call_count == 3


@respx.mock
async def test_kev_cached_for_24h() -> None:
    route = respx.get(S.kev_url).mock(return_value=httpx.Response(200, json=KEV))
    cache = MemoryCache()
    async with IntelClient(cache=cache) as client:
        a = await client.kev()
        b = await client.kev()
    assert route.call_count == 1 and "CVE-2023-4863" in a and a == b


@respx.mock
async def test_graceful_degradation_marks_partial() -> None:
    respx.post(S.osv_querybatch_url).mock(return_value=httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-p6mc-m468-83gw"}]}]}))
    respx.get(S.osv_vuln_url.format(id="GHSA-p6mc-m468-83gw")).mock(return_value=httpx.Response(200, json=GHSA))
    respx.get(S.epss_url).mock(return_value=httpx.Response(503))
    respx.get(S.kev_url).mock(side_effect=httpx.ConnectError("down"))
    async with IntelClient(cache=MemoryCache()) as client:
        findings, stats = await enrich_async([LODASH], client)
    assert len(findings) == 1 and findings[0].extra["intel_partial"]
    assert set(stats["intel_partial_sources"]) == {"epss", "kev"} and findings[0].extra["epss"] is None


def test_cvss_v3_v4_and_label_fallback() -> None:
    assert cvss_from_vuln(GHSA)["score"] == pytest.approx(7.4)
    v4 = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}
    assert cvss_from_vuln(v4) == {"score": 9.3, "vector": v4["severity"][0]["score"], "version": "4.0", "source": "vector"}
    assert cvss_from_vuln({"database_specific": {"severity": "MODERATE"}})["source"] == "label:MODERATE"


def test_fixed_version_picks_matching_range() -> None:
    vuln = {"affected": [{"package": {"ecosystem": "PyPI", "name": "Django"}, "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "3.2"}, {"fixed": "3.2.14"}, {"introduced": "4.0"}, {"fixed": "4.0.6"}]}]}]}
    django = Component(name="django", version="3.2.0", ecosystem="PyPI", purl="pkg:pypi/django@3.2.0", file="r")
    assert fixed_version(vuln, django) == "3.2.14"


def test_version_ordering() -> None:
    assert version_key("PyPI", "3.2.10") > version_key("PyPI", "3.2.9")
    assert version_key("npm", "1.0.0-beta.2") < version_key("npm", "1.0.0")
    assert version_key("Maven", "2.17.0") > version_key("Maven", "2.15.0")
    assert version_key("Maven", "2.0-rc1") < version_key("Maven", "2.0")


def test_upgrade_commands() -> None:
    assert upgrade_command(PILLOW, "10.0.1") == 'pip install "pillow>=10.0.1"'
    trans = Component(name="semver", version="5.7.1", ecosystem="npm", purl="pkg:npm/semver@5.7.1", file="x", direct=False)
    assert "overrides.semver" in upgrade_command(trans, "5.7.2")
    go = Component(name="github.com/gin-gonic/gin", version="v1.6.0", ecosystem="Go", purl="p", file="go.mod")
    assert upgrade_command(go, "1.9.1") == "go get github.com/gin-gonic/gin@v1.9.1"


def test_vuln_count_set_on_components() -> None:
    comp = Component(name="lodash", version="4.17.15", ecosystem="npm", purl="pkg:npm/lodash@4.17.15", file="x")
    build_dependency_findings([comp], {comp.purl: ["GHSA-p6mc-m468-83gw"]}, {"GHSA-p6mc-m468-83gw": GHSA}, {}, {}, False)
    assert comp.vuln_count == 1
