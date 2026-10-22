"""Module 2b: live threat intelligence (OSV.dev, FIRST EPSS, CISA KEV) with a SQLite cache.

* OSV ``querybatch`` (chunks of 500) maps components to advisory IDs, then
  ``/v1/vulns/{id}`` supplies aliases, CVSS vectors and affected ranges.
* EPSS (batches of 100 CVEs) gives the probability of exploitation in the
  next 30 days and its percentile.
* The KEV catalogue is downloaded once and cached for 24 hours.

Every response is cached in ``FeedCache`` with a TTL. Requests use a 30 s
timeout and retry with exponential backoff. If a feed is unavailable the scan
continues and affected findings are marked ``intel_partial``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Protocol

import httpx
from cvss import CVSS2, CVSS3, CVSS4
from packaging.version import InvalidVersion, Version

from app.config import Settings, get_settings
from app.scanners.base import Component, Finding

log = logging.getLogger(__name__)

USER_AGENT = "CodeSentinel/1.0 (+https://github.com/; supply-chain security research)"
GENERIC_CWES = {"CWE-20", "CWE-400", "CWE-noinfo", "NVD-CWE-Other", "NVD-CWE-noinfo"}
LABEL_SCORES = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}


class Cache(Protocol):
    """Minimal cache interface (database-backed in the app, in-memory in tests)."""

    def get(self, key: str) -> Any | None: ...

    def set(self, key: str, source: str, value: Any, ttl_hours: float) -> None: ...


class MemoryCache:
    """Process-local cache used by unit tests."""

    def __init__(self) -> None:
        self.store: dict[str, tuple[datetime, Any]] = {}

    def get(self, key: str) -> Any | None:
        item = self.store.get(key)
        if not item or item[0] < datetime.now(UTC):
            return None
        return item[1]

    def set(self, key: str, source: str, value: Any, ttl_hours: float) -> None:
        self.store[key] = (datetime.now(UTC) + timedelta(hours=ttl_hours), value)


class DBCache:
    """``FeedCache`` table-backed cache with per-entry expiry."""

    def get(self, key: str) -> Any | None:
        from app.db import session_scope
        from app.models import FeedCache

        with session_scope() as s:
            row = s.get(FeedCache, key)
            if row is None:
                return None
            exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
            if exp < datetime.now(UTC):
                return None
            return json.loads(row.payload)

    def get_many(self, keys: list[str]) -> dict[str, Any]:
        """Bulk lookup to avoid one round-trip per key."""
        from sqlalchemy import select

        from app.db import session_scope
        from app.models import FeedCache

        out: dict[str, Any] = {}
        now = datetime.now(UTC)
        with session_scope() as s:
            for i in range(0, len(keys), 500):
                for row in s.scalars(select(FeedCache).where(FeedCache.key.in_(keys[i:i + 500]))):
                    exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
                    if exp >= now:
                        out[row.key] = json.loads(row.payload)
        return out

    def set(self, key: str, source: str, value: Any, ttl_hours: float) -> None:
        self.set_many([(key, value)], source, ttl_hours)

    def set_many(self, items: list[tuple[str, Any]], source: str, ttl_hours: float) -> None:
        """Bulk upsert."""
        from app.db import session_scope
        from app.models import FeedCache

        now = datetime.now(UTC)
        with session_scope() as s:
            for key, value in items:
                s.merge(FeedCache(key=key, source=source, payload=json.dumps(value), fetched_at=now,
                                  expires_at=now + timedelta(hours=ttl_hours)))


def _get_many(cache: Cache, keys: list[str]) -> dict[str, Any]:
    if hasattr(cache, "get_many"):
        return cache.get_many(keys)  # type: ignore[no-any-return]
    return {k: v for k in keys if (v := cache.get(k)) is not None}


def _set_many(cache: Cache, items: list[tuple[str, Any]], source: str, ttl: float) -> None:
    if hasattr(cache, "set_many"):
        cache.set_many(items, source, ttl)
    else:
        for k, v in items:
            cache.set(k, source, v, ttl)


class FeedError(Exception):
    """A feed could not be reached after all retries."""


class IntelClient:
    """Async client for OSV, EPSS and KEV with caching, retries and degradation."""

    def __init__(self, settings: Settings | None = None, cache: Cache | None = None) -> None:
        self.settings = settings or get_settings()
        self.cache: Cache = cache if cache is not None else DBCache()
        self.partial_sources: set[str] = set()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> IntelClient:
        self._client = httpx.AsyncClient(timeout=self.settings.http_timeout_seconds,
                                         headers={"User-Agent": USER_AGENT}, follow_redirects=True)
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client:
            await self._client.aclose()

    async def _request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        assert self._client is not None, "use `async with IntelClient()`"
        delay = 0.5
        last: Exception | None = None
        for attempt in range(self.settings.http_retries):
            try:
                r = await self._client.request(method, url, **kw)
                if r.status_code == 429 or r.status_code >= 500:
                    raise httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
                return r
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                last = exc
                if attempt < self.settings.http_retries - 1:
                    await asyncio.sleep(delay)
                    delay *= 2
        raise FeedError(f"{method} {url} failed: {last}")

    # ------------------------------------------------------------------ OSV
    async def osv_query(self, components: list[Component]) -> dict[str, list[str]]:
        """Map component purls to OSV advisory IDs via ``querybatch``."""
        out: dict[str, list[str]] = {}
        todo: list[Component] = []
        keys = {c.purl: f"osv:q:{c.ecosystem}:{c.name}:{c.version}" for c in components if c.version}
        cached = _get_many(self.cache, list(keys.values()))
        for c in components:
            if not c.version:
                continue
            hit = cached.get(keys[c.purl])
            if hit is not None:
                out[c.purl] = hit
            else:
                todo.append(c)
        size = self.settings.osv_batch_size
        for i in range(0, len(todo), size):
            chunk = todo[i:i + size]
            body = {"queries": [{"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version}
                                for c in chunk]}
            try:
                r = await self._request("POST", self.settings.osv_querybatch_url, json=body)
                r.raise_for_status()
                results = r.json().get("results", [])
            except (FeedError, httpx.HTTPError, ValueError) as exc:
                log.warning("OSV querybatch unavailable: %s", exc)
                self.partial_sources.add("osv")
                continue
            to_cache = []
            for c, res in zip(chunk, results, strict=False):
                ids = [v["id"] for v in res.get("vulns", [])]
                token = res.get("next_page_token")
                while token:  # very large result sets are paginated per query
                    q = {"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version, "page_token": token}
                    try:
                        page = (await self._request("POST", self.settings.osv_querybatch_url,
                                                    json={"queries": [q]})).json()["results"][0]
                    except (FeedError, ValueError, KeyError, IndexError):
                        self.partial_sources.add("osv")
                        break
                    ids += [v["id"] for v in page.get("vulns", [])]
                    token = page.get("next_page_token")
                out[c.purl] = ids
                to_cache.append((keys[c.purl], ids))
            _set_many(self.cache, to_cache, "osv", self.settings.ttl_osv_query_hours)
        return out

    async def osv_vulns(self, ids: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch full OSV records (cached) with bounded concurrency."""
        ids = sorted(set(ids))
        cached = _get_many(self.cache, [f"osv:v:{i}" for i in ids])
        out = {i: cached[f"osv:v:{i}"] for i in ids if f"osv:v:{i}" in cached}
        missing = [i for i in ids if i not in out]
        sem = asyncio.Semaphore(self.settings.http_concurrency)
        fetched: list[tuple[str, Any]] = []

        async def one(vid: str) -> None:
            async with sem:
                try:
                    r = await self._request("GET", self.settings.osv_vuln_url.format(id=vid))
                    if r.status_code == 200:
                        data = r.json()
                        out[vid] = data
                        fetched.append((f"osv:v:{vid}", data))
                except (FeedError, ValueError) as exc:
                    log.warning("OSV vuln %s unavailable: %s", vid, exc)
                    self.partial_sources.add("osv")

        await asyncio.gather(*(one(v) for v in missing))
        _set_many(self.cache, fetched, "osv", self.settings.ttl_osv_vuln_hours)
        return out

    # ------------------------------------------------------------------ EPSS
    async def epss(self, cves: list[str]) -> dict[str, dict[str, float]]:
        """Return ``{cve: {"epss": p, "percentile": q, "date": d}}`` for known CVEs."""
        cves = sorted({c.upper() for c in cves if c.upper().startswith("CVE-")})
        cached = _get_many(self.cache, [f"epss:{c}" for c in cves])
        out: dict[str, dict[str, Any]] = {}
        missing = []
        for c in cves:
            v = cached.get(f"epss:{c}")
            if v is None:
                missing.append(c)
            elif v:
                out[c] = v
        size = self.settings.epss_batch_size
        for i in range(0, len(missing), size):
            batch = missing[i:i + size]
            try:
                r = await self._request("GET", self.settings.epss_url, params={"cve": ",".join(batch)})
                r.raise_for_status()
                rows = r.json().get("data", [])
            except (FeedError, httpx.HTTPError, ValueError) as exc:
                log.warning("EPSS unavailable: %s", exc)
                self.partial_sources.add("epss")
                continue
            got = {row["cve"].upper(): {"epss": float(row["epss"]), "percentile": float(row["percentile"]),
                                        "date": row.get("date")} for row in rows}
            out.update(got)
            # cache misses too (empty dict) so unknown CVEs are not re-queried every scan
            _set_many(self.cache, [(f"epss:{c}", got.get(c, {})) for c in batch], "epss", self.settings.ttl_epss_hours)
        return out

    # ------------------------------------------------------------------ KEV
    async def kev(self) -> dict[str, dict[str, Any]]:
        """Return the CISA KEV catalogue keyed by CVE (cached for 24 h)."""
        cached = self.cache.get("kev:catalog")
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        try:
            r = await self._request("GET", self.settings.kev_url)
            r.raise_for_status()
            data = r.json()
        except (FeedError, httpx.HTTPError, ValueError) as exc:
            log.warning("CISA KEV unavailable: %s", exc)
            self.partial_sources.add("kev")
            return {}
        catalog = {
            v["cveID"].upper(): {
                "dueDate": v.get("dueDate"), "dateAdded": v.get("dateAdded"),
                "name": v.get("vulnerabilityName"), "ransomware": v.get("knownRansomwareCampaignUse"),
                "action": v.get("requiredAction"),
            }
            for v in data.get("vulnerabilities", [])
        }
        self.cache.set("kev:catalog", "kev", catalog, self.settings.ttl_kev_hours)
        self.cache.set("kev:meta", "kev", {"catalogVersion": data.get("catalogVersion"), "count": len(catalog)},
                       self.settings.ttl_kev_hours)
        return catalog


# =========================================================================== analysis helpers

_NUM = re.compile(r"\d+|[A-Za-z]+")
_QUAL = {"alpha": -4, "a": -4, "beta": -3, "b": -3, "milestone": -2, "m": -2, "rc": -1, "cr": -1,
         "snapshot": -0.5, "final": 0, "ga": 0, "release": 0, "sp": 1}


def version_key(ecosystem: str, v: str) -> tuple:
    """Comparable key for a version string in the given ecosystem."""
    v = (v or "").strip()
    if ecosystem == "PyPI":
        try:
            return (0, Version(v))
        except InvalidVersion:
            pass
    if ecosystem in ("npm", "Go"):
        v = v.lstrip("v")
        main, _, pre = v.partition("-")
        nums = tuple(int(x) if x.isdigit() else 0 for x in main.split("+")[0].split("."))
        nums = (nums + (0, 0, 0))[:3]
        pre_key = (1,) if not pre else (0, *[(0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")])
        return (1, nums, pre_key)
    toks = _NUM.findall(v)
    nums: list[int] = []
    while toks and toks[0].isdigit():
        nums.append(int(toks.pop(0)))
    while nums and nums[-1] == 0:
        nums.pop()
    if not toks:  # plain release sorts after any pre-release qualifier of the same number
        return (2, tuple(nums), (0,))
    qual = _QUAL.get(toks[0].lower(), -5)
    rest = tuple(int(t) if t.isdigit() else 0 for t in toks[1:])
    return (2, tuple(nums), (qual, rest))


def _vcmp(eco: str, a: str, b: str) -> int:
    ka, kb = version_key(eco, a), version_key(eco, b)
    try:
        return (ka > kb) - (ka < kb)
    except TypeError:
        return 0


def _names_match(eco: str, a: str, b: str) -> bool:
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", a).lower() == re.sub(r"[-_.]+", "-", b).lower()
    return a == b


def fixed_version(vuln: dict[str, Any], comp: Component) -> str | None:
    """Smallest ``fixed`` event above the component's version for a matching range."""
    candidates: list[str] = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != comp.ecosystem or not _names_match(comp.ecosystem, pkg.get("name", ""), comp.name):
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev and introduced is not None:
                    fx = ev["fixed"]
                    lo_ok = introduced == "0" or _vcmp(comp.ecosystem, comp.version, introduced) >= 0
                    if lo_ok and _vcmp(comp.ecosystem, comp.version, fx) < 0:
                        candidates.append(fx)
                    introduced = None
                elif "last_affected" in ev:
                    introduced = None
    if not candidates:
        return None
    best = candidates[0]
    for c in candidates[1:]:
        if _vcmp(comp.ecosystem, c, best) < 0:
            best = c
    return best


def cvss_from_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    """Compute CVSS base score(s) from vectors; fall back to the database label."""
    best: dict[str, Any] = {}
    for sev in vuln.get("severity", []) + [s for a in vuln.get("affected", []) for s in a.get("severity", [])]:
        typ, vec = sev.get("type"), sev.get("score", "")
        try:
            if typ == "CVSS_V3" and vec.startswith("CVSS:3"):
                score = float(CVSS3(vec).scores()[0])
                ver = "3.1" if vec.startswith("CVSS:3.1") else "3.0"
            elif typ == "CVSS_V4" and vec.startswith("CVSS:4"):
                score = float(CVSS4(vec).base_score)
                ver = "4.0"
            elif typ == "CVSS_V2":
                score = float(CVSS2(vec).scores()[0])
                ver = "2.0"
            else:
                continue
        except Exception as exc:  # noqa: BLE001  (the cvss library raises many error types)
            log.debug("bad CVSS vector %s: %s", vec, exc)
            continue
        rank = {"3.1": 3, "3.0": 3, "4.0": 2, "2.0": 1}[ver]
        if not best or rank > best["rank"] or (rank == best["rank"] and score > best["score"]):
            best = {"score": score, "vector": vec, "version": ver, "rank": rank, "source": "vector"}
    if best:
        best.pop("rank")
        return best
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if label in LABEL_SCORES:
        return {"score": LABEL_SCORES[label], "vector": None, "version": None, "source": f"label:{label}"}
    return {}


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to a qualitative severity."""
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def upgrade_command(comp: Component, fixed: str | None) -> str | None:
    """Exact command (or edit) that moves the component to a fixed version."""
    if not fixed:
        return None
    if comp.ecosystem == "PyPI":
        return f'pip install "{comp.name}>={fixed}"'
    if comp.ecosystem == "npm":
        if comp.direct:
            return f"npm install {comp.name}@{fixed}"
        return f'npm pkg set overrides.{comp.name}="{fixed}" && npm install'
    if comp.ecosystem == "Maven":
        return (f"mvn versions:use-dep-version -Dincludes={comp.name} -DdepVersion={fixed} -DforceVersion=true")
    if comp.ecosystem == "Go":
        return f"go get {comp.name}@{fixed if fixed.startswith('v') else 'v' + fixed}"
    return None


def _group_vulns(ids: list[str], details: dict[str, dict[str, Any]]) -> list[list[str]]:
    """Union OSV IDs that share any alias (GHSA + PYSEC + CVE for one issue)."""
    parent = {i: i for i in ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    alias_owner: dict[str, str] = {}
    for i in ids:
        for a in [i, *details.get(i, {}).get("aliases", [])]:
            if a in alias_owner:
                parent[find(i)] = find(alias_owner[a])
            else:
                alias_owner[a] = i
    groups: dict[str, list[str]] = {}
    for i in ids:
        groups.setdefault(find(i), []).append(i)
    return list(groups.values())


def _primary_id(ids: list[str], cves: list[str]) -> str:
    if cves:
        return sorted(cves)[0]
    for prefix in ("GHSA-", "PYSEC-", "GO-", "RUSTSEC-"):
        for i in ids:
            if i.startswith(prefix):
                return i
    return sorted(ids)[0]


def build_dependency_findings(
    components: list[Component], ids_by_purl: dict[str, list[str]], details: dict[str, dict[str, Any]],
    epss: dict[str, dict[str, Any]], kev: dict[str, dict[str, Any]], partial: bool,
) -> list[Finding]:
    """Turn OSV/EPSS/KEV data into one finding per (component, distinct vulnerability)."""
    findings: list[Finding] = []
    for comp in components:
        ids = ids_by_purl.get(comp.purl, [])
        groups = _group_vulns(ids, details)
        comp.vuln_count = len(groups)
        for group in groups:
            recs = [details[i] for i in group if i in details]
            cves = sorted({a for r in recs for a in [r.get("id", ""), *r.get("aliases", [])] if a.startswith("CVE-")})
            cvss: dict[str, Any] = {}
            for r in recs:
                c = cvss_from_vuln(r)
                if c and (not cvss or (c["source"] == "vector" and (cvss["source"] != "vector" or c["score"] > cvss["score"]))):
                    cvss = c
            fixes = [f for r in recs if (f := fixed_version(r, comp))]
            fixed = None
            for f in fixes:
                if fixed is None or _vcmp(comp.ecosystem, f, fixed) > 0:
                    fixed = f  # the highest per-advisory fix satisfies every alias
            ep = max((epss[c] for c in cves if c in epss), key=lambda e: e["epss"], default=None)
            kev_hits = [kev[c] | {"cve": c} for c in cves if c in kev]
            summary = next((r.get("summary") for r in recs if r.get("summary")), None)
            details_txt = next((r.get("details") for r in recs if r.get("details")), "") or ""
            if not summary:
                summary = (details_txt.strip().split("\n")[0][:160]) or "Known vulnerability"
            cwes = sorted({c for r in recs for c in (r.get("database_specific") or {}).get("cwe_ids", []) or []})
            refs: list[str] = []
            for r in recs:
                for ref in r.get("references", []):
                    url = ref.get("url")
                    if url and url not in refs:
                        refs.append(url)
            primary = _primary_id(group, cves)
            head = [f"https://osv.dev/vulnerability/{group[0]}"]
            if cves:
                head.append(f"https://nvd.nist.gov/vuln/detail/{cves[0]}")
            refs = head + [r for r in refs if r not in head][:7]
            score = cvss.get("score")
            cmd = upgrade_command(comp, fixed)
            published = min((r.get("published", "") for r in recs if r.get("published")), default="")[:10]
            sev = severity_from_score(score)
            remediation = (f"Upgrade {comp.name} from {comp.version} to {fixed} or later.\n\n    {cmd}"
                           if fixed else
                           f"No fixed release of {comp.name} is listed for this advisory. Consider replacing the "
                           f"package, isolating the affected feature, or applying the vendor's mitigation.")
            if not comp.direct and fixed:
                remediation += ("\n\nThis is a transitive dependency: upgrade the direct dependency that pulls it in, "
                                "or pin it with an override/resolution.")
            findings.append(Finding(
                module="dependencies", rule_id=primary,
                title=f"{comp.name} {comp.version}: {summary}"[:300],
                severity=sev, file=comp.file, line=comp.line,
                description=(details_txt.strip()[:1200] or summary),
                remediation=remediation,
                secure_example=(cmd or ""),
                cwe=next((c for c in cwes if c not in GENERIC_CWES), cwes[0] if cwes else None), owasp="A06",
                references=refs,
                confidence="medium" if comp.version_inferred else "high",
                extra={
                    "fp_key": f"{comp.ecosystem}:{comp.name}:{primary}",
                    "package": comp.name, "version": comp.version, "ecosystem": comp.ecosystem, "purl": comp.purl,
                    "direct": comp.direct, "version_inferred": comp.version_inferred, "scope": comp.scope,
                    "vuln_ids": sorted(group), "cves": cves,
                    "cvss_score": score, "cvss_vector": cvss.get("vector"), "cvss_version": cvss.get("version"),
                    "cvss_source": cvss.get("source"),
                    "epss": ep["epss"] if ep else None, "epss_percentile": ep["percentile"] if ep else None,
                    "epss_date": ep.get("date") if ep else None,
                    "in_kev": bool(kev_hits), "kev_due_date": kev_hits[0]["dueDate"] if kev_hits else None,
                    "kev_date_added": kev_hits[0]["dateAdded"] if kev_hits else None,
                    "kev_ransomware": kev_hits[0].get("ransomware") if kev_hits else None,
                    "kev_cves": [k["cve"] for k in kev_hits],
                    "cwes": cwes, "fixed_version": fixed, "upgrade_command": cmd, "published": published,
                    "intel_partial": partial,
                },
            ))
    return findings


async def enrich_async(components: list[Component], client: IntelClient) -> tuple[list[Finding], dict[str, Any]]:
    """Run the full OSV -> EPSS/KEV enrichment for a component list."""
    queryable = [c for c in components if c.version]
    ids_by_purl = await client.osv_query(queryable)
    all_ids = sorted({i for ids in ids_by_purl.values() for i in ids})
    details, kev = await asyncio.gather(client.osv_vulns(all_ids), client.kev())
    cves = sorted({a for d in details.values() for a in [d.get("id", ""), *d.get("aliases", [])] if a.startswith("CVE-")})
    epss = await client.epss(cves)
    partial = bool(client.partial_sources)
    findings = build_dependency_findings(components, ids_by_purl, details, epss, kev, partial)
    kev_meta = client.cache.get("kev:meta") or {}
    stats = {
        "advisories_fetched": len(details), "cves": len({c for f in findings for c in f.extra["cves"]}),
        "kev_hits": sum(1 for f in findings if f.extra["in_kev"]),
        "epss_populated": sum(1 for f in findings if f.extra["epss"] is not None),
        "intel_partial_sources": sorted(client.partial_sources),
        "kev_catalog_version": kev_meta.get("catalogVersion"), "kev_catalog_size": len(kev),
    }
    return findings, stats


def enrich(components: list[Component], settings: Settings | None = None, cache: Cache | None = None
           ) -> tuple[list[Finding], dict[str, Any]]:
    """Synchronous wrapper around :func:`enrich_async`."""

    async def run() -> tuple[list[Finding], dict[str, Any]]:
        async with IntelClient(settings, cache) as client:
            return await enrich_async(components, client)

    return asyncio.run(run())


def to_float(v: Any) -> float | None:
    """Coerce Decimal/str/None to float."""
    if v is None:
        return None
    if isinstance(v, Decimal):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
