"""Scan pipeline orchestration shared by the CLI and the web application.

Stages: Cloning -> Secrets -> History -> Dependencies -> Intel enrichment ->
SAST -> IaC -> Crypto -> Scoring -> Exports. Each stage reports progress
through an optional callback so the UI can show a live stage list.
"""

from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.config import APP_NAME, APP_VERSION, Settings, get_settings
from app.ingest import Target
from app.policy import apply_suppressions, load_policy
from app.scanners.base import SEVERITY_RANK, Component, CryptoAsset, Finding, list_files, matches_any
from app.scanners.crypto import scan_crypto
from app.scanners.dependencies import discover_components
from app.scanners.iac import scan_iac
from app.scanners.intel import enrich
from app.scanners.sast_js import scan_js
from app.scanners.sast_python import scan_python
from app.scanners.secrets import ENTROPY_RULE_ID, GENERIC_RULE_ID, scan_secrets
from app.scoring import GateResult, evaluate, normalise_gate, sort_findings

log = logging.getLogger(__name__)

STAGES = ["Cloning", "Secrets", "History", "Dependencies", "Intel enrichment", "SAST", "IaC", "Crypto", "Scoring",
          "Exports"]
MODULES = ("secrets", "dependencies", "sast", "iac", "crypto")
ProgressCb = Callable[[str, str], None]


@dataclass
class ScanOptions:
    """User-selectable scan options."""

    include_history: bool = True
    include_transitive: bool = True
    fail_on: str | None = None  # None = repository policy, then settings default
    offline: bool = False  # skip live intel (used only by unit tests)


@dataclass
class ScanReport:
    """Everything a scan produced; the input to every exporter."""

    target: str
    source: str
    source_type: str
    commit_sha: str | None
    branch: str | None
    started_at: str
    finished_at: str
    duration_seconds: float
    findings: list[Finding]
    components: list[Component]
    crypto_assets: list[CryptoAsset]
    gate: GateResult
    stats: dict[str, Any] = field(default_factory=dict)
    policy_errors: list[str] = field(default_factory=list)
    intel_partial: bool = False
    options: dict[str, Any] = field(default_factory=dict)
    tool: dict[str, str] = field(default_factory=lambda: {"name": APP_NAME, "version": APP_VERSION})

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "tool": self.tool, "target": self.target, "source": self.source, "source_type": self.source_type,
            "commit_sha": self.commit_sha, "branch": self.branch, "started_at": self.started_at,
            "finished_at": self.finished_at, "duration_seconds": self.duration_seconds,
            "gate": {"passed": self.gate.passed, "fail_on": self.gate.fail_on, "reasons": self.gate.reasons,
                     "score": self.gate.score, "grade": self.gate.grade, "counts": self.gate.counts,
                     "total_risk": self.gate.total_risk},
            "stats": self.stats, "policy_errors": self.policy_errors, "intel_partial": self.intel_partial,
            "options": self.options,
            "findings": [f.to_dict() for f in self.findings],
            "components": [c.to_dict() for c in self.components],
            "crypto_assets": [a.to_dict() for a in self.crypto_assets],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScanReport:
        """Rebuild a report (used by the web exporters)."""
        g = d["gate"]
        return cls(
            target=d["target"], source=d["source"], source_type=d["source_type"], commit_sha=d.get("commit_sha"),
            branch=d.get("branch"), started_at=d["started_at"], finished_at=d["finished_at"],
            duration_seconds=d["duration_seconds"], findings=[Finding.from_dict(f) for f in d["findings"]],
            components=[Component.from_dict(c) for c in d["components"]],
            crypto_assets=[CryptoAsset.from_dict(a) for a in d["crypto_assets"]],
            gate=GateResult(score=g["score"], grade=g["grade"], passed=g["passed"], fail_on=g["fail_on"],
                            reasons=g["reasons"], counts=g["counts"], total_risk=g.get("total_risk", 0.0)),
            stats=d.get("stats", {}), policy_errors=d.get("policy_errors", []),
            intel_partial=d.get("intel_partial", False), options=d.get("options", {}),
        )

    @property
    def active_findings(self) -> list[Finding]:
        """Findings that count toward the score and gate."""
        return [f for f in self.findings if f.status == "open"]


def merge_colocated(findings: list[Finding]) -> list[Finding]:
    """Remove cross-module duplicates that point at the same file and line.

    * A generic/entropy secret hit on a line that another module also flags
      (for example a hard-coded ``SECRET_KEY`` or compose password) is dropped
      in favour of the more specific rule.
    * A crypto finding on a line with a SAST finding is folded into the SAST
      finding, which inherits the crypto classification (so broken crypto still
      ranks P1) and the higher severity.
    """
    groups: dict[tuple[str, int], list[Finding]] = defaultdict(list)
    for f in findings:
        if f.module != "dependencies" and f.line and not f.extra.get("historical"):
            groups[(f.file, f.line)].append(f)
    drop: set[int] = set()
    for group in groups.values():
        if len({f.module for f in group}) < 2:
            continue
        for f in group:
            if f.module == "secrets" and f.rule_id in (GENERIC_RULE_ID, ENTROPY_RULE_ID) and any(
                    g.module != "secrets" for g in group):
                drop.add(id(f))
        sast = [g for g in group if g.module == "sast"]
        if sast:
            for c in (g for g in group if g.module == "crypto"):
                s = sast[0]
                if s.extra.get("crypto_class") != "broken":
                    s.extra["crypto_class"] = c.extra.get("crypto_class")
                s.extra.setdefault("related_rules", []).append(c.rule_id)
                if SEVERITY_RANK[c.severity] < SEVERITY_RANK[s.severity]:
                    s.severity = c.severity
                drop.add(id(c))
    return [f for f in findings if id(f) not in drop]


def _stage(progress: ProgressCb | None, name: str, state: str) -> None:
    if progress:
        progress(name, state)


def run_scan(target: Target, options: ScanOptions | None = None, progress: ProgressCb | None = None,
             settings: Settings | None = None) -> ScanReport:
    """Run every scanner against an already-materialised target."""
    settings = settings or get_settings()
    options = options or ScanOptions()
    t0 = time.perf_counter()
    started = datetime.now(UTC)
    root = target.root
    policy = load_policy(root)
    files = list_files(root, policy.ignore_paths)
    stats: dict[str, Any] = {"files_scanned": len(files)}
    findings: list[Finding] = []
    timings: dict[str, float] = {}

    def timed(name: str, fn: Callable[[], Any]) -> Any:
        s = time.perf_counter()
        _stage(progress, name, "running")
        try:
            return fn()
        finally:
            timings[name] = round(time.perf_counter() - s, 2)
            _stage(progress, name, "done")

    # Secrets (+ History)
    _stage(progress, "Secrets", "running")
    s0 = time.perf_counter()
    history_started: list[float] = []

    def on_history() -> None:
        history_started.append(time.perf_counter())
        timings["Secrets"] = round(history_started[0] - s0, 2)
        _stage(progress, "Secrets", "done")
        _stage(progress, "History", "running")

    sec_findings, sec_stats = scan_secrets(root, files, include_history=options.include_history, is_git=target.is_git,
                                           ignore=policy.ignore_paths, on_history=on_history)
    if history_started:
        timings["History"] = round(time.perf_counter() - history_started[0], 2)
        _stage(progress, "History", "done")
    else:
        timings["Secrets"] = round(time.perf_counter() - s0, 2)
        _stage(progress, "Secrets", "done")
        _stage(progress, "History", "skipped")
    findings += sec_findings
    stats.update(sec_stats)

    components: list[Component] = timed("Dependencies", lambda: discover_components(
        root, files, include_transitive=options.include_transitive))
    intel_stats: dict[str, Any] = {}
    intel_partial = False
    if options.offline:
        _stage(progress, "Intel enrichment", "skipped")
        intel_partial = True
    else:
        dep_findings, intel_stats = timed("Intel enrichment", lambda: enrich(components, settings))
        findings += dep_findings
        intel_partial = bool(intel_stats.get("intel_partial_sources"))
    findings += timed("SAST", lambda: scan_python(root, files) + scan_js(root, files))
    findings += timed("IaC", lambda: scan_iac(root, files, is_git=target.is_git))
    crypto_assets, crypto_findings = timed("Crypto", lambda: scan_crypto(root, files))
    findings += crypto_findings

    _stage(progress, "Scoring", "running")
    s = time.perf_counter()
    findings = merge_colocated(findings)
    if policy.ignore_paths:
        findings = [f for f in findings if not (f.file and matches_any(f.file, policy.ignore_paths))]
    for f in findings:
        f.compute_fingerprint()
    apply_suppressions(findings, policy)
    fail_on = normalise_gate(options.fail_on or policy.fail_on or settings.default_fail_on)
    gate = evaluate(findings, fail_on, settings.score_normaliser)
    findings = sort_findings(findings)
    timings["Scoring"] = round(time.perf_counter() - s, 2)
    _stage(progress, "Scoring", "done")

    secret_f = [f for f in findings if f.module == "secrets" and f.status == "open"]
    stats.update({
        "secrets_head": sum(1 for f in secret_f if not f.extra.get("historical") and not f.extra.get("placeholder")),
        "secrets_history": sum(1 for f in secret_f if f.extra.get("historical")),
        "secrets_placeholder": sum(1 for f in secret_f if f.extra.get("placeholder")),
    })
    dep_f = [f for f in findings if f.module == "dependencies"]
    stats.update({
        "components": len(components),
        "components_direct": sum(1 for c in components if c.direct),
        "components_transitive": sum(1 for c in components if not c.direct),
        "components_vulnerable": sum(1 for c in components if c.vuln_count),
        "ecosystems": dict(Counter(c.ecosystem for c in components)),
        "dependency_vulns": len(dep_f),
        "cves": len({c for f in dep_f for c in f.extra.get("cves", [])}),
        "kev_hits": sum(1 for f in dep_f if f.extra.get("in_kev")),
        "epss_populated": sum(1 for f in dep_f if f.extra.get("epss") is not None),
        "by_module": {m: sum(1 for f in findings if f.module == m and f.status == "open") for m in MODULES},
        "by_priority": gate.counts,
        "by_severity": dict(Counter(f.severity for f in findings if f.status == "open")),
        "suppressed": sum(1 for f in findings if f.status == "suppressed"),
        "crypto_assets": len(crypto_assets),
        "crypto_by_class": dict(Counter(a.classification for a in crypto_assets)),
        "quantum_vulnerable_assets": sum(1 for a in crypto_assets if a.quantum_vulnerable),
        "stage_seconds": timings,
        **{k: v for k, v in intel_stats.items() if k not in ("cves", "kev_hits", "epss_populated")},
    })
    finished = datetime.now(UTC)
    return ScanReport(
        target=target.label, source=target.source, source_type=target.source_type, commit_sha=target.commit_sha,
        branch=target.branch, started_at=started.isoformat(timespec="seconds"),
        finished_at=finished.isoformat(timespec="seconds"), duration_seconds=round(time.perf_counter() - t0, 2),
        findings=findings, components=components, crypto_assets=crypto_assets, gate=gate, stats=stats,
        policy_errors=policy.errors, intel_partial=intel_partial,
        options={"include_history": options.include_history, "include_transitive": options.include_transitive,
                 "fail_on": fail_on},
    )
