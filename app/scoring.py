"""Module 6: exploit-aware prioritisation, repository grade and CI gate.

Priority tiers
--------------
P0 Critical-Now
    dependency CVE in CISA KEV; or CVSS >= 9.0 and EPSS >= 0.10; or a
    live-format, non-placeholder secret in HEAD; or a tainted SQL/command injection.
P1 High
    CVSS >= 7.0 with EPSS >= 0.01 (or EPSS unknown); a historical secret;
    ``pull_request_target`` misuse; broken cryptography; other high/critical rules.
P2 Medium
    other CVSS >= 4.0; unpinned actions; root containers; weak cryptography;
    untainted SAST hits; other medium rules.
P3 Low/Info
    everything else, including placeholders.

Risk and score
--------------
risk = severity_weight x exploit_multiplier x exposure_multiplier, where
exploit_multiplier = 1 + 4*EPSS (+2 if in KEV) and exposure_multiplier is
1.0 for HEAD code and direct deps, 0.6 for transitive deps, 0.5 for
history-only secrets and 0.3 for test files.

score = 100 - min(100, sum(risk) / normaliser); A >= 90, B >= 80, C >= 70,
D >= 55, F < 55.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from app.scanners.base import SEVERITY_RANK, Finding, is_test_path

SEVERITY_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.25}
PRIORITIES = ("P0", "P1", "P2", "P3")
GATE_TO_TIERS = {"p0": {"P0"}, "p1": {"P0", "P1"}, "p2": {"P0", "P1", "P2"}}
GATE_ALIASES = {"critical": "p0", "high": "p1", "medium": "p2"}
ACTIVE_STATUSES = {"open"}


def normalise_gate(level: str | None, default: str = "p0") -> str:
    """Accept ``p0|p1|p2`` or ``critical|high|medium``."""
    lv = (level or default).lower().strip()
    lv = GATE_ALIASES.get(lv, lv)
    if lv not in GATE_TO_TIERS:
        raise ValueError(f"fail-on must be one of p0, p1, p2 (got {level!r})")
    return lv


def _sev_fallback(sev: str) -> str:
    if sev in ("critical", "high"):
        return "P1"
    if sev == "medium":
        return "P2"
    return "P3"


def priority_for(f: Finding) -> tuple[str, str]:
    """Return ``(tier, reason)`` for a finding according to the published rules."""
    x = f.extra
    if f.module == "dependencies":
        cvss = x.get("cvss_score")
        epss = x.get("epss")
        if x.get("in_kev"):
            return "P0", f"listed in CISA KEV (actively exploited; due {x.get('kev_due_date')})"
        if cvss is not None and epss is not None and cvss >= 9.0 and epss >= 0.10:
            return "P0", f"CVSS {cvss:.1f} and EPSS {epss:.1%}"
        if cvss is not None and cvss >= 7.0 and (epss is None or epss >= 0.01):
            return "P1", f"CVSS {cvss:.1f}" + (f" with EPSS {epss:.1%}" if epss is not None else " (no EPSS score)")
        if cvss is not None and cvss >= 4.0:
            return "P2", f"CVSS {cvss:.1f}" + (f", EPSS {epss:.2%}" if epss is not None else "")
        if cvss is None:
            return _sev_fallback(f.severity), "severity label (no CVSS vector)"
        return "P3", f"CVSS {cvss:.1f}"
    if f.module == "secrets":
        if x.get("placeholder"):
            return "P3", "placeholder / example value"
        if x.get("historical"):
            return "P1", "secret recoverable from git history"
        if x.get("live_format"):
            return "P0", "live-format credential present in HEAD"
        if f.rule_id == "generic-secret-assignment":
            return "P1", "hard-coded credential in HEAD"
        return _sev_fallback(f.severity), "possible credential in HEAD"
    if f.module == "sast":
        base = f.rule_id.split("-", 1)[-1]
        if f.tainted and base in ("SQLI", "CMDI"):
            return "P0", "user input reaches an injection sink (taint-confirmed)"
        if x.get("crypto_class") == "broken":
            return "P1", "broken cryptography"
        if f.tainted:
            return "P1", "user input reaches a dangerous sink"
        return "P2", "static-analysis finding (no taint path confirmed)"
    if f.module == "crypto":
        return ("P1", "broken cryptography") if x.get("crypto_class") == "broken" else ("P2", "weak cryptography")
    if f.module == "iac":
        if f.rule_id == "GHA-PRT-CHECKOUT":
            return "P1", "pull_request_target runs untrusted code with secrets"
        if f.rule_id in ("GHA-UNPINNED-ACTION", "DOCKER-ROOT-USER"):
            return "P2", "supply-chain / hardening gap"
        return _sev_fallback(f.severity), f"{f.severity} configuration issue"
    return _sev_fallback(f.severity), f.severity


def exposure_multiplier(f: Finding) -> float:
    """Exposure factor used in the risk formula."""
    if f.module == "secrets" and f.extra.get("historical"):
        return 0.5
    if f.module == "dependencies" and not f.extra.get("direct", True):
        return 0.6
    if f.file and is_test_path(f.file):
        return 0.3
    return 1.0


def exploit_multiplier(f: Finding) -> float:
    """1 + 4*EPSS, plus 2 when the CVE is in CISA KEV."""
    epss = f.extra.get("epss") or 0.0
    return 1.0 + 4.0 * float(epss) + (2.0 if f.extra.get("in_kev") else 0.0)


def score_finding(f: Finding) -> None:
    """Assign priority and risk score to a finding in place."""
    tier, reason = priority_for(f)
    f.priority = tier
    f.extra["priority_reason"] = reason
    f.risk_score = round(SEVERITY_WEIGHT.get(f.severity, 1.0) * exploit_multiplier(f) * exposure_multiplier(f), 3)


@dataclass
class GateResult:
    """Outcome of grading and the CI gate."""

    score: float
    grade: str
    passed: bool
    fail_on: str
    reasons: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    total_risk: float = 0.0


def grade_for(score: float) -> str:
    """Letter grade from a 0-100 score."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"


def _reason_line(f: Finding) -> str:
    x = f.extra
    if f.module == "dependencies":
        ids = x.get("kev_cves") or x.get("cves") or [f.rule_id]
        return f"{ids[0]} in {x.get('package')} {x.get('version')}: {x.get('priority_reason')}"
    loc = f"{f.file}:{f.line}" if f.line else f.file
    return f"{f.title} at {loc}"


def evaluate(findings: list[Finding], fail_on: str = "p0", normaliser: float = 10.0) -> GateResult:
    """Score every finding, compute the repository grade and the gate decision."""
    fail_on = normalise_gate(fail_on)
    for f in findings:
        score_finding(f)
    active = [f for f in findings if f.status in ACTIVE_STATUSES]
    total = sum(f.risk_score for f in active)
    score = round(max(0.0, 100.0 - min(100.0, total / max(normaliser, 0.001))), 1)
    counts = Counter(f.priority for f in active)
    blocking = [f for f in active if f.priority in GATE_TO_TIERS[fail_on]]
    blocking.sort(key=lambda f: (PRIORITIES.index(f.priority), -f.risk_score))
    reasons: list[str] = []
    if blocking:
        by_tier = Counter(f.priority for f in blocking)
        summary = ", ".join(f"{n} {t}" for t, n in sorted(by_tier.items()))
        reasons.append(f"{len(blocking)} blocking finding(s) at or above {fail_on.upper()}: {summary}")
        reasons += [_reason_line(f) for f in blocking[:8]]
        if len(blocking) > 8:
            reasons.append(f"... and {len(blocking) - 8} more")
    else:
        reasons.append(f"No open findings at or above {fail_on.upper()}.")
    return GateResult(score=score, grade=grade_for(score), passed=not blocking, fail_on=fail_on, reasons=reasons,
                      counts={p: counts.get(p, 0) for p in PRIORITIES}, total_risk=round(total, 2))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order by tier, then risk, then severity."""
    return sorted(findings, key=lambda f: (PRIORITIES.index(f.priority) if f.priority in PRIORITIES else 9,
                                           -f.risk_score, SEVERITY_RANK.get(f.severity, 9), f.file, f.line or 0))
