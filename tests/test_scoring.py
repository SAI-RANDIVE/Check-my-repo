"""Module 6: priority tiers, risk formula, grade, gate, policy file and cross-module de-duplication."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from app.engine import merge_colocated
from app.policy import apply_suppressions, load_policy
from app.scanners.base import Finding
from app.scoring import evaluate, exploit_multiplier, grade_for, normalise_gate, priority_for, score_finding


def dep(cvss: float | None, epss: float | None, kev: bool = False, direct: bool = True) -> Finding:
    sev = "critical" if (cvss or 0) >= 9 else "high" if (cvss or 0) >= 7 else "medium" if (cvss or 0) >= 4 else "low"
    return Finding(module="dependencies", rule_id="CVE-2020-0001", title="t", severity=sev,
                   extra={"cvss_score": cvss, "epss": epss, "in_kev": kev, "direct": direct, "package": "p", "version": "1"})


@pytest.mark.parametrize("finding,tier", [
    (dep(5.0, 0.001, kev=True), "P0"),
    (dep(9.8, 0.15), "P0"),
    (dep(9.8, 0.05), "P1"),
    (dep(7.5, 0.02), "P1"),
    (dep(7.5, None), "P1"),
    (dep(7.5, 0.001), "P2"),
    (dep(5.0, 0.5), "P2"),
    (dep(2.0, 0.0), "P3"),
])
def test_dependency_tiers(finding: Finding, tier: str) -> None:
    assert priority_for(finding)[0] == tier


def sec(**extra: object) -> Finding:
    return Finding(module="secrets", rule_id="aws-access-key-id", title="t", severity="critical", extra=dict(extra))


def test_secret_tiers() -> None:
    assert priority_for(sec(live_format=True))[0] == "P0"
    assert priority_for(sec(historical=True, live_format=True))[0] == "P1"
    assert priority_for(sec(placeholder=True))[0] == "P3"


def test_sast_iac_crypto_tiers() -> None:
    tainted = Finding(module="sast", rule_id="PY-SQLI", title="t", severity="critical", tainted=True)
    plain = Finding(module="sast", rule_id="PY-SQLI", title="t", severity="high")
    prt = Finding(module="iac", rule_id="GHA-PRT-CHECKOUT", title="t", severity="high")
    pin = Finding(module="iac", rule_id="GHA-UNPINNED-ACTION", title="t", severity="medium")
    broken = Finding(module="crypto", rule_id="CRYPTO-MD5", title="t", severity="high", extra={"crypto_class": "broken"})
    weak = Finding(module="crypto", rule_id="CRYPTO-SHA1", title="t", severity="medium", extra={"crypto_class": "weak"})
    assert [priority_for(f)[0] for f in (tainted, plain, prt, pin, broken, weak)] == ["P0", "P2", "P1", "P2", "P1", "P2"]


def test_risk_formula() -> None:
    f = dep(9.8, 0.5, kev=True)
    assert exploit_multiplier(f) == pytest.approx(1 + 4 * 0.5 + 2)
    score_finding(f)
    assert f.risk_score == pytest.approx(10 * 5.0 * 1.0)
    t = dep(9.8, 0.5, kev=True, direct=False)
    score_finding(t)
    assert t.risk_score == pytest.approx(10 * 5.0 * 0.6)
    h = sec(historical=True)
    score_finding(h)
    assert h.risk_score == pytest.approx(6 * 1 * 0.5) or h.risk_score == pytest.approx(10 * 0.5)
    test_file = Finding(module="sast", rule_id="PY-EVAL", title="t", severity="high", file="tests/test_x.py")
    score_finding(test_file)
    assert test_file.risk_score == pytest.approx(6 * 0.3)


@pytest.mark.parametrize("score,grade", [(100, "A"), (90, "A"), (89.9, "B"), (80, "B"), (70, "C"), (55, "D"), (54.9, "F"), (0, "F")])
def test_grade_boundaries(score: float, grade: str) -> None:
    assert grade_for(score) == grade


def test_gate_levels_and_aliases() -> None:
    findings = [dep(7.5, 0.02)]  # P1
    assert evaluate(findings, "p0").passed
    assert not evaluate(findings, "p1").passed
    assert normalise_gate("high") == "p1" and normalise_gate("critical") == "p0"
    with pytest.raises(ValueError):
        normalise_gate("p9")


def test_gate_ignores_triaged_findings() -> None:
    f = dep(9.8, 0.9)
    f.status = "false_positive"
    r = evaluate([f], "p0")
    assert r.passed and r.score == 100


def test_score_normalisation() -> None:
    findings = [Finding(module="sast", rule_id="X", title="t", severity="high") for _ in range(5)]  # 5 * 6 = 30
    assert evaluate(findings, "p0", normaliser=10).score == pytest.approx(97.0)


def test_policy_suppressions_justification_and_expiry(tmp_path: Path) -> None:
    (tmp_path / ".codesentinel.yml").write_text(
        "fail_on: p1\nignore_paths: [docs/**]\nsuppressions:\n"
        "  - rule: PY-DEBUG-ENABLED\n    justification: Local dev runner only\n    expires: 2099-01-01\n"
        "  - rule: PY-EVAL\n    justification: Sandboxed calculator, reviewed\n    expires: 2020-01-01\n"
        "  - rule: PY-SQLI\n    expires: 2099-01-01\n")
    pol = load_policy(tmp_path)
    assert pol.fail_on == "p1" and pol.ignore_paths == ["docs/**"]
    assert len(pol.suppressions) == 2 and any("justification is mandatory" in e for e in pol.errors)
    a = Finding(module="sast", rule_id="PY-DEBUG-ENABLED", title="t", severity="medium")
    b = Finding(module="sast", rule_id="PY-EVAL", title="t", severity="high")
    apply_suppressions([a, b], pol, today=date(2026, 10, 22))
    assert a.status == "suppressed" and b.status == "open" and b.extra["suppression_expired"] == "2020-01-01"


def test_merge_colocated_folds_crypto_into_sast_and_drops_generic_secret() -> None:
    s = Finding(module="sast", rule_id="PY-WEAK-PASSWORD-HASH", title="t", severity="high", file="a.py", line=3)
    c = Finding(module="crypto", rule_id="CRYPTO-MD5", title="t", severity="high", file="a.py", line=3,
                extra={"crypto_class": "broken"})
    k = Finding(module="sast", rule_id="PY-HARDCODED-SECRET-KEY", title="t", severity="high", file="b.py", line=1)
    g = Finding(module="secrets", rule_id="generic-secret-assignment", title="t", severity="high", file="b.py", line=1)
    out = merge_colocated([s, c, k, g])
    assert out == [s, k] and s.extra["crypto_class"] == "broken" and priority_for(s)[0] == "P1"
