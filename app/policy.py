"""Repository policy file: ``.codesentinel.yml``.

Example::

    fail_on: p1                    # gate level for this repository
    ignore_paths:
      - docs/**
      - tests/fixtures/**
    suppressions:
      - rule: PY-DEBUG-ENABLED
        path: app/dev_server.py    # optional; omit to apply repository-wide
        justification: Local-only development entry point, never deployed.
        expires: 2026-12-31        # mandatory; expired entries stop applying

A suppression without a justification or an expiry date is rejected (and
reported in ``policy.errors``). Once a suppression expires, its findings come
back as open, so accepted risk has to be reviewed on a schedule.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from app.scanners.base import Finding, matches_any

log = logging.getLogger(__name__)
POLICY_FILES = (".codesentinel.yml", ".codesentinel.yaml")
GATE_LEVELS = ("p0", "p1", "p2")


@dataclass
class Suppression:
    """One rule suppression."""

    rule: str
    justification: str
    expires: date
    path: str | None = None

    def matches(self, f: Finding) -> bool:
        """True when this suppression applies to the finding."""
        if self.rule not in (f.rule_id, "*"):
            return False
        return self.path is None or matches_any(f.file, [self.path])


@dataclass
class Policy:
    """Parsed repository policy."""

    fail_on: str | None = None
    ignore_paths: list[str] = field(default_factory=list)
    suppressions: list[Suppression] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source: str | None = None


def _to_date(v: object) -> date | None:
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v))
    except ValueError:
        return None


def load_policy(root: Path) -> Policy:
    """Load ``.codesentinel.yml`` from the target root (missing file = empty policy)."""
    for name in POLICY_FILES:
        p = root / name
        if p.is_file():
            break
    else:
        return Policy()
    pol = Policy(source=name)
    try:
        data = yaml.safe_load(p.read_text("utf-8")) or {}
    except (yaml.YAMLError, OSError) as exc:
        pol.errors.append(f"{name}: could not parse ({exc})")
        return pol
    if not isinstance(data, dict):
        pol.errors.append(f"{name}: top level must be a mapping")
        return pol
    fail_on = str(data.get("fail_on", "")).lower() or None
    if fail_on and fail_on not in GATE_LEVELS:
        pol.errors.append(f"fail_on must be one of {GATE_LEVELS}, got {fail_on!r}")
        fail_on = None
    pol.fail_on = fail_on
    pol.ignore_paths = [str(x) for x in data.get("ignore_paths", []) or []]
    for i, s in enumerate(data.get("suppressions", []) or []):
        if not isinstance(s, dict) or not s.get("rule"):
            pol.errors.append(f"suppressions[{i}]: 'rule' is required")
            continue
        just = str(s.get("justification") or "").strip()
        exp = _to_date(s.get("expires"))
        if not just:
            pol.errors.append(f"suppressions[{i}] ({s['rule']}): a justification is mandatory; suppression ignored")
            continue
        if exp is None:
            pol.errors.append(f"suppressions[{i}] ({s['rule']}): an expiry date (YYYY-MM-DD) is mandatory; suppression ignored")
            continue
        pol.suppressions.append(Suppression(str(s["rule"]), just, exp, s.get("path")))
    return pol


def apply_suppressions(findings: list[Finding], policy: Policy, today: date | None = None) -> None:
    """Mark findings ``suppressed`` (or note an expired suppression) in place."""
    today = today or date.today()
    for f in findings:
        for s in policy.suppressions:
            if not s.matches(f):
                continue
            if s.expires >= today:
                f.status = "suppressed"
                f.justification = f"{s.justification} (suppressed until {s.expires.isoformat()} via {policy.source})"
            else:
                f.extra["suppression_expired"] = s.expires.isoformat()
                f.justification = f"Suppression expired on {s.expires.isoformat()}; finding resurfaced. Original reason: {s.justification}"
            break
