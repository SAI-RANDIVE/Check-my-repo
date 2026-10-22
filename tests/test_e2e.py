"""End-to-end: the generated demo repositories, the CLI gate, ground truth and secret hygiene."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_vulnerable_shop_fails_and_fixed_passes(offline_reports: dict) -> None:
    v, f = offline_reports["vulnerable"], offline_reports["fixed"]
    assert not v.gate.passed and v.gate.counts["P0"] >= 3
    assert f.gate.passed and f.gate.counts["P0"] == 0 and f.gate.grade in ("A", "B")


def test_ground_truth_fully_detected(offline_reports: dict, demo_repos: dict) -> None:
    found = {(f.rule_id, f.file, f.line, bool(f.extra.get("historical"))) for f in offline_reports["vulnerable"].findings}
    loose = {(f.rule_id, f.file, bool(f.extra.get("historical"))) for f in offline_reports["vulnerable"].findings}
    for g in demo_repos["ground_truth"]["findings"]:
        if g.get("historical"):
            assert (g["rule"], g["file"], True) in loose, g
        else:
            assert (g["rule"], g["file"], g["line"], False) in found, g


def test_decoys_not_flagged(offline_reports: dict, demo_repos: dict) -> None:
    locs = {(f.file, f.line) for f in offline_reports["vulnerable"].findings if f.module != "dependencies"}
    for d in demo_repos["ground_truth"]["decoys"]:
        assert (d["file"], d["line"]) not in locs, d


def test_no_raw_secret_in_report(offline_reports: dict, demo_repos: dict) -> None:
    mdr = demo_repos["module"]
    blob = json.dumps(offline_reports["vulnerable"].to_dict())
    for value in (mdr.AWS_KEY_ID, mdr.AWS_SECRET, mdr.STRIPE_TEST, mdr.STRIPE_LIVE, mdr.STRIPE_DECOY, mdr.DB_PASSWORD,
                  mdr.MAIL_PASSWORD):
        assert value not in blob


def run_cli(target: Path, tmp: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, "-m", "codesentinel", "scan", str(target), "--fail-on", "p0",
                           "--sarif", str(tmp / "r.sarif"), "--sbom", str(tmp / "s.json")],
                          cwd=ROOT, capture_output=True, text=True, encoding="utf-8", env=env, timeout=600)


@pytest.mark.skipif(os.environ.get("CS_LIVE_TESTS") != "1", reason="set CS_LIVE_TESTS=1 to run against live OSV/EPSS/KEV")
def test_cli_live_gate(demo_repos: dict, tmp_path: Path) -> None:
    bad = run_cli(demo_repos["vulnerable"], tmp_path)
    assert bad.returncode == 1, bad.stdout + bad.stderr
    assert "CISA KEV" in bad.stdout and "History-only secrets" in bad.stdout
    good = run_cli(demo_repos["fixed"], tmp_path)
    assert good.returncode == 0, good.stdout + good.stderr
    sarif = json.loads((tmp_path / "r.sarif").read_text())
    assert sarif["version"] == "2.1.0"
