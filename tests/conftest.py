"""Shared fixtures. The test session uses an isolated data directory and never touches live APIs
(HTTP is mocked with respx in the intel tests; other tests run scans with intel disabled)."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CS_DATA_DIR", tempfile.mkdtemp(prefix="cs-test-data-"))
os.environ.setdefault("CS_LOG_LEVEL", "WARNING")
os.environ["CS_ALLOW_LOCAL_PATHS"] = "true"

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
HEX = "0123456789abcdef"
B64 = ALNUM + "+/"


def rnd(n: int, alphabet: str = ALNUM, seed: str = "t") -> str:
    """Deterministic pseudo-random test string (assembled at runtime, never a real credential)."""
    out, i = "", 0
    while len(out) < n:
        out += "".join(alphabet[b % len(alphabet)] for b in hashlib.sha256(f"{seed}{i}".encode()).digest())
        i += 1
    return out[:n]


def git(repo: Path, *args: str, date: str = "2024-01-01T10:00:00+00:00") -> None:
    """Run git with a fixed identity and no signing/hooks."""
    env = {**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "Test",
           "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
                   check=True, capture_output=True, env=env)


@pytest.fixture(scope="session", autouse=True)
def _db() -> None:
    from app.db import init_db

    init_db()


@pytest.fixture(scope="session")
def demo_repos(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Generate the vulnerable and fixed demo repositories once per session."""
    sys.path.insert(0, str(ROOT / "demo"))
    import make_demo_repo as mdr

    base = tmp_path_factory.mktemp("demo")
    vuln, fixed = base / "vulnerable-shop", base / "vulnerable-shop-fixed"
    gt = mdr.build_vulnerable(vuln)
    mdr.build_fixed(fixed)
    return {"vulnerable": vuln, "fixed": fixed, "ground_truth": gt, "module": mdr}


@pytest.fixture(scope="session")
def offline_reports(demo_repos: dict) -> dict:
    """Scan both demo repos with intel disabled (deterministic, no network)."""
    from app.engine import ScanOptions, run_scan
    from app.ingest import local_target

    return {k: run_scan(local_target(str(demo_repos[k])), ScanOptions(offline=True)) for k in ("vulnerable", "fixed")}
