"""Shared data structures and file utilities used by every scanner module."""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "site-packages", "bower_components", ".gradle", ".idea", "target",
}
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz", ".pdf", ".zip", ".gz", ".tgz", ".bz2",
    ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".pyc",
    ".pyo", ".whl", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav",
    ".ogg", ".webm", ".psd", ".sqlite", ".db", ".bin", ".dat", ".pkl", ".npy", ".h5", ".onnx", ".pt",
}
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "packages.lock.json", "uv.lock",
}
TEST_PATH_MARKERS = ("/tests/", "/test/", "/__tests__/", "/spec/", "/testdata/", "/fixtures/")

CWE_URL = "https://cwe.mitre.org/data/definitions/{n}.html"
OWASP_URLS = {
    "A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}
OWASP_NAMES = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}


def cwe_url(cwe: str | None) -> str | None:
    """Return the MITRE URL for a ``CWE-123`` identifier."""
    if not cwe or not cwe.upper().startswith("CWE-"):
        return None
    return CWE_URL.format(n=cwe.split("-", 1)[1])


@dataclass
class Finding:
    """A normalised security finding produced by any module."""

    module: str  # secrets | dependencies | sast | iac | crypto
    rule_id: str
    title: str
    severity: str
    file: str = ""
    line: int | None = None
    description: str = ""
    remediation: str = ""
    secure_example: str = ""
    cwe: str | None = None
    owasp: str | None = None  # "A03"
    snippet: list[dict[str, Any]] = field(default_factory=list)
    tainted: bool = False
    confidence: str = "high"
    references: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    # set by scoring / policy
    priority: str = "P3"
    risk_score: float = 0.0
    status: str = "open"
    justification: str | None = None
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        """Stable identity used for de-duplication and scan-to-scan diffs.

        Line numbers are deliberately excluded so that a finding survives
        unrelated edits that shift it up or down the file.
        """
        key = self.extra.get("fp_key")
        if not key:
            hit = next((s["text"] for s in self.snippet if s.get("hit")), "")
            key = " ".join(hit.split())
        raw = f"{self.module}|{self.rule_id}|{self.file}|{key}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()
        return self.fingerprint

    @property
    def owasp_name(self) -> str | None:
        """Full OWASP Top 10:2021 category name."""
        return OWASP_NAMES.get(self.owasp or "")

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dict (secrets are already redacted)."""
        d = asdict(self)
        d["cwe_url"] = cwe_url(self.cwe)
        d["owasp_name"] = self.owasp_name
        d["owasp_url"] = OWASP_URLS.get(self.owasp or "")
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        """Inverse of :meth:`to_dict`."""
        names = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in names})


@dataclass
class Component:
    """A dependency discovered in a manifest or lockfile."""

    name: str
    version: str
    ecosystem: str  # PyPI | npm | Maven | Go
    purl: str
    file: str
    line: int | None = None
    direct: bool = True
    scope: str = "required"  # required | optional
    version_inferred: bool = False
    license: str | None = None
    dependencies: list[str] = field(default_factory=list)  # purls
    vuln_count: int = 0

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity tuple (ecosystem, name, version)."""
        return (self.ecosystem, self.name, self.version)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Component:
        """Inverse of :meth:`to_dict`."""
        names = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in names})


@dataclass
class CryptoAsset:
    """A single occurrence of cryptography usage (one CBOM evidence entry)."""

    name: str  # e.g. "AES-128-ECB", "RSA-1024", "MD5"
    family: str  # AES, RSA, MD5, TLS ...
    primitive: str  # CycloneDX primitive: hash, block-cipher, pke, signature, kdf, drbg, ...
    asset_type: str  # algorithm | protocol
    classification: str  # approved | weak | broken
    file: str
    line: int
    language: str
    mode: str | None = None
    parameter: str | None = None  # key size / curve / iteration count
    crypto_functions: list[str] = field(default_factory=list)
    quantum_vulnerable: bool = False
    nist_quantum_level: int | None = None
    classical_level: int | None = None
    library: str | None = None
    reason: str = ""
    security_context: bool = False
    snippet: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CryptoAsset:
        """Inverse of :meth:`to_dict`."""
        names = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in names})


# --------------------------------------------------------------------------- files


def is_test_path(rel: str) -> bool:
    """Heuristic: does this path belong to tests/fixtures (lower exposure)?"""
    p = "/" + rel.replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    return (
        any(m in p for m in TEST_PATH_MARKERS)
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts", "_test.go"))
    )


def matches_any(rel: str, patterns: list[str]) -> bool:
    """True when ``rel`` matches any glob in ``patterns`` (``dir/**`` supported)."""
    rel = rel.replace("\\", "/")
    for pat in patterns:
        pat = pat.strip().replace("\\", "/").lstrip("./")
        if not pat:
            continue
        if fnmatch.fnmatch(rel, pat) or (pat.endswith("/**") and rel.startswith(pat[:-3] + "/")):
            return True
        if "/" not in pat and fnmatch.fnmatch(rel.rsplit("/", 1)[-1], pat):
            return True
        if rel.startswith(pat.rstrip("/") + "/"):
            return True
    return False


def _git_listed_files(root: Path) -> list[str] | None:
    """Tracked + untracked-but-not-ignored files when ``root`` is a git work tree."""
    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, timeout=60, check=True,
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("git ls-files failed (%s); falling back to directory walk", exc)
        return None
    files = sorted({p for p in out.split("\0") if p})
    return [f for f in files if (root / f).is_file()]


def list_files(root: Path, ignore: list[str] | None = None) -> list[str]:
    """List candidate source files below ``root`` as POSIX relative paths.

    For git repositories the list honours ``.gitignore`` (an ignored local
    ``.env`` is not "in the repository"). Vendored and dependency directories
    are always skipped.
    """
    ignore = ignore or []
    listed = _git_listed_files(root)
    if listed is None:
        listed = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                full = Path(dirpath) / fn
                if full.is_symlink():
                    continue
                listed.append(full.relative_to(root).as_posix())
    result = []
    for rel in listed:
        parts = rel.split("/")
        if any(p in SKIP_DIRS for p in parts[:-1]):
            continue
        if ignore and matches_any(rel, ignore):
            continue
        result.append(rel)
    return sorted(result)


def is_binary_path(rel: str) -> bool:
    """True for file extensions that are never text."""
    return Path(rel).suffix.lower() in BINARY_EXTS


def read_text(path: Path, max_bytes: int = 1_000_000) -> str | None:
    """Read a text file; return None for binaries, oversized or unreadable files."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def make_snippet(lines: list[str], line_no: int | None, context: int = 3) -> list[dict[str, Any]]:
    """Return ``context`` lines either side of ``line_no`` with secrets redacted."""
    from app.scanners.secrets import redact_text  # local import avoids a cycle

    if not line_no or line_no < 1 or not lines:
        return []
    start = max(1, line_no - context)
    end = min(len(lines), line_no + context)
    out = []
    for n in range(start, end + 1):
        text = lines[n - 1].rstrip("\r\n")
        if len(text) > 400:
            text = text[:400] + " …"
        out.append({"n": n, "text": redact_text(text), "hit": n == line_no})
    return out
