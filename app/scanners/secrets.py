"""Module 1: secret detection in the working tree and in git history.

Detection layers, applied per line:

1. Provider signatures: fixed-format credentials (AWS, GitHub, Stripe, ...).
2. Generic assignments: ``password = "..."`` style key/value pairs.
3. Shannon entropy: long random-looking strings on lines that mention a
   credential keyword.

Raw secret values never leave this module. Each hit is reduced to a SHA-256
fingerprint and a redacted preview (first 4 + ``****`` + last 4) before a
``Finding`` is built, and snippets pass through :func:`redact_text`.
Secrets are never validated against provider APIs.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings
from app.scanners.base import (
    BINARY_EXTS,
    LOCKFILES,
    SKIP_DIRS,
    Finding,
    make_snippet,
    matches_any,
    read_text,
)

log = logging.getLogger(__name__)

IGNORE_MARKER = "codesentinel:ignore"


@dataclass(frozen=True)
class SecretRule:
    """A provider-specific secret signature."""

    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str
    group: int = 0
    live_format: bool = True
    keywords: tuple[str, ...] = ()
    min_entropy: float = 0.0


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


RULES: list[SecretRule] = [
    SecretRule("aws-access-key-id", "AWS access key ID", _r(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b"), "critical", 1),
    SecretRule("aws-secret-access-key", "AWS secret access key",
               _r(r"(?i)aws.{0,25}?(?:secret|private)?.{0,10}?['\"=:\s]\s*['\"]?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
               "critical", 1, keywords=("aws",), min_entropy=4.0),
    SecretRule("github-pat", "GitHub personal access token", _r(r"\b(ghp_[A-Za-z0-9]{36})\b"), "critical", 1),
    SecretRule("github-oauth-token", "GitHub OAuth access token", _r(r"\b(gho_[A-Za-z0-9]{36})\b"), "critical", 1),
    SecretRule("github-app-token", "GitHub app/server token", _r(r"\b((?:ghs|ghu)_[A-Za-z0-9]{36})\b"), "critical", 1),
    SecretRule("github-fine-grained-pat", "GitHub fine-grained token", _r(r"\b(github_pat_[A-Za-z0-9_]{82})\b"), "critical", 1),
    SecretRule("gitlab-pat", "GitLab personal access token", _r(r"\b(glpat-[A-Za-z0-9_\-]{20})\b"), "critical", 1),
    SecretRule("slack-token", "Slack token", _r(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,72})\b"), "high", 1),
    SecretRule("slack-webhook", "Slack incoming webhook",
               _r(r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24})"), "high", 1),
    SecretRule("stripe-live-key", "Stripe live secret/restricted key", _r(r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,99})\b"), "critical", 1),
    SecretRule("stripe-test-key", "Stripe test-mode secret key", _r(r"\b((?:sk|rk)_test_[A-Za-z0-9]{24,99})\b"), "medium", 1,
               live_format=False),
    SecretRule("google-api-key", "Google API key", _r(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), "high", 1),
    SecretRule("twilio-api-key", "Twilio API key SID", _r(r"\b(SK[0-9a-f]{32})\b"), "high", 1),
    SecretRule("twilio-auth-token", "Twilio auth token",
               _r(r"(?i)twilio.{0,30}?['\"=:\s]\s*['\"]?([0-9a-f]{32})\b"), "high", 1, keywords=("twilio",)),
    SecretRule("sendgrid-api-key", "SendGrid API key", _r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), "high", 1),
    SecretRule("anthropic-api-key", "Anthropic API key", _r(r"\b(sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,120})"), "critical", 1),
    SecretRule("openai-api-key", "OpenAI-style API key",
               _r(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{48})\b"),
               "high", 1),
    SecretRule("razorpay-live-key", "Razorpay live key ID", _r(r"\b(rzp_live_[A-Za-z0-9]{14})\b"), "critical", 1),
    SecretRule("npm-token", "npm access token", _r(r"\b(npm_[A-Za-z0-9]{36})\b"), "critical", 1),
    SecretRule("pypi-token", "PyPI upload token", _r(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"), "critical", 1),
    SecretRule("telegram-bot-token", "Telegram bot token", _r(r"\b(\d{8,10}:AA[0-9A-Za-z_\-]{33})\b"), "high", 1),
    SecretRule("discord-webhook", "Discord webhook URL",
               _r(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,})"), "high", 1),
    SecretRule("azure-storage-key", "Azure storage account key",
               _r(r"AccountKey=([A-Za-z0-9+/]{86}==)"), "critical", 1),
    SecretRule("jwt", "JSON Web Token",
               _r(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), "medium", 1, live_format=False),
    SecretRule("private-key", "Private key (PEM)",
               _r(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), "critical", 1),
    SecretRule("db-connection-string", "Database URI with inline password",
               _r(r"\b(?:postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mssql)://[^\s:/@'\"]+:([^\s@'\"/]{3,})@[^\s'\"]+"),
               "high", 1),
    SecretRule("mongodb-connection-string", "MongoDB URI with inline password",
               _r(r"\bmongodb(?:\+srv)?://[^\s:/@'\"]+:([^\s@'\"/]{3,})@[^\s'\"]+"), "high", 1),
]
RULES_BY_ID = {r.id: r for r in RULES}
# One cheap pass decides whether any provider signature can possibly match the line.
PROVIDER_HINT = re.compile(
    r"AKIA|ASIA|gh[pousr]_|github_pat_|glpat-|xox[baprs]-|hooks\.slack|[sr]k_(?:live|test)_|AIza|SK[0-9a-f]{32}|"
    r"[Tt][Ww][Ii][Ll][Ii][Oo]|SG\.|sk-|rzp_live_|npm_|pypi-|:AA|discord|AccountKey=|eyJ|PRIVATE KEY|"
    r"://[^\s:/@'\"]+:[^\s@'\"/]+@|[Aa][Ww][Ss]"
)

GENERIC_RULE_ID = "generic-secret-assignment"
ENTROPY_RULE_ID = "high-entropy-string"
ALL_RULE_IDS = [r.id for r in RULES] + [GENERIC_RULE_ID, ENTROPY_RULE_ID]

_KEY_WORDS = r"(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token|access[_\-]?token|token|client[_\-]?secret|private[_\-]?key|credentials?)"
GENERIC_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.\-])(?P<key>[A-Za-z0-9_.\-]{0,40}?" + _KEY_WORDS + r"[A-Za-z0-9_\-]{0,40})[\"']?\s*(?:=|:=|:|=>)\s*"
    r"(?P<q>[\"'`])(?P<val>[^\"'`\s]{8,200})(?P=q)"
)
DOTENV_RE = re.compile(r"(?i)^\s*(?:export\s+)?(?P<key>[A-Za-z0-9_.\-]{0,40}?" + _KEY_WORDS + r"[A-Za-z0-9_\-]{0,40})\s*[=:]\s*(?P<val>[^\s#'\"]{8,200})")
KEY_SUFFIX_EXCLUDE = re.compile(
    r"(?i)(?:_name|_field|_path|_file|_url|_uri|_type|_header|_param|_label|_placeholder|_regex|_pattern|_policy|"
    r"_length|_len|_min|_max|_id|_env|_var|_prefix|_endpoint|_expiry|_ttl|_timeout|_count|_hint|address|_addr)$"
)
UI_KEY = re.compile(r"(?i)(label|title|text|msg|message|tooltip|hint|error|placeholder|button|header|description|"
                    r"caption|heading|prompt|_link|_url)")
KEYWORD_PREFILTER = re.compile(r"(?i)pass|pwd|secret|api|key|token|credential")
LOCALE_PATH = re.compile(r"(?i)(^|/)(i18n|l10n|locales?|lang|languages|translations)/")
QUOTED_RE = re.compile(r"(?P<q>[\"'`])(?P<val>[A-Za-z0-9+/=_\-.]{20,500})(?P=q)")
UNQUOTED_VALUE_RE = re.compile(r"[=:]\s*(?P<val>[A-Za-z0-9+/=_\-.]{20,500})\s*$")
CONTEXT_WORDS = ("key", "secret", "token", "passw", "pwd", "auth", "credential", "api", "private", "signature", "bearer")
HEX_CHARS = set("0123456789abcdefABCDEF")
B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-.")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
LONG_B64_LINE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/])")

PLACEHOLDER_MARKERS = (
    "example", "xxxx", "changeme", "change_me", "change-me", "your_", "your-", "yourkey", "your_api_key", "dummy",
    "placeholder", "sample", "redacted", "insert", "replace", "todo", "fixme", "notreal", "not_real", "fake",
    "<", ">", "{{", "${", "%(", "****", "...", "secret_here", "key_here", "token_here",
)
SEQUENTIAL = ("0123456789", "123456789", "abcdefghij", "abcdef123")


def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits per character: H = -sum(p_i * log2 p_i)."""
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    """True for documentation/example values such as ``AKIAIOSFODNN7EXAMPLE``."""
    v = value.lower()
    if any(m in v for m in PLACEHOLDER_MARKERS):
        return True
    if any(s in v for s in SEQUENTIAL):
        return True
    core = re.sub(r"^(?:sk|rk)_(?:live|test)_|^(?:ghp|gho|ghs|ghu|npm|glpat)[_-]|^(?:akia|asia)", "", v)
    return len(set(core)) <= 3


def fingerprint(value: str) -> str:
    """SHA-256 fingerprint of a secret value (the only form ever stored)."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def redact(value: str) -> str:
    """Redacted preview: first 4 + ``****`` + last 4 (shorter values reveal less)."""
    if len(value) >= 16:
        return f"{value[:4]}****{value[-4:]}"
    if len(value) >= 8:
        return f"{value[:2]}****"
    return "****"


@dataclass
class SecretHit:
    """A raw detection on a single line (value kept only transiently)."""

    rule_id: str
    name: str
    severity: str
    value: str
    start: int
    end: int
    live_format: bool
    placeholder: bool
    entropy: float


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < e and end > s for s, e in spans)


def _entropy_ok(val: str, cfg_b64: float, cfg_hex: float, min_len: int) -> tuple[bool, float]:
    if len(val) < min_len:
        return False, 0.0
    low = val.lower()
    if low.startswith(("sha1-", "sha256-", "sha384-", "sha512-")) or UUID_RE.match(val):
        return False, 0.0
    if "/" in val and val.count("/") >= 3 and not any(c in val for c in "+="):  # looks like a path
        return False, 0.0
    if re.fullmatch(r"[a-z_.\-]+", val) or re.fullmatch(r"[A-Z_.\-]+", val):  # identifiers / constants
        return False, 0.0
    ent = shannon_entropy(val)
    if set(val) <= HEX_CHARS:
        return ent >= cfg_hex, ent
    if set(val) <= B64_CHARS:
        return ent >= cfg_b64, ent
    return False, ent


def detect_line(line: str, is_dotenv: bool = False, honour_ignore: bool = True,
                provider_only: bool = False) -> list[SecretHit]:
    """Run every detector over a single line and return non-overlapping hits."""
    if honour_ignore and IGNORE_MARKER in line:
        return []
    if len(line) > 5000:
        line = line[:5000]
    cfg = get_settings()
    hits: list[SecretHit] = []
    spans: list[tuple[int, int]] = []
    low = line.lower()
    for rule in RULES if PROVIDER_HINT.search(line) else []:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        for m in rule.pattern.finditer(line):
            val = m.group(rule.group)
            s, e = m.span(rule.group)
            if _overlaps(s, e, spans):
                continue
            ent = shannon_entropy(val)
            if rule.min_entropy and ent < rule.min_entropy and not is_placeholder(val):
                continue
            spans.append((s, e))
            hits.append(SecretHit(rule.id, rule.name, rule.severity, val, s, e, rule.live_format,
                                  is_placeholder(val), ent))
    if provider_only:
        return hits
    # generic key = "value" assignments
    generic = [GENERIC_RE, DOTENV_RE] if is_dotenv else [GENERIC_RE]
    for regex in generic if KEYWORD_PREFILTER.search(line) else []:
        for m in regex.finditer(line):
            key, val = m.group("key"), m.group("val")
            s, e = m.span("val")
            if _overlaps(s, e, spans) or KEY_SUFFIX_EXCLUDE.search(key) or UI_KEY.search(key):
                continue
            if val.isalpha() and not (len(val) >= 20 and shannon_entropy(val) >= 3.8):
                continue  # a single dictionary word (UI text, translations) is not a credential
            if val.startswith(("$", "%", "{", "os.environ", "process.env")) or val.lower() == key.lower():
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*\(.*", val):  # function call
                continue
            ent = shannon_entropy(val)
            placeholder = is_placeholder(val)
            has_mixed = bool(re.search(r"\d", val)) or bool(re.search(r"[^A-Za-z0-9]", val))
            if not placeholder and not has_mixed and ent < 3.0:
                continue
            spans.append((s, e))
            hits.append(SecretHit(GENERIC_RULE_ID, "Hard-coded credential assignment", "high", val, s, e,
                                  False, placeholder, ent))
    # entropy with keyword context
    if any(w in low for w in CONTEXT_WORDS):
        candidates = list(QUOTED_RE.finditer(line))
        if is_dotenv:
            candidates += list(UNQUOTED_VALUE_RE.finditer(line))
        for m in candidates:
            val = m.group("val")
            s, e = m.span("val")
            if _overlaps(s, e, spans):
                continue
            ok, ent = _entropy_ok(val, cfg.entropy_base64_threshold, cfg.entropy_hex_threshold, cfg.entropy_min_length)
            if not ok or is_placeholder(val):
                continue
            spans.append((s, e))
            hits.append(SecretHit(ENTROPY_RULE_ID, "High-entropy string near a credential keyword", "medium",
                                  val, s, e, False, False, ent))
    return hits


def redact_text(text: str) -> str:
    """Mask every secret-looking value inside ``text`` (used for all snippets)."""
    hits = detect_line(text, is_dotenv=True, honour_ignore=False)
    out = text
    for h in sorted(hits, key=lambda h: h.start, reverse=True):
        out = out[: h.start] + redact(h.value) + out[h.end :]
    # Safety net for key material without keywords (PEM bodies, base64 blobs).
    return LONG_B64_LINE.sub(lambda m: redact(m.group(0)) if shannon_entropy(m.group(0)) >= 4.0 else m.group(0), out)


def should_scan(rel: str) -> bool:
    """Apply the secret-scanner file filters (lockfiles, minified, vendored...)."""
    name = rel.rsplit("/", 1)[-1]
    if name in LOCKFILES or name.endswith((".min.js", ".min.css", ".map", ".svg")):
        return False
    if any(p in SKIP_DIRS for p in rel.split("/")[:-1]):
        return False
    return "." + name.rsplit(".", 1)[-1].lower() not in BINARY_EXTS if "." in name else True


def _is_dotenv(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    return name.startswith(".env") or name.endswith((".env", ".properties", ".ini", ".cfg", ".conf"))


@dataclass
class _Occurrence:
    hit: SecretHit
    file: str
    line: int
    commit: str | None = None
    commit_date: str | None = None


REMEDIATION = (
    "1. Revoke or rotate this credential at the provider now. Deleting it from the code does not invalidate it.\n"
    "2. Remove the literal from source and load it at runtime from an environment variable or a secret manager "
    "(AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets).\n"
    "3. If the value was ever pushed, assume it is compromised and purge it from history with `git filter-repo` "
    "or BFG, then force-push and ask collaborators to re-clone.\n"
    "4. Add a pre-commit secret scan (this tool, gitleaks or GitHub push protection) so it cannot recur."
)
SECURE_EXAMPLE = (
    "import os\n\n"
    "# Before: STRIPE_KEY = \"sk_live_...\"\n"
    "STRIPE_KEY = os.environ[\"STRIPE_KEY\"]  # injected by the runtime / secret manager\n"
)


def _article(name: str) -> str:
    return "An" if name[:1].upper() in "AEIOU" else "A"


def _make_finding(occ: _Occurrence, lines: list[str] | None, historical: bool, other_locations: list[str]) -> Finding:
    h = occ.hit
    fp = fingerprint(h.value)
    preview = redact(h.value)
    if h.placeholder:
        title = f"Placeholder {h.name.lower()} (info)"
        severity = "info"
        desc = (f"A value in the format of a {h.name} was found, but it looks like a documentation or example "
                f"placeholder ({preview}). It is reported for awareness only.")
    elif historical:
        title = f"{h.name} in git history (deleted from HEAD)"
        severity = h.severity if h.severity in ("critical", "high") else "high"
        desc = (f"{_article(h.name)} {h.name} ({preview}) was committed in {occ.commit[:10] if occ.commit else '?'} "
                f"on {occ.commit_date or '?'} and later removed from the working tree. Removing a secret does "
                f"not revoke it: anyone with a clone or fork can still read it from history. GitGuardian found "
                f"that about 70% of secrets leaked in 2022 were still valid two years later.")
    else:
        title = f"{h.name} committed to source"
        severity = h.severity
        desc = f"{_article(h.name)} {h.name} ({preview}) is present in the current tree. Anyone with read access to the repository can use it."
    snippet = make_snippet(lines, occ.line) if lines else [{"n": occ.line, "text": redact_text(lines_hit_text(occ)), "hit": True}]
    return Finding(
        module="secrets", rule_id=h.rule_id, title=title, severity=severity, file=occ.file, line=occ.line,
        description=desc, remediation=REMEDIATION if not h.placeholder else
        "Confirm the value is a non-functional example. If it is, leave it or add `codesentinel:ignore` on the line.",
        secure_example=SECURE_EXAMPLE, cwe="CWE-798", owasp="A07", snippet=snippet,
        confidence="high" if h.rule_id not in (GENERIC_RULE_ID, ENTROPY_RULE_ID) else "medium",
        references=["https://cwe.mitre.org/data/definitions/798.html",
                    "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"],
        extra={
            "fp_key": fp, "secret_fingerprint": fp, "redacted": preview, "historical": historical,
            "placeholder": h.placeholder, "live_format": h.live_format and not h.placeholder,
            "entropy": round(h.entropy, 2), "commit": occ.commit, "commit_date": occ.commit_date,
            "location": "history" if historical else "HEAD", "other_locations": other_locations,
        },
    )


def lines_hit_text(occ: _Occurrence) -> str:
    """Rebuild a redacted single-line context for a history hit."""
    return occ.hit.value and ("…" + redact(occ.hit.value) + "…")


def scan_tree(root: Path, files: list[str]) -> tuple[list[_Occurrence], dict[str, list[str]]]:
    """Scan current files; return occurrences and the file lines (for snippets)."""
    cfg = get_settings()
    occs: list[_Occurrence] = []
    file_lines: dict[str, list[str]] = {}
    for rel in files:
        if not should_scan(rel):
            continue
        text = read_text(root / rel, cfg.max_file_bytes)
        if text is None:
            continue
        dotenv = _is_dotenv(rel)
        locale = bool(LOCALE_PATH.search(rel))
        lines = text.splitlines()
        found = False
        for i, line in enumerate(lines, 1):
            for hit in detect_line(line, is_dotenv=dotenv, provider_only=locale):
                occs.append(_Occurrence(hit, rel, i))
                found = True
        if found:
            file_lines[rel] = lines
    return occs, file_lines


def iter_history(root: Path, max_commits: int, ignore: list[str]) -> Iterator[_Occurrence]:
    """Stream ``git log -p`` and yield secret hits on added lines of every commit."""
    cmd = ["git", "-C", str(root), "-c", "core.quotepath=false", "log", "-p", "--no-color", "--no-ext-diff",
           "--unified=0", "--diff-filter=AM", "-n", str(max_commits), "--format=%x01CS%x01%H%x01%aI"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        log.warning("history scan unavailable: %s", exc)
        return
    assert proc.stdout is not None
    commit = date = None
    path: str | None = None
    lineno = 0
    hunk = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
            if line.startswith("\x01CS\x01"):
                _, _, commit, date = line.split("\x01", 3)
                path = None
                continue
            if line.startswith("+++ "):
                p = line[4:]
                path = p[2:] if p.startswith("b/") else None
                if path and (not should_scan(path) or (ignore and matches_any(path, ignore))):
                    path = None
                continue
            if line.startswith("@@"):
                m = hunk.match(line)
                lineno = int(m.group(1)) if m else 0
                continue
            if path and line.startswith("+") and not line.startswith("+++"):
                text = line[1:]
                for hit in detect_line(text, is_dotenv=_is_dotenv(path), provider_only=bool(LOCALE_PATH.search(path))):
                    yield _Occurrence(hit, path, lineno, commit, (date or "")[:10])
                lineno += 1
    finally:
        proc.stdout.close()
        proc.wait(timeout=60)


def _file_at_commit(root: Path, commit: str, path: str) -> list[str] | None:
    try:
        out = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{path}"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8", "replace").splitlines()


def scan_secrets(root: Path, files: list[str], include_history: bool = False, is_git: bool = False,
                 ignore: list[str] | None = None,
                 on_history: Callable[[], None] | None = None) -> tuple[list[Finding], dict[str, int]]:
    """Scan HEAD (and optionally history) and return de-duplicated findings.

    De-duplication is by secret fingerprint: one finding per distinct secret,
    with any further locations listed in ``extra.other_locations``. A secret
    seen only in history becomes a ``historical`` finding pinned to the commit
    that introduced it.
    """
    head_occs, file_lines = scan_tree(root, files)
    by_fp: dict[str, list[_Occurrence]] = {}
    for o in head_occs:
        by_fp.setdefault(fingerprint(o.hit.value), []).append(o)
    findings: list[Finding] = []
    first_seen: dict[str, _Occurrence] = {}
    hist_only: dict[str, _Occurrence] = {}
    commits_scanned = 0
    if include_history and is_git:
        if on_history:
            on_history()
        for occ in iter_history(root, get_settings().history_max_commits, ignore or []):
            fp = fingerprint(occ.hit.value)
            if fp in by_fp:
                first_seen[fp] = occ  # log is newest-first; last write = oldest commit
            elif not occ.hit.placeholder:
                hist_only[fp] = occ
        try:
            commits_scanned = int(subprocess.run(
                ["git", "-C", str(root), "rev-list", "--count", "HEAD"], capture_output=True, text=True, timeout=30
            ).stdout.strip() or 0)
        except (OSError, subprocess.SubprocessError, ValueError):
            commits_scanned = 0
        commits_scanned = min(commits_scanned, get_settings().history_max_commits)
    for fp, occs in by_fp.items():
        primary = occs[0]
        others = [f"{o.file}:{o.line}" for o in occs[1:]]
        f = _make_finding(primary, file_lines.get(primary.file), False, others)
        if fp in first_seen:
            f.extra["introduced_in"] = first_seen[fp].commit
            f.extra["introduced_on"] = first_seen[fp].commit_date
        findings.append(f)
    for occ in hist_only.values():
        lines = _file_at_commit(root, occ.commit, occ.file) if occ.commit else None
        findings.append(_make_finding(occ, lines, True, []))
    stats = {
        "secrets_head": sum(1 for f in findings if not f.extra["historical"] and not f.extra["placeholder"]),
        "secrets_history": sum(1 for f in findings if f.extra["historical"]),
        "secrets_placeholder": sum(1 for f in findings if f.extra["placeholder"]),
        "commits_scanned": commits_scanned,
    }
    return findings, stats
