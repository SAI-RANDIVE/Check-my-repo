"""Target ingestion: clone a GitHub URL, extract an uploaded zip, or use a local path.

Safety properties:

* clones run with a hard timeout and a size cap and land in a private temp dir;
* zip extraction rejects path traversal ("zip-slip"), symlinks and zip bombs;
* nothing from the target is ever executed: no hooks, no install scripts,
  no builds. Files are only read.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import httpx

from app.config import Settings, get_settings

log = logging.getLogger(__name__)

GITHUB_URL_RE = re.compile(r"^https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")


class IngestError(Exception):
    """Raised when a target cannot be ingested safely."""


@dataclass
class Target:
    """A materialised scan target on local disk."""

    root: Path
    label: str
    source: str
    source_type: str  # url | zip | path
    is_git: bool = False
    commit_sha: str | None = None
    branch: str | None = None
    _temp_dirs: list[Path] = field(default_factory=list)

    def cleanup(self) -> None:
        """Delete any temporary directories created for this target."""
        for d in self._temp_dirs:
            remove_tree(d)
        self._temp_dirs.clear()

    def __enter__(self) -> Target:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()


def _on_rm_error(func, path, _exc) -> None:  # type: ignore[no-untyped-def]
    # git marks pack files read-only on Windows; make them writable and retry.
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        log.warning("could not remove %s", path)


def remove_tree(path: Path) -> None:
    """Robust recursive delete that copes with read-only git objects on Windows."""
    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_on_rm_error)
    else:  # Python 3.11 (the Docker image) only has `onerror`
        shutil.rmtree(path, onerror=lambda f, p, e: _on_rm_error(f, p, e))


def dir_size_bytes(path: Path) -> int:
    """Total size of regular files below ``path``."""
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            with contextlib.suppress(OSError):
                total += (Path(dirpath) / f).lstat().st_size
    return total


def validate_github_url(url: str) -> tuple[str, str]:
    """Validate ``https://github.com/owner/repo`` and return ``(owner, repo)``."""
    m = GITHUB_URL_RE.match(url.strip())
    if not m:
        raise IngestError("Only public GitHub repository URLs of the form https://github.com/owner/repo are accepted.")
    return m.group(1), m.group(2)


def _git_info(root: Path) -> tuple[str | None, str | None]:
    def run(*args: str) -> str | None:
        try:
            return subprocess.run(
                ["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30, check=True
            ).stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            return None

    return run("rev-parse", "HEAD"), run("rev-parse", "--abbrev-ref", "HEAD")


def _github_size_precheck(owner: str, repo: str, settings: Settings) -> None:
    """Best-effort size check using the GitHub REST API before cloning."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "CodeSentinel"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    try:
        r = httpx.get(f"{settings.github_api_url}/repos/{owner}/{repo}", headers=headers, timeout=10)
    except httpx.HTTPError as exc:
        log.info("GitHub size pre-check skipped: %s", exc)
        return
    if r.status_code == 404:
        raise IngestError(f"Repository {owner}/{repo} was not found or is private.")
    if r.status_code != 200:
        return
    size_mb = r.json().get("size", 0) / 1024
    if size_mb > settings.max_repo_mb * 2:
        # API size includes all history; HEAD-only clones are usually much smaller.
        raise IngestError(f"Repository is about {size_mb:.0f} MB, above the {settings.max_repo_mb} MB limit.")


def clone_repo(url: str, include_history: bool = True, settings: Settings | None = None) -> Target:
    """Clone a public GitHub repository into a temporary directory.

    Without history the clone is shallow (depth 1). With history the depth is
    capped at ``history_max_commits`` so that history scanning has exactly the
    commits it is allowed to walk and no more.
    """
    settings = settings or get_settings()
    owner, repo = validate_github_url(url)
    _github_size_precheck(owner, repo, settings)
    tmp = Path(tempfile.mkdtemp(prefix="cs-clone-"))
    dest = tmp / repo
    depth = settings.history_max_commits + 1 if include_history else 1
    cmd = [
        "git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "core.symlinks=false",
        "clone", "--quiet", "--no-tags", "--single-branch", "--depth", str(depth),
        f"https://github.com/{owner}/{repo}.git", str(dest),
    ]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "echo"}
    log.info("cloning %s/%s (depth=%s)", owner, repo, depth)
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=settings.clone_timeout_seconds, env=env)
    except subprocess.TimeoutExpired as exc:
        remove_tree(tmp)
        raise IngestError(f"Clone exceeded the {settings.clone_timeout_seconds}s time limit.") from exc
    except subprocess.CalledProcessError as exc:
        remove_tree(tmp)
        msg = exc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] if exc.stderr else []
        raise IngestError(f"git clone failed: {' '.join(msg) or 'unknown error'}") from exc
    size = dir_size_bytes(dest)
    if size > settings.max_repo_mb * 1024 * 1024:
        remove_tree(tmp)
        raise IngestError(f"Repository is {size / 1048576:.0f} MB on disk, above the {settings.max_repo_mb} MB limit.")
    sha, branch = _git_info(dest)
    return Target(root=dest, label=f"{owner}/{repo}", source=f"https://github.com/{owner}/{repo}",
                  source_type="url", is_git=True, commit_sha=sha, branch=branch, _temp_dirs=[tmp])


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def safe_extract_zip(zip_path: Path, dest: Path, settings: Settings | None = None) -> None:
    """Extract ``zip_path`` into ``dest``, refusing traversal, symlinks and bombs."""
    settings = settings or get_settings()
    dest_resolved = dest.resolve()
    limit = settings.max_repo_mb * 1024 * 1024
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise IngestError("The upload is not a valid zip archive.") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > settings.max_zip_files:
            raise IngestError(f"Archive has {len(infos)} entries, above the {settings.max_zip_files} limit.")
        if sum(i.file_size for i in infos) > limit:
            raise IngestError(f"Archive expands beyond the {settings.max_repo_mb} MB limit.")
        for info in infos:
            name = info.filename.replace("\\", "/")
            pure = PurePosixPath(name)
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in pure.parts:
                raise IngestError(f"Blocked unsafe path in archive (zip-slip): {name!r}")
            target = (dest / name).resolve()
            if not target.is_relative_to(dest_resolved):
                raise IngestError(f"Blocked unsafe path in archive (zip-slip): {name!r}")
            if _is_symlink(info):
                raise IngestError(f"Blocked symbolic link in archive: {name!r}")
        written = 0
        for info in infos:
            target = (dest / info.filename.replace("\\", "/")).resolve()
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(65536):
                    written += len(chunk)
                    if written > limit:
                        raise IngestError("Archive expands beyond the size limit (possible zip bomb).")
                    out.write(chunk)


def extract_upload(zip_path: Path, display_name: str, settings: Settings | None = None) -> Target:
    """Extract an uploaded zip into a temp directory and return the target."""
    settings = settings or get_settings()
    if zip_path.stat().st_size > settings.max_upload_mb * 1024 * 1024:
        raise IngestError(f"Upload exceeds the {settings.max_upload_mb} MB limit.")
    tmp = Path(tempfile.mkdtemp(prefix="cs-zip-"))
    dest = tmp / "src"
    dest.mkdir()
    try:
        safe_extract_zip(zip_path, dest, settings)
    except Exception:
        remove_tree(tmp)
        raise
    entries = [p for p in dest.iterdir() if p.name not in {"__MACOSX"}]
    root = entries[0] if len(entries) == 1 and entries[0].is_dir() else dest
    is_git = (root / ".git").exists()
    sha, branch = _git_info(root) if is_git else (None, None)
    name = Path(display_name).stem or "upload"
    return Target(root=root, label=name, source=f"upload:{name}", source_type="zip", is_git=is_git,
                  commit_sha=sha, branch=branch, _temp_dirs=[tmp])


def local_target(path: str, settings: Settings | None = None, allow: bool | None = None) -> Target:
    """Use a directory on local disk as the target (read-only, never copied)."""
    settings = settings or get_settings()
    if allow is None:
        allow = settings.allow_local_paths
    if not allow:
        raise IngestError("Local path scanning is disabled on this server.")
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise IngestError(f"Path does not exist or is not a directory: {path}")
    is_git = (root / ".git").exists()
    sha, branch = _git_info(root) if is_git else (None, None)
    return Target(root=root, label=root.name, source=str(root), source_type="path", is_git=is_git,
                  commit_sha=sha, branch=branch)


def resolve_target(target: str, include_history: bool = True, settings: Settings | None = None,
                   allow_local: bool | None = None) -> Target:
    """Dispatch on the target string: GitHub URL, ``.zip`` file, or directory."""
    t = target.strip()
    if t.startswith(("http://", "https://")):
        return clone_repo(t, include_history, settings)
    if t.lower().endswith(".zip") and Path(t).is_file():
        return extract_upload(Path(t), Path(t).name, settings)
    return local_target(t, settings, allow=allow_local)
