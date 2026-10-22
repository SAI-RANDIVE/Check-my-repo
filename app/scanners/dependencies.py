"""Module 2a: manifest and lockfile parsers that build the component inventory (SBOM).

Supported: ``requirements*.txt`` (with ``-r`` includes), ``Pipfile.lock``,
``poetry.lock``, ``package-lock.json`` (v1/v2/v3), ``package.json`` (ranges
resolved to their minimum, flagged ``version_inferred``), ``pom.xml`` (direct
dependencies with property substitution) and ``go.mod``.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from app.scanners.base import Component, read_text

log = logging.getLogger(__name__)

MANIFEST_NAMES = {"Pipfile.lock", "poetry.lock", "package-lock.json", "npm-shrinkwrap.json", "package.json",
                  "pom.xml", "go.mod"}


def normalise_pypi(name: str) -> str:
    """PEP 503 normalised project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def make_purl(ecosystem: str, name: str, version: str | None) -> str:
    """Build a Package URL (https://github.com/package-url/purl-spec)."""
    v = f"@{quote(version, safe='.+-_~')}" if version else ""
    if ecosystem == "PyPI":
        return f"pkg:pypi/{normalise_pypi(name)}{v}"
    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:
            scope, pkg = name.split("/", 1)
            return f"pkg:npm/{quote(scope)}/{pkg}{v}"
        return f"pkg:npm/{name}{v}"
    if ecosystem == "Maven":
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{group}/{artifact}{v}"
    if ecosystem == "Go":
        return f"pkg:golang/{name}{v}"
    return f"pkg:generic/{name}{v}"


def is_manifest(rel: str) -> bool:
    """True when the file is one of the supported manifests/lockfiles."""
    name = rel.rsplit("/", 1)[-1]
    if name in MANIFEST_NAMES:
        return True
    return bool(re.fullmatch(r"requirements[\w.\-]*\.txt", name)) or (
        "/requirements/" in "/" + rel and name.endswith(".txt")
    )


# ----------------------------------------------------------------------------- PyPI

REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _version_from_spec(spec: str) -> tuple[str, bool]:
    """Return (version, inferred) from a PEP 440 specifier string."""
    spec = spec.strip().strip(",")
    if not spec:
        return "", False
    try:
        ss = SpecifierSet(spec)
    except InvalidSpecifier:
        return "", False
    exact = [s for s in ss if s.operator in ("==", "===") and "*" not in s.version]
    if exact:
        return exact[0].version, False
    lower = [s for s in ss if s.operator in (">=", "~=", "==", ">")]
    if lower:
        return lower[0].version.replace(".*", ".0"), True
    return "", False


def parse_requirements(root: Path, rel: str, seen: set[str] | None = None) -> list[Component]:
    """Parse a pip requirements file, following ``-r``/``--requirement`` includes."""
    seen = seen if seen is not None else set()
    if rel in seen:
        return []
    seen.add(rel)
    text = read_text(root / rel)
    if text is None:
        return []
    comps: list[Component] = []
    logical: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        logical.append((start, buf + raw))
        buf = ""
    for lineno, raw in logical:
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement")):
            inc = line.split(None, 1)[1].strip() if " " in line else line.split("=", 1)[1]
            inc_rel = (Path(rel).parent / inc).as_posix()
            if (root / inc_rel).is_file():
                comps.extend(parse_requirements(root, inc_rel, seen))
            continue
        if line.startswith(("-", "git+", "http:", "https:", "file:", ".", "/")) or "://" in line:
            continue
        line = line.split(";", 1)[0].split(" --hash", 1)[0].strip()
        m = REQ_RE.match(line)
        if not m:
            continue
        name = normalise_pypi(m.group(1))
        version, inferred = _version_from_spec(m.group(3))
        comps.append(Component(name=name, version=version, ecosystem="PyPI", purl=make_purl("PyPI", name, version),
                               file=rel, line=lineno, direct=True, version_inferred=inferred))
    return comps


def _find_line(lines: list[str], pattern: str) -> int | None:
    rx = re.compile(pattern)
    for i, ln in enumerate(lines, 1):
        if rx.search(ln):
            return i
    return None


def parse_pipfile_lock(root: Path, rel: str) -> list[Component]:
    """Parse ``Pipfile.lock``; direct-ness comes from a sibling ``Pipfile`` when present."""
    text = read_text(root / rel)
    if not text:
        return []
    data = json.loads(text)
    lines = text.splitlines()
    direct_names: set[str] | None = None
    pipfile = root / Path(rel).parent / "Pipfile"
    if pipfile.is_file():
        try:
            pf = tomllib.loads(pipfile.read_text("utf-8"))
            direct_names = {normalise_pypi(n) for sec in ("packages", "dev-packages") for n in pf.get(sec, {})}
        except (tomllib.TOMLDecodeError, OSError):
            direct_names = None
    comps = []
    for section, scope in (("default", "required"), ("develop", "optional")):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta.get("version") or "").lstrip("=")
            n = normalise_pypi(name)
            comps.append(Component(
                name=n, version=ver, ecosystem="PyPI", purl=make_purl("PyPI", n, ver), file=rel,
                line=_find_line(lines, rf'^\s*"{re.escape(name)}"\s*:'), scope=scope,
                direct=True if direct_names is None else n in direct_names))
    return comps


def _pep508_name(req: str) -> str:
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._\-]*)", req)
    return normalise_pypi(m.group(1)) if m else ""


def parse_poetry_lock(root: Path, rel: str) -> list[Component]:
    """Parse ``poetry.lock`` and mark direct deps from ``pyproject.toml``."""
    text = read_text(root / rel)
    if not text:
        return []
    data = tomllib.loads(text)
    lines = text.splitlines()
    direct: set[str] = set()
    pyproject = root / Path(rel).parent / "pyproject.toml"
    if pyproject.is_file():
        try:
            pp = tomllib.loads(pyproject.read_text("utf-8"))
            poetry = pp.get("tool", {}).get("poetry", {})
            direct |= {normalise_pypi(n) for n in poetry.get("dependencies", {}) if n != "python"}
            direct |= {normalise_pypi(n) for n in poetry.get("dev-dependencies", {})}
            for grp in poetry.get("group", {}).values():
                direct |= {normalise_pypi(n) for n in grp.get("dependencies", {})}
            direct |= {_pep508_name(r) for r in pp.get("project", {}).get("dependencies", [])}
        except (tomllib.TOMLDecodeError, OSError):
            pass
    pkgs = data.get("package", [])
    versions = {normalise_pypi(p["name"]): p.get("version", "") for p in pkgs}
    comps = []
    for p in pkgs:
        n = normalise_pypi(p["name"])
        ver = p.get("version", "")
        deps = [make_purl("PyPI", d, versions[normalise_pypi(d)]) for d in (p.get("dependencies") or {})
                if normalise_pypi(d) in versions]
        groups = p.get("groups") or [p.get("category", "main")]
        comps.append(Component(
            name=n, version=ver, ecosystem="PyPI", purl=make_purl("PyPI", n, ver), file=rel,
            line=_find_line(lines, rf'^name = "{re.escape(p["name"])}"'),
            direct=(n in direct) if direct else True,
            scope="required" if "main" in groups else "optional", dependencies=deps))
    return comps


# ----------------------------------------------------------------------------- npm

_SEMVER_MIN = re.compile(r"(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(-[0-9A-Za-z.\-]+)?")


def npm_min_version(rng: str) -> str:
    """Resolve an npm range (``^1.2.3``, ``~1.2``, ``>=1 <2``, ``1.x``) to its minimum version."""
    rng = rng.strip()
    if not rng or rng in ("*", "latest", "x") or any(t in rng for t in ("://", "git", "file:", "link:", "npm:", "/")):
        return ""
    first = rng.split("||")[0].strip()
    m = _SEMVER_MIN.search(first)
    if not m:
        return ""
    parts = [m.group(1), m.group(2), m.group(3)]
    parts = ["0" if (p is None or p in ("x", "*")) else p for p in parts]
    return ".".join(parts) + (m.group(4) or "")


def _npm_line_index(lines: list[str]) -> dict[str, int]:
    idx: dict[str, int] = {}
    rx = re.compile(r'^\s*"((?:[^"]*node_modules/)?[^"]+)":\s*\{')
    for i, ln in enumerate(lines, 1):
        m = rx.match(ln)
        if m and m.group(1) not in idx:
            idx[m.group(1)] = i
    return idx


def parse_package_lock(root: Path, rel: str) -> list[Component]:
    """Parse ``package-lock.json`` / ``npm-shrinkwrap.json`` (lockfile v1, v2, v3)."""
    text = read_text(root / rel, max_bytes=50_000_000)
    if not text:
        return []
    data = json.loads(text)
    lines = text.splitlines()
    line_idx = _npm_line_index(lines)
    comps: list[Component] = []
    packages = data.get("packages")
    if packages:  # v2 / v3
        root_pkg = packages.get("", {})
        direct = set(root_pkg.get("dependencies", {})) | set(root_pkg.get("devDependencies", {})) | set(
            root_pkg.get("optionalDependencies", {}))
        path_to_purl: dict[str, str] = {}
        for path, meta in packages.items():
            if not path or meta.get("link") or "node_modules/" not in path:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
            path_to_purl[path] = make_purl("npm", name, meta.get("version", ""))

        def resolve(from_path: str, dep: str) -> str | None:
            base = from_path
            while True:
                cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
                if cand in path_to_purl:
                    return path_to_purl[cand]
                if not base:
                    return None
                base = base.rsplit("/node_modules/", 1)[0] if "/node_modules/" in base else ""

        for path, meta in packages.items():
            if path not in path_to_purl:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
            deps = [p for d in {**meta.get("dependencies", {}), **meta.get("optionalDependencies", {})}
                    if (p := resolve(path, d))]
            comps.append(Component(
                name=name, version=meta.get("version", ""), ecosystem="npm", purl=path_to_purl[path], file=rel,
                line=line_idx.get(path), direct=path == f"node_modules/{name}" and name in direct,
                scope="optional" if meta.get("dev") or meta.get("devOptional") else "required", dependencies=deps,
                license=meta.get("license") if isinstance(meta.get("license"), str) else None))
        return comps
    # v1: nested "dependencies" tree
    direct_names: set[str] = set()
    pj = root / Path(rel).parent / "package.json"
    if pj.is_file():
        try:
            pjd = json.loads(pj.read_text("utf-8"))
            direct_names = set(pjd.get("dependencies", {})) | set(pjd.get("devDependencies", {}))
        except (json.JSONDecodeError, OSError):
            pass

    def walk(deps: dict, depth: int) -> None:
        for name, meta in deps.items():
            ver = meta.get("version", "")
            if ver.startswith(("file:", "git", "http")):
                continue
            children = meta.get("dependencies", {})
            comps.append(Component(
                name=name, version=ver, ecosystem="npm", purl=make_purl("npm", name, ver), file=rel,
                line=line_idx.get(name), direct=depth == 0 and (not direct_names or name in direct_names),
                scope="optional" if meta.get("dev") else "required",
                dependencies=[make_purl("npm", r, (children.get(r) or deps.get(r) or {}).get("version", ""))
                              for r in meta.get("requires", {})]))
            walk(children, depth + 1)

    walk(data.get("dependencies", {}), 0)
    return comps


def parse_package_json(root: Path, rel: str) -> list[Component]:
    """Parse ``package.json`` ranges (only used when no lockfile sits beside it)."""
    text = read_text(root / rel)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    lines = text.splitlines()
    comps = []
    for section, scope in (("dependencies", "required"), ("devDependencies", "optional"),
                           ("optionalDependencies", "optional")):
        for name, rng in (data.get(section) or {}).items():
            if not isinstance(rng, str):
                continue
            ver = npm_min_version(rng)
            comps.append(Component(
                name=name, version=ver, ecosystem="npm", purl=make_purl("npm", name, ver), file=rel,
                line=_find_line(lines, rf'^\s*"{re.escape(name)}"\s*:'), direct=True, scope=scope,
                version_inferred=bool(ver) and not re.fullmatch(r"\d+\.\d+\.\d+(-[\w.\-]+)?", rng.strip())))
    return comps


# ----------------------------------------------------------------------------- Maven


def _strip_ns(tree: ET.Element) -> ET.Element:
    for el in tree.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return tree


def parse_pom(root: Path, rel: str) -> list[Component]:
    """Parse direct dependencies from ``pom.xml`` with ``${property}`` substitution."""
    text = read_text(root / rel)
    if not text:
        return []
    if "<!ENTITY" in text:  # never expand entities from untrusted XML
        log.warning("skipping %s: DTD entities are not allowed", rel)
        return []
    try:
        proj = _strip_ns(ET.fromstring(text))
    except ET.ParseError:
        return []
    lines = text.splitlines()
    props: dict[str, str] = {}
    parent = proj.find("parent")
    if parent is not None:
        for k in ("groupId", "version"):
            v = parent.findtext(k)
            if v:
                props[f"project.parent.{k}"] = v.strip()
                props[f"parent.{k}"] = v.strip()
    for k in ("groupId", "artifactId", "version"):
        v = proj.findtext(k) or (parent.findtext(k) if parent is not None and k != "artifactId" else None)
        if v:
            props[f"project.{k}"] = v.strip()
            props[k] = v.strip()
    pnode = proj.find("properties")
    if pnode is not None:
        for p in pnode:
            if isinstance(p.tag, str):
                props[p.tag] = (p.text or "").strip()

    def sub(val: str | None, depth: int = 0) -> str:
        if not val:
            return ""
        out = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), val.strip())
        return sub(out, depth + 1) if "${" in out and depth < 5 and out != val else out

    managed: dict[str, str] = {}
    dm = proj.find("dependencyManagement/dependencies")
    if dm is not None:
        for d in dm.findall("dependency"):
            managed[f"{sub(d.findtext('groupId'))}:{sub(d.findtext('artifactId'))}"] = sub(d.findtext("version"))
    comps = []
    deps = proj.find("dependencies")
    for d in (deps.findall("dependency") if deps is not None else []):
        g, a = sub(d.findtext("groupId")), sub(d.findtext("artifactId"))
        if not g or not a:
            continue
        name = f"{g}:{a}"
        ver = sub(d.findtext("version")) or managed.get(name, "")
        if "${" in ver:
            ver = ""
        scope = (d.findtext("scope") or "compile").strip()
        comps.append(Component(
            name=name, version=ver, ecosystem="Maven", purl=make_purl("Maven", name, ver), file=rel,
            line=_find_line(lines, rf"<artifactId>\s*{re.escape(a)}\s*</artifactId>"), direct=True,
            scope="optional" if scope in ("test", "provided") else "required"))
    return comps


# ----------------------------------------------------------------------------- Go


def parse_go_mod(root: Path, rel: str) -> list[Component]:
    """Parse ``require`` directives from ``go.mod`` (``// indirect`` = transitive)."""
    text = read_text(root / rel)
    if not text:
        return []
    comps = []
    in_block = False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        body = None
        if in_block:
            body = line
        elif line.startswith("require "):
            body = line[len("require "):]
        if not body or body.startswith("//"):
            continue
        indirect = "// indirect" in body
        parts = body.split("//")[0].split()
        if len(parts) < 2:
            continue
        mod, ver = parts[0], parts[1]
        comps.append(Component(name=mod, version=ver, ecosystem="Go", purl=make_purl("Go", mod, ver), file=rel,
                               line=i, direct=not indirect))
    return comps


# ----------------------------------------------------------------------------- driver


def discover_components(root: Path, files: list[str], include_transitive: bool = True) -> list[Component]:
    """Parse every manifest in ``files`` and return a de-duplicated component list."""
    comps: list[Component] = []
    manifests = [f for f in files if is_manifest(f)]
    lock_dirs = {str(Path(f).parent) for f in manifests if f.rsplit("/", 1)[-1] in ("package-lock.json",
                                                                                      "npm-shrinkwrap.json")}
    seen_req: set[str] = set()
    for rel in manifests:
        name = rel.rsplit("/", 1)[-1]
        try:
            if name == "Pipfile.lock":
                comps += parse_pipfile_lock(root, rel)
            elif name == "poetry.lock":
                comps += parse_poetry_lock(root, rel)
            elif name in ("package-lock.json", "npm-shrinkwrap.json"):
                comps += parse_package_lock(root, rel)
            elif name == "package.json":
                if str(Path(rel).parent) not in lock_dirs:
                    comps += parse_package_json(root, rel)
            elif name == "pom.xml":
                comps += parse_pom(root, rel)
            elif name == "go.mod":
                comps += parse_go_mod(root, rel)
            else:
                comps += parse_requirements(root, rel, seen_req)
        except (ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
            log.warning("could not parse %s: %s", rel, exc)
    merged: dict[tuple[str, str, str], Component] = {}
    for c in comps:
        existing = merged.get(c.key)
        if existing is None:
            merged[c.key] = c
        else:
            existing.direct = existing.direct or c.direct
            existing.dependencies = sorted(set(existing.dependencies) | set(c.dependencies))
            if c.scope == "required":
                existing.scope = "required"
    result = list(merged.values())
    if not include_transitive:
        result = [c for c in result if c.direct]
    return sorted(result, key=lambda c: (c.ecosystem, c.name, c.version))
