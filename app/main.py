"""FastAPI application: web UI (Jinja2) + REST API (documented at /docs)."""

from __future__ import annotations

import logging
import re
import secrets
import shutil
import tempfile
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.config import APP_NAME, APP_VERSION, PROJECT_ROOT, configure_logging, get_settings
from app.db import get_session, init_db, session_scope
from app.engine import STAGES, ScanOptions, ScanReport, run_scan
from app.exporters import FORMATS, render
from app.ingest import IngestError, Target, clone_repo, extract_upload, local_target, validate_github_url
from app.models import Component, CryptoAsset, FeedCache, Finding, Project, Scan, utcnow
from app.scanners.base import OWASP_URLS, cwe_url
from app.scanners.base import Finding as FindingRec
from app.scoring import evaluate, normalise_gate, sort_findings

log = logging.getLogger("codesentinel.web")
HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
_executor: ThreadPoolExecutor | None = None
DEMO_DIR = PROJECT_ROOT / "demo"


# ============================================================================ lifecycle


@asynccontextmanager
async def lifespan(_app: FastAPI):  # type: ignore[no-untyped-def]
    """Initialise logging, the database and the worker pool."""
    global _executor
    configure_logging()
    init_db()
    with session_scope() as s:
        for scan in s.scalars(select(Scan).where(Scan.status.in_(["queued", "running"]))):
            scan.status, scan.error = "error", "Interrupted: the server restarted while this scan was running."
    _executor = ThreadPoolExecutor(max_workers=get_settings().worker_threads, thread_name_prefix="scan")
    yield
    _executor.shutdown(wait=False, cancel_futures=True)


app = FastAPI(
    title=f"{APP_NAME} API", version=APP_VERSION, lifespan=lifespan,
    description="Software supply-chain security gate: leaked secrets (HEAD + history), exploit-aware dependency "
                "risk (OSV + EPSS + CISA KEV), SAST, IaC/CI audit, CycloneDX SBOM/CBOM and SARIF.",
)
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


# ============================================================================ security middleware

CDN_SCRIPTS = "https://cdn.tailwindcss.com https://cdn.jsdelivr.net"


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Attach a per-request CSP nonce and standard security headers to every response."""
    nonce = secrets.token_urlsafe(16)
    request.state.nonce = nonce
    response: Response = await call_next(request)
    if request.url.path in ("/docs", "/redoc", "/docs/oauth2-redirect"):
        script_src = f"'self' 'unsafe-inline' {CDN_SCRIPTS}"  # Swagger UI ships an inline bootstrap script
    else:
        script_src = f"'self' 'nonce-{nonce}' {CDN_SCRIPTS}"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src {script_src}; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://fastapi.tiangolo.com; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class RateLimiter:
    """Sliding-window limiter keyed by client IP (in-process)."""

    def __init__(self, limit: int, window: float = 60.0) -> None:
        self.limit, self.window = limit, window
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> bool:
        """Record a hit; return False when the key is over its limit."""
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


rate_limiter = RateLimiter(get_settings().rate_limit_per_minute)


def client_ip(request: Request) -> str:
    """Client IP, honouring the first X-Forwarded-For hop (Render runs behind a proxy)."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ============================================================================ persistence


def _new_stages() -> list[dict[str, Any]]:
    return [{"name": s, "state": "pending", "seconds": None} for s in STAGES]


def _update_stage(scan_id: int, stage: str, state: str) -> None:
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            return
        stages = [dict(x) for x in (scan.stages or _new_stages())]
        now = time.time()
        for st in stages:
            if st["name"] == stage:
                if state == "running":
                    st["started"] = now
                elif "started" in st and state == "done":
                    st["seconds"] = round(now - st["started"], 2)
                st["state"] = state
        scan.stages = stages
        if state == "running":
            scan.stage = stage


def persist_report(scan_id: int, report: ScanReport) -> None:
    """Store a finished report's findings, components and crypto assets."""
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        assert scan is not None
        scan.commit_sha, scan.branch = report.commit_sha, report.branch
        scan.score, scan.grade = report.gate.score, report.gate.grade
        scan.gate_passed, scan.gate_reasons, scan.fail_on = report.gate.passed, report.gate.reasons, report.gate.fail_on
        scan.stats = {**report.stats, "policy_errors": report.policy_errors, "total_risk": report.gate.total_risk}
        scan.intel_partial = report.intel_partial
        for f in report.findings:
            s.add(Finding(scan_id=scan_id, fingerprint=f.fingerprint, module=f.module, rule_id=f.rule_id,
                          title=f.title[:400], severity=f.severity, priority=f.priority, risk_score=f.risk_score,
                          file=f.file[:1000], line=f.line, status=f.status, justification=f.justification,
                          data=f.to_dict()))
        for c in report.components:
            s.add(Component(scan_id=scan_id, name=c.name, version=c.version, ecosystem=c.ecosystem, purl=c.purl,
                            direct=c.direct, vuln_count=c.vuln_count, data=c.to_dict()))
        for a in report.crypto_assets:
            s.add(CryptoAsset(scan_id=scan_id, name=a.name, primitive=a.primitive, classification=a.classification,
                              quantum_vulnerable=a.quantum_vulnerable, file=a.file, line=a.line, data=a.to_dict()))


def load_report(s: Session, scan: Scan) -> ScanReport:
    """Rebuild a :class:`ScanReport` from the database (triage state included)."""
    findings = []
    for row in s.scalars(select(Finding).where(Finding.scan_id == scan.id)):
        d = dict(row.data)
        d["status"], d["justification"] = row.status, row.justification
        findings.append(d)
    started = scan.started_at or scan.created_at
    finished = scan.finished_at or started
    d = {
        "target": scan.project.name, "source": scan.project.source, "source_type": scan.project.source_type,
        "commit_sha": scan.commit_sha, "branch": scan.branch, "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"), "duration_seconds": scan.duration_seconds or 0.0,
        "gate": {"score": scan.score or 0, "grade": scan.grade or "-", "passed": bool(scan.gate_passed),
                 "fail_on": scan.fail_on, "reasons": scan.gate_reasons or [],
                 "counts": (scan.stats or {}).get("by_priority", {}), "total_risk": (scan.stats or {}).get("total_risk", 0)},
        "stats": scan.stats or {}, "intel_partial": scan.intel_partial, "options": scan.options or {},
        "findings": findings,
        "components": [c.data for c in s.scalars(select(Component).where(Component.scan_id == scan.id))],
        "crypto_assets": [a.data for a in s.scalars(select(CryptoAsset).where(CryptoAsset.scan_id == scan.id))],
    }
    rep = ScanReport.from_dict(d)
    rep.findings = sort_findings(rep.findings)
    return rep


def export_dir(scan_id: int) -> Path:
    """Folder holding cached export files for a scan."""
    return get_settings().scans_dir / str(scan_id)


def _run_job(scan_id: int, kind: str, value: str, options: ScanOptions) -> None:
    """Background worker: ingest, scan, persist, pre-render exports."""
    t0 = time.perf_counter()
    target: Target | None = None
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        assert scan is not None
        scan.status, scan.started_at = "running", utcnow()
    try:
        _update_stage(scan_id, "Cloning", "running")
        if kind == "url":
            target = clone_repo(value, include_history=options.include_history)
        elif kind == "zip":
            target = extract_upload(Path(value), Path(value).name)
        else:
            target = local_target(value)
        _update_stage(scan_id, "Cloning", "done")
        report = run_scan(target, options, progress=lambda st, state: _update_stage(scan_id, st, state))
        persist_report(scan_id, report)
        _update_stage(scan_id, "Exports", "running")
        out = export_dir(scan_id)
        out.mkdir(parents=True, exist_ok=True)
        for fmt in ("sbom", "cbom", "sarif", "pdf"):
            (out / FORMATS[fmt][1]).write_bytes(render(report, fmt))
        _update_stage(scan_id, "Exports", "done")
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            assert scan is not None
            scan.status, scan.stage = "done", "Complete"
    except IngestError as exc:
        _fail(scan_id, str(exc))
    except Exception as exc:  # noqa: BLE001  (surface any scanner crash to the UI)
        log.exception("scan %s failed", scan_id)
        _fail(scan_id, f"Internal error: {type(exc).__name__}: {exc}")
    finally:
        if target is not None:
            target.cleanup()
        if kind == "zip":
            shutil.rmtree(Path(value).parent, ignore_errors=True)
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            if scan is not None:
                scan.finished_at = utcnow()
                scan.duration_seconds = round(time.perf_counter() - t0, 2)


def _fail(scan_id: int, message: str) -> None:
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is not None:
            scan.status, scan.error = "error", message
            stages = [dict(x) for x in scan.stages or []]
            for st in stages:
                if st["state"] == "running":
                    st["state"] = "error"
            scan.stages = stages


def create_scan(kind: str, value: str, name: str, source: str, options: ScanOptions) -> int:
    """Create Project/Scan rows and enqueue the job; returns the scan id."""
    with session_scope() as s:
        project = s.scalar(select(Project).where(Project.source == source))
        if project is None:
            project = Project(name=name, source=source, source_type=kind)
            s.add(project)
            s.flush()
        scan = Scan(project_id=project.id, status="queued", stage="Queued", stages=_new_stages(),
                    options={"include_history": options.include_history,
                             "include_transitive": options.include_transitive, "fail_on": options.fail_on},
                    fail_on=options.fail_on or get_settings().default_fail_on)
        s.add(scan)
        s.flush()
        scan_id = scan.id
    assert _executor is not None, "worker pool not started"
    _executor.submit(_run_job, scan_id, kind, value, options)
    return scan_id


def _get_scan(s: Session, scan_id: int) -> Scan:
    scan = s.scalar(select(Scan).options(selectinload(Scan.project)).where(Scan.id == scan_id))
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


# ============================================================================ view helpers

CVSS3_METRICS = {
    "AV": ("Attack vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User interaction", {"N": "None", "R": "Required", "P": "Passive", "A": "Active"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("Confidentiality", {"N": "None", "L": "Low", "H": "High"}),
    "I": ("Integrity", {"N": "None", "L": "Low", "H": "High"}),
    "A": ("Availability", {"N": "None", "L": "Low", "H": "High"}),
    "AT": ("Attack requirements", {"N": "None", "P": "Present"}),
    "VC": ("Vulnerable system confidentiality", {"N": "None", "L": "Low", "H": "High"}),
    "VI": ("Vulnerable system integrity", {"N": "None", "L": "Low", "H": "High"}),
    "VA": ("Vulnerable system availability", {"N": "None", "L": "Low", "H": "High"}),
    "SC": ("Subsequent system confidentiality", {"N": "None", "L": "Low", "H": "High"}),
    "SI": ("Subsequent system integrity", {"N": "None", "L": "Low", "H": "High"}),
    "SA": ("Subsequent system availability", {"N": "None", "L": "Low", "H": "High"}),
}


def explain_vector(vector: str | None) -> list[tuple[str, str, str]]:
    """Turn a CVSS vector into (metric, value, raw) rows."""
    if not vector:
        return []
    rows = []
    for part in vector.split("/")[1:]:
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        if k in CVSS3_METRICS:
            name, vals = CVSS3_METRICS[k]
            rows.append((name, vals.get(v, v), f"{k}:{v}"))
    return rows


def ago(dt: datetime | None) -> str:
    """Human 'x minutes ago'."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    secs = (datetime.now(UTC) - dt).total_seconds()
    for unit, n in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if secs >= n:
            v = int(secs // n)
            return f"{v} {unit}{'s' if v != 1 else ''} ago"
    return "just now"


def paragraphs(text: str | None) -> list[dict[str, Any]]:
    """Split advisory text (often Markdown) into plain paragraphs and headings for safe display."""
    out: list[dict[str, Any]] = []
    for block in re.split(r"\n\s*\n", text or ""):
        block = block.strip()
        if not block:
            continue
        block = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r"\1 (\2)", block)
        block = re.sub(r"\*\*([^*]+)\*\*", r"\1", block)
        m = re.fullmatch(r"#{1,6}\s*(.+)", block)
        out.append({"heading": bool(m), "text": m.group(1) if m else block})
    return out


templates.env.filters["ago"] = ago
templates.env.filters["paragraphs"] = paragraphs
templates.env.globals.update(app_name=APP_NAME, app_version=APP_VERSION, cwe_url=cwe_url, owasp_urls=OWASP_URLS)


def render_page(request: Request, name: str, **ctx: Any) -> HTMLResponse:
    """Render a template with the CSP nonce and common context."""
    return templates.TemplateResponse(request, name, {"nonce": request.state.nonce, **ctx})


def scan_summary(scan: Scan) -> dict[str, Any]:
    """JSON-safe summary of a scan row."""
    st = scan.stats or {}
    return {
        "id": scan.id, "project_id": scan.project_id, "target": scan.project.name, "source": scan.project.source,
        "status": scan.status, "stage": scan.stage, "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "duration_seconds": scan.duration_seconds, "commit_sha": scan.commit_sha, "branch": scan.branch,
        "score": scan.score, "grade": scan.grade, "gate_passed": scan.gate_passed, "fail_on": scan.fail_on,
        "gate_reasons": scan.gate_reasons, "intel_partial": scan.intel_partial, "options": scan.options,
        "counts": st.get("by_priority", {}),
        "stats": {k: st.get(k) for k in ("components", "components_direct", "components_transitive", "cves", "kev_hits",
                                         "epss_populated", "secrets_head", "secrets_history", "secrets_placeholder",
                                         "files_scanned", "commits_scanned", "crypto_assets", "dependency_vulns",
                                         "by_module", "stage_seconds")},
    }


def demo_targets() -> list[dict[str, str]]:
    """Local demo repositories offered as one-click targets (dev mode only)."""
    if not get_settings().allow_local_paths:
        return []
    out = []
    for name, label in (("vulnerable-shop", "Vulnerable demo shop"), ("vulnerable-shop-fixed", "Remediated demo shop")):
        p = DEMO_DIR / name
        if (p / ".git").exists():
            out.append({"path": str(p), "label": label, "name": name})
    return out


# ============================================================================ HTML pages


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index(request: Request, s: Session = Depends(get_session)) -> HTMLResponse:
    """New-scan page with recent scans."""
    recent = s.scalars(select(Scan).options(selectinload(Scan.project)).order_by(Scan.id.desc()).limit(8)).all()
    return render_page(request, "index.html", recent=recent, demos=demo_targets(),
                       allow_local=get_settings().allow_local_paths, max_upload=get_settings().max_upload_mb)


@app.get("/scans/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
def scan_page(scan_id: int, request: Request, s: Session = Depends(get_session)) -> HTMLResponse:
    """Progress view while running, full report when done."""
    scan = _get_scan(s, scan_id)
    if scan.status != "done":
        return render_page(request, "scan.html", scan=scan, report=None, stages=STAGES)
    rep = load_report(s, scan)
    rows = s.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    findings = []
    for r in sorted(rows, key=lambda r: (order.get(r.priority, 9), -r.risk_score)):
        x = r.data.get("extra", {})
        findings.append({
            "id": r.id, "priority": r.priority, "risk": r.risk_score, "severity": r.severity, "module": r.module,
            "rule": r.rule_id, "title": r.title, "file": r.file, "line": r.line, "status": r.status,
            "tainted": bool(r.data.get("tainted")), "historical": bool(x.get("historical")),
            "kev": bool(x.get("in_kev")), "cvss": x.get("cvss_score"), "epss": x.get("epss"),
            "package": x.get("package"), "version": x.get("version"), "reason": x.get("priority_reason"),
        })
    crypto: dict[str, dict[str, Any]] = {}
    for a in rep.crypto_assets:
        e = crypto.setdefault(a.name, {"name": a.name, "primitive": a.primitive, "class": a.classification,
                                       "qv": a.quantum_vulnerable, "uses": 0, "locations": [], "library": a.library,
                                       "param": a.parameter, "mode": a.mode})
        e["uses"] += 1
        e["locations"].append(f"{a.file}:{a.line}")
    crypto_rows = sorted(crypto.values(), key=lambda e: ({"broken": 0, "weak": 1, "approved": 2}[e["class"]], e["name"]))
    comps = sorted(rep.components, key=lambda c: (-c.vuln_count, c.ecosystem, c.name))
    iac = [f for f in findings if f["module"] == "iac"]
    return render_page(request, "scan.html", scan=scan, report=rep, findings=findings, crypto_rows=crypto_rows,
                       components=comps, iac=iac, stages=STAGES)


@app.get("/findings/{finding_id}", response_class=HTMLResponse, include_in_schema=False)
def finding_page(finding_id: int, request: Request, s: Session = Depends(get_session)) -> HTMLResponse:
    """Finding detail page."""
    row = s.get(Finding, finding_id)
    if row is None:
        raise HTTPException(404, "Finding not found")
    scan = _get_scan(s, row.scan_id)
    f = FindingRec.from_dict(row.data)
    f.status, f.justification = row.status, row.justification
    return render_page(request, "finding.html", row=row, f=f, scan=scan, d=row.data,
                       vector_rows=explain_vector(f.extra.get("cvss_vector")))


@app.get("/history", response_class=HTMLResponse, include_in_schema=False)
def history_index(request: Request, s: Session = Depends(get_session)) -> HTMLResponse:
    """Projects overview."""
    projects = s.scalars(select(Project).options(selectinload(Project.scans)).order_by(Project.id.desc())).all()
    return render_page(request, "history.html", projects=projects, project=None)


@app.get("/projects/{project_id}", response_class=HTMLResponse, include_in_schema=False)
def project_page(project_id: int, request: Request, base: int | None = None, head: int | None = None,
                 s: Session = Depends(get_session)) -> HTMLResponse:
    """Score trend and scan-to-scan diff for one project."""
    project = s.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "Project not found")
    scans = [sc for sc in sorted(project.scans, key=lambda x: x.id) if sc.status == "done"]
    diff = None
    if len(scans) >= 2:
        head_id = head or scans[-1].id
        base_id = base or scans[-2].id
        diff = compute_diff(s, base_id, head_id)
    return render_page(request, "history.html", project=project, scans=scans, diff=diff, projects=None)


@app.get("/about", response_class=HTMLResponse, include_in_schema=False)
def about(request: Request) -> HTMLResponse:
    """Methodology page."""
    return render_page(request, "about.html")


# ============================================================================ API


def _flag(value: str | None, default: bool = True) -> bool:
    """Parse an optional form boolean; an omitted field means the documented default."""
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "on", "yes")


class ScanCreated(BaseModel):
    """Response for a newly queued scan."""

    id: int
    status: str = "queued"
    status_url: str
    report_url: str


@app.post("/api/scans", response_model=ScanCreated, status_code=202, tags=["scans"])
async def api_create_scan(
    request: Request,
    url: str | None = Form(None, description="Public GitHub URL: https://github.com/owner/repo"),
    path: str | None = Form(None, description="Local directory (development mode only)"),
    file: UploadFile | None = File(None, description="Zip archive of the source tree (max 50 MB)"),
    include_history: str | None = Form(None, description="true/false (default true)"),
    include_transitive: str | None = Form(None, description="true/false (default true)"),
    fail_on: str | None = Form(None, description="p0, p1 or p2"),
) -> ScanCreated:
    """Queue a scan of a GitHub repository, an uploaded zip, or a local path."""
    if not rate_limiter.check(client_ip(request)):
        raise HTTPException(429, f"Rate limit: {get_settings().rate_limit_per_minute} scans per minute per IP.")
    settings = get_settings()
    try:
        level = normalise_gate(fail_on) if fail_on else None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    opts = ScanOptions(include_history=_flag(include_history), include_transitive=_flag(include_transitive),
                       fail_on=level)
    provided = [x for x in (url, path) if x and x.strip()] + ([file] if file is not None and file.filename else [])
    if len(provided) != 1:
        raise HTTPException(422, "Provide exactly one of: url, file, path.")
    if url and url.strip():
        try:
            owner, repo = validate_github_url(url)
        except IngestError as exc:
            raise HTTPException(422, str(exc)) from exc
        source = f"https://github.com/{owner}/{repo}"
        scan_id = create_scan("url", source, f"{owner}/{repo}", source, opts)
    elif path and path.strip():
        if not settings.allow_local_paths:
            raise HTTPException(403, "Local path scanning is disabled on this server.")
        p = Path(path.strip()).expanduser().resolve()
        if not p.is_dir():
            raise HTTPException(422, f"Not a directory: {path}")
        scan_id = create_scan("path", str(p), p.name, str(p), opts)
    else:
        assert file is not None
        if not (file.filename or "").lower().endswith(".zip"):
            raise HTTPException(422, "Upload must be a .zip archive.")
        tmp = Path(tempfile.mkdtemp(prefix="cs-upload-"))
        dest = tmp / Path(file.filename or "upload.zip").name
        limit = settings.max_upload_mb * 1024 * 1024
        size = 0
        with dest.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    out.close()
                    shutil.rmtree(tmp, ignore_errors=True)
                    raise HTTPException(413, f"Upload exceeds {settings.max_upload_mb} MB.")
                out.write(chunk)
        stem = Path(file.filename or "upload").stem
        scan_id = create_scan("zip", str(dest), stem, f"upload:{stem}", opts)
    return ScanCreated(id=scan_id, status_url=f"/api/scans/{scan_id}/status", report_url=f"/scans/{scan_id}")


@app.get("/api/scans", tags=["scans"])
def api_list_scans(limit: int = 50, s: Session = Depends(get_session)) -> list[dict[str, Any]]:
    """Most recent scans."""
    rows = s.scalars(select(Scan).options(selectinload(Scan.project)).order_by(Scan.id.desc()).limit(min(limit, 200)))
    return [scan_summary(r) for r in rows]


@app.get("/api/scans/{scan_id}", tags=["scans"])
def api_get_scan(scan_id: int, s: Session = Depends(get_session)) -> dict[str, Any]:
    """Scan summary: grade, gate decision, counts and statistics."""
    return scan_summary(_get_scan(s, scan_id))


@app.get("/api/scans/{scan_id}/status", tags=["scans"])
def api_scan_status(scan_id: int, s: Session = Depends(get_session)) -> dict[str, Any]:
    """Live progress: current stage, per-stage state and elapsed time."""
    scan = _get_scan(s, scan_id)
    start = scan.started_at or scan.created_at
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    end = scan.finished_at
    if end is not None and end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    elapsed = ((end or datetime.now(UTC)) - start).total_seconds()
    stages = [{"name": x["name"], "state": x["state"], "seconds": x.get("seconds")} for x in scan.stages or []]
    return {"id": scan.id, "status": scan.status, "stage": scan.stage, "stages": stages,
            "elapsed_seconds": round(elapsed, 1), "error": scan.error, "grade": scan.grade,
            "gate_passed": scan.gate_passed}


@app.get("/api/scans/{scan_id}/findings", tags=["scans"])
def api_findings(scan_id: int, priority: str | None = None, module: str | None = None, status: str | None = None,
                 s: Session = Depends(get_session)) -> list[dict[str, Any]]:
    """All findings for a scan (filter by priority, module, status). Secret values are redacted."""
    _get_scan(s, scan_id)
    q = select(Finding).where(Finding.scan_id == scan_id)
    if priority:
        q = q.where(Finding.priority == priority.upper())
    if module:
        q = q.where(Finding.module == module)
    if status:
        q = q.where(Finding.status == status)
    rows = s.scalars(q.order_by(Finding.priority, Finding.risk_score.desc())).all()
    return [{**r.data, "id": r.id, "status": r.status, "justification": r.justification, "priority": r.priority}
            for r in rows]


@app.get("/api/scans/{scan_id}/export/{fmt}", tags=["exports"])
def api_export(scan_id: int, fmt: str, s: Session = Depends(get_session)) -> Response:
    """Download sbom | cbom | sarif | pdf | csv | json."""
    if fmt not in FORMATS:
        raise HTTPException(404, f"Unknown format {fmt!r}; use one of {', '.join(FORMATS)}")
    scan = _get_scan(s, scan_id)
    if scan.status != "done":
        raise HTTPException(409, "Scan has not finished yet.")
    media, filename = FORMATS[fmt]
    cached = export_dir(scan_id) / filename
    if cached.is_file():
        data = cached.read_bytes()
    else:
        data = render(load_report(s, scan), fmt)
        if fmt in ("sbom", "cbom", "sarif", "pdf"):
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(data)
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in scan.project.name)
    return Response(content=data, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{safe}-scan{scan_id}-{filename}"'})


class TriageIn(BaseModel):
    """Triage decision for a finding."""

    status: str = Field(pattern="^(open|false_positive|accepted_risk)$")
    justification: str = Field(default="", max_length=2000)


@app.post("/api/findings/{finding_id}/triage", tags=["findings"])
def api_triage(finding_id: int, body: TriageIn, s: Session = Depends(get_session)) -> dict[str, Any]:
    """Mark a finding as false positive / accepted risk (justification required) and re-evaluate the gate."""
    row = s.get(Finding, finding_id)
    if row is None:
        raise HTTPException(404, "Finding not found")
    if body.status != "open" and len(body.justification.strip()) < 10:
        raise HTTPException(422, "A justification of at least 10 characters is required.")
    row.status = body.status
    row.justification = body.justification.strip() or None
    s.flush()
    scan = _get_scan(s, row.scan_id)
    recs = []
    for r in s.scalars(select(Finding).where(Finding.scan_id == scan.id)):
        f = FindingRec.from_dict(r.data)
        f.status = r.status
        recs.append(f)
    gate = evaluate(recs, scan.fail_on, get_settings().score_normaliser)
    scan.score, scan.grade, scan.gate_passed, scan.gate_reasons = gate.score, gate.grade, gate.passed, gate.reasons
    stats = dict(scan.stats or {})
    stats["by_priority"], stats["total_risk"] = gate.counts, gate.total_risk
    stats["by_module"] = {m: sum(1 for f in recs if f.module == m and f.status == "open")
                          for m in ("secrets", "dependencies", "sast", "iac", "crypto")}
    scan.stats = stats
    shutil.rmtree(export_dir(scan.id), ignore_errors=True)  # exports must reflect triage
    return {"id": row.id, "status": row.status, "justification": row.justification, "scan": scan_summary(scan)}


@app.get("/api/projects", tags=["projects"])
def api_projects(s: Session = Depends(get_session)) -> list[dict[str, Any]]:
    """All projects."""
    rows = s.scalars(select(Project).order_by(Project.id.desc()))
    return [{"id": p.id, "name": p.name, "source": p.source, "source_type": p.source_type} for p in rows]


@app.get("/api/projects/{project_id}/history", tags=["projects"])
def api_history(project_id: int, s: Session = Depends(get_session)) -> dict[str, Any]:
    """Score trend for every completed scan of a project."""
    project = s.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "Project not found")
    scans = [sc for sc in sorted(project.scans, key=lambda x: x.id) if sc.status == "done"]
    return {"project": {"id": project.id, "name": project.name, "source": project.source},
            "scans": [{"id": sc.id, "created_at": sc.created_at.isoformat(), "score": sc.score, "grade": sc.grade,
                       "gate_passed": sc.gate_passed, "commit_sha": sc.commit_sha,
                       "counts": (sc.stats or {}).get("by_priority", {})} for sc in scans]}


def compute_diff(s: Session, base_id: int, head_id: int) -> dict[str, Any]:
    """New / fixed / unchanged findings between two scans, matched by fingerprint."""
    def load(sid: int) -> dict[str, Finding]:
        return {r.fingerprint: r for r in s.scalars(select(Finding).where(Finding.scan_id == sid))}

    a, b = load(base_id), load(head_id)

    def brief(r: Finding) -> dict[str, Any]:
        return {"id": r.id, "priority": r.priority, "module": r.module, "rule": r.rule_id, "title": r.title,
                "file": r.file, "line": r.line}

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    new = sorted((brief(b[k]) for k in b.keys() - a.keys()), key=lambda x: order[x["priority"]])
    fixed = sorted((brief(a[k]) for k in a.keys() - b.keys()), key=lambda x: order[x["priority"]])
    same = sorted((brief(b[k]) for k in a.keys() & b.keys()), key=lambda x: order[x["priority"]])
    return {"base": base_id, "head": head_id, "new": new, "fixed": fixed, "unchanged": same}


@app.get("/api/projects/{project_id}/diff", tags=["projects"])
def api_diff(project_id: int, base: int, head: int, s: Session = Depends(get_session)) -> dict[str, Any]:
    """Diff two scans of the same project."""
    for sid in (base, head):
        sc = _get_scan(s, sid)
        if sc.project_id != project_id:
            raise HTTPException(422, f"Scan {sid} does not belong to project {project_id}")
    return compute_diff(s, base, head)


@app.get("/health", tags=["meta"])
def health(s: Session = Depends(get_session)) -> dict[str, Any]:
    """Liveness/readiness probe with feed-cache status."""
    db_ok = True
    try:
        n = s.scalar(select(func.count()).select_from(FeedCache))
    except Exception:  # noqa: BLE001
        db_ok, n = False, 0
    return {"status": "ok" if db_ok else "degraded", "version": APP_VERSION, "database": db_ok,
            "feed_cache_entries": n, "time": datetime.now(UTC).isoformat(timespec="seconds")}


@app.exception_handler(404)
async def not_found(request: Request, exc: HTTPException) -> Response:
    """HTML 404 for pages, JSON for the API."""
    if request.url.path.startswith("/api/") or "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"detail": getattr(exc, "detail", "Not found")}, status_code=404)
    resp = render_page(request, "base.html", not_found=True)
    resp.status_code = 404
    return resp


@app.get("/scan", include_in_schema=False)
def legacy_redirect() -> RedirectResponse:
    """Convenience redirect."""
    return RedirectResponse("/")
