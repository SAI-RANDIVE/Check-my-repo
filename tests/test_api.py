"""REST API and HTML pages via FastAPI's TestClient (intel enrichment stubbed: no network)."""

from __future__ import annotations

import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(demo_repos: dict):
    import app.engine as engine
    import app.main as main

    original = engine.enrich
    engine.enrich = lambda components, settings=None: ([], {"intel_partial_sources": []})
    main.rate_limiter.limit = 1000
    with TestClient(main.app) as c:
        yield c
    engine.enrich = original


def wait(client: TestClient, scan_id: int, timeout: float = 90) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        s = client.get(f"/api/scans/{scan_id}/status").json()
        if s["status"] in ("done", "error"):
            return s
        time.sleep(0.3)
    raise AssertionError("scan did not finish")


@pytest.fixture(scope="module")
def scans(client: TestClient, demo_repos: dict) -> dict:
    a = client.post("/api/scans", data={"path": str(demo_repos["vulnerable"])}).json()["id"]
    b = client.post("/api/scans", data={"path": str(demo_repos["vulnerable"])}).json()["id"]
    c = client.post("/api/scans", data={"path": str(demo_repos["fixed"])}).json()["id"]
    for sid in (a, b, c):
        assert wait(client, sid)["status"] == "done"
    return {"vuln": a, "vuln2": b, "fixed": c}


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_security_headers_and_csp_nonce(client: TestClient) -> None:
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "'nonce-" in csp and "unsafe-eval" not in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"' in r.text


def test_pages_render(client: TestClient, scans: dict) -> None:
    for url in ("/", "/about", "/history", f"/scans/{scans['vuln']}"):
        r = client.get(url)
        assert r.status_code == 200 and "CodeSentinel" in r.text, url
    assert "FAIL" in client.get(f"/scans/{scans['vuln']}").text
    assert "PASS" in client.get(f"/scans/{scans['fixed']}").text


def test_scan_summary_and_status(client: TestClient, scans: dict) -> None:
    s = client.get(f"/api/scans/{scans['vuln']}").json()
    assert s["gate_passed"] is False and s["grade"] and s["counts"]["P0"] >= 1
    st = client.get(f"/api/scans/{scans['vuln']}/status").json()
    names = [x["name"] for x in st["stages"]]
    assert names[0] == "Cloning" and names[-1] == "Exports" and all(x["state"] in ("done", "skipped") for x in st["stages"])
    assert client.get(f"/api/scans/{scans['fixed']}").json()["gate_passed"] is True


def test_findings_api_filters(client: TestClient, scans: dict) -> None:
    allf = client.get(f"/api/scans/{scans['vuln']}/findings").json()
    p0 = client.get(f"/api/scans/{scans['vuln']}/findings", params={"priority": "P0"}).json()
    sec = client.get(f"/api/scans/{scans['vuln']}/findings", params={"module": "secrets"}).json()
    assert len(p0) < len(allf) and all(f["priority"] == "P0" for f in p0)
    assert all(f["module"] == "secrets" for f in sec) and any(f["extra"]["historical"] for f in sec)


def test_finding_page(client: TestClient, scans: dict) -> None:
    fid = client.get(f"/api/scans/{scans['vuln']}/findings", params={"priority": "P0"}).json()[0]["id"]
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200 and "Triage" in r.text


@pytest.mark.parametrize("fmt,ctype", [("sbom", "cyclonedx"), ("cbom", "cyclonedx"), ("sarif", "sarif"), ("csv", "csv"),
                                       ("pdf", "pdf"), ("json", "json")])
def test_exports(client: TestClient, scans: dict, fmt: str, ctype: str) -> None:
    r = client.get(f"/api/scans/{scans['vuln']}/export/{fmt}")
    assert r.status_code == 200 and ctype in r.headers["content-type"] and "attachment" in r.headers["content-disposition"]
    if fmt in ("sbom", "cbom", "sarif", "json"):
        r.json()


def test_unknown_export_404(client: TestClient, scans: dict) -> None:
    assert client.get(f"/api/scans/{scans['vuln']}/export/docx").status_code == 404


def test_triage_requires_justification_and_reevaluates_gate(client: TestClient, scans: dict) -> None:
    sid = scans["vuln2"]
    p0 = client.get(f"/api/scans/{sid}/findings", params={"priority": "P0"}).json()
    assert client.post(f"/api/findings/{p0[0]['id']}/triage", json={"status": "false_positive", "justification": "no"}).status_code == 422
    out = None
    for f in p0:
        out = client.post(f"/api/findings/{f['id']}/triage",
                          json={"status": "accepted_risk", "justification": "Mitigated by WAF rule 1042 until Q4 release"}).json()
    assert out["scan"]["gate_passed"] is True
    stored = client.get(f"/api/scans/{sid}/findings", params={"status": "accepted_risk"}).json()
    assert len(stored) == len(p0) and stored[0]["justification"].startswith("Mitigated")


def test_history_and_diff(client: TestClient, scans: dict) -> None:
    pid = client.get(f"/api/scans/{scans['vuln']}").json()["project_id"]
    h = client.get(f"/api/projects/{pid}/history").json()
    assert len(h["scans"]) >= 2
    d = client.get(f"/api/projects/{pid}/diff", params={"base": scans["vuln"], "head": scans["vuln2"]}).json()
    assert not d["new"] and not d["fixed"] and d["unchanged"]
    page = client.get(f"/projects/{pid}")
    assert page.status_code == 200 and "Compare scans" in page.text


def test_input_validation(client: TestClient) -> None:
    assert client.post("/api/scans", data={"url": "https://evil.example/a/b"}).status_code == 422
    assert client.post("/api/scans", data={}).status_code == 422
    assert client.post("/api/scans", data={"path": "/definitely/not/here"}).status_code == 422
    assert client.post("/api/scans", data={"path": ".", "fail_on": "p7"}).status_code == 422


def test_zip_upload_and_zip_slip_rejected(client: TestClient) -> None:
    good = io.BytesIO()
    with zipfile.ZipFile(good, "w") as zf:
        zf.writestr("svc/app.py", "import yaml\nyaml.load(open('x'))\n")
    r = client.post("/api/scans", files={"file": ("svc.zip", good.getvalue(), "application/zip")})
    assert r.status_code == 202
    assert wait(client, r.json()["id"])["status"] == "done"
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../../evil.py", "x")
    r = client.post("/api/scans", files={"file": ("evil.zip", evil.getvalue(), "application/zip")})
    s = wait(client, r.json()["id"])
    assert s["status"] == "error" and "zip-slip" in s["error"]


def test_rate_limit(client: TestClient) -> None:
    import app.main as main

    main.rate_limiter.limit = 2
    main.rate_limiter.hits.clear()
    try:
        codes = [client.post("/api/scans", data={"url": "https://bad"}).status_code for _ in range(3)]
        assert codes[-1] == 429
    finally:
        main.rate_limiter.limit = 1000
        main.rate_limiter.hits.clear()


def test_404s(client: TestClient) -> None:
    assert client.get("/api/scans/999999").status_code == 404
    assert client.get("/scans/999999").status_code == 404
