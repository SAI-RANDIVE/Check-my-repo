<div align="center">

<img src="https://user-images.githubusercontent.com/74038190/221352989-518609ab-b4d1-459e-929f-a08cd2bd9b3c.gif" width="400" alt="CodeSentinel">

# CodeSentinel

**A software supply-chain security gate for leaked-secret detection, exploit-aware dependency risk prioritisation and SBOM/CBOM generation.**

<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="600">

</div>

<div align="center">
  <img src="https://user-images.githubusercontent.com/74038190/213866269-5d00981c-7c98-46d7-8a8e-16f462f15227.gif" width="110" alt="Animated coding graphic">
  <img src="https://user-images.githubusercontent.com/74038190/212257454-16e3712e-945a-4ca2-b238-408ad0bf87e6.gif" width="90" alt="Animated Python logo">
  <img src="https://user-images.githubusercontent.com/74038190/212257472-08e52665-c503-4bd9-aa20-f5a4dae769b5.gif" width="90" alt="Animated JavaScript logo">
  <img src="https://user-images.githubusercontent.com/74038190/212257468-1e9a91f1-b626-4baa-b15d-5c385dfa7ed2.gif" width="90" alt="Animated GitHub logo">
  <img src="https://user-images.githubusercontent.com/74038190/235294002-8aafea24-3179-45af-91d9-412ad7ff5359.gif" width="90" alt="Animated developer icon">
</div>

CodeSentinel scans a Git repository (public GitHub URL, uploaded `.zip`, or local path) and answers one question for a CI pipeline: *should this build ship?* It finds leaked credentials in the code **and its history**, ranks vulnerable dependencies by how likely they are to be exploited (FIRST EPSS + CISA KEV, not CVSS alone), checks Python/JavaScript code, Dockerfiles and GitHub Actions workflows, and inventories cryptography. The output is a prioritised findings list, an A–F grade, a PASS/FAIL gate with a CI exit code, a CycloneDX 1.6 SBOM and CBOM, SARIF for GitHub code scanning, and a PDF report.

Everything is real: vulnerability data is pulled live from OSV.dev, FIRST EPSS and the CISA KEV catalogue, and the demo dependencies are genuine historical package versions with published advisories.

![Scan report](docs/screenshots/02-report.png)

---

## Contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Architecture](#architecture)
- [Scoring methodology](#scoring-methodology)
- [Data sources](#data-sources)
- [Quick start](#quick-start)
- [CLI usage](#cli-usage)
- [Use CodeSentinel as a gate in your own repository](#use-codesentinel-as-a-gate-in-your-own-repository)
- [Repository policy file](#repository-policy-file-codesentinelyml)
- [REST API](#rest-api)
- [Evaluation](#evaluation)
- [Deploy to Render](#deploy-to-render)
- [Configuration](#configuration)
- [Ethics statement](#ethics-statement)
- [Limitations and future work](#limitations-and-future-work)
- [Project layout](#project-layout)

---

## Why this exists

**Secret sprawl.** GitGuardian's *State of Secrets Sprawl 2025* counted 23.8 million secrets leaked on public GitHub in 2024, up 25% year on year, and found that roughly 70% of the secrets leaked in 2022 were still valid. Deleting a key in a later commit does not help: the old commit is still in every clone and fork. CodeSentinel walks git history and reports secrets that exist *only* in history.

**CVSS alone is noisy.** A typical application has hundreds of known CVEs in its dependency tree; most will never be exploited. The [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/) estimates the probability that a CVE is exploited in the next 30 days, and CISA's [Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalogue lists CVEs already exploited in the wild. CodeSentinel combines all three, so Log4Shell (CVSS 10, EPSS 0.99, in KEV) rises above a CVSS 9.8 bug that nobody targets.

**Regulation is catching up.** CERT-In's *Technical Guidelines on SBOM* (October 2024) and *BOM Guidelines v2.0* (July 2025) extend bill-of-materials expectations to CBOM, QBOM, AIBOM and HBOM. SEBI's Cybersecurity and Cyber Resilience Framework (CSCRF, August 2024) requires regulated entities to obtain SBOMs for core and critical software. CodeSentinel produces a CycloneDX SBOM and a cryptographic BOM with post-quantum readiness flags from the same scan.

**CI is part of the supply chain.** In March 2025 the `tj-actions/changed-files` GitHub Action (CVE-2025-30066) was compromised: its version tags were repointed to a commit that printed CI secrets into public build logs across thousands of repositories. Workflows pinned to a full commit SHA were unaffected. CodeSentinel's CI auditor flags unpinned third-party actions, `pull_request_target` misuse and script injection.

## Features

| Module | What it does |
|---|---|
| **Secrets** | 27 provider signatures (AWS, GitHub, GitLab, Slack, Stripe, Google, Twilio, SendGrid, OpenAI, Anthropic, Razorpay, npm, PyPI, Telegram, Discord, Azure, JWT, PEM keys, Postgres/MySQL/Redis/MongoDB URIs), generic `password = "..."` assignments and Shannon entropy (base64 ≥ 4.3, hex ≥ 3.0 bits/char, length ≥ 20) with keyword context. **Git history scan** of up to 500 commits reports secrets deleted from HEAD with commit SHA and date. Placeholders such as `AKIAIOSFODNN7EXAMPLE` are reported as info; `codesentinel:ignore` suppresses a line. Values are reduced to a SHA-256 fingerprint and a redacted preview, never stored. |
| **Dependencies** | Parses `requirements*.txt` (with `-r` includes), `Pipfile.lock`, `poetry.lock`, `package-lock.json` v1–v3, `package.json` (ranges resolved to their minimum, flagged), `pom.xml` (property substitution, dependency management) and `go.mod`. Direct vs transitive, Package URLs, licences. Live OSV `querybatch` + advisory details, CVSS v3.1/v4 computed from vectors, EPSS, KEV. Every finding carries the fixed version and the exact upgrade command. |
| **SAST: Python** | Real `ast` traversal with intra-procedural taint tracking from `request.*`, `input()`, `sys.argv` and web-route parameters. 13 rules: SQL injection, command injection, eval/exec, pickle, unsafe YAML, `verify=False`, debug mode, hard-coded `SECRET_KEY`, weak random for tokens, MD5/SHA-1 passwords, `mktemp`, `assert` for auth, path traversal. CWE + OWASP Top 10:2021 on every rule. |
| **SAST: JS/TS** | Comment-aware token rules: `eval`/`new Function`, `child_process.exec` with templates, `innerHTML`/`dangerouslySetInnerHTML`, SQL template literals, `jwt.verify` without an algorithm allow-list or with `none`, `Math.random` tokens, wildcard CORS with credentials, hard-coded JWT secrets. |
| **IaC & CI/CD** | Dockerfile (root user, `:latest`, remote `ADD`, `curl \| sh`, secrets in `ENV`/`ARG`, `EXPOSE 22`, no `HEALTHCHECK`, apt cache), docker-compose (privileged, host network, Docker socket, plaintext passwords), committed `.env`, GitHub Actions (unpinned third-party actions, `pull_request_target` + PR checkout, script injection, missing/`write-all` permissions, echoed secrets). |
| **Crypto → CBOM** | Inventory of hashes, ciphers and modes, key sizes, curves, KDF iteration counts, TLS versions, certificate verification, JWT algorithms and RNG sources across Python and JS. Classified `approved` / `weak` / `broken`, with `quantum_vulnerable` for RSA/ECC/DSA. Exported as CycloneDX 1.6 `cryptographic-asset` components. |
| **Scoring & gate** | P0–P3 tiers, risk score, A–F grade, `--fail-on p0\|p1\|p2`, `.codesentinel.yml` suppressions that need a justification and expire. |
| **Outputs** | Web UI, CLI, PDF (cover, executive summary, charts, per-tier tables, dependency and crypto tables, methodology, appendix), CycloneDX SBOM with vulnerabilities, CBOM, SARIF 2.1.0, CSV, JSON. |

Screenshots:

| New scan | KEV finding | History diff |
|---|---|---|
| ![New scan](docs/screenshots/01-new-scan.png) | ![KEV finding](docs/screenshots/03-finding-kev.png) | ![History diff](docs/screenshots/05-history-diff.png) |
| **Taint-confirmed SQL injection** | **Methodology** | **PDF report** |
| ![SQLi](docs/screenshots/04-finding-sqli.png) | ![Methodology](docs/screenshots/06-methodology.png) | ![PDF](docs/screenshots/08-pdf-summary.png) |

## Architecture

```mermaid
flowchart LR
    subgraph Input
        U[GitHub URL] --> I
        Z[.zip upload] --> I
        P[Local path / CLI / CI] --> I
    end
    I[Ingest sandbox<br/>timeout, size cap,<br/>zip-slip guard] --> POL[.codesentinel.yml]
    POL --> S1[Secrets<br/>HEAD + history]
    POL --> S2[Dependencies<br/>6 manifest formats]
    POL --> S3[SAST<br/>Python AST + JS]
    POL --> S4[IaC & GitHub Actions]
    POL --> S5[Crypto inventory]
    S2 <--> TI[(Threat intel<br/>OSV · EPSS · KEV<br/>SQLite TTL cache)]
    S1 & S2 & S3 & S4 & S5 --> SC[De-duplicate · suppress<br/>P0–P3 · risk · grade · gate]
    SC --> O1[Web UI]
    SC --> O2[CLI exit code]
    SC --> O3[PDF]
    SC --> O4[SBOM / CBOM]
    SC --> O5[SARIF → GitHub]
```

FastAPI serves the Jinja2 UI and the REST API; scans run in a worker thread pool and stream stage progress into SQLite. The CLI and the web app share one pipeline (`app/engine.py`). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for sequence and data-model diagrams.

## Scoring methodology

**Priority tiers**

| Tier | Rule |
|---|---|
| **P0 Critical-now** | Dependency CVE in CISA KEV; **or** CVSS ≥ 9.0 **and** EPSS ≥ 0.10; **or** a live-format, non-placeholder secret in HEAD; **or** a taint-confirmed SQL/command injection. |
| **P1 High** | CVSS ≥ 7.0 with EPSS ≥ 0.01 (or no EPSS score yet); a secret recoverable from git history; `pull_request_target` checking out PR code; broken cryptography; other high-severity rules. |
| **P2 Medium** | Other CVSS ≥ 4.0; unpinned third-party actions; root containers; weak cryptography; static-analysis hits without a confirmed taint path. |
| **P3 Low/Info** | Everything else, including placeholders. |

**Risk and grade**

```
risk     = severity_weight × exploit_multiplier × exposure_multiplier
           severity_weight      critical 10 · high 6 · medium 3 · low 1 · info 0.25
           exploit_multiplier   1 + 4·EPSS (+2 if in CISA KEV)
           exposure_multiplier  1.0 HEAD / direct · 0.6 transitive · 0.5 history-only secret · 0.3 test files

score    = 100 − min(100, Σ risk ÷ 10)
grade    = A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 55 · F < 55
gate     = FAIL when any open finding is at or above --fail-on (default P0)
```

Findings marked *false positive* or *accepted risk* in the UI (justification required), or suppressed in `.codesentinel.yml`, do not count toward the score or the gate; triage re-evaluates both immediately.

## Data sources

| Source | Used for | Access |
|---|---|---|
| [OSV.dev](https://osv.dev) | Advisories for PyPI, npm, Maven and Go; aliases, CVSS vectors, affected ranges → fixed versions | `POST /v1/querybatch` (500 per request), `GET /v1/vulns/{id}` |
| [FIRST EPSS](https://www.first.org/epss/api) | Probability of exploitation in the next 30 days, percentile | `GET /data/v1/epss?cve=…` (100 per request) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited CVEs, date added, federal due date, ransomware use | JSON feed, cached 24 h |
| [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) | SBOM and CBOM format | — |
| [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) | GitHub code scanning | — |

No API keys are needed. Responses are cached in SQLite with a TTL (OSV 12–24 h, EPSS 24 h, KEV 24 h); requests use 30 s timeouts with exponential backoff, and if a feed is down the scan completes with affected findings marked `intel_partial`.

## Quick start

Requirements: Python 3.11+ and Git on `PATH`. No database server and no API keys.

**Windows**

```bat
run.bat
```

**Linux / macOS**

```sh
./run.sh
```

Both scripts create `.venv`, install `requirements.txt`, copy `.env.example` to `.env`, generate the two demo repositories and start the server at **http://localhost:8000**.

Manual steps:

```sh
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Linux / macOS
pip install -r requirements.txt
python demo/make_demo_repo.py   # builds demo/vulnerable-shop and demo/vulnerable-shop-fixed
uvicorn app.main:app --reload --port 8000
```

Run the tests and the evaluation:

```sh
python -m pytest                             # 270 tests (the live-feed test runs with CS_LIVE_TESTS=1)
python eval/evaluate.py --real-world         # writes docs/EVALUATION.md
ruff check .
```

## CLI usage

```sh
python -m codesentinel scan <target> [options]
```

`<target>` is a local directory, a `.zip` file, or `https://github.com/owner/repo`.

| Option | Meaning |
|---|---|
| `--fail-on p0\|p1\|p2` | Gate level (aliases `critical`, `high`, `medium`). Default: `.codesentinel.yml`, then `p0`. |
| `--sarif FILE` | Write SARIF 2.1.0 |
| `--sbom FILE` / `--cbom FILE` | Write CycloneDX 1.6 SBOM / CBOM |
| `--pdf FILE` / `--csv FILE` / `--json FILE` | Write the PDF report / CSV findings / full JSON report |
| `--no-history` | Skip the git history secret scan |
| `--no-transitive` | Only direct dependencies |
| `--show N` | Rows printed per table |

Exit codes: **0** gate passed, **1** gate failed, **2** the scan could not run.

```sh
python -m codesentinel scan demo/vulnerable-shop --fail-on p0 --pdf report.pdf   # exits 1
python -m codesentinel scan demo/vulnerable-shop-fixed --fail-on p0              # exits 0
python -m codesentinel scan https://github.com/adeyosemanputra/pygoat --sbom pygoat.cdx.json
```

## Use CodeSentinel as a gate in your own repository

Copy this workflow to `.github/workflows/codesentinel.yml` in the repository you want to protect. It installs CodeSentinel from its own repository (replace `<owner>/<codesentinel-repo>`), fails the build on P0 findings, uploads SARIF to the **Security → Code scanning** tab and keeps the SBOM/CBOM as build artifacts. Every action is pinned to a full commit SHA.

```yaml
name: CodeSentinel
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  codesentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0            # full history for the secret scan
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          repository: <owner>/<codesentinel-repo>
          path: .codesentinel-tool
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97  # v7.0.0
        with:
          python-version: "3.11"
      - name: Install CodeSentinel outside the scanned workspace
        run: |
          mv .codesentinel-tool "$RUNNER_TEMP/codesentinel"
          pip install -r "$RUNNER_TEMP/codesentinel/requirements.txt"
      - name: Security gate
        run: >
          python "$RUNNER_TEMP/codesentinel/cli.py" scan . --fail-on p0
          --sarif results.sarif --sbom sbom.cdx.json --cbom cbom.cdx.json
      - uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370  # v4.39.1
        if: always()
        with:
          sarif_file: results.sarif
          category: codesentinel
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9  # v7.0.2
        if: always()
        with:
          name: bom
          path: |
            sbom.cdx.json
            cbom.cdx.json
```

The tool is moved to `$RUNNER_TEMP` before the scan so that its own test fixtures and demo data are not scanned as part of your code. This repository runs the same gate on itself in [.github/workflows/codesentinel.yml](.github/workflows/codesentinel.yml).

## Repository policy file (`.codesentinel.yml`)

```yaml
fail_on: p1                         # default gate for this repository
ignore_paths:
  - docs/**
  - tests/fixtures/**
suppressions:
  - rule: PY-DEBUG-ENABLED
    path: app/dev_server.py          # optional
    justification: Local-only development runner, never deployed.
    expires: 2026-12-31              # mandatory; expired suppressions resurface
```

A suppression without a justification or an expiry date is rejected and reported as a policy warning.

## REST API

Interactive documentation at **`/docs`** (Swagger UI) and `/redoc`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/scans` | Queue a scan. Multipart form: one of `url`, `file` (.zip), `path`; optional `include_history`, `include_transitive`, `fail_on`. Rate-limited to 5/min per IP. |
| `GET` | `/api/scans/{id}` | Summary: grade, gate, counts, statistics |
| `GET` | `/api/scans/{id}/status` | Live stage progress and elapsed time |
| `GET` | `/api/scans/{id}/findings` | Findings (`?priority=&module=&status=`) |
| `GET` | `/api/scans/{id}/export/{sbom\|cbom\|sarif\|pdf\|csv\|json}` | Downloads |
| `POST` | `/api/findings/{id}/triage` | `{"status": "false_positive"\|"accepted_risk"\|"open", "justification": "…"}` |
| `GET` | `/api/projects/{id}/history` | Score trend |
| `GET` | `/api/projects/{id}/diff?base=&head=` | New / fixed / unchanged findings between two scans |
| `GET` | `/health` | Liveness and feed-cache status |

```sh
curl -F url=https://github.com/adeyosemanputra/pygoat http://localhost:8000/api/scans
curl http://localhost:8000/api/scans/1/status
curl -o sbom.json http://localhost:8000/api/scans/1/export/sbom
```

## Evaluation

Full results, regenerated by `python eval/evaluate.py --real-world`, are in [docs/EVALUATION.md](docs/EVALUATION.md).

**Labelled demo repository** (`demo/vulnerable-shop`, 10 commits, 56 planted issues including 17 genuinely vulnerable packages and 3 decoys):

| Module | Precision | Recall | F1 |
|---|---:|---:|---:|
| Secrets (HEAD + history) | 1.00 | 1.00 | 1.00 |
| SAST (Python + JS) | 1.00 | 1.00 | 1.00 |
| IaC / CI | 1.00 | 1.00 | 1.00 |
| Crypto | 1.00 | 1.00 | 1.00 |
| Dependencies (packages) | 1.00 | 1.00 | 1.00 |

All 3 decoys stayed silent. The scan found 179 CVEs across 32 components, with 3 in CISA KEV (Log4Shell CVE-2021-44228, CVE-2021-45046, and the libwebp CVE-2023-4863 via Pillow 8.0.0) and 3 secrets recoverable only from git history. Gate **FAIL, grade F**; the remediated twin is **PASS, grade A**.

**Real repositories** (live feeds):

| Repository | Components | CVEs | KEV | P0 | Grade | Scan time |
|---|---:|---:|---:|---:|---|---:|
| [OWASP PyGoat](https://github.com/adeyosemanputra/pygoat) (500 commits of history) | 46 | 153 | 1 | 6 | F | 14.1 s |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (HEAD only) | 170 | 40 | 0 | 1 | F | 36.7 s |

PyGoat's P0s include taint-confirmed SQL injection (`introduction/views.py:162`, `:878`) and command injection (`:430`) in its deliberately vulnerable labs, plus CVE-2023-4863 (KEV) in Pillow 9.4.0. Juice Shop's P0 is an RSA private key embedded in `infrastructure/terraform/networking.tf`.

## Deploy to Render

CodeSentinel is a server-rendered FastAPI application, not a static frontend. It needs a Python backend process for the UI, scan workers, SQLite database and REST API. The repository includes a Dockerfile and `render.yaml` for the backend.

1. Push this repository to GitHub.
2. In Render, create a Blueprint from the repository, or choose **New → Web Service → Build and deploy from a Git repository**.
3. Use the Docker runtime and the Free plan. Render detects the included `Dockerfile`.
4. Set `CS_ALLOW_LOCAL_PATHS=false`. Set `CS_GITHUB_TOKEN` only when scanning private repositories.
5. Use `/health` as the health check path and deploy.

The container binds `$PORT`, runs as a non-root user with a `HEALTHCHECK`, and keeps SQLite in `/app/data`. Render's free tier has ephemeral storage, so scan history resets after redeploy; attach a persistent disk mounted at `/app/data` if history and generated exports must survive restarts.

Netlify can host a separate static frontend, but it cannot run this Python FastAPI application through the current Netlify Functions setup. If you keep a Netlify site, configure it as a proxy to the deployed Render backend; do not use Netlify's default static publish page as the application URL.

## Configuration

All settings are environment variables prefixed `CS_` (or entries in `.env`); see [.env.example](.env.example). None are required.

| Variable | Default | Purpose |
|---|---|---|
| `CS_ALLOW_LOCAL_PATHS` | `true` (`false` in Docker) | Allow scanning server-side paths from the UI |
| `CS_DATA_DIR` / `CS_DATABASE_URL` | `./data` / SQLite in data dir | Storage |
| `CS_RATE_LIMIT_PER_MINUTE` | `5` | Scan submissions per IP |
| `CS_CLONE_TIMEOUT_SECONDS` / `CS_MAX_REPO_MB` / `CS_MAX_UPLOAD_MB` | `120` / `200` / `50` | Ingestion limits |
| `CS_HISTORY_MAX_COMMITS` | `500` | History scan depth |
| `CS_GITHUB_TOKEN` | empty | Optional; only raises the GitHub API limit for the pre-clone size check |
| `CS_SCORE_NORMALISER` / `CS_DEFAULT_FAIL_ON` | `10` / `p0` | Scoring |

## Ethics statement

- **Scan only repositories you own or are authorised to assess**, or public repositories for research and education. The demo repositories in this project are generated locally and contain fake credentials derived from fixed seeds.
- **Secrets are never validated.** CodeSentinel does not call AWS, GitHub, Stripe or any provider to test a key. Using a credential you do not own is unauthorised access even when the credential is public.
- **Secrets are never stored in full.** Each value is reduced to a SHA-256 fingerprint and a redacted preview (first 4 + `****` + last 4, less for short values) before it leaves the detector. Code snippets are redacted too. The test suite and the evaluation grep the database, exports, logs and rendered pages for every planted secret.
- **Scanned code is never executed.** No installs, builds, hooks or scripts; clones live in a temporary directory and are deleted after the scan.
- Findings about third-party projects should be reported to their maintainers through responsible disclosure.

## Limitations and future work

- **Reachability analysis.** A vulnerable package is reported even if the vulnerable function is never called. Call-graph reachability (as in Semgrep Supply Chain or Endor Labs) would cut noise further.
- **Container image layer scanning.** Dockerfiles are audited as text; OS packages inside built images are not inventoried (a Syft/Trivy-style layer scan would close this).
- **AIBOM.** CERT-In BOM v2.0 also covers AI models and datasets; detecting model files, licences and provenance is a natural next module.
- **Secret validity checks with owner consent.** For organisations scanning their own estate, an opt-in verifier that checks whether a leaked key is still live would sharpen prioritisation.
- **IDE plugin and pre-commit hook.** Catching a secret before the commit is cheaper than rewriting history after it.
- Taint tracking is intra-procedural; flows through helper functions or across files are not followed. JavaScript rules are token-based rather than AST-based. Go, Java and Rust source code are inventoried for dependencies but not analysed by SAST.
- `package.json` without a lockfile resolves ranges to their *minimum* version, which can over-report.

## Project layout

```
app/
  main.py            FastAPI app: pages, REST API, worker pool, security headers, rate limiting
  engine.py          scan pipeline shared by CLI and web
  config.py          settings (CS_* environment variables)
  db.py, models.py   SQLAlchemy: Project, Scan, Finding, Component, CryptoAsset, FeedCache
  ingest.py          GitHub clone, zip extraction (zip-slip safe), local paths
  policy.py          .codesentinel.yml
  scoring.py         tiers, risk, grade, gate
  scanners/          secrets, dependencies, intel, sast_python, sast_js, iac, crypto
  exporters/         sbom, cbom, sarif, csv_export, pdf
  templates/, static/
cli.py, codesentinel/   python -m codesentinel
demo/                make_demo_repo.py, ground_truth.json, data/ (real npm lockfiles)
eval/evaluate.py     precision/recall/F1 + real-world scans → docs/EVALUATION.md
tests/               270 tests (pytest, respx, TestClient)
docs/                ARCHITECTURE, EVALUATION, REPORT_CONTENT, VIVA_QA, screenshots/
```

<div align="center">

<img src="https://user-images.githubusercontent.com/74038190/212284115-f47cd8ff-2ffb-4b04-b5bf-4d1c14c0247f.gif" width="600">

<img src="https://user-images.githubusercontent.com/74038190/215283039-83bf4f37-3fe5-4d25-a42a-249d1a7e9e4f.gif" width="200" alt="Mission bug termination">
<img src="https://github.com/Anmol-Baranwal/Cool-GIFs-For-GitHub/assets/74038190/0b335028-1d3d-4ee5-b5b3-a373d499be7e" width="300" alt="Security stats">

</div>
