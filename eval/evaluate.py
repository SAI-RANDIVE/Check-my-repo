"""Evaluate CodeSentinel against the labelled demo repository and real public repositories.

Usage::

    python eval/evaluate.py                 # demo ground truth only (live intel)
    python eval/evaluate.py --real-world    # also clone and scan pygoat and juice-shop

Writes ``docs/EVALUATION.md``. Real-world results are cached in
``data/eval_realworld.json`` so the document can be regenerated without
re-cloning.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))

from app.config import APP_VERSION, configure_logging, get_settings  # noqa: E402
from app.db import init_db  # noqa: E402
from app.engine import ScanOptions, ScanReport, run_scan  # noqa: E402
from app.ingest import clone_repo, local_target  # noqa: E402

log = logging.getLogger("evaluate")
MODULES = ("secrets", "sast", "iac", "crypto", "dependencies")
REAL_WORLD = [
    {"url": "https://github.com/adeyosemanputra/pygoat", "history": True,
     "note": "OWASP PyGoat: intentionally vulnerable Django application"},
    {"url": "https://github.com/juice-shop/juice-shop", "history": False,
     "note": "OWASP Juice Shop: intentionally vulnerable Node/Angular application (shallow clone, HEAD only)"},
]


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """Precision, recall and F1 (1.0 when the denominator is empty)."""
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def evaluate_demo(report: ScanReport, gt: dict[str, Any]) -> dict[str, Any]:
    """Match findings to ground truth; return per-module metrics and error lists."""
    code = [f for f in report.findings if f.module != "dependencies"]
    used: set[int] = set()
    matched_gt: set[str] = set()
    for g in gt["findings"]:
        for i, f in enumerate(code):
            if i in used or f.rule_id != g["rule"] or f.file != g["file"]:
                continue
            if bool(f.extra.get("historical")) != bool(g.get("historical")):
                continue
            if not g.get("historical") and abs((f.line or 0) - g["line"]) > 1:
                continue
            used.add(i)
            matched_gt.add(g["id"])
            break
    per: dict[str, dict[str, Any]] = {m: {"tp": 0, "fp": 0, "fn": 0, "fps": [], "fns": []} for m in MODULES}
    for i, f in enumerate(code):
        m = per[f.module]
        if i in used:
            m["tp"] += 1
        else:
            m["fp"] += 1
            m["fps"].append(f"{f.rule_id} at {f.file}:{f.line}")
    for g in gt["findings"]:
        if g["id"] not in matched_gt:
            per[g["module"]]["fn"] += 1
            per[g["module"]]["fns"].append(f"{g['rule']} at {g['file']}:{g['line']}")
    # dependencies at package level
    expected = {(d["ecosystem"], d["package"]) for d in gt["vulnerable_dependencies"]}
    detected = {(f.extra["ecosystem"], f.extra["package"]) for f in report.findings if f.module == "dependencies"}
    dm = per["dependencies"]
    dm["tp"] = len(expected & detected)
    dm["fp"] = len(detected - expected)
    dm["fn"] = len(expected - detected)
    dm["fps"] = [f"{e}:{p}" for e, p in sorted(detected - expected)]
    dm["fns"] = [f"{e}:{p}" for e, p in sorted(expected - detected)]
    for m in per.values():
        m["precision"], m["recall"], m["f1"] = prf(m["tp"], m["fp"], m["fn"])
    tot = {k: sum(per[m][k] for m in MODULES) for k in ("tp", "fp", "fn")}
    tot["precision"], tot["recall"], tot["f1"] = prf(tot["tp"], tot["fp"], tot["fn"])
    decoys = []
    locs = {(f.file, f.line) for f in code}
    for d in gt["decoys"]:
        decoys.append({**d, "flagged": (d["file"], d["line"]) in locs})
    return {"modules": per, "total": tot, "decoys": decoys}


def summarise(report: ScanReport) -> dict[str, Any]:
    """Headline numbers for a scan."""
    st = report.stats
    deps = [f for f in report.findings if f.module == "dependencies"]
    kev = sorted({c for f in deps for c in f.extra.get("kev_cves", [])})
    top = sorted(deps, key=lambda f: -f.risk_score)[:5]
    return {
        "target": report.target, "commit": (report.commit_sha or "")[:12], "grade": report.gate.grade,
        "score": report.gate.score, "gate": "PASS" if report.gate.passed else "FAIL", "counts": report.gate.counts,
        "components": st.get("components", 0), "direct": st.get("components_direct", 0),
        "transitive": st.get("components_transitive", 0), "ecosystems": st.get("ecosystems", {}),
        "vulnerable_components": st.get("components_vulnerable", 0), "dependency_vulns": st.get("dependency_vulns", 0),
        "cves": st.get("cves", 0), "kev_hits": st.get("kev_hits", 0), "kev_cves": kev,
        "epss_populated": st.get("epss_populated", 0), "by_module": st.get("by_module", {}),
        "secrets_head": st.get("secrets_head", 0), "secrets_history": st.get("secrets_history", 0),
        "commits_scanned": st.get("commits_scanned", 0), "files": st.get("files_scanned", 0),
        "duration": report.duration_seconds, "stage_seconds": st.get("stage_seconds", {}),
        "intel_partial": report.intel_partial,
        "p0": [{"rule": f.rule_id, "title": f.title, "where": f"{f.file}:{f.line}", "why": f.extra.get("priority_reason")}
               for f in report.active_findings if f.priority == "P0"],
        "top_risks": [{"id": f.rule_id, "package": f"{f.extra['package']} {f.extra['version']}",
                       "cvss": f.extra.get("cvss_score"), "epss": f.extra.get("epss"), "kev": f.extra.get("in_kev"),
                       "priority": f.priority} for f in top],
    }


def run_real_world() -> list[dict[str, Any]]:
    """Clone and scan the public validation repositories."""
    out = []
    for rw in REAL_WORLD:
        log.info("scanning %s", rw["url"])
        t0 = time.perf_counter()
        target = clone_repo(rw["url"], include_history=rw["history"])
        clone_s = time.perf_counter() - t0
        try:
            rep = run_scan(target, ScanOptions(include_history=rw["history"]))
        finally:
            target.cleanup()
        s = summarise(rep)
        s.update({"url": rw["url"], "note": rw["note"], "history": rw["history"], "clone_seconds": round(clone_s, 1)})
        out.append(s)
    return out


def fmt_epss(v: float | None) -> str:
    return "-" if v is None else f"{v:.3f}"


def pct(x: float) -> str:
    return f"{x:.2f}"


def write_markdown(demo: dict[str, Any], metrics: dict[str, Any], fixed: dict[str, Any], real: list[dict[str, Any]],
                   path: Path) -> None:
    """Render docs/EVALUATION.md."""
    now = datetime.now(UTC).strftime("%d %B %Y")
    L: list[str] = []
    a = L.append
    a("# Evaluation\n")
    a(f"Generated by `python eval/evaluate.py --real-world` on {now} with CodeSentinel {APP_VERSION}. "
      "All dependency intelligence was fetched live from OSV.dev, FIRST EPSS and the CISA KEV catalogue at run time, "
      "so CVE and EPSS figures reflect the feeds on that date.\n")
    a("## 1. Ground-truth evaluation on `demo/vulnerable-shop`\n")
    a("`demo/make_demo_repo.py` builds a 10-commit Flask + Node + Java repository with every planted issue labelled in "
      "`demo/ground_truth.json` (module, rule, file, line). Code findings are matched on rule + file + line (±1); "
      "history-only secrets on rule + file + historical flag; dependencies at package level (a planted vulnerable "
      "package counts as detected when at least one advisory is reported for it).\n")
    a("| Module | Planted | TP | FP | FN | Precision | Recall | F1 |")
    a("|---|---:|---:|---:|---:|---:|---:|---:|")
    labels = {"secrets": "Secrets (HEAD + history)", "sast": "SAST (Python + JS)", "iac": "IaC / CI", "crypto": "Crypto",
              "dependencies": "Dependencies (packages)"}
    for m in MODULES:
        x = metrics["modules"][m]
        a(f"| {labels[m]} | {x['tp'] + x['fn']} | {x['tp']} | {x['fp']} | {x['fn']} | {pct(x['precision'])} | "
          f"{pct(x['recall'])} | {pct(x['f1'])} |")
    t = metrics["total"]
    a(f"| **Overall (micro)** | **{t['tp'] + t['fn']}** | **{t['tp']}** | **{t['fp']}** | **{t['fn']}** | "
      f"**{pct(t['precision'])}** | **{pct(t['recall'])}** | **{pct(t['f1'])}** |\n")
    a(f"Targets: recall ≥ 0.95 and precision ≥ 0.90. Result: recall **{pct(t['recall'])}**, precision "
      f"**{pct(t['precision'])}**.\n")
    fps = [f"{m}: {e}" for m in MODULES for e in metrics["modules"][m]["fps"]]
    fns = [f"{m}: {e}" for m in MODULES for e in metrics["modules"][m]["fns"]]
    a("**False positives:** " + ("; ".join(fps) if fps else "none.") + "\n")
    a("**False negatives:** " + ("; ".join(fns) if fns else "none.") + "\n")
    a("### Decoys (must not be flagged)\n")
    a("| Decoy | Location | Flagged |")
    a("|---|---|---|")
    for d in metrics["decoys"]:
        a(f"| {d['description']} | `{d['file']}:{d['line']}` | {'**yes (failure)**' if d['flagged'] else 'no'} |")
    a("")
    a("### Scan of the vulnerable demo\n")
    c = demo["counts"]
    a(f"- Gate **{demo['gate']}**, grade **{demo['grade']}** ({demo['score']:.0f}/100); P0 {c['P0']}, P1 {c['P1']}, "
      f"P2 {c['P2']}, P3 {c['P3']}.")
    a(f"- {demo['components']} components ({demo['direct']} direct, {demo['transitive']} transitive; "
      + ", ".join(f"{k} {v}" for k, v in demo["ecosystems"].items()) + f"), {demo['vulnerable_components']} vulnerable, "
      f"{demo['dependency_vulns']} distinct advisories covering {demo['cves']} CVEs.")
    a(f"- CISA KEV hits: **{demo['kev_hits']}** ({', '.join(demo['kev_cves'])}). EPSS populated for "
      f"{demo['epss_populated']} of {demo['dependency_vulns']} dependency findings.")
    a(f"- Secrets: {demo['secrets_head']} live in HEAD, {demo['secrets_history']} recoverable only from history "
      f"({demo['commits_scanned']} commits walked).")
    a(f"- Scan time {demo['duration']:.1f} s (" + ", ".join(f"{k} {v:.2f} s" for k, v in demo["stage_seconds"].items())
      + "). Intel enrichment dominates on a cold cache and drops below 1 s once the SQLite feed cache is warm.\n")
    a("Highest-risk dependency findings:\n")
    a("| Vulnerability | Package | CVSS | EPSS | KEV | Tier |")
    a("|---|---|---:|---:|---|---|")
    for r in demo["top_risks"]:
        a(f"| {r['id']} | {r['package']} | {r['cvss'] if r['cvss'] is not None else '-'} | "
          f"{fmt_epss(r['epss'])} | {'yes' if r['kev'] else 'no'} | {r['priority']} |")
    a("")
    a("### Remediated twin `demo/vulnerable-shop-fixed`\n")
    fc = fixed["counts"]
    a(f"Gate **{fixed['gate']}**, grade **{fixed['grade']}** ({fixed['score']:.0f}/100); P0 {fc['P0']}, P1 {fc['P1']}, "
      f"P2 {fc['P2']}, P3 {fc['P3']} (remaining P3 items are `.env.example` placeholders). {fixed['components']} "
      f"components, {fixed['cves']} known CVEs. This is the FAIL → PASS transition shown in the demo.\n")
    a("## 2. Real-world validation\n")
    if not real:
        a("_Run `python eval/evaluate.py --real-world` to populate this section._\n")
    else:
        a("| Repository | Commit | Components | Vulnerable | CVEs | KEV hits | EPSS populated | P0 / P1 / P2 / P3 | Grade | Gate | Scan time |")
        a("|---|---|---:|---:|---:|---:|---:|---|---|---|---:|")
        for r in real:
            c = r["counts"]
            a(f"| [{r['target']}]({r['url']}) | `{r['commit']}` | {r['components']} | {r['vulnerable_components']} | "
              f"{r['cves']} | {r['kev_hits']} | {r['epss_populated']}/{r['dependency_vulns']} | "
              f"{c['P0']} / {c['P1']} / {c['P2']} / {c['P3']} | {r['grade']} | {r['gate']} | "
              f"{r['duration']:.1f} s (+{r['clone_seconds']:.1f} s clone) |")
        a("")
        for r in real:
            a(f"### {r['target']}\n")
            a(f"{r['note']}. History scanned: {'yes, ' + str(r['commits_scanned']) + ' commits' if r['history'] else 'no'}; "
              f"{r['files']} files; ecosystems " + ", ".join(f"{k} {v}" for k, v in r["ecosystems"].items()) + ".\n")
            a("- Open findings by module: " + ", ".join(f"{k} {v}" for k, v in r["by_module"].items()) + ".")
            if r["kev_cves"]:
                a(f"- CVEs in CISA KEV: {', '.join(r['kev_cves'])}.")
            a(f"- Secrets: {r['secrets_head']} in HEAD, {r['secrets_history']} history-only.")
            if r.get("p0"):
                a("- P0 findings: " + "; ".join(f"`{x['rule']}` {x['where']} ({x['why']})" for x in r["p0"]) + ".")
            a("")
            a("| Top-risk vulnerability | Package | CVSS | EPSS | KEV | Tier |")
            a("|---|---|---:|---:|---|---|")
            for t_ in r["top_risks"]:
                a(f"| {t_['id']} | {t_['package']} | {t_['cvss'] if t_['cvss'] is not None else '-'} | "
                  f"{fmt_epss(t_['epss'])} | {'yes' if t_['kev'] else 'no'} | {t_['priority']} |")
            a("")
    a("## 3. Method notes and threats to validity\n")
    a("- The demo ground truth is written by the same author as the rules, so it measures whether each rule "
      "fires where intended and stays quiet on the decoys. It is not an estimate of performance on arbitrary code.")
    a("- Dependency precision is measured at package level: every advisory OSV returns for a pinned version is "
      "reported. Whether the vulnerable function is reachable is not analysed (see Limitations in the README).")
    a("- Real-world repositories have no ground truth; the table reports volumes and exploit signals. Spot checks of "
      "the P0 items (KEV-listed CVEs, taint-confirmed injections) are described in `docs/REPORT_CONTENT.md`.")
    a("- EPSS scores change daily and OSV advisories are added continuously, so re-running will change the counts.")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--real-world", action="store_true", help="also clone and scan pygoat and juice-shop")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "EVALUATION.md")
    args = ap.parse_args(argv)
    configure_logging("INFO")
    init_db()
    import make_demo_repo as mdr

    vuln, fixed = ROOT / "demo" / "vulnerable-shop", ROOT / "demo" / "vulnerable-shop-fixed"
    gt = mdr.build_vulnerable(vuln)
    mdr.build_fixed(fixed)
    (ROOT / "demo" / "ground_truth.json").write_text(json.dumps(gt, indent=2) + "\n", encoding="utf-8")
    rep = run_scan(local_target(str(vuln)), ScanOptions())
    metrics = evaluate_demo(rep, gt)
    demo = summarise(rep)
    fixed_s = summarise(run_scan(local_target(str(fixed)), ScanOptions()))
    cache = get_settings().data_dir / "eval_realworld.json"
    real: list[dict[str, Any]] = []
    if args.real_world:
        real = run_real_world()
        cache.write_text(json.dumps(real, indent=2), encoding="utf-8")
    elif cache.is_file():
        real = json.loads(cache.read_text("utf-8"))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_markdown(demo, metrics, fixed_s, real, args.out)
    (get_settings().data_dir / "eval_metrics.json").write_text(json.dumps(
        {"metrics": metrics, "demo": demo, "fixed": fixed_s, "real": real}, indent=2, default=str), encoding="utf-8")
    t = metrics["total"]
    log.info("overall precision %.3f recall %.3f f1 %.3f; decoys flagged: %d", t["precision"], t["recall"], t["f1"],
             sum(d["flagged"] for d in metrics["decoys"]))
    log.info("wrote %s", args.out)
    return 0 if t["recall"] >= 0.95 and t["precision"] >= 0.90 and not any(d["flagged"] for d in metrics["decoys"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
