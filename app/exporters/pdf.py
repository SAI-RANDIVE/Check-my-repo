"""Executive + technical PDF report built with reportlab (charts rendered with matplotlib)."""

from __future__ import annotations

import io
from collections import Counter, defaultdict
from datetime import datetime
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

import matplotlib
import matplotlib.ticker

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.config import APP_NAME, APP_VERSION  # noqa: E402
from app.scanners.base import Finding  # noqa: E402

if TYPE_CHECKING:
    from app.engine import ScanReport

INK = colors.HexColor("#14161a")
MUTED = colors.HexColor("#5b6070")
RULE = colors.HexColor("#d9dbe1")
ACCENT = colors.HexColor("#4f5bd5")
ZEBRA = colors.HexColor("#f6f7f9")
PRIORITY_HEX = {"P0": "#d03b3b", "P1": "#ec835a", "P2": "#fab219", "P3": "#9a9ca5"}
GRADE_HEX = {"A": "#0ca30c", "B": "#4f9a3a", "C": "#c98500", "D": "#ec835a", "F": "#d03b3b"}
MODULE_LABEL = {"secrets": "Secrets", "dependencies": "Dependencies", "sast": "SAST", "iac": "IaC / CI", "crypto": "Crypto"}

ss = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=ss["Normal"], fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.6, leading=9.6)
MUTED_P = ParagraphStyle("muted", parent=BODY, textColor=MUTED, fontSize=8.5, leading=11.5)
H1 = ParagraphStyle("h1", parent=BODY, fontName="Helvetica-Bold", fontSize=17, leading=21, spaceAfter=6, spaceBefore=4)
H2 = ParagraphStyle("h2", parent=BODY, fontName="Helvetica-Bold", fontSize=12, leading=15, spaceBefore=10, spaceAfter=5)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=7.6, leading=9.4)
CELL_B = ParagraphStyle("cellb", parent=CELL, fontName="Helvetica-Bold")


def _p(text: object, style: ParagraphStyle = CELL) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")), style)


def _table(rows: list[list[object]], widths: list[float], header: bool = True, zebra: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
    ]
    if header:
        style += [("LINEBELOW", (0, 0), (-1, 0), 0.8, INK)]
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    t.setStyle(TableStyle(style))
    return t


def _png(fig: plt.Figure) -> io.BytesIO:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf


def _style_axes(ax: plt.Axes) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#c9ccd4")
    ax.tick_params(colors="#5b6070", labelsize=8)
    ax.yaxis.label.set_color("#5b6070")
    ax.xaxis.label.set_color("#5b6070")


def chart_modules(report: ScanReport) -> io.BytesIO:
    """Bar chart: open findings per module (single series, one hue)."""
    counts = report.stats.get("by_module", {})
    labels = [MODULE_LABEL[m] for m in MODULE_LABEL]
    values = [counts.get(m, 0) for m in MODULE_LABEL]
    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    bars = ax.bar(labels, values, color="#2a78d6", width=0.55, edgecolor="white", linewidth=1)
    ax.bar_label(bars, padding=2, fontsize=8, color="#14161a")
    ax.set_title("Open findings by module", fontsize=9.5, loc="left", color="#14161a", fontweight="bold")
    ax.grid(axis="y", color="#eceef2", linewidth=0.6)
    ax.set_axisbelow(True)
    _style_axes(ax)
    return _png(fig)


def chart_priority(report: ScanReport) -> io.BytesIO:
    """Doughnut: open findings by priority tier (status colours, labelled)."""
    c = report.gate.counts
    tiers = [t for t in ("P0", "P1", "P2", "P3") if c.get(t)]
    fig, ax = plt.subplots(figsize=(3.2, 2.6))
    if tiers:
        ax.pie([c[t] for t in tiers], colors=[PRIORITY_HEX[t] for t in tiers], startangle=90, counterclock=False,
               wedgeprops={"width": 0.38, "edgecolor": "white", "linewidth": 2},
               labels=[f"{t}  {c[t]}" for t in tiers], textprops={"fontsize": 8, "color": "#14161a"})
    else:
        ax.text(0, 0, "No open findings", ha="center", va="center", fontsize=9, color="#5b6070")
    ax.set_title("By priority", fontsize=9.5, loc="left", color="#14161a", fontweight="bold")
    ax.axis("equal")
    return _png(fig)


def chart_scatter(report: ScanReport) -> io.BytesIO | None:
    """CVSS vs EPSS scatter with CISA KEV points highlighted (the exploit-aware view)."""
    pts = [(f.extra["cvss_score"], f.extra["epss"], f.extra.get("in_kev")) for f in report.findings
           if f.module == "dependencies" and f.extra.get("cvss_score") is not None and f.extra.get("epss") is not None]
    if not pts:
        return None
    fig, ax = plt.subplots(figsize=(7.2, 3.3))
    normal = [(x, y) for x, y, k in pts if not k]
    kev = [(x, y) for x, y, k in pts if k]
    if normal:
        ax.scatter(*zip(*normal, strict=True), s=22, color="#2a78d6", alpha=0.75, edgecolors="white", linewidths=0.6,
                   label="Not in KEV")
    if kev:
        ax.scatter(*zip(*kev, strict=True), s=70, color="#d03b3b", edgecolors="#14161a", linewidths=1.0,
                   label="In CISA KEV", zorder=3)
    ax.set_yscale("symlog", linthresh=0.01)
    ax.set_ylim(0, 1.6)
    ax.set_yticks([0, 0.01, 0.1, 1.0])
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0%}"))
    ax.set_xlim(0, 10.3)
    ax.axvline(9.0, color="#9a9ca5", linewidth=0.7, linestyle=(0, (3, 3)))
    ax.axhline(0.10, color="#9a9ca5", linewidth=0.7, linestyle=(0, (3, 3)))
    ax.text(9.08, 0.13, "P0 zone", fontsize=7.5, color="#5b6070")
    ax.set_xlabel("CVSS base score", fontsize=8)
    ax.set_ylabel("EPSS (probability of exploitation, 30 days)", fontsize=8)
    ax.set_title("Severity vs. likelihood of exploitation", fontsize=9.5, loc="left", color="#14161a",
                 fontweight="bold")
    ax.grid(color="#eceef2", linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(fontsize=7.5, frameon=False, loc="upper left")
    _style_axes(ax)
    return _png(fig)


def top_actions(report: ScanReport, n: int = 5) -> list[str]:
    """The ``n`` highest-impact remediation actions, grouped by package where possible."""
    actions: list[tuple[float, str]] = []
    by_pkg: dict[str, list[Finding]] = defaultdict(list)
    for f in report.active_findings:
        if f.module == "dependencies":
            by_pkg[f.extra["package"] + "|" + f.extra["ecosystem"]].append(f)
    for _key, fs in by_pkg.items():
        risk = sum(f.risk_score for f in fs)
        f0 = max(fs, key=lambda f: f.risk_score)
        fixed = [f.extra.get("fixed_version") for f in fs if f.extra.get("fixed_version")]
        kev = sorted({c for f in fs for c in f.extra.get("kev_cves", [])})
        from app.scanners.intel import _vcmp

        target = None
        for v in fixed:
            if target is None or _vcmp(f0.extra["ecosystem"], v, target) > 0:
                target = v
        text = (f"Upgrade {f0.extra['package']} {f0.extra['version']} to {target or 'a patched release'} "
                f"(resolves {len(fs)} known vulnerabilit{'y' if len(fs) == 1 else 'ies'}"
                + (f", including actively exploited {', '.join(kev)}" if kev else "") + ").")
        actions.append((risk, text))
    for f in report.active_findings:
        if f.module == "dependencies" or f.priority not in ("P0", "P1"):
            continue
        if f.module == "secrets":
            text = (f"Revoke and rotate the {f.title.split(' (')[0].replace(' committed to source', '').replace(' in git history', '')} "
                    f"({f.extra.get('redacted')}) found {'in history, commit ' + str(f.extra.get('commit'))[:8] if f.extra.get('historical') else 'in ' + f.file}.")
        else:
            text = f"Fix {f.title.lower()} in {f.file}:{f.line}."
        actions.append((f.risk_score, text))
    actions.sort(key=lambda a: -a[0])
    seen: list[str] = []
    for _, t in actions:
        if t not in seen:
            seen.append(t)
        if len(seen) == n:
            break
    return seen


def _header_footer(canvas, doc) -> None:  # type: ignore[no-untyped-def]
    canvas.saveState()
    w, h = A4
    if doc.page > 1:
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(INK)
        canvas.drawString(18 * mm, h - 12 * mm, APP_NAME)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(w - 18 * mm, h - 12 * mm, doc.cs_target)
        canvas.setStrokeColor(RULE)
        canvas.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "Confidential: security assessment. Secret values are redacted; only fingerprints are stored.")
    canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _cover(canvas, doc) -> None:  # type: ignore[no-untyped-def]
    _header_footer(canvas, doc)
    r = doc.cs_report
    w, h = A4
    canvas.saveState()
    # shield mark
    x, y = 18 * mm, h - 40 * mm
    p = canvas.beginPath()
    p.moveTo(x + 7 * mm, y + 9 * mm)
    p.lineTo(x + 14 * mm, y + 6.5 * mm)
    p.lineTo(x + 14 * mm, y + 1 * mm)
    p.curveTo(x + 14 * mm, y - 4 * mm, x + 10 * mm, y - 7 * mm, x + 7 * mm, y - 8.5 * mm)
    p.curveTo(x + 4 * mm, y - 7 * mm, x, y - 4 * mm, x, y + 1 * mm)
    p.lineTo(x, y + 6.5 * mm)
    p.close()
    canvas.setFillColor(ACCENT)
    canvas.drawPath(p, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 20)
    canvas.setFillColor(INK)
    canvas.drawString(x + 19 * mm, y - 1 * mm, APP_NAME)
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(MUTED)
    canvas.drawString(x + 19 * mm, y - 6 * mm, "Software supply-chain security assessment")
    # grade block
    gx, gy = w - 18 * mm - 34 * mm, h - 48 * mm
    canvas.setFillColor(colors.HexColor(GRADE_HEX.get(r.gate.grade, "#5b6070")))
    canvas.roundRect(gx, gy, 34 * mm, 26 * mm, 3 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 34)
    canvas.drawCentredString(gx + 17 * mm, gy + 10 * mm, r.gate.grade)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(gx + 17 * mm, gy + 4 * mm, f"score {r.gate.score:.0f} / 100")
    canvas.restoreState()


def build_pdf(report: ScanReport) -> bytes:
    """Render the full PDF report and return its bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm,
                            bottomMargin=18 * mm, title=f"{APP_NAME} report: {report.target}", author=APP_NAME,
                            subject="Security assessment")
    doc.cs_target = report.target  # type: ignore[attr-defined]
    doc.cs_report = report  # type: ignore[attr-defined]
    st = report.stats
    gate = report.gate
    story: list = []
    width = A4[0] - 36 * mm

    # ---------------------------------------------------------------- cover
    story.append(Spacer(1, 52 * mm))
    story.append(Paragraph(escape(report.target), ParagraphStyle("t", parent=H1, fontSize=24, leading=29)))
    when = datetime.fromisoformat(report.finished_at).strftime("%d %B %Y, %H:%M UTC")
    meta = [
        ["Source", report.source], ["Commit", (report.commit_sha or "n/a")[:40]], ["Branch", report.branch or "n/a"],
        ["Scanned", when], ["Duration", f"{report.duration_seconds:.1f} s"],
        ["Gate", f"{'PASS' if gate.passed else 'FAIL'} (fail on {gate.fail_on.upper()})"],
        ["Tool", f"{APP_NAME} {APP_VERSION}"],
    ]
    story.append(_table([[_p(k, CELL_B), _p(v)] for k, v in meta], [32 * mm, width - 32 * mm], header=False, zebra=False))
    story.append(Spacer(1, 10 * mm))
    verdict_color = "#d03b3b" if not gate.passed else "#0ca30c"
    story.append(Paragraph(f'<font color="{verdict_color}"><b>{"GATE FAILED" if not gate.passed else "GATE PASSED"}</b></font>'
                           f" &nbsp; {escape(gate.reasons[0])}", BODY))
    kpis = [["P0", "P1", "P2", "P3", "Components", "CVEs", "KEV hits", "Secrets (HEAD / history)"],
            [gate.counts.get("P0", 0), gate.counts.get("P1", 0), gate.counts.get("P2", 0), gate.counts.get("P3", 0),
             st.get("components", 0), st.get("cves", 0), st.get("kev_hits", 0),
             f"{st.get('secrets_head', 0)} / {st.get('secrets_history', 0)}"]]
    story.append(Spacer(1, 6 * mm))
    story.append(_table([[_p(c, CELL_B) for c in kpis[0]], [_p(c) for c in kpis[1]]], [width / 8] * 8))
    story.append(PageBreak())

    # ---------------------------------------------------------------- executive summary
    story.append(Paragraph("Executive summary", H1))
    p0, p1 = gate.counts.get("P0", 0), gate.counts.get("P1", 0)
    risk_word = "critical" if p0 else "high" if p1 else "moderate" if gate.counts.get("P2") else "low"
    summary = (
        f"{escape(report.target)} received grade <b>{gate.grade}</b> ({gate.score:.0f}/100). Overall risk is "
        f"<b>{risk_word}</b>. The scan inventoried {st.get('components', 0)} third-party components "
        f"({st.get('components_vulnerable', 0)} with known vulnerabilities, {st.get('cves', 0)} distinct CVEs), "
        f"{st.get('files_scanned', 0)} files and {st.get('commits_scanned', 0)} commits of history. "
    )
    if st.get("kev_hits"):
        summary += (f"<b>{st['kev_hits']} dependency vulnerabilit{'y is' if st['kev_hits'] == 1 else 'ies are'} on the "
                    f"CISA Known Exploited Vulnerabilities list</b>, so attackers are already using them in the wild. ")
    if st.get("secrets_head") or st.get("secrets_history"):
        summary += (f"{st.get('secrets_head', 0)} credential(s) are present in the current code and "
                    f"{st.get('secrets_history', 0)} more can still be recovered from git history. ")
    summary += (f"There are {p0} P0 (act now) and {p1} P1 (fix this sprint) findings. The CI gate "
                f"{'blocks' if not gate.passed else 'allows'} this build at the {gate.fail_on.upper()} threshold.")
    story.append(Paragraph(summary, BODY))
    story.append(Paragraph("Gate decision", H2))
    for r in gate.reasons[:10]:
        story.append(Paragraph("&bull; " + escape(r), BODY))
    story.append(Paragraph("Top 5 actions", H2))
    for i, a in enumerate(top_actions(report), 1):
        story.append(Paragraph(f"<b>{i}.</b> {escape(a)}", BODY))
    if report.intel_partial:
        story.append(Spacer(1, 4))
        story.append(Paragraph("Note: one or more threat-intelligence feeds were unavailable during this scan; "
                               "affected findings are marked intel_partial.", MUTED_P))
    story.append(Paragraph("Risk overview", H2))
    row = Table([[Image(chart_modules(report), width=96 * mm, height=59 * mm),
                  Image(chart_priority(report), width=74 * mm, height=60 * mm)]], colWidths=[100 * mm, width - 100 * mm])
    story.append(row)
    sc = chart_scatter(report)
    if sc:
        story.append(KeepTogether([Image(sc, width=width, height=width * 3.3 / 7.2),
                                   Paragraph("Each dot is one dependency vulnerability. CVSS measures how bad it would be; "
                                             "EPSS estimates how likely it is to be exploited in the next 30 days. Red dots "
                                             "are in CISA KEV and are always P0.", MUTED_P)]))
    story.append(PageBreak())

    # ---------------------------------------------------------------- findings per priority
    story.append(Paragraph("Findings by priority", H1))
    for tier in ("P0", "P1", "P2", "P3"):
        fs = [f for f in report.active_findings if f.priority == tier]
        story.append(Paragraph(f'<font color="{PRIORITY_HEX[tier]}">&#9632;</font> {tier}: {len(fs)} finding(s)', H2))
        if not fs:
            story.append(Paragraph("None.", MUTED_P))
            continue
        rows = [[_p(h, CELL_B) for h in ("Module", "Rule", "Finding", "Location", "Why this tier")]]
        for f in fs[:45]:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            rows.append([_p(MODULE_LABEL.get(f.module, f.module)), _p(f.rule_id), _p(f.title), _p(loc),
                         _p(f.extra.get("priority_reason", ""))])
        story.append(_table(rows, [20 * mm, 30 * mm, 58 * mm, 34 * mm, width - 142 * mm]))
        if len(fs) > 45:
            story.append(Paragraph(f"{len(fs) - 45} more {tier} findings are listed in the appendix.", MUTED_P))
    story.append(PageBreak())

    # ---------------------------------------------------------------- dependencies
    story.append(Paragraph("Dependency vulnerabilities", H1))
    story.append(Paragraph(
        f"{st.get('components', 0)} components ({st.get('components_direct', 0)} direct, "
        f"{st.get('components_transitive', 0)} transitive) across "
        f"{', '.join(f'{k} ({v})' for k, v in (st.get('ecosystems') or {}).items()) or 'no ecosystems'}. "
        "Sorted by risk score = severity weight x (1 + 4*EPSS + 2 if KEV) x exposure.", MUTED_P))
    deps = sorted([f for f in report.findings if f.module == "dependencies"], key=lambda f: -f.risk_score)
    if deps:
        rows = [[_p(h, CELL_B) for h in ("Tier", "Package", "Vulnerability", "CVSS", "EPSS", "KEV", "Fix")]]
        for f in deps[:70]:
            x = f.extra
            rows.append([_p(f.priority), _p(f"{x['package']} {x['version']}"), _p(f.rule_id),
                         _p(f"{x['cvss_score']:.1f}" if x.get("cvss_score") is not None else "-"),
                         _p(f"{x['epss']:.3f} (p{x['epss_percentile'] * 100:.0f})" if x.get("epss") is not None else "-"),
                         _p(f"Yes, due {x['kev_due_date']}" if x.get("in_kev") else "No"),
                         _p(x.get("fixed_version") or "none")])
        story.append(_table(rows, [11 * mm, 38 * mm, 32 * mm, 13 * mm, 24 * mm, 28 * mm, width - 146 * mm]))
        if len(deps) > 70:
            story.append(Paragraph(f"{len(deps) - 70} lower-risk vulnerabilities omitted here; see the appendix and SBOM.", MUTED_P))
    else:
        story.append(Paragraph("No known vulnerabilities in the inventoried components.", BODY))

    # ---------------------------------------------------------------- crypto
    story.append(Paragraph("Cryptography inventory (CBOM)", H1))
    if report.crypto_assets:
        agg: dict[str, list] = {}
        for a in report.crypto_assets:
            agg.setdefault(a.name, [a, 0, set()])
            agg[a.name][1] += 1
            agg[a.name][2].add(a.file)
        rows = [[_p(h, CELL_B) for h in ("Algorithm", "Primitive", "Class", "Quantum-vulnerable", "Uses", "Files")]]
        for name, (a, n, files) in sorted(agg.items(), key=lambda kv: ({"broken": 0, "weak": 1, "approved": 2}[kv[1][0].classification], kv[0])):
            rows.append([_p(name), _p(a.primitive), _p(a.classification), _p("yes" if a.quantum_vulnerable else "no"),
                         _p(n), _p(", ".join(sorted(files))[:120])])
        story.append(_table(rows, [42 * mm, 22 * mm, 18 * mm, 24 * mm, 11 * mm, width - 117 * mm]))
        cls = Counter(a.classification for a in report.crypto_assets)
        story.append(Paragraph(f"{cls.get('broken', 0)} broken, {cls.get('weak', 0)} weak, {cls.get('approved', 0)} approved usages; "
                               f"{st.get('quantum_vulnerable_assets', 0)} rely on RSA/ECC and need a post-quantum migration plan.", MUTED_P))
    else:
        story.append(Paragraph("No cryptographic API usage detected.", BODY))
    story.append(PageBreak())

    # ---------------------------------------------------------------- methodology
    story.append(Paragraph("Methodology and data sources", H1))
    for line in [
        "<b>Secrets</b>: 27 provider signatures, generic credential assignments and Shannon entropy (base64 &ge; 4.3, "
        "hex &ge; 3.0 bits/char, length &ge; 20) with keyword context; full git history up to 500 commits. Values are never "
        "stored or validated against providers; only SHA-256 fingerprints and redacted previews are kept.",
        "<b>Dependencies</b>: manifests and lockfiles (pip, Pipenv, Poetry, npm v1-v3, Maven, Go) resolved to package URLs, "
        "matched against OSV.dev; CVSS computed from vectors; exploit likelihood from FIRST EPSS; active exploitation from the "
        "CISA KEV catalogue. Feeds are cached with a TTL; outages degrade gracefully.",
        "<b>SAST</b>: Python via abstract-syntax-tree analysis with intra-procedural taint tracking from request data, input() "
        "and sys.argv; JavaScript/TypeScript via comment-aware token rules.",
        "<b>IaC / CI</b>: Dockerfile, docker-compose, committed .env and GitHub Actions workflow rules, including action "
        "pinning (tj-actions/changed-files, CVE-2025-30066), pull_request_target misuse and script injection.",
        "<b>Crypto</b>: algorithm, mode, key size and protocol inventory classified approved / weak / broken, with "
        "quantum-vulnerability flags, exported as a CycloneDX 1.6 CBOM.",
        "<b>Prioritisation</b>: P0 = KEV, or CVSS &ge; 9 with EPSS &ge; 0.10, or a live secret in HEAD, or taint-confirmed "
        "injection. P1 = CVSS &ge; 7 with EPSS &ge; 0.01, history secrets, pull_request_target misuse, broken crypto. "
        "P2 = other CVSS &ge; 4, unpinned actions, root containers, weak crypto, untainted SAST. P3 = the rest.",
        "<b>Score</b>: 100 - min(100, total risk / normaliser); A &ge; 90, B &ge; 80, C &ge; 70, D &ge; 55, F below.",
    ]:
        story.append(Paragraph(line, BODY))
        story.append(Spacer(1, 3))
    story.append(Paragraph("Sources", H2))
    for s in ["OSV.dev vulnerability database: https://osv.dev", "FIRST EPSS: https://www.first.org/epss/",
              "CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
              "CycloneDX 1.6: https://cyclonedx.org/specification/overview/",
              "SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/",
              "CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM (v2.0, July 2025)",
              "OWASP Top 10:2021 and MITRE CWE"]:
        story.append(Paragraph("&bull; " + escape(s), BODY))
    story.append(PageBreak())

    # ---------------------------------------------------------------- appendix
    story.append(Paragraph(f"Appendix: all findings ({len(report.findings)})", H1))
    rows = [[_p(h, CELL_B) for h in ("#", "Tier", "Sev.", "Rule", "Title", "Location", "Status")]]
    for i, f in enumerate(report.findings, 1):
        rows.append([_p(i, SMALL), _p(f.priority, SMALL), _p(f.severity, SMALL), _p(f.rule_id, SMALL),
                     _p(f.title, SMALL), _p(f"{f.file}:{f.line}" if f.line else f.file, SMALL), _p(f.status, SMALL)])
    story.append(_table(rows, [8 * mm, 9 * mm, 13 * mm, 30 * mm, 66 * mm, 32 * mm, width - 158 * mm]))

    doc.build(story, onFirstPage=_cover, onLaterPages=_header_footer)
    return buf.getvalue()
