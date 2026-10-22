"""Module 3b: JavaScript/TypeScript static analysis (token/regex based).

Comments are removed first by a small tokenizer that understands string,
template and comment syntax, so commented-out code never produces findings
and offsets still map to the original line numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.scanners.base import Finding, make_snippet, read_text
from app.scanners.sast_python import SECURITY_WORDS, _tokens

JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


@dataclass(frozen=True)
class JsRule:
    """Static metadata for a JavaScript SAST rule."""

    id: str
    title: str
    severity: str
    cwe: str
    owasp: str
    description: str
    remediation: str
    secure_example: str


RULES: dict[str, JsRule] = {r.id: r for r in [
    JsRule("JS-EVAL", "Dynamic code execution (eval / new Function)", "high", "CWE-95", "A03",
           "`eval` or the `Function` constructor compiles a string into code at runtime. Attacker-influenced input becomes code execution.",
           "Remove dynamic evaluation. Parse data with `JSON.parse` and dispatch with an object map of allowed functions.",
           "const handlers = { sum, avg };\nconst fn = handlers[req.query.op];\nif (!fn) return res.sendStatus(400);"),
    JsRule("JS-CMDI", "OS command injection via child_process.exec", "high", "CWE-78", "A03",
           "`exec`/`execSync` runs its argument through `/bin/sh`. Interpolating variables into the command lets an attacker append arbitrary commands.",
           "Use `execFile`/`spawn` with an argument array (no shell) and validate the input against an allow-list.",
           "const { execFile } = require('child_process');\nexecFile('convert', [inputPath, outputPath], (err) => { /* ... */ });"),
    JsRule("JS-XSS-INNERHTML", "DOM XSS: HTML sink assigned from a variable", "high", "CWE-79", "A03",
           "Assigning dynamic data to `innerHTML`/`outerHTML`, `document.write` or React's `dangerouslySetInnerHTML` parses it as HTML, so injected markup and scripts run in the victim's session.",
           "Use `textContent` (or React's default escaping) for text. If HTML is required, sanitise it with DOMPurify.",
           "el.textContent = product.name;\n// or, when HTML is genuinely needed:\nel.innerHTML = DOMPurify.sanitize(html);"),
    JsRule("JS-SQLI", "SQL injection: template literal or concatenation in query()", "high", "CWE-89", "A03",
           "The SQL text passed to `.query()` is built with `${...}` or `+`, so user input can change the statement.",
           "Use placeholders and pass values separately.",
           "await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);"),
    JsRule("JS-JWT-VERIFY", "jwt.verify without a strict algorithms allow-list", "high", "CWE-347", "A02",
           "Without `algorithms`, older jsonwebtoken versions accept whatever algorithm the token header names, which enables the "
           "`none` algorithm and HS/RS confusion attacks (CVE-2015-9235, CVE-2022-23540). Allowing `none` disables signature checks entirely.",
           "Always pass an explicit allow-list containing only the algorithm you issue.",
           "jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] });"),
    JsRule("JS-WEAK-RANDOM", "Math.random used for a security value", "medium", "CWE-338", "A02",
           "`Math.random()` is not cryptographically secure; V8's xorshift128+ state can be recovered from a few outputs, making tokens predictable.",
           "Use the Web Crypto API or Node's `crypto` module.",
           "const token = crypto.randomBytes(32).toString('hex');\n// browser\nconst id = crypto.randomUUID();"),
    JsRule("JS-CORS-WILDCARD", "CORS allows any origin with credentials", "medium", "CWE-942", "A05",
           "`origin: '*'` (or reflecting every origin) combined with `credentials: true` lets any website make authenticated requests "
           "on a logged-in user's behalf and read the responses.",
           "Allow-list the exact origins that need access.",
           "app.use(cors({ origin: ['https://shop.example.com'], credentials: true }));"),
    JsRule("JS-HARDCODED-JWT-SECRET", "Hard-coded JWT signing secret", "high", "CWE-798", "A07",
           "The JWT signing key is a literal in source code. Anyone who can read the repository can mint valid tokens for any user.",
           "Load the key from the environment or a secret manager; prefer asymmetric keys (RS256/EdDSA).",
           "const token = jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });"),
]}


def strip_comments(src: str) -> str:
    """Replace ``//`` and ``/* */`` comments with spaces, preserving newlines and strings."""
    out = []
    i, n = 0, len(src)
    state = "code"
    quote = ""
    tmpl_depth: list[int] = []
    brace = 0
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
                continue
            if c in ("'", '"'):
                state, quote = "str", c
            elif c == "`":
                state = "tmpl"
            elif c == "{":
                brace += 1
            elif c == "}":
                if tmpl_depth and brace == tmpl_depth[-1]:
                    tmpl_depth.pop()
                    state = "tmpl"
                else:
                    brace -= 1
            out.append(c)
            i += 1
        elif state == "line":
            if c == "\n":
                state = "code"
                out.append(c)
            else:
                out.append(" ")
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
        elif state == "str":
            out.append(c)
            if c == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if c == quote or c == "\n":
                state = "code"
            i += 1
        else:  # template literal
            out.append(c)
            if c == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if c == "`":
                state = "code"
            elif c == "$" and nxt == "{":
                out.append("{")
                tmpl_depth.append(brace)
                state = "code"
                i += 2
                continue
            i += 1
    return "".join(out)


EVAL_RE = re.compile(r"(?<![\w$.])eval\s*\(\s*(?!['\"][^'\"\n]*['\"]\s*\))|\bnew\s+Function\s*\(")
CMDI_RE = re.compile(r"\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"\n]*['\"]\s*\+|[A-Za-z_$][\w$.]*\s*\+)")
HTML_SINK_RE = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(?P<rhs>[^;\n]+)")
DOCWRITE_RE = re.compile(r"\bdocument\.write(?:ln)?\s*\(\s*(?P<rhs>[^;\n]+)\)")
INSERT_ADJ_RE = re.compile(r"\.insertAdjacentHTML\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?P<rhs>[^;\n]+)\)")
DANGEROUS_RE = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?P<rhs>[^}]+)\}")
SQLI_RE = re.compile(r"\.(?:query|execute|raw)\s*\(\s*(?:`(?P<tmpl>[^`]*\$\{[^`]*)`|['\"](?P<str>[^'\"\n]*)['\"]\s*\+)")
SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|from|where|values|drop|create)\b")
JWT_VERIFY_RE = re.compile(r"\bjwt\s*\.\s*verify\s*\(")
MATH_RANDOM_RE = re.compile(r"\bMath\.random\s*\(\s*\)")
CORS_RE = re.compile(r"\bcors\s*\(\s*\{(?P<body>[^{}]*)\}", re.S)
JWT_SIGN_LITERAL_RE = re.compile(r"\bjwt\s*\.\s*(?:sign|verify)\s*\(\s*[^,]+,\s*(['\"`])(?P<val>[^'\"`\n]{4,})\1")
JWT_SECRET_ASSIGN_RE = re.compile(
    r"\b(?P<key>JWT_SECRET|jwtSecret|jwt_secret|JWT_KEY|jwtKey|TOKEN_SECRET|tokenSecret|SESSION_SECRET|sessionSecret)"
    r"\s*[:=]\s*(['\"`])(?P<val>[^'\"`\n]{4,})\2")


def _is_pure_literal(expr: str) -> bool:
    e = expr.strip().rstrip(";").strip()
    if re.fullmatch(r"'[^'\\]*'|\"[^\"\\]*\"", e):
        return True
    return bool(re.fullmatch(r"`[^`$]*`", e))


def _balanced_args(text: str, start: int) -> str:
    depth = 0
    for j in range(start, min(len(text), start + 600)):
        ch = text[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:j]
    return text[start + 1:start + 600]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _security_context(lines: list[str], line_no: int) -> bool:
    window = lines[max(0, line_no - 6):line_no]
    idents: set[str] = set()
    for ln in window:
        for ident in re.findall(r"[A-Za-z_$][\w$]*", ln):
            idents |= _tokens(ident)
    return bool(idents & SECURITY_WORDS)


def analyze_js(source: str, rel: str) -> list[Finding]:
    """Analyse one JS/TS source string."""
    code = strip_comments(source)
    lines = source.splitlines()
    code_lines = code.splitlines()
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def report(rule_id: str, offset: int, note: str = "") -> None:
        line = _line_of(code, offset)
        if (rule_id, line) in seen:
            return
        seen.add((rule_id, line))
        r = RULES[rule_id]
        findings.append(Finding(
            module="sast", rule_id=rule_id, title=r.title + (f" ({note})" if note else ""), severity=r.severity,
            file=rel, line=line, description=r.description, remediation=r.remediation,
            secure_example=r.secure_example, cwe=r.cwe, owasp=r.owasp, snippet=make_snippet(lines, line),
            references=[f"https://cwe.mitre.org/data/definitions/{r.cwe.split('-')[1]}.html"],
            extra={"language": "javascript"},
        ))

    for m in EVAL_RE.finditer(code):
        report("JS-EVAL", m.start())
    if "child_process" in code or re.search(r"\bexec(Sync)?\s*\(", code):
        for m in CMDI_RE.finditer(code):
            if "child_process" in code:
                report("JS-CMDI", m.start())
    for rx in (HTML_SINK_RE, DOCWRITE_RE, INSERT_ADJ_RE, DANGEROUS_RE):
        for m in rx.finditer(code):
            if not _is_pure_literal(m.group("rhs")):
                report("JS-XSS-INNERHTML", m.start())
    for m in SQLI_RE.finditer(code):
        body = m.group("tmpl") or m.group("str") or ""
        if SQL_WORDS.search(body):
            report("JS-SQLI", m.start())
    for m in JWT_VERIFY_RE.finditer(code):
        args = _balanced_args(code, m.end() - 1)
        alg = re.search(r"algorithms\s*:\s*\[([^\]]*)\]", args)
        if alg is None:
            report("JS-JWT-VERIFY", m.start(), "no algorithms allow-list")
        elif re.search(r"['\"`]none['\"`]", alg.group(1), re.I):
            report("JS-JWT-VERIFY", m.start(), "'none' algorithm allowed")
    for m in MATH_RANDOM_RE.finditer(code):
        ln = _line_of(code, m.start())
        if _security_context(code_lines, ln):
            report("JS-WEAK-RANDOM", m.start())
    for m in CORS_RE.finditer(code):
        body = m.group("body")
        wildcard = re.search(r"origin\s*:\s*(?:['\"`]\*['\"`]|true)", body)
        creds = re.search(r"credentials\s*:\s*true", body)
        if wildcard and creds:
            report("JS-CORS-WILDCARD", m.start())
    for rx in (JWT_SIGN_LITERAL_RE, JWT_SECRET_ASSIGN_RE):
        for m in rx.finditer(code):
            val = m.group("val")
            if "process.env" in val or val.startswith("$"):
                continue
            report("JS-HARDCODED-JWT-SECRET", m.start("val"))
    return findings


def scan_js(root: Path, files: list[str]) -> list[Finding]:
    """Run the JS/TS analyser across source files (minified bundles are skipped)."""
    findings: list[Finding] = []
    for rel in files:
        if not rel.endswith(JS_EXTS) or rel.endswith((".min.js", ".bundle.js")) or rel.endswith(".d.ts"):
            continue
        text = read_text(root / rel)
        if text is None:
            continue
        findings.extend(analyze_js(text, rel))
    return findings
