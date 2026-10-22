"""Module 3a: Python static analysis using the standard-library ``ast`` module.

The analyser walks each module once, keeping a scope per function. Within a
scope it tracks:

* **tainted names**: variables assigned from ``request.args/form/json/...``,
  ``input()``, ``sys.argv`` or the parameters of a web route; taint
  propagates through any expression that mentions a tainted name;
* **dynamic SQL names**: variables built with f-strings, ``%`` or ``+``
  formatting, so ``q = f"..."; cur.execute(q)`` is caught as well as the
  inline form.

A sink reached by tainted data raises the finding's severity and sets
``tainted=True``, which the scoring engine uses for the P0 tier.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.scanners.base import Finding, is_test_path, make_snippet, read_text

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PyRule:
    """Static metadata for a Python SAST rule."""

    id: str
    title: str
    severity: str
    cwe: str
    owasp: str
    description: str
    remediation: str
    secure_example: str


RULES: dict[str, PyRule] = {r.id: r for r in [
    PyRule("PY-SQLI", "SQL injection: query built from string formatting", "high", "CWE-89", "A03",
           "The SQL statement is assembled with an f-string, `%` or `+` and passed to a database execute call. "
           "If any part comes from a user, they can change the query's meaning (read or delete data, bypass login).",
           "Pass values as bound parameters and keep the SQL text constant. Never interpolate user input into SQL.",
           'cur.execute("SELECT * FROM products WHERE name = %s", (name,))\n'
           '# SQLAlchemy\nsession.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})'),
    PyRule("PY-CMDI", "OS command injection: shell command built from variables", "high", "CWE-78", "A03",
           "A shell command is executed with a non-literal string (`os.system`, `os.popen`, or `subprocess` with "
           "`shell=True`). Shell metacharacters in the variable (`;`, `|`, `$()`) run arbitrary commands.",
           "Call the program directly with an argument list and `shell=False` (the default). Validate inputs against an allow-list.",
           'subprocess.run(["ping", "-c", "1", host], check=True, timeout=5)  # no shell, argv list'),
    PyRule("PY-EVAL", "Dynamic code execution with eval/exec", "high", "CWE-95", "A03",
           "`eval` or `exec` runs a non-literal expression. If an attacker can influence it they can execute arbitrary Python.",
           "Remove eval/exec. Use `ast.literal_eval` for literals, `json.loads` for data, or an explicit dispatch table.",
           "import ast\nvalue = ast.literal_eval(user_text)  # only literals, never code"),
    PyRule("PY-PICKLE", "Unsafe deserialisation with pickle/marshal", "high", "CWE-502", "A08",
           "`pickle`/`marshal` can execute arbitrary code while loading. Loading data from an untrusted source is remote code execution.",
           "Use a data-only format such as JSON. If you must unpickle, sign the payload with HMAC and verify it first.",
           "import json\nobj = json.loads(payload)"),
    PyRule("PY-YAML-LOAD", "Unsafe YAML load without SafeLoader", "high", "CWE-502", "A08",
           "`yaml.load` without `Loader=SafeLoader` can construct arbitrary Python objects (CVE-2017-18342, CVE-2020-1747).",
           "Use `yaml.safe_load()` or pass `Loader=yaml.SafeLoader`.",
           "import yaml\nconfig = yaml.safe_load(stream)"),
    PyRule("PY-TLS-VERIFY", "TLS certificate verification disabled", "high", "CWE-295", "A07",
           "`verify=False` turns off certificate validation, so a network attacker can intercept and modify the traffic (man-in-the-middle).",
           "Remove `verify=False`. For private CAs, pass the CA bundle path: `verify='/etc/ssl/corp-ca.pem'`.",
           'requests.get(url, timeout=10)  # verification on by default\nrequests.get(url, verify="/etc/ssl/certs/internal-ca.pem")'),
    PyRule("PY-DEBUG-ENABLED", "Debug mode enabled", "medium", "CWE-489", "A05",
           "Flask `debug=True` exposes the Werkzeug interactive debugger (remote code execution if reachable). Django "
           "`DEBUG = True` leaks settings, SQL and stack traces.",
           "Drive debug mode from the environment and default it to off in production.",
           'app.run(debug=os.environ.get("FLASK_DEBUG") == "1")\nDEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"'),
    PyRule("PY-HARDCODED-SECRET-KEY", "Hard-coded framework SECRET_KEY", "high", "CWE-798", "A07",
           "The framework secret key signs sessions, CSRF tokens and password-reset links. A key committed to source lets anyone forge sessions.",
           "Load the key from the environment or a secret manager and rotate the committed value.",
           'SECRET_KEY = os.environ["SECRET_KEY"]\napp.secret_key = os.environ["FLASK_SECRET_KEY"]'),
    PyRule("PY-WEAK-RANDOM", "Non-cryptographic random used for a security value", "medium", "CWE-338", "A02",
           "The `random` module (Mersenne Twister) is predictable: 624 outputs reveal its full state. It must not generate tokens, passwords, OTPs or salts.",
           "Use the `secrets` module.",
           "import secrets\ntoken = secrets.token_urlsafe(32)\notp = f\"{secrets.randbelow(10**6):06d}\""),
    PyRule("PY-WEAK-PASSWORD-HASH", "Password hashed with a fast, broken hash (MD5/SHA-1)", "high", "CWE-328", "A02",
           "MD5 and SHA-1 are fast general-purpose hashes; GPUs test billions of guesses per second and unsalted values fall to rainbow tables.",
           "Use a slow, salted password hash: Argon2id, scrypt, bcrypt, or PBKDF2-HMAC-SHA256 with at least 600,000 iterations.",
           "from argon2 import PasswordHasher\nph = PasswordHasher()\nstored = ph.hash(password)\nph.verify(stored, attempt)"),
    PyRule("PY-INSECURE-TEMPFILE", "Insecure temporary file (tempfile.mktemp)", "medium", "CWE-377", "A01",
           "`mktemp` returns a name without creating the file. Another process can create or symlink that path first (TOCTOU race).",
           "Use `tempfile.NamedTemporaryFile`, `mkstemp` or `TemporaryDirectory`, which create the file atomically.",
           "import tempfile\nwith tempfile.NamedTemporaryFile(delete=False) as fh:\n    fh.write(data)"),
    PyRule("PY-ASSERT-AUTH", "assert used for an authorisation check", "medium", "CWE-703", "A04",
           "Assertions are removed when Python runs with `-O`, so this access check disappears in optimised deployments.",
           "Use an explicit `if` and raise or abort.",
           "if not user.is_admin:\n    abort(403)"),
    PyRule("PY-PATH-TRAVERSAL", "Path traversal: file path from request data", "high", "CWE-22", "A01",
           "A file is opened with a path derived from user input. `../` sequences can read files outside the intended directory (for example `/etc/passwd` or `.env`).",
           "Resolve the path against a fixed base directory and reject anything outside it, or use `werkzeug.utils.safe_join` / `send_from_directory`.",
           "base = Path(\"/srv/uploads\").resolve()\ntarget = (base / filename).resolve()\nif not target.is_relative_to(base):\n    abort(400)\nreturn send_file(target)"),
]}

SOURCE_ATTRS = {"args", "form", "json", "values", "cookies", "headers", "data", "files", "GET", "POST", "body",
                "query_params", "path_params", "query_string", "COOKIES", "META", "FILES"}
SOURCE_CALLS = {"get_json", "get_data"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_route", "websocket"}
SECURITY_WORDS = {"token", "tokens", "password", "passwd", "pwd", "secret", "otp", "nonce", "salt", "session", "apikey",
                  "key", "reset", "csrf", "auth", "verification", "verify", "code", "pin", "invite", "coupon"}
AUTH_WORDS = {"auth", "authenticated", "admin", "login", "logged", "permission", "permissions", "staff", "superuser",
              "role", "roles", "authorized", "authorised", "token", "user", "owner"}
PASSWORD_WORDS = {"pass", "password", "passwd", "pwd", "pw", "passphrase"}


def _tokens(identifier: str) -> set[str]:
    """Split ``snake_case``/``camelCase`` identifiers into lower-case word tokens."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", identifier)
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}


def _has_word(identifiers: list[str], words: set[str]) -> bool:
    return any(_tokens(i) & words for i in identifiers)
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "text", "from_statement", "mogrify"}
SHELL_FUNCS = {"os.system", "os.popen", "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput",
               "os.popen2", "os.popen3"}
SUBPROCESS_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
                    "subprocess.check_call"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "Client", "AsyncClient",
                "Session", "stream", "urlopen"}
RANDOM_FUNCS = {"random", "randint", "choice", "choices", "getrandbits", "randrange", "sample", "uniform", "randbytes"}


@dataclass
class _Scope:
    name: str
    tainted: set[str] = field(default_factory=set)
    dynamic_sql: set[str] = field(default_factory=set)


def _identifiers(node: ast.AST) -> list[str]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, ast.Attribute):
            out.append(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 40:
            out.append(n.value)
    return out


def _is_literal(node: ast.AST | None) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_literal(e) for e in node.elts)
    return False


class _Analyzer(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str]) -> None:
        self.rel = rel
        self.lines = lines
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}
        self.scopes: list[_Scope] = [_Scope("<module>")]
        self.assign_targets: list[str] = []
        self._seen: set[tuple[str, int]] = set()

    # ------------------------------------------------------------ helpers
    @property
    def scope(self) -> _Scope:
        return self.scopes[-1]

    def dotted(self, node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        elif isinstance(node, ast.Call):
            parts.append(self.dotted(node.func) + "()")
        else:
            parts.append("?")
        return ".".join(reversed(parts))

    def is_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute):
            root = node.value
            if isinstance(root, ast.Name) and root.id == "request" and node.attr in SOURCE_ATTRS:
                return True
            if self.dotted(node) == "sys.argv":
                return True
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and self.aliases.get(f.id, f.id) == "input":
                return True
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "request" \
                    and f.attr in SOURCE_CALLS:
                return True
        return False

    def is_tainted(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in self.scope.tainted:
                return True
            if self.is_source(n):
                return True
        return False

    def is_dynamic_str(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mod) and isinstance(node.left, (ast.Constant, ast.JoinedStr)):
                return True
            if isinstance(node.op, ast.Add):
                sides = (node.left, node.right)
                has_str = any(isinstance(s, (ast.Constant, ast.JoinedStr)) and not isinstance(getattr(s, "value", ""), (int, float))
                              or self.is_dynamic_str(s) or (isinstance(s, ast.Name) and s.id in self.scope.dynamic_sql)
                              for s in sides)
                non_lit = any(not isinstance(s, ast.Constant) for s in sides)
                return has_str and non_lit
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
                and isinstance(node.func.value, ast.Constant):
            return bool(node.args or node.keywords)
        if isinstance(node, ast.Name):
            return node.id in self.scope.dynamic_sql
        return False

    def report(self, rule_id: str, node: ast.AST, tainted: bool = False, note: str = "") -> None:
        line = getattr(node, "lineno", 1)
        if (rule_id, line) in self._seen:
            return
        self._seen.add((rule_id, line))
        r = RULES[rule_id]
        severity = r.severity
        if tainted:
            severity = "critical" if rule_id in ("PY-SQLI", "PY-CMDI", "PY-EVAL") else "high"
        desc = r.description + (f" {note}" if note else "")
        if tainted:
            desc += " Taint analysis traced user-controlled input (request data, input() or sys.argv) into this call."
        self.findings.append(Finding(
            module="sast", rule_id=rule_id, title=r.title + (" (user input reaches sink)" if tainted else ""),
            severity=severity, file=self.rel, line=line, description=desc, remediation=r.remediation,
            secure_example=r.secure_example, cwe=r.cwe, owasp=r.owasp, snippet=make_snippet(self.lines, line),
            tainted=tainted, references=[f"https://cwe.mitre.org/data/definitions/{r.cwe.split('-')[1]}.html"],
            extra={"language": "python"},
        ))

    # ------------------------------------------------------------ visitors
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        sc = _Scope(node.name)
        is_route = False
        for d in node.decorator_list:
            target = d.func if isinstance(d, ast.Call) else d
            if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
                is_route = True
        if is_route:
            sc.tainted |= {a.arg for a in node.args.args if a.arg not in ("self", "cls", "request")}
        self.scopes.append(sc)
        for d in node.decorator_list:
            self.visit(d)
        for stmt in node.body:
            self.visit(stmt)
        self.scopes.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def _target_names(self, targets: list[ast.expr]) -> list[str]:
        names = []
        for t in targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name):
                    names.append(n.id)
                elif isinstance(n, ast.Attribute):
                    names.append(n.attr)
                elif isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
                    names.append(n.slice.value)
        return names

    def visit_Assign(self, node: ast.Assign) -> None:
        names = self._target_names(node.targets)
        self.assign_targets = list(names)
        self.visit(node.value)
        self.assign_targets = []
        tainted = self.is_tainted(node.value)
        dynamic = self.is_dynamic_str(node.value)
        for t in node.targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name):
                    (self.scope.tainted.add if tainted else self.scope.tainted.discard)(n.id)
                    (self.scope.dynamic_sql.add if dynamic else self.scope.dynamic_sql.discard)(n.id)
        self._check_assign_rules(node, names)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit_Assign(ast.Assign(targets=[node.target], value=node.value, lineno=node.lineno,
                                         col_offset=node.col_offset))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            if self.is_tainted(node.value):
                self.scope.tainted.add(node.target.id)
            if isinstance(node.op, ast.Add) and (node.target.id in self.scope.dynamic_sql
                                                 or self.is_dynamic_str(node.value)):
                self.scope.dynamic_sql.add(node.target.id)

    def _check_assign_rules(self, node: ast.Assign, names: list[str]) -> None:
        val = node.value
        is_str_const = isinstance(val, ast.Constant) and isinstance(val.value, str) and val.value.strip() != ""
        if is_str_const and any(n in ("SECRET_KEY", "secret_key") for n in names):
            self.report("PY-HARDCODED-SECRET-KEY", node)
        if len(self.scopes) == 1 and "DEBUG" in names and isinstance(val, ast.Constant) and val.value is True:
            self.report("PY-DEBUG-ENABLED", node, note="(`DEBUG = True` at module level.)")

    def visit_Assert(self, node: ast.Assert) -> None:
        ids = _identifiers(node.test)
        if not is_test_path(self.rel) and _has_word(ids, AUTH_WORDS):  # pytest relies on assert
            self.report("PY-ASSERT-AUTH", node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self.dotted(node.func)
        method = name.rsplit(".", 1)[-1]
        args = node.args
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        arg0 = args[0] if args else None

        # SQL injection
        is_sql_call = method in SQL_METHODS or name in ("sqlalchemy.text", "sqlalchemy.sql.text")
        if is_sql_call and arg0 is not None and (
                self.is_dynamic_str(arg0) or (isinstance(arg0, ast.Name) and arg0.id in self.scope.tainted)):
            self.report("PY-SQLI", node, tainted=self.is_tainted(arg0))
        # command injection
        if name in SHELL_FUNCS and arg0 is not None and not _is_literal(arg0):
            self.report("PY-CMDI", node, tainted=self.is_tainted(arg0))
        if name in SUBPROCESS_FUNCS:
            shell = kw.get("shell")
            if isinstance(shell, ast.Constant) and shell.value is True and arg0 is not None and not _is_literal(arg0):
                self.report("PY-CMDI", node, tainted=self.is_tainted(arg0))
        # eval / exec
        if name in ("eval", "exec", "builtins.eval", "builtins.exec") and arg0 is not None and not _is_literal(arg0):
            self.report("PY-EVAL", node, tainted=self.is_tainted(arg0))
        # deserialisation
        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "dill.loads", "marshal.loads",
                    "_pickle.loads", "jsonpickle.decode"):
            self.report("PY-PICKLE", node, tainted=self.is_tainted(arg0))
        if name in ("yaml.load", "yaml.load_all"):
            loader = kw.get("Loader") or (args[1] if len(args) > 1 else None)
            loader_name = self.dotted(loader) if loader is not None else ""
            if not loader_name.endswith(("SafeLoader", "CSafeLoader", "BaseLoader")):
                self.report("PY-YAML-LOAD", node, tainted=self.is_tainted(arg0))
        if name in ("yaml.unsafe_load", "yaml.unsafe_load_all"):
            self.report("PY-YAML-LOAD", node, tainted=self.is_tainted(arg0))
        # TLS verification
        v = kw.get("verify")
        if isinstance(v, ast.Constant) and v.value is False and method in HTTP_METHODS:
            self.report("PY-TLS-VERIFY", node)
        # debug
        d = kw.get("debug")
        if method == "run" and isinstance(d, ast.Constant) and d.value is True:
            self.report("PY-DEBUG-ENABLED", node, note="(`app.run(debug=True)`.)")
        # weak randomness in a security context
        if (name.startswith("random.") and method in RANDOM_FUNCS
                and _has_word(self.assign_targets + [self.scope.name], SECURITY_WORDS)):
            self.report("PY-WEAK-RANDOM", node)
        # weak password hashing
        algo = None
        if name in ("hashlib.md5", "hashlib.sha1"):
            algo = method
        elif name == "hashlib.new" and isinstance(arg0, ast.Constant) and str(arg0.value).lower() in ("md5", "sha1"):
            algo = str(arg0.value).lower()
        if algo:
            used_for_security = kw.get("usedforsecurity")
            not_security = isinstance(used_for_security, ast.Constant) and used_for_security.value is False
            if not not_security and _has_word(_identifiers(node) + self.assign_targets + [self.scope.name], PASSWORD_WORDS):
                self.report("PY-WEAK-PASSWORD-HASH", node, note=f"Algorithm: {algo.upper()}.")
        # insecure temp file
        if name == "tempfile.mktemp":
            self.report("PY-INSECURE-TEMPFILE", node)
        # path traversal
        if (name in ("open", "io.open", "codecs.open", "flask.send_file", "send_file", "os.open")
                or method in ("send_file",)) and arg0 is not None and self.is_tainted(arg0):
            self.report("PY-PATH-TRAVERSAL", node, tainted=True)
        self.generic_visit(node)


def analyze_source(source: str, rel: str) -> list[Finding]:
    """Analyse one Python source string; syntax errors yield no findings."""
    try:
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, ValueError) as exc:
        log.debug("skipping %s: %s", rel, exc)
        return []
    lines = source.splitlines()
    an = _Analyzer(rel, lines)
    an.visit(tree)
    return an.findings


def scan_python(root: Path, files: list[str]) -> list[Finding]:
    """Run the Python analyser over every ``.py`` file in ``files``."""
    findings: list[Finding] = []
    for rel in files:
        if not rel.endswith(".py"):
            continue
        text = read_text(root / rel)
        if text is None:
            continue
        findings.extend(analyze_source(text, rel))
    return findings
