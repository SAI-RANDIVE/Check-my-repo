"""Module 3a: Python AST analysis, every rule positive + negative, plus taint tracking."""

from __future__ import annotations

import textwrap

import pytest

from app.scanners.sast_python import RULES, analyze_source


def rules(src: str) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in analyze_source(textwrap.dedent(src), "app.py"):
        out.setdefault(f.rule_id, []).append(f)
    return out


CASES = {
    "PY-SQLI": ("""
        def q(cur, name):
            cur.execute(f"SELECT * FROM t WHERE name = '{name}'")
        """, """
        def q(cur, name):
            cur.execute("SELECT * FROM t WHERE name = %s", (name,))
        """),
    "PY-CMDI": ("""
        import subprocess
        def run(host):
            subprocess.run("ping " + host, shell=True)
        """, """
        import subprocess
        def run(host):
            subprocess.run(["ping", "-c", "1", host])
        """),
    "PY-EVAL": ("""
        def calc(expr):
            return eval(expr)
        """, """
        def calc():
            return eval("1 + 1")
        """),
    "PY-PICKLE": ("""
        import pickle
        def load(b):
            return pickle.loads(b)
        """, """
        import json
        def load(b):
            return json.loads(b)
        """),
    "PY-YAML-LOAD": ("""
        import yaml
        def load(s):
            return yaml.load(s)
        """, """
        import yaml
        def load(s):
            return yaml.load(s, Loader=yaml.SafeLoader)
        """),
    "PY-TLS-VERIFY": ("""
        import requests
        requests.get("https://x", verify=False)
        """, """
        import requests
        requests.get("https://x", timeout=5)
        """),
    "PY-DEBUG-ENABLED": ("""
        app.run(debug=True)
        """, """
        app.run(debug=False)
        """),
    "PY-HARDCODED-SECRET-KEY": ("""
        SECRET_KEY = "django-insecure-abc123"
        """, """
        import os
        SECRET_KEY = os.environ["SECRET_KEY"]
        """),
    "PY-WEAK-RANDOM": ("""
        import random
        def make_reset_token():
            return random.getrandbits(64)
        """, """
        import random
        def shuffle_banner(items):
            return random.choice(items)
        """),
    "PY-WEAK-PASSWORD-HASH": ("""
        import hashlib
        def store(password):
            return hashlib.md5(password.encode()).hexdigest()
        """, """
        import hashlib
        def etag(body):
            return hashlib.md5(body).hexdigest()
        """),
    "PY-INSECURE-TEMPFILE": ("""
        import tempfile
        path = tempfile.mktemp()
        """, """
        import tempfile
        fh = tempfile.NamedTemporaryFile()
        """),
    "PY-ASSERT-AUTH": ("""
        def delete(user):
            assert user.is_admin
        """, """
        def area(w, h):
            assert w > 0
        """),
    "PY-PATH-TRAVERSAL": ("""
        from flask import request
        def download():
            name = request.args["f"]
            return open("files/" + name).read()
        """, """
        def read_config():
            return open("config.yml").read()
        """),
}


def test_every_rule_has_a_case() -> None:
    assert set(CASES) == set(RULES)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_positive(rule_id: str) -> None:
    assert rule_id in rules(CASES[rule_id][0])


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_negative(rule_id: str) -> None:
    assert rule_id not in rules(CASES[rule_id][1])


def test_taint_from_request_raises_severity() -> None:
    found = rules("""
        from flask import request
        @app.route("/s")
        def search():
            term = request.args.get("q")
            sql = "SELECT * FROM p WHERE n = '" + term + "'"
            cur.execute(sql)
        """)
    f = found["PY-SQLI"][0]
    assert f.tainted and f.severity == "critical" and f.cwe == "CWE-89" and f.owasp == "A03"


def test_route_parameters_are_tainted() -> None:
    f = rules("""
        @app.route("/ping/<host>")
        def ping(host):
            os.system("ping " + host)
        """)["PY-CMDI"][0]
    assert f.tainted


def test_untainted_sqli_is_high_not_critical() -> None:
    f = rules("""
        def report(cur, table):
            cur.execute("SELECT count(*) FROM %s" % table)
        """)["PY-SQLI"][0]
    assert not f.tainted and f.severity == "high"


def test_snippet_has_context_and_hit_line() -> None:
    f = rules("""
        import yaml
        a = 1
        b = 2
        data = yaml.load(open("x"))
        c = 3
        """)["PY-YAML-LOAD"][0]
    hits = [s for s in f.snippet if s["hit"]]
    assert hits and hits[0]["n"] == f.line and len(f.snippet) >= 5


def test_syntax_error_is_skipped() -> None:
    assert analyze_source("def broken(:\n", "x.py") == []
