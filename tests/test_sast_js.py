"""Module 3b: JavaScript/TypeScript rules (positive + negative) and comment stripping."""

from __future__ import annotations

import pytest

from app.scanners.sast_js import RULES, analyze_js, strip_comments

CASES = {
    "JS-EVAL": ("const r = eval(req.query.expr);", "const r = eval('2 + 2');"),
    "JS-CMDI": ("const { exec } = require('child_process');\nexec(`convert ${file} out.png`);",
                "const { execFile } = require('child_process');\nexecFile('convert', [file, 'out.png']);"),
    "JS-XSS-INNERHTML": ("el.innerHTML = '<b>' + user.name + '</b>';", "el.innerHTML = '<b>Welcome</b>';"),
    "JS-SQLI": ("db.query(`SELECT * FROM users WHERE id = ${id}`);", "db.query('SELECT * FROM users WHERE id = $1', [id]);"),
    "JS-JWT-VERIFY": ("jwt.verify(token, key);", "jwt.verify(token, key, { algorithms: ['RS256'] });"),
    "JS-WEAK-RANDOM": ("function makeSessionToken() {\n  return Math.random().toString(36);\n}",
                       "function shuffle(a) {\n  return a.sort(() => Math.random() - 0.5);\n}"),
    "JS-CORS-WILDCARD": ("app.use(cors({ origin: '*', credentials: true }));",
                         "app.use(cors({ origin: ['https://shop.example'], credentials: true }));"),
    "JS-HARDCODED-JWT-SECRET": ("const JWT_SECRET = 'super-secret-signing-key';",
                                "const JWT_SECRET = process.env.JWT_SECRET;"),
}


def ids(src: str) -> set[str]:
    return {f.rule_id for f in analyze_js(src, "index.js")}


def test_every_rule_has_a_case() -> None:
    assert set(CASES) == set(RULES)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_positive(rule_id: str) -> None:
    assert rule_id in ids(CASES[rule_id][0])


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_negative(rule_id: str) -> None:
    assert rule_id not in ids(CASES[rule_id][1])


def test_jwt_none_algorithm_flagged() -> None:
    f = [f for f in analyze_js("jwt.verify(t, k, { algorithms: ['none', 'HS256'] });", "a.js") if f.rule_id == "JS-JWT-VERIFY"]
    assert f and "none" in f[0].title


def test_dangerously_set_inner_html() -> None:
    assert "JS-XSS-INNERHTML" in ids("<div dangerouslySetInnerHTML={{ __html: post.body }} />")


def test_commented_code_is_ignored_and_lines_preserved() -> None:
    src = "// el.innerHTML = user.bio;\n/* eval(x)\n */\nconst ok = 1;\nel.innerHTML = name;\n"
    stripped = strip_comments(src)
    assert stripped.count("\n") == src.count("\n")
    found = analyze_js(src, "a.js")
    assert [f.rule_id for f in found] == ["JS-XSS-INNERHTML"] and found[0].line == 5


def test_strings_containing_comment_markers_survive() -> None:
    src = "const u = 'http://example.com'; el.innerHTML = u;"
    assert "http://example.com" in strip_comments(src)
    assert "JS-XSS-INNERHTML" in ids(src)
