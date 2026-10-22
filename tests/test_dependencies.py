"""Module 2a: manifest and lockfile parsers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.scanners.dependencies import (
    discover_components,
    make_purl,
    npm_min_version,
    parse_go_mod,
    parse_package_json,
    parse_package_lock,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pom,
    parse_requirements,
)

ROOT = Path(__file__).resolve().parent.parent


def write(root: Path, rel: str, text: str) -> str:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return rel


def test_requirements_pins_ranges_extras_comments_and_includes(tmp_path: Path) -> None:
    write(tmp_path, "base.txt", "PyYAML==5.3  # pinned\n")
    rel = write(tmp_path, "requirements.txt", "# app\n-r base.txt\nDjango==3.2.0\nrequests[socks]>=2.19.0\n"
                "urllib3==1.24.1 ; python_version >= '3.6'\nflask\n-e git+https://example.com/x.git#egg=x\n"
                "Jinja2==2.10 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    comps = {c.name: c for c in parse_requirements(tmp_path, rel)}
    assert comps["django"].version == "3.2.0" and not comps["django"].version_inferred
    assert comps["requests"].version == "2.19.0" and comps["requests"].version_inferred
    assert comps["pyyaml"].file == "base.txt"
    assert comps["urllib3"].version == "1.24.1"
    assert comps["jinja2"].version == "2.10"
    assert comps["flask"].version == ""
    assert comps["django"].purl == "pkg:pypi/django@3.2.0"


def test_pipfile_lock_direct_from_pipfile(tmp_path: Path) -> None:
    write(tmp_path, "Pipfile", '[packages]\ndjango = "*"\n')
    rel = write(tmp_path, "Pipfile.lock", json.dumps({
        "default": {"django": {"version": "==3.2.0"}, "sqlparse": {"version": "==0.4.1"}},
        "develop": {"pytest": {"version": "==6.0.0"}}}))
    comps = {c.name: c for c in parse_pipfile_lock(tmp_path, rel)}
    assert comps["django"].direct and not comps["sqlparse"].direct
    assert comps["pytest"].scope == "optional" and comps["sqlparse"].version == "0.4.1"


def test_poetry_lock(tmp_path: Path) -> None:
    write(tmp_path, "pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.19"\n')
    rel = write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.19.0"\n'
                '[package.dependencies]\nurllib3 = "*"\n\n[[package]]\nname = "urllib3"\nversion = "1.24.1"\n')
    comps = {c.name: c for c in parse_poetry_lock(tmp_path, rel)}
    assert comps["requests"].direct and not comps["urllib3"].direct
    assert comps["requests"].dependencies == ["pkg:pypi/urllib3@1.24.1"]


def test_package_lock_v3_real_file() -> None:
    root = ROOT / "demo" / "data" / "vulnerable"
    comps = {c.name: c for c in parse_package_lock(root, "package-lock.json")}
    assert comps["lodash"].version == "4.17.15" and comps["lodash"].direct
    assert not comps["follow-redirects"].direct and comps["follow-redirects"].version == "1.13.1"
    assert "pkg:npm/follow-redirects@1.13.1" in comps["axios"].dependencies
    assert comps["lodash"].license == "MIT" and comps["lodash"].line


def test_package_lock_v1(tmp_path: Path) -> None:
    write(tmp_path, "package.json", json.dumps({"dependencies": {"express": "^4.17.1"}}))
    rel = write(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
        "express": {"version": "4.17.1", "requires": {"qs": "6.7.0"}, "dependencies": {"qs": {"version": "6.7.0"}}},
        "minimist": {"version": "1.2.0", "dev": True}}}))
    comps = {c.name: c for c in parse_package_lock(tmp_path, rel)}
    assert comps["express"].direct and not comps["qs"].direct and not comps["minimist"].direct
    assert comps["minimist"].scope == "optional"


@pytest.mark.parametrize("rng,expected", [("^4.17.15", "4.17.15"), ("~1.2", "1.2.0"), (">=1.0.0 <2", "1.0.0"),
                                          ("1.x", "1.0.0"), ("*", ""), ("latest", ""), ("git+https://x/y.git", "")])
def test_npm_range_minimum(rng: str, expected: str) -> None:
    assert npm_min_version(rng) == expected


def test_package_json_marks_inferred(tmp_path: Path) -> None:
    rel = write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "^4.17.15", "axios": "0.21.0"},
                                                     "devDependencies": {"jest": "~26.0.0"}}))
    comps = {c.name: c for c in parse_package_json(tmp_path, rel)}
    assert comps["lodash"].version_inferred and not comps["axios"].version_inferred
    assert comps["jest"].scope == "optional"


def test_pom_property_substitution_and_management(tmp_path: Path) -> None:
    rel = write(tmp_path, "pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>in.shop</groupId><artifactId>svc</artifactId><version>1.0</version>
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencyManagement><dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId><version>2.9.8</version></dependency></dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
  </dependencies></project>""")
    comps = {c.name: c for c in parse_pom(tmp_path, rel)}
    assert comps["org.apache.logging.log4j:log4j-core"].version == "2.14.1"
    assert comps["com.fasterxml.jackson.core:jackson-databind"].version == "2.9.8"
    assert comps["junit:junit"].scope == "optional"
    assert comps["org.apache.logging.log4j:log4j-core"].purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_pom_rejects_entities(tmp_path: Path) -> None:
    rel = write(tmp_path, "pom.xml", '<!DOCTYPE p [<!ENTITY x "y">]><project/>')
    assert parse_pom(tmp_path, rel) == []


def test_go_mod_direct_and_indirect(tmp_path: Path) -> None:
    rel = write(tmp_path, "go.mod", "module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n"
                "\tgolang.org/x/text v0.3.2 // indirect\n)\nrequire github.com/pkg/errors v0.9.1\n")
    comps = {c.name: c for c in parse_go_mod(tmp_path, rel)}
    assert comps["github.com/gin-gonic/gin"].direct and not comps["golang.org/x/text"].direct
    assert comps["github.com/pkg/errors"].version == "v0.9.1"
    assert comps["github.com/gin-gonic/gin"].purl == "pkg:golang/github.com/gin-gonic/gin@v1.6.0"


def test_purl_scoped_npm() -> None:
    assert make_purl("npm", "@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"


def test_discover_dedupes_and_filters_transitive(tmp_path: Path) -> None:
    lock = (ROOT / "demo" / "data" / "vulnerable" / "package-lock.json").read_text()
    write(tmp_path, "api/package-lock.json", lock)
    write(tmp_path, "api/package.json", "{}")
    write(tmp_path, "requirements.txt", "Django==3.2.0\n")
    write(tmp_path, "requirements-dev.txt", "Django==3.2.0\n")
    files = ["api/package-lock.json", "api/package.json", "requirements.txt", "requirements-dev.txt"]
    all_c = discover_components(tmp_path, files)
    direct = discover_components(tmp_path, files, include_transitive=False)
    assert sum(1 for c in all_c if c.name == "django") == 1
    assert len(direct) < len(all_c) and all(c.direct for c in direct)
