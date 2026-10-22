"""Module 4: Dockerfile, compose, .env and GitHub Actions rules."""

from __future__ import annotations

from pathlib import Path

from app.scanners.iac import scan_compose, scan_dockerfile, scan_iac, scan_workflow

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def test_dockerfile_insecure() -> None:
    df = ("FROM python:latest\nRUN apt-get update && apt-get install -y curl\n"
          "RUN curl -fsSL https://get.example.com | sh\nADD https://example.com/tool.tgz /opt/\n"
          "ENV DB_PASSWORD=hunter2hunter2\nEXPOSE 22\nCMD [\"python\"]\n")
    found = ids(scan_dockerfile("Dockerfile", df))
    assert found == {"DOCKER-LATEST-TAG", "DOCKER-APT-NO-CLEANUP", "DOCKER-CURL-PIPE-SH", "DOCKER-ADD-REMOTE",
                     "DOCKER-SECRET-IN-ENV", "DOCKER-EXPOSE-SSH", "DOCKER-ROOT-USER", "DOCKER-NO-HEALTHCHECK"}


def test_dockerfile_hardened_is_clean() -> None:
    df = ("FROM python:3.12-slim AS build\nRUN pip wheel . -w /w\nFROM python:3.12-slim\n"
          "RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*\n"
          "COPY --from=build /w /w\nUSER app\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n")
    assert scan_dockerfile("Dockerfile", df) == []


def test_dockerfile_user_root_last() -> None:
    assert "DOCKER-ROOT-USER" in ids(scan_dockerfile("Dockerfile", "FROM alpine:3.20\nUSER app\nUSER root\nHEALTHCHECK NONE\n"))


def test_compose_rules() -> None:
    yml = ("services:\n  app:\n    image: x:1\n    privileged: true\n    network_mode: host\n    volumes:\n"
           "      - /var/run/docker.sock:/var/run/docker.sock\n    environment:\n      DB_PASSWORD: plain-text-1\n"
           "      API_TOKEN: ${API_TOKEN}\n")
    found = scan_compose("docker-compose.yml", yml)
    assert ids(found) == {"COMPOSE-PRIVILEGED", "COMPOSE-HOST-NETWORK", "COMPOSE-DOCKER-SOCK", "COMPOSE-PLAINTEXT-SECRET"}
    assert sum(1 for f in found if f.rule_id == "COMPOSE-PLAINTEXT-SECRET") == 1


def test_dotenv_committed_but_example_ignored(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("A=1\nB=2\n")
    (tmp_path / ".env.example").write_text("A=\n")
    found = scan_iac(tmp_path, [".env", ".env.example"])
    assert [f.rule_id for f in found] == ["DOTENV-COMMITTED"] and found[0].file == ".env"


WF_BAD = """name: bad
on:
  pull_request_target:
  issues:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v35
      - run: |
          echo "${{ github.event.issue.title }}"
          echo ${{ secrets.DEPLOY_KEY }}
"""

WF_GOOD = f"""name: good
on: [pull_request]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}
      - uses: tj-actions/changed-files@{SHA}  # v46
      - env:
          TITLE: ${{{{ github.event.pull_request.title }}}}
        run: echo "$TITLE"
"""


def test_workflow_insecure_patterns() -> None:
    found = ids(scan_workflow(".github/workflows/ci.yml", WF_BAD))
    assert found == {"GHA-PRT-CHECKOUT", "GHA-UNPINNED-ACTION", "GHA-SCRIPT-INJECTION", "GHA-SECRET-ECHO", "GHA-PERMISSIONS"}


def test_workflow_hardened_is_clean() -> None:
    assert scan_workflow(".github/workflows/ci.yml", WF_GOOD) == []


def test_unpinned_action_remediation_cites_tj_actions() -> None:
    f = next(f for f in scan_workflow("w.yml", WF_BAD) if f.rule_id == "GHA-UNPINNED-ACTION")
    assert "CVE-2025-30066" in f.description and f.extra["action"] == "tj-actions/changed-files"


def test_write_all_permissions() -> None:
    wf = "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    assert "GHA-PERMISSIONS" in ids(scan_workflow("w.yml", wf))
