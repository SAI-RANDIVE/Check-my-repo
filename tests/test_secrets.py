"""Module 1: secret detection (every rule positive + negative), entropy, placeholders, history, redaction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.scanners.secrets import (
    ALL_RULE_IDS,
    RULES,
    detect_line,
    fingerprint,
    is_placeholder,
    redact,
    redact_text,
    scan_secrets,
    shannon_entropy,
    should_scan,
)
from tests.conftest import B64, HEX, UPPER_NUM, git, rnd

POSITIVE = {
    "aws-access-key-id": lambda: 'key = "' + "AK" + "IA" + rnd(16, UPPER_NUM, "aws") + '"',
    "aws-secret-access-key": lambda: 'aws_secret_access_key = "' + rnd(40, B64, "awss") + '"',
    "github-pat": lambda: "token: " + "gh" + "p_" + rnd(36, seed="ghp"),
    "github-oauth-token": lambda: "gh" + "o_" + rnd(36, seed="gho"),
    "github-app-token": lambda: "gh" + "s_" + rnd(36, seed="ghs"),
    "github-fine-grained-pat": lambda: "github" + "_pat_" + rnd(82, seed="ghf"),
    "gitlab-pat": lambda: "gl" + "pat-" + rnd(20, seed="gl"),
    "slack-token": lambda: "xo" + "xb-" + rnd(12, HEX, "s1") + "-" + rnd(24, seed="s2"),
    "slack-webhook": lambda: "https://hooks.slack.com/services/T" + rnd(9, UPPER_NUM, "w1") + "/B" + rnd(9, UPPER_NUM, "w2") + "/" + rnd(24, seed="w3"),
    "stripe-live-key": lambda: "sk" + "_live_" + rnd(24, seed="stl"),
    "stripe-test-key": lambda: "sk" + "_test_" + rnd(24, seed="stt"),
    "google-api-key": lambda: "AI" + "za" + rnd(35, seed="goog"),
    "twilio-api-key": lambda: "SK" + rnd(32, HEX, "twk"),
    "twilio-auth-token": lambda: 'TWILIO_AUTH_TOKEN = "' + rnd(32, HEX, "twa") + '"',
    "sendgrid-api-key": lambda: "SG." + rnd(22, seed="sg1") + "." + rnd(43, seed="sg2"),
    "anthropic-api-key": lambda: "sk-" + "ant-api03-" + rnd(93, seed="ant"),
    "openai-api-key": lambda: "sk-" + "proj-" + rnd(24, seed="o1") + "T3Blbk" + "FJ" + rnd(24, seed="o2"),
    "razorpay-live-key": lambda: "rzp" + "_live_" + rnd(14, seed="rzp"),
    "npm-token": lambda: "np" + "m_" + rnd(36, seed="npm"),
    "pypi-token": lambda: "pypi-" + "AgEIcHlwaS5vcmc" + rnd(60, seed="pypi"),
    "telegram-bot-token": lambda: "bot = '7123456789:" + "AA" + rnd(33, seed="tg") + "'",
    "discord-webhook": lambda: "https://discord.com/api/webhooks/123456789012345678/" + rnd(68, seed="dc"),
    "azure-storage-key": lambda: "DefaultEndpointsProtocol=https;AccountName=shop;AccountKey=" + rnd(86, B64, "az") + "==",
    "jwt": lambda: "ey" + "J" + rnd(20, seed="j1") + ".ey" + "J" + rnd(30, seed="j2") + "." + rnd(30, seed="j3"),
    "private-key": lambda: "-----BEGIN " + "RSA PRIVATE KEY-----",
    "db-connection-string": lambda: "DATABASE_URL=postgres://shop:" + rnd(14, seed="pg") + "@db.internal:5432/shop",
    "mongodb-connection-string": lambda: "mongodb+srv://app:" + rnd(14, seed="mg") + "@cluster0.example.net/shop",
    "generic-secret-assignment": lambda: 'db_password = "' + rnd(10, seed="gen") + '!9"',
    "high-entropy-string": lambda: 'signing = {"key_material": "' + rnd(40, B64, "ent") + '"}',
}

NEGATIVE = {
    "aws-access-key-id": "AKIA" + "SHORT123",
    "aws-secret-access-key": 'aws_region = "ap-south-1"',
    "github-pat": "gh" + "p_" + "tooShort123",
    "github-oauth-token": "gho_ is the OAuth prefix",
    "github-app-token": "ghs_" + "x",
    "github-fine-grained-pat": "github_pat_" + "abc",
    "gitlab-pat": "glpat-short",
    "slack-token": "xoxb-",
    "slack-webhook": "https://hooks.slack.com/services/",
    "stripe-live-key": "sk_live_" + "abc",
    "stripe-test-key": "sk_test_ is a test-mode prefix",
    "google-api-key": "AIza" + "short",
    "twilio-api-key": "SK" + "123",
    "twilio-auth-token": 'twilio_region = "ie1"',
    "sendgrid-api-key": "SG.short.value",
    "anthropic-api-key": "sk-ant-" + "short",
    "openai-api-key": "sk-" + "short",
    "razorpay-live-key": "rzp_live_" + "x1",
    "npm-token": "npm_" + "abc",
    "pypi-token": "pypi-" + "token",
    "telegram-bot-token": "version 1:AA",
    "discord-webhook": "https://discord.com/api/webhooks/",
    "azure-storage-key": "AccountKey=short",
    "jwt": "eyJhbGciOi",
    "private-key": "-----BEGIN PUBLIC KEY-----",
    "db-connection-string": "postgres://localhost:5432/shop",
    "mongodb-connection-string": "mongodb://localhost:27017/shop",
    "generic-secret-assignment": 'password_field = "user_password"',
    "high-entropy-string": 'api_version = "2024-01-01-preview-release"',
}


def test_rule_inventory_has_at_least_20_provider_signatures() -> None:
    assert len(RULES) >= 20
    assert set(POSITIVE) == set(ALL_RULE_IDS) == set(NEGATIVE)


@pytest.mark.parametrize("rule_id", sorted(POSITIVE))
def test_rule_positive(rule_id: str) -> None:
    hits = detect_line(POSITIVE[rule_id](), is_dotenv=rule_id == "db-connection-string")
    assert rule_id in {h.rule_id for h in hits}, hits


@pytest.mark.parametrize("rule_id", sorted(NEGATIVE))
def test_rule_negative(rule_id: str) -> None:
    hits = detect_line(NEGATIVE[rule_id])
    assert rule_id not in {h.rule_id for h in hits}


def test_shannon_entropy_math() -> None:
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("0123456789abcdef") == pytest.approx(4.0)


def test_aws_documentation_key_is_info_placeholder() -> None:
    hits = detect_line('k = "' + "AKIA" + "IOSFODNN7EXAMPLE" + '"')
    assert hits and hits[0].rule_id == "aws-access-key-id" and hits[0].placeholder


@pytest.mark.parametrize("value", ["changeme123", "your_api_key_here", "<token>", "xxxxxxxxxxxx", "sk_live_EXAMPLEKEY"])
def test_placeholders(value: str) -> None:
    assert is_placeholder(value)


def test_inline_ignore_marker() -> None:
    line = "sk" + "_live_" + rnd(24, seed="ign") + "  # codesentinel:ignore"
    assert detect_line(line) == []


def test_sri_integrity_hash_is_not_a_secret() -> None:
    line = '"integrity": "sha512-' + rnd(86, B64, "sri") + '=="'
    assert detect_line(line) == []


def test_redaction_and_fingerprint() -> None:
    secret = "sk" + "_live_" + rnd(24, seed="red")
    assert redact(secret) == secret[:4] + "****" + secret[-4:]
    assert len(fingerprint(secret)) == 64 and secret not in fingerprint(secret)
    masked = redact_text(f'STRIPE = "{secret}"')
    assert secret not in masked and "****" in masked


def test_file_filters() -> None:
    assert not should_scan("package-lock.json")
    assert not should_scan("static/vendor.min.js")
    assert not should_scan("node_modules/x/index.js")
    assert not should_scan("img/logo.png")
    assert should_scan("config/settings.py")


def test_history_only_secret_is_reported_with_commit(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    key = "AK" + "IA" + rnd(16, UPPER_NUM, "hist")
    (repo / "settings.py").write_text(f'AWS_KEY = "{key}"\n')
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "add key", date="2024-02-01T10:00:00+00:00")
    (repo / "settings.py").write_text('import os\nAWS_KEY = os.environ["AWS_KEY"]\n')
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "remove key", date="2024-02-05T10:00:00+00:00")
    findings, stats = scan_secrets(repo, ["settings.py"], include_history=True, is_git=True)
    hist = [f for f in findings if f.extra["historical"]]
    assert len(hist) == 1 and stats["secrets_history"] == 1
    f = hist[0]
    assert f.rule_id == "aws-access-key-id" and f.extra["commit_date"] == "2024-02-01" and len(f.extra["commit"]) == 40
    assert key not in json.dumps(f.to_dict())  # the raw secret never leaves the module


def test_head_secret_deduplicated_across_history(tmp_path: Path) -> None:
    repo = tmp_path / "r2"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    tok = "gh" + "p_" + rnd(36, seed="dedupe")
    (repo / "a.py").write_text(f'T = "{tok}"\n')
    (repo / "b.py").write_text(f'T = "{tok}"\n')
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    findings, _ = scan_secrets(repo, ["a.py", "b.py"], include_history=True, is_git=True)
    assert len(findings) == 1
    assert findings[0].extra["other_locations"] == ["b.py:1"]
    assert findings[0].extra["introduced_in"]
