"""Build the labelled demo repositories used for the live demo and the evaluation.

Creates two local git repositories:

* ``demo/vulnerable-shop/``: "KiranaKart", a small Flask + Node online shop
  with ten commits of realistic history and a known set of planted issues;
* ``demo/vulnerable-shop-fixed/``: the same application with every issue
  remediated, so the CI gate goes from FAIL to PASS.

Every planted issue is written to ``demo/ground_truth.json`` (module, rule,
file, line). Line numbers are computed from the generated files, so the
ground truth cannot drift from the code.

Secret-looking values are derived at runtime from SHA-256 of fixed seeds and
assembled from fragments, so this source file contains no string that a
secret scanner (or GitHub push protection) would recognise. None of the
values are real credentials.

Dependency data is real: the npm lockfiles in ``demo/data`` were resolved
against the live npm registry (the vulnerable one with
``npm install --package-lock-only --before=2020-12-15``), and every pinned
Python, npm and Maven version has published advisories in OSV.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("make_demo_repo")

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
AUTHOR = ("Rohan Mehta", "rohan.mehta@kiranakart.example")
CO_AUTHOR = ("Ananya Iyer", "ananya.iyer@kiranakart.example")

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
B64 = ALNUM + "+/"


def derive(seed: str, length: int, alphabet: str) -> str:
    """Deterministic pseudo-random string from a seed (not a real credential)."""
    out = ""
    counter = 0
    while len(out) < length:
        digest = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        out += "".join(alphabet[b % len(alphabet)] for b in digest)
        counter += 1
    return out[:length]


# Fake credentials, assembled so no complete token appears in this file.
AWS_KEY_ID = "AK" + "IA" + derive("kirana-aws-id", 16, UPPER_NUM)
AWS_SECRET = derive("kirana-aws-secret", 40, B64)
STRIPE_TEST = "sk" + "_test_" + derive("kirana-stripe-test", 24, ALNUM)
STRIPE_LIVE = "sk" + "_live_" + derive("kirana-stripe-live", 24, ALNUM)
STRIPE_DECOY = "sk" + "_live_" + derive("kirana-docs-sample", 24, ALNUM)
DB_PASSWORD = "Kk" + derive("kirana-db-pass", 14, ALNUM) + "!9"
MAIL_PASSWORD = "Ml" + derive("kirana-mail-pass", 12, ALNUM) + "#4x"
COMPOSE_PASSWORD = "Pg" + derive("kirana-pg-pass", 12, ALNUM) + "7z"
AWS_DOC_EXAMPLE = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"  # the key printed in AWS documentation


# =========================================================================== vulnerable files

CONFIG_V1 = '''"""KiranaKart configuration."""
import os

SECRET_KEY = "kirana-dev-secret-2019-rotate-me"
DEBUG_TOOLBAR = os.environ.get("DEBUG_TOOLBAR") == "1"

# Example credentials from the AWS docs, used by the local S3 mock (moto):
S3_MOCK_ACCESS_KEY = "{aws_doc}"
'''

CONFIG_WITH_SECRETS = CONFIG_V1 + '''
# --- payments -------------------------------------------------------------
AWS_ACCESS_KEY_ID = "{aws_id}"
AWS_SECRET_ACCESS_KEY = "{aws_secret}"
RECEIPTS_BUCKET = "kiranakart-receipts"
STRIPE_API_KEY = "{stripe_test}"
'''

CONFIG_FINAL = CONFIG_V1 + '''
# --- payments -------------------------------------------------------------
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
RECEIPTS_BUCKET = "kiranakart-receipts"
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")
# Live keys look like {stripe_decoy} and are issued from the vault.  codesentinel:ignore
'''

APP_V1 = '''"""KiranaKart storefront API (Flask)."""
import os
import sqlite3

from flask import Flask, jsonify, request

from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
DB_PATH = os.path.join(os.path.dirname(__file__), "shop.db")


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/products/search")
def search_products():
    term = request.args.get("q", "")
    cur = get_db().cursor()
    cur.execute(f"SELECT id, name, price FROM products WHERE name LIKE '%{term}%'")
    return jsonify(cur.fetchall())


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    cur = get_db().cursor()
    cur.execute("SELECT id, name, price FROM products WHERE id = ?", (product_id,))
    return jsonify(cur.fetchone())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
'''

APP_FINAL = '''"""KiranaKart storefront API (Flask)."""
import os
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, jsonify, request

from auth import require_admin
from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
DB_PATH = os.path.join(os.path.dirname(__file__), "shop.db")


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/products/search")
def search_products():
    term = request.args.get("q", "")
    cur = get_db().cursor()
    cur.execute(f"SELECT id, name, price FROM products WHERE name LIKE '%{term}%'")
    return jsonify(cur.fetchall())


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    cur = get_db().cursor()
    cur.execute("SELECT id, name, price FROM products WHERE id = ?", (product_id,))
    return jsonify(cur.fetchone())


@app.route("/admin/ping")
def ping_supplier():
    require_admin(request.headers)
    host = request.args.get("host", "localhost")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/admin/import", methods=["POST"])
def import_catalog():
    catalog = yaml.load(request.data)
    return jsonify({"imported": len(catalog)})


@app.route("/shipping/<order_id>")
def shipping_status(order_id):
    resp = requests.get(f"https://api.courier.example/track/{order_id}", verify=False)
    return resp.json()


@app.route("/invoices/<name>")
def invoice(name):
    with open(os.path.join("invoices", name)) as fh:
        return fh.read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
'''

AUTH = '''"""Authentication helpers."""
import hashlib
import random
import string


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def check_password(password, stored):
    return hash_password(password) == stored


def new_reset_token():
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(32))


def require_admin(headers):
    assert headers.get("X-Role") == "admin", "admin only"
'''

CRYPTO_UTILS = '''"""Card tokenisation and invoice signing."""
import os

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

CARD_KEY = bytes.fromhex(os.environ.get("CARD_KEY_HEX", "00" * 16))


def encrypt_card_number(card_number: str) -> bytes:
    cipher = AES.new(CARD_KEY, AES.MODE_ECB)
    padded = card_number.encode().ljust(32, b"\\0")
    return cipher.encrypt(padded)


def generate_invoice_signing_key():
    return RSA.generate(1024)
'''

REQUIREMENTS = """# Storefront API
Flask==1.1.2
Werkzeug==1.0.1
Jinja2==2.10
requests==2.19.0
urllib3==1.24.1
PyYAML==5.3
pycryptodome==3.9.8
# Product image thumbnails
Pillow==8.0.0
# Back-office (Django admin)
Django==3.2.0
"""

DOTENV = f"""FLASK_ENV=development
DATABASE_URL=postgres://shop_admin:{DB_PASSWORD}@db.internal:5432/kiranakart
STRIPE_SECRET_KEY={STRIPE_LIVE}
MAIL_PASSWORD={MAIL_PASSWORD}
"""

DOCKERFILE = """FROM python:latest
WORKDIR /app
RUN apt-get update && apt-get install -y wkhtmltopdf
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
"""

COMPOSE = f"""services:
  web:
    build: .
    ports:
      - "5000:5000"
    env_file: .env
  db:
    image: postgres:13
    environment:
      POSTGRES_USER: shop_admin
      POSTGRES_PASSWORD: {COMPOSE_PASSWORD}
  monitor:
    image: portainer/portainer-ce:2.9.3
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""

WF_CI = """name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@v35
        id: changed
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt && python -m pytest
"""

WF_PREVIEW = """name: PR preview
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run build:preview
"""

WF_TRIAGE = """name: Issue triage
on:
  issues:
    types: [opened]

permissions:
  issues: write

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Classify issue
        run: |
          echo "New issue: ${{ github.event.issue.title }}"
          ./scripts/label.sh
"""

SHOP_JS = """// KiranaKart storefront widgets
function renderReviews(container, reviews) {
  container.innerHTML = reviews.map((r) => `<li><b>${r.author}</b>: ${r.text}</li>`).join("");
}

function newCartSessionToken() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function showBanner(el) {
  el.innerHTML = "<strong>Free delivery on orders above ₹999</strong>";
}

function shuffleRecommendations(items) {
  return items.sort(() => Math.random() - 0.5);
}

module.exports = { renderReviews, newCartSessionToken, showBanner, shuffleRecommendations };
"""

SERVER_JS = """const http = require("http");
const { exec } = require("child_process");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const db = require("./db");

const JWT_SECRET = "kiranakart-jwt-signing-key-2020";
const corsMiddleware = cors({ origin: "*", credentials: true });

function authenticate(req) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  return jwt.verify(token, JWT_SECRET);
}

async function orderHistory(req, res, userId) {
  const rows = await db.query(`SELECT * FROM orders WHERE user_id = ${userId} ORDER BY created_at DESC`);
  res.end(JSON.stringify(rows));
}

function generateInvoice(orderId, res) {
  exec(`wkhtmltopdf http://localhost:5000/invoices/${orderId} /tmp/invoice-${orderId}.pdf`, (err) => {
    res.end(err ? "failed" : "ok");
  });
}

http
  .createServer((req, res) =>
    corsMiddleware(req, res, async () => {
      const user = authenticate(req);
      if (req.url.startsWith("/orders")) return orderHistory(req, res, user.id);
      if (req.url.startsWith("/invoice/")) return generateInvoice(req.url.split("/")[2], res);
      res.statusCode = 404;
      res.end();
    })
  )
  .listen(3000);
"""

DB_JS = """// Thin wrapper around the reporting database driver.
const pool = { query: async (sql, params) => [] };
module.exports = { query: (sql, params) => pool.query(sql, params) };
"""

POM_VULN = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>in.kiranakart</groupId>
  <artifactId>reports-service</artifactId>
  <version>0.3.1</version>
  <name>KiranaKart sales reports</name>

  <properties>
    <maven.compiler.release>11</maven.compiler.release>
    <log4j.version>{log4j}</log4j.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${{log4j.version}}</version>
    </dependency>
  </dependencies>
</project>
"""

README = """# KiranaKart

Neighbourhood grocery delivery: a Flask storefront API, a Node order/invoice
service and a small Java reports job.

> **Training repository.** This project is generated by CodeSentinel's
> `demo/make_demo_repo.py` and deliberately contains vulnerable code,
> outdated dependencies and fake credentials. Do not deploy it.
"""

REPORTS_README = "Nightly sales report generator (Java 11, Log4j 2 logging).\n"


# =========================================================================== fixed files

APP_FIXED = '''"""KiranaKart storefront API (Flask)."""
import os
import re
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, abort, jsonify, request, send_from_directory

from auth import require_admin
from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
DB_PATH = os.path.join(os.path.dirname(__file__), "shop.db")
HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/products/search")
def search_products():
    term = request.args.get("q", "")
    cur = get_db().cursor()
    cur.execute("SELECT id, name, price FROM products WHERE name LIKE ?", (f"%{term}%",))
    return jsonify(cur.fetchall())


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    cur = get_db().cursor()
    cur.execute("SELECT id, name, price FROM products WHERE id = ?", (product_id,))
    return jsonify(cur.fetchone())


@app.route("/admin/ping")
def ping_supplier():
    require_admin(request.headers)
    host = request.args.get("host", "localhost")
    if not HOST_RE.match(host):
        abort(400)
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5, check=False)
    return result.stdout


@app.route("/admin/import", methods=["POST"])
def import_catalog():
    catalog = yaml.safe_load(request.data)
    return jsonify({"imported": len(catalog)})


@app.route("/shipping/<order_id>")
def shipping_status(order_id):
    resp = requests.get(f"https://api.courier.example/track/{order_id}", timeout=10)
    return resp.json()


@app.route("/invoices/<name>")
def invoice(name):
    return send_from_directory("invoices", name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
'''

AUTH_FIXED = '''"""Authentication helpers."""
import hashlib
import hmac
import os
import secrets

ITERATIONS = 600_000


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return salt.hex() + ":" + digest.hex()


def check_password(password, stored):
    salt_hex, digest_hex = stored.split(":")
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 600_000)
    return hmac.compare_digest(candidate.hex(), digest_hex)


def new_reset_token():
    return secrets.token_urlsafe(32)


def require_admin(headers):
    if headers.get("X-Role") != "admin":
        raise PermissionError("admin only")
'''

CRYPTO_FIXED = '''"""Card tokenisation and invoice signing."""
import os

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

CARD_KEY = bytes.fromhex(os.environ["CARD_KEY_HEX"])


def encrypt_card_number(card_number: str) -> tuple[bytes, bytes, bytes]:
    cipher = AES.new(CARD_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(card_number.encode())
    return cipher.nonce, ciphertext, tag


def generate_invoice_signing_key():
    return RSA.generate(3072)
'''

CONFIG_FIXED = '''"""KiranaKart configuration (all secrets come from the environment)."""
import os

SECRET_KEY = os.environ["SECRET_KEY"]
DEBUG_TOOLBAR = os.environ.get("DEBUG_TOOLBAR") == "1"

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
RECEIPTS_BUCKET = "kiranakart-receipts"
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")
'''

REQUIREMENTS_FIXED = """# Storefront API
Flask==3.1.3
Werkzeug==3.1.9
Jinja2==3.1.6
requests==2.34.2
urllib3==2.8.0
PyYAML==6.0.3
pycryptodome==3.23.0
# Product image thumbnails
Pillow==13.0.0
# Back-office (Django admin)
Django==6.1.2
"""

DOTENV_EXAMPLE = """FLASK_ENV=production
DATABASE_URL=postgres://shop_admin:<password>@db.internal:5432/kiranakart
STRIPE_SECRET_KEY=<from-secret-manager>
MAIL_PASSWORD=<from-secret-manager>
"""

GITIGNORE_FIXED = ".env\n__pycache__/\nnode_modules/\n*.pdf\n"

DOCKERFILE_FIXED = """FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends wkhtmltopdf curl \\
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10001 shop
USER shop
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://localhost:5000/products/1 || exit 1
CMD ["python", "app.py"]
"""

COMPOSE_FIXED = """services:
  web:
    build: .
    ports:
      - "5000:5000"
    env_file: .env
  db:
    image: postgres:16.4
    environment:
      POSTGRES_USER: shop_admin
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
"""

WF_CI_FIXED = """name: CI
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
      - uses: tj-actions/changed-files@ed68ef82c095e0d48ec87eccea555d944a631a4c  # v46.0.5
        id: changed
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97  # v7.0.0
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt && python -m pytest
"""

WF_PREVIEW_FIXED = """name: PR preview
on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
      - run: npm ci && npm run build:preview
"""

WF_TRIAGE_FIXED = """name: Issue triage
on:
  issues:
    types: [opened]

permissions:
  issues: write

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Classify issue
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        run: |
          echo "New issue: $ISSUE_TITLE"
          ./scripts/label.sh
"""

SHOP_JS_FIXED = """// KiranaKart storefront widgets
function renderReviews(container, reviews) {
  container.replaceChildren(
    ...reviews.map((r) => {
      const li = document.createElement("li");
      const who = document.createElement("b");
      who.textContent = r.author;
      li.append(who, ": " + r.text);
      return li;
    })
  );
}

function newCartSessionToken() {
  return crypto.randomUUID();
}

function showBanner(el) {
  el.textContent = "Free delivery on orders above ₹999";
}

module.exports = { renderReviews, newCartSessionToken, showBanner };
"""

SERVER_JS_FIXED = """const http = require("http");
const { execFile } = require("child_process");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const db = require("./db");

const JWT_SECRET = process.env.JWT_SECRET;
const corsMiddleware = cors({ origin: ["https://shop.kiranakart.example"], credentials: true });

function authenticate(req) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  return jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
}

async function orderHistory(req, res, userId) {
  const rows = await db.query("SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC", [userId]);
  res.end(JSON.stringify(rows));
}

function generateInvoice(orderId, res) {
  if (!/^[0-9]+$/.test(orderId)) {
    res.statusCode = 400;
    return res.end();
  }
  execFile("wkhtmltopdf", [`http://localhost:5000/invoices/${orderId}`, `/tmp/invoice-${orderId}.pdf`], (err) => {
    res.end(err ? "failed" : "ok");
  });
}

http
  .createServer((req, res) =>
    corsMiddleware(req, res, async () => {
      const user = authenticate(req);
      if (req.url.startsWith("/orders")) return orderHistory(req, res, user.id);
      if (req.url.startsWith("/invoice/")) return generateInvoice(req.url.split("/")[2], res);
      res.statusCode = 404;
      res.end();
    })
  )
  .listen(3000);
"""


# =========================================================================== git helpers


def _rm_readonly(func, path, _exc) -> None:  # type: ignore[no-untyped-def]
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _rmtree(path: Path) -> None:
    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_rm_readonly)
    else:
        shutil.rmtree(path, onerror=_rm_readonly)


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> None:
    base = ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
            "-c", "core.hooksPath=" + os.devnull]
    subprocess.run(base + list(args), check=True, capture_output=True, env={**os.environ, **(env or {})})


def _commit(repo: Path, files: dict[str, str], message: str, when: str, author: tuple[str, str] = AUTHOR,
            delete: tuple[str, ...] = ()) -> None:
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")
    for rel in delete:
        (repo / rel).unlink(missing_ok=True)
    _git(repo, "add", "-A")
    stamp = f"{when}T10:{len(message) % 50 + 10:02d}:00+05:30"
    env = {"GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1], "GIT_AUTHOR_DATE": stamp,
           "GIT_COMMITTER_NAME": author[0], "GIT_COMMITTER_EMAIL": author[1], "GIT_COMMITTER_DATE": stamp}
    _git(repo, "commit", "-q", "-m", message, env=env)


def _init(repo: Path) -> None:
    _rmtree(repo)
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")


def _line(text: str, marker: str, nth: int = 1) -> int:
    count = 0
    for i, ln in enumerate(text.splitlines(), 1):
        if marker in ln:
            count += 1
            if count == nth:
                return i
    raise ValueError(f"marker not found: {marker!r}")


# =========================================================================== builders


def build_vulnerable(dest: Path) -> dict:
    """Create the vulnerable repository and return its ground truth."""
    lock = (DATA / "vulnerable" / "package-lock.json").read_text("utf-8")
    pkg = (DATA / "vulnerable" / "package.json").read_text("utf-8")
    config_v1 = CONFIG_V1.format(aws_doc=AWS_DOC_EXAMPLE)
    config_secrets = CONFIG_WITH_SECRETS.format(aws_doc=AWS_DOC_EXAMPLE, aws_id=AWS_KEY_ID, aws_secret=AWS_SECRET,
                                                stripe_test=STRIPE_TEST)
    config_final = CONFIG_FINAL.format(aws_doc=AWS_DOC_EXAMPLE, stripe_decoy=STRIPE_DECOY)
    pom = POM_VULN.format(log4j="2.14.1")

    _init(dest)
    _commit(dest, {"README.md": README, "app.py": APP_V1, "config.py": config_v1, "requirements.txt": REQUIREMENTS},
            "Initial Flask storefront with product search", "2023-01-09")
    _commit(dest, {"Dockerfile": DOCKERFILE, "docker-compose.yml": COMPOSE, ".env": DOTENV},
            "Add Docker setup and local environment", "2023-01-21")
    _commit(dest, {"config.py": config_secrets, "crypto_utils.py": CRYPTO_UTILS},
            "Integrate payments: S3 receipts and Stripe", "2023-02-03", author=CO_AUTHOR)
    _commit(dest, {"auth.py": AUTH}, "Add password hashing and reset tokens", "2023-02-17")
    _commit(dest, {"server/index.js": SERVER_JS, "server/db.js": DB_JS, "server/package.json": pkg,
                   "server/package-lock.json": lock}, "Add Node order and invoice API", "2023-03-02", author=CO_AUTHOR)
    _commit(dest, {"config.py": config_final}, "Remove secrets, load them from the environment", "2023-03-15")
    _commit(dest, {"static/js/shop.js": SHOP_JS}, "Storefront reviews widget and cart session", "2023-04-04")
    _commit(dest, {".github/workflows/ci.yml": WF_CI, ".github/workflows/pr-preview.yml": WF_PREVIEW,
                   ".github/workflows/triage.yml": WF_TRIAGE}, "Add CI, PR preview and issue triage workflows",
            "2023-04-28", author=CO_AUTHOR)
    _commit(dest, {"app.py": APP_FINAL}, "Admin tools: supplier ping, catalogue import, invoices", "2023-05-12")
    _commit(dest, {"reports-service/pom.xml": pom, "reports-service/README.md": REPORTS_README},
            "Add nightly sales reports service", "2023-06-01", author=CO_AUTHOR)

    gt: list[dict] = []

    def add(module: str, rule: str, file: str, text: str, marker: str, nth: int = 1, **kw: object) -> None:
        gt.append({"module": module, "rule": rule, "file": file, "line": _line(text, marker, nth), **kw})

    # secrets (HEAD)
    add("secrets", "db-connection-string", ".env", DOTENV, "DATABASE_URL=")
    add("secrets", "stripe-live-key", ".env", DOTENV, "STRIPE_SECRET_KEY=")
    add("secrets", "generic-secret-assignment", ".env", DOTENV, "MAIL_PASSWORD=")
    add("secrets", "aws-access-key-id", "config.py", config_final, "S3_MOCK_ACCESS_KEY", placeholder=True)
    # secrets (history only)
    for rule, marker in (("aws-access-key-id", "AWS_ACCESS_KEY_ID ="), ("aws-secret-access-key", "AWS_SECRET_ACCESS_KEY ="),
                         ("stripe-test-key", "STRIPE_API_KEY =")):
        add("secrets", rule, "config.py", config_secrets, marker, historical=True)
    # SAST python
    add("sast", "PY-SQLI", "app.py", APP_FINAL, "WHERE name LIKE", tainted=True)
    add("sast", "PY-CMDI", "app.py", APP_FINAL, "shell=True", tainted=True)
    add("sast", "PY-YAML-LOAD", "app.py", APP_FINAL, "yaml.load(")
    add("sast", "PY-TLS-VERIFY", "app.py", APP_FINAL, "verify=False")
    add("sast", "PY-PATH-TRAVERSAL", "app.py", APP_FINAL, "with open(", tainted=True)
    add("sast", "PY-DEBUG-ENABLED", "app.py", APP_FINAL, "debug=True")
    add("sast", "PY-HARDCODED-SECRET-KEY", "config.py", config_final, 'SECRET_KEY = "')
    add("sast", "PY-WEAK-PASSWORD-HASH", "auth.py", AUTH, "hashlib.md5")
    add("sast", "PY-WEAK-RANDOM", "auth.py", AUTH, "random.choice")
    add("sast", "PY-ASSERT-AUTH", "auth.py", AUTH, "assert ")
    # SAST JavaScript
    add("sast", "JS-XSS-INNERHTML", "static/js/shop.js", SHOP_JS, "container.innerHTML")
    add("sast", "JS-WEAK-RANDOM", "static/js/shop.js", SHOP_JS, "Math.random().toString")
    add("sast", "JS-HARDCODED-JWT-SECRET", "server/index.js", SERVER_JS, "const JWT_SECRET")
    add("sast", "JS-CORS-WILDCARD", "server/index.js", SERVER_JS, "cors({")
    add("sast", "JS-JWT-VERIFY", "server/index.js", SERVER_JS, "jwt.verify(")
    add("sast", "JS-SQLI", "server/index.js", SERVER_JS, "db.query(")
    add("sast", "JS-CMDI", "server/index.js", SERVER_JS, "exec(`")
    # crypto
    add("crypto", "CRYPTO-AES-ECB", "crypto_utils.py", CRYPTO_UTILS, "MODE_ECB")
    add("crypto", "CRYPTO-RSA-SHORT-KEY", "crypto_utils.py", CRYPTO_UTILS, "RSA.generate(1024)")
    # IaC / CI
    add("iac", "DOCKER-LATEST-TAG", "Dockerfile", DOCKERFILE, "FROM python:latest")
    add("iac", "DOCKER-ROOT-USER", "Dockerfile", DOCKERFILE, "FROM python:latest")
    add("iac", "DOCKER-NO-HEALTHCHECK", "Dockerfile", DOCKERFILE, "FROM python:latest")
    add("iac", "DOCKER-APT-NO-CLEANUP", "Dockerfile", DOCKERFILE, "apt-get install")
    add("iac", "DOCKER-CURL-PIPE-SH", "Dockerfile", DOCKERFILE, "| bash")
    add("iac", "COMPOSE-PLAINTEXT-SECRET", "docker-compose.yml", COMPOSE, "POSTGRES_PASSWORD")
    add("iac", "COMPOSE-PRIVILEGED", "docker-compose.yml", COMPOSE, "privileged: true")
    add("iac", "COMPOSE-DOCKER-SOCK", "docker-compose.yml", COMPOSE, "docker.sock")
    add("iac", "DOTENV-COMMITTED", ".env", DOTENV, "FLASK_ENV")
    add("iac", "GHA-UNPINNED-ACTION", ".github/workflows/ci.yml", WF_CI, "tj-actions/changed-files@v35")
    add("iac", "GHA-PERMISSIONS", ".github/workflows/ci.yml", WF_CI, "jobs:")
    add("iac", "GHA-PRT-CHECKOUT", ".github/workflows/pr-preview.yml", WF_PREVIEW, "ref: ${{")
    add("iac", "GHA-SCRIPT-INJECTION", ".github/workflows/triage.yml", WF_TRIAGE, "github.event.issue.title")

    deps = [
        {"ecosystem": "PyPI", "package": p, "version": v, "file": "requirements.txt"}
        for p, v in (("flask", "1.1.2"), ("werkzeug", "1.0.1"), ("jinja2", "2.10"), ("requests", "2.19.0"),
                     ("urllib3", "1.24.1"), ("pyyaml", "5.3"), ("pycryptodome", "3.9.8"), ("pillow", "8.0.0"),
                     ("django", "3.2.0"))
    ] + [
        {"ecosystem": "npm", "package": p, "version": v, "file": "server/package-lock.json", "direct": d}
        for p, v, d in (("axios", "0.21.0", True), ("jsonwebtoken", "8.5.0", True), ("lodash", "4.17.15", True),
                        ("minimist", "1.2.0", True), ("follow-redirects", "1.13.1", False), ("jws", "3.2.2", False),
                        ("semver", "5.7.1", False))
    ] + [
        {"ecosystem": "Maven", "package": "org.apache.logging.log4j:log4j-core", "version": "2.14.1",
         "file": "reports-service/pom.xml"},
    ]
    decoys = [
        {"file": "config.py", "line": _line(config_final, "codesentinel:ignore"),
         "description": "Live-format Stripe key in a comment marked `codesentinel:ignore` (inline allow-list)."},
        {"file": "server/package-lock.json", "line": _line(lock, '"integrity": "sha512-'),
         "description": "SRI integrity hash (sha512, base64) in an npm lockfile: high entropy, not a secret."},
        {"file": "app.py", "line": _line(APP_FINAL, "WHERE id = ?"),
         "description": "Parametrised SQL query (`?` placeholder with a tuple of values): safe, must not be flagged as SQLi."},
    ]
    expected_kev = ["CVE-2023-4863 (pillow 8.0.0)", "CVE-2021-44228 (log4j-core 2.14.1)"]
    for i, g in enumerate(gt, 1):
        g["id"] = f"GT-{i:02d}"
    return {"repository": "demo/vulnerable-shop", "commits": 10, "findings": gt, "vulnerable_dependencies": deps,
            "decoys": decoys, "expected_kev": expected_kev}


def fixed_files() -> dict[str, str]:
    """Every file of the remediated application."""
    return {
        "README.md": README.replace("deliberately contains vulnerable code,\n> outdated dependencies and fake credentials. Do not deploy it.",
                                    "is the remediated twin of `vulnerable-shop`."),
        "app.py": APP_FIXED, "config.py": CONFIG_FIXED, "auth.py": AUTH_FIXED, "crypto_utils.py": CRYPTO_FIXED,
        "requirements.txt": REQUIREMENTS_FIXED, ".gitignore": GITIGNORE_FIXED, ".env.example": DOTENV_EXAMPLE,
        "Dockerfile": DOCKERFILE_FIXED, "docker-compose.yml": COMPOSE_FIXED, "server/index.js": SERVER_JS_FIXED,
        "server/db.js": DB_JS, "server/package.json": (DATA / "fixed" / "package.json").read_text("utf-8"),
        "server/package-lock.json": (DATA / "fixed" / "package-lock.json").read_text("utf-8"),
        "static/js/shop.js": SHOP_JS_FIXED, ".github/workflows/ci.yml": WF_CI_FIXED,
        ".github/workflows/pr-preview.yml": WF_PREVIEW_FIXED, ".github/workflows/triage.yml": WF_TRIAGE_FIXED,
        "reports-service/pom.xml": POM_VULN.format(log4j="2.26.1"), "reports-service/README.md": REPORTS_README,
    }


def build_fixed(dest: Path) -> None:
    """Create the remediated repository (fresh history, three commits)."""
    files = fixed_files()
    groups = [
        (["README.md", "app.py", "config.py", "auth.py", "crypto_utils.py", "requirements.txt", ".gitignore", ".env.example"],
         "KiranaKart v2: storefront API with security fixes", "2023-07-03", AUTHOR),
        (["Dockerfile", "docker-compose.yml", "server/index.js", "server/db.js", "server/package.json",
          "server/package-lock.json", "static/js/shop.js"], "Harden container, Node API and storefront widgets",
         "2023-07-05", CO_AUTHOR),
        ([".github/workflows/ci.yml", ".github/workflows/pr-preview.yml", ".github/workflows/triage.yml",
          "reports-service/pom.xml", "reports-service/README.md"],
         "Pin actions to SHAs, least-privilege tokens, upgrade log4j", "2023-07-08", AUTHOR),
    ]
    _init(dest)
    for names, msg, when, who in groups:
        _commit(dest, {n: files[n] for n in names}, msg, when, author=who)


def remediate(dest: Path) -> None:
    """Commit the fixes on top of the existing vulnerable repository (same project, new commit).

    Rescanning afterwards shows the FAIL -> PASS transition in the history diff. The
    deleted secrets stay in git history, so they are still reported (P1) until the
    credentials are rotated and history is rewritten.
    """
    if not (dest / ".git").exists():
        raise SystemExit(f"{dest} is not a git repository; run without --remediate first")
    _commit(dest, fixed_files(), "Security remediation: fix CodeSentinel P0/P1 findings", "2023-07-10",
            delete=(".env",))


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=HERE, help="directory to create the repositories in")
    ap.add_argument("--remediate", action="store_true",
                    help="commit the fixes on top of the existing vulnerable-shop (for the history-diff demo)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    vuln, fixed = args.out / "vulnerable-shop", args.out / "vulnerable-shop-fixed"
    if args.remediate:
        remediate(vuln)
        log.info("committed the remediation to %s; scan it again and open its History page", vuln)
        return 0
    gt = build_vulnerable(vuln)
    build_fixed(fixed)
    (HERE / "ground_truth.json").write_text(json.dumps(gt, indent=2) + "\n", encoding="utf-8")
    log.info("created %s (%d planted findings, %d vulnerable dependencies, %d decoys)", vuln, len(gt["findings"]),
             len(gt["vulnerable_dependencies"]), len(gt["decoys"]))
    log.info("created %s", fixed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
