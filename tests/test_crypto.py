"""Module 5: cryptography inventory, classification and quantum flags."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from app.scanners.crypto import inventory_js, inventory_python, scan_crypto


def py(src: str) -> dict[str, object]:
    return {a.name: a for a, _ in inventory_python(textwrap.dedent(src), "c.py")}


def js(src: str) -> dict[str, object]:
    return {a.name: a for a, _ in inventory_js(src, "c.js")}


@pytest.mark.parametrize("src,name,cls", [
    ("import hashlib\nhashlib.md5(b'x')", "MD5", "broken"),
    ("import hashlib\nhashlib.sha1(b'x')", "SHA-1", "weak"),
    ("import hashlib\nhashlib.sha256(b'x')", "SHA-256", "approved"),
    ("import hashlib\nhashlib.pbkdf2_hmac('sha256', p, s, 1000)", "PBKDF2-HMAC-SHA-256", "weak"),
    ("import hashlib\nhashlib.pbkdf2_hmac('sha256', p, s, 600_000)", "PBKDF2-HMAC-SHA-256", "approved"),
    ("import bcrypt\nbcrypt.hashpw(p, bcrypt.gensalt())", "bcrypt", "approved"),
    ("from argon2 import PasswordHasher\nPasswordHasher()", "Argon2id", "approved"),
    ("from Crypto.Cipher import AES\nAES.new(k, AES.MODE_ECB)", "AES-ECB", "broken"),
    ("from Crypto.Cipher import AES\nAES.new(k, AES.MODE_GCM)", "AES-GCM", "approved"),
    ("from Crypto.Cipher import DES\nDES.new(k, DES.MODE_CBC)", "DES", "broken"),
    ("from Crypto.Cipher import DES3\nDES3.new(k, DES3.MODE_CBC)", "3DES", "weak"),
    ("from Crypto.Cipher import ARC4\nARC4.new(k)", "RC4", "broken"),
    ("from Crypto.PublicKey import RSA\nRSA.generate(1024)", "RSA-1024", "broken"),
    ("from Crypto.PublicKey import RSA\nRSA.generate(3072)", "RSA-3072", "approved"),
    ("from cryptography.hazmat.primitives.asymmetric import ec\nec.generate_private_key(ec.SECP256R1())", "ECC-P-256", "approved"),
    ("from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nCipher(algorithms.AES(k), modes.ECB())", "AES-ECB", "broken"),
    ("import ssl\nssl.SSLContext(ssl.PROTOCOL_TLSv1)", "TLS-TLSv1.0", "broken"),
    ("import requests\nrequests.get(u, verify=False)", "TLS (certificate verification disabled)", "broken"),
    ("import jwt\njwt.decode(t, k, algorithms=['none'])", "JWT-none", "broken"),
    ("import jwt\njwt.encode(p, k, algorithm='RS256')", "JWT-RS256", "approved"),
    ("import secrets\nsecrets.token_hex(16)", "CSPRNG (OS entropy)", "approved"),
    ("import random\ndef new_token():\n    return random.random()", "Mersenne Twister PRNG", "weak"),
])
def test_python_classification(src: str, name: str, cls: str) -> None:
    assets = py(src)
    assert name in assets, assets.keys()
    assert assets[name].classification == cls


def test_random_outside_security_context_not_inventoried() -> None:
    assert "Mersenne Twister PRNG" not in py("import random\ndef pick(xs):\n    return random.choice(xs)")


def test_quantum_vulnerable_flags() -> None:
    assets = py("from Crypto.PublicKey import RSA\nRSA.generate(2048)\nimport hashlib\nhashlib.sha256(b'')")
    assert assets["RSA-2048"].quantum_vulnerable and not assets["SHA-256"].quantum_vulnerable


@pytest.mark.parametrize("src,name,cls", [
    ("crypto.createHash('md5')", "MD5", "broken"),
    ("crypto.createCipheriv('aes-256-gcm', k, iv)", "AES-256-GCM", "approved"),
    ("crypto.createCipheriv('aes-128-ecb', k, null)", "AES-128-ECB", "broken"),
    ("crypto.createCipheriv('des-ede3-cbc', k, iv)", "3DES", "weak"),
    ("crypto.generateKeyPairSync('rsa', { modulusLength: 1024 })", "RSA-1024", "broken"),
    ("crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })", "ECC-P-256", "approved"),
    ("crypto.pbkdf2Sync(pw, salt, 1000, 64, 'sha512')", "PBKDF2-HMAC-SHA-512", "weak"),
    ("tls.connect({ host, rejectUnauthorized: false })", "TLS (certificate verification disabled)", "broken"),
    ("jwt.sign(p, k, { algorithm: 'HS256' })", "JWT-HS256", "approved"),
])
def test_js_classification(src: str, name: str, cls: str) -> None:
    assets = js(src)
    assert name in assets and assets[name].classification == cls


def test_findings_only_for_weak_or_broken(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.sha256(b'')\nhashlib.md5(b'')\n")
    assets, findings = scan_crypto(tmp_path, ["a.py"])
    assert len(assets) == 2 and [f.rule_id for f in findings] == ["CRYPTO-MD5"]
    assert findings[0].extra["crypto_class"] == "broken" and findings[0].owasp == "A02"
