"""Module 5: cryptography inventory for the CBOM (cryptographic bill of materials).

Each detected use of cryptography becomes a :class:`CryptoAsset` with a
classification:

* ``approved``: current best practice (AES-GCM, SHA-256, Argon2, RSA >= 2048 ...)
* ``weak``: deprecated or under-parameterised (SHA-1, 3DES, low PBKDF2 iterations)
* ``broken``: practically attackable (MD5, DES, RC4, ECB mode, RSA < 2048,
  legacy TLS, disabled certificate checks, JWT ``none``)

RSA, DSA, DH and elliptic-curve algorithms are also flagged
``quantum_vulnerable`` because Shor's algorithm breaks them. This supports the
post-quantum readiness view that CERT-In's BOM guidelines v2.0 (CBOM/QBOM)
ask organisations to maintain.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.scanners.base import CryptoAsset, Finding, make_snippet, read_text
from app.scanners.sast_js import JS_EXTS, strip_comments
from app.scanners.sast_python import SECURITY_WORDS, _has_word


@dataclass
class _Spec:
    name: str
    family: str
    primitive: str
    classification: str
    asset_type: str = "algorithm"
    mode: str | None = None
    parameter: str | None = None
    functions: list[str] = field(default_factory=list)
    quantum_vulnerable: bool = False
    nist_q: int | None = None
    classical: int | None = None
    reason: str = ""
    rule: str | None = None
    cwe: str = "CWE-327"


HASHES: dict[str, _Spec] = {
    "md5": _Spec("MD5", "MD5", "hash", "broken", functions=["digest"], classical=0, rule="CRYPTO-MD5", cwe="CWE-328",
                 reason="MD5 collisions can be computed in seconds (Wang et al. 2004; Flame malware 2012)."),
    "sha1": _Spec("SHA-1", "SHA-1", "hash", "weak", functions=["digest"], classical=63, rule="CRYPTO-SHA1", cwe="CWE-328",
                  reason="Practical SHA-1 collisions exist (SHAttered 2017, chosen-prefix 2020); NIST retires SHA-1 by 2030."),
    "sha224": _Spec("SHA-224", "SHA-2", "hash", "approved", parameter="224", functions=["digest"], nist_q=1, classical=112),
    "sha256": _Spec("SHA-256", "SHA-2", "hash", "approved", parameter="256", functions=["digest"], nist_q=2, classical=128),
    "sha384": _Spec("SHA-384", "SHA-2", "hash", "approved", parameter="384", functions=["digest"], nist_q=4, classical=192),
    "sha512": _Spec("SHA-512", "SHA-2", "hash", "approved", parameter="512", functions=["digest"], nist_q=5, classical=256),
    "sha3_256": _Spec("SHA3-256", "SHA-3", "hash", "approved", parameter="256", functions=["digest"], nist_q=2, classical=128),
    "sha3_512": _Spec("SHA3-512", "SHA-3", "hash", "approved", parameter="512", functions=["digest"], nist_q=5, classical=256),
    "blake2b": _Spec("BLAKE2b", "BLAKE2", "hash", "approved", parameter="512", functions=["digest"], classical=256),
    "blake2s": _Spec("BLAKE2s", "BLAKE2", "hash", "approved", parameter="256", functions=["digest"], classical=128),
}
HASH_ALIASES = {"sha-1": "sha1", "sha-256": "sha256", "sha-512": "sha512", "sha-384": "sha384", "rsa-md5": "md5"}

SYMMETRIC: dict[str, _Spec] = {
    "DES": _Spec("DES", "DES", "block-cipher", "broken", parameter="56", functions=["encrypt", "decrypt"], classical=56,
                 rule="CRYPTO-DES", reason="56-bit DES keys can be brute-forced in under a day."),
    "DES3": _Spec("3DES", "3DES", "block-cipher", "weak", parameter="168", functions=["encrypt", "decrypt"], classical=112,
                  rule="CRYPTO-3DES", reason="64-bit block size enables Sweet32 birthday attacks; NIST disallowed 3DES after 2023."),
    "TripleDES": _Spec("3DES", "3DES", "block-cipher", "weak", parameter="168", functions=["encrypt", "decrypt"],
                       classical=112, rule="CRYPTO-3DES", reason="64-bit block size (Sweet32); disallowed by NIST after 2023."),
    "ARC4": _Spec("RC4", "RC4", "stream-cipher", "broken", functions=["encrypt", "decrypt"], rule="CRYPTO-RC4",
                  reason="RC4 keystream biases are exploitable; prohibited in TLS by RFC 7465."),
    "Blowfish": _Spec("Blowfish", "Blowfish", "block-cipher", "weak", functions=["encrypt", "decrypt"],
                      rule="CRYPTO-BLOWFISH", reason="64-bit block size (Sweet32)."),
    "ChaCha20": _Spec("ChaCha20", "ChaCha20", "stream-cipher", "approved", parameter="256", functions=["encrypt", "decrypt"],
                      classical=256),
    "Salsa20": _Spec("Salsa20", "Salsa20", "stream-cipher", "approved", parameter="256", functions=["encrypt", "decrypt"]),
}

AES_MODES_OK = {"GCM", "CCM", "EAX", "SIV", "OCB", "GCMSIV", "CTR", "CBC", "CFB", "OFB", "XTS"}
CURVES = {"secp256r1": "P-256", "prime256v1": "P-256", "p-256": "P-256", "secp384r1": "P-384", "p-384": "P-384",
          "secp521r1": "P-521", "p-521": "P-521", "secp256k1": "secp256k1", "ed25519": "Ed25519", "x25519": "X25519",
          "secp192r1": "P-192", "prime192v1": "P-192", "secp224r1": "P-224", "ed448": "Ed448"}
WEAK_CURVES = {"P-192", "P-224"}


def _aes(mode: str | None, bits: str | None = None) -> _Spec:
    m = (mode or "ECB").upper()
    name = "AES" + (f"-{bits}" if bits else "") + f"-{m}"
    nq = {"128": 1, "192": 3, "256": 5}.get(bits or "")
    if m == "ECB":
        return _Spec(name, "AES", "block-cipher", "broken", mode="ecb", parameter=bits, functions=["encrypt", "decrypt"],
                     nist_q=nq, rule="CRYPTO-AES-ECB",
                     reason="ECB encrypts identical blocks to identical ciphertext, leaking data patterns (the \"ECB penguin\").")
    prim = "ae" if m in ("GCM", "CCM", "EAX", "SIV", "OCB", "GCMSIV") else "block-cipher"
    return _Spec(name, "AES", prim, "approved", mode=m.lower(), parameter=bits, functions=["encrypt", "decrypt"],
                 nist_q=nq, classical=int(bits) if bits else None)


def _rsa(bits: int | None, primitive: str = "pke") -> _Spec:
    b = str(bits) if bits else None
    if bits and bits < 2048:
        return _Spec(f"RSA-{bits}", "RSA", primitive, "broken", parameter=b, functions=["keygen", "sign", "encrypt"],
                     quantum_vulnerable=True, nist_q=0, classical=80 if bits >= 1024 else 56, rule="CRYPTO-RSA-SHORT-KEY",
                     cwe="CWE-326",
                     reason=f"{bits}-bit RSA is below the 2048-bit minimum (NIST SP 800-131A); 1024-bit keys are within reach of well-funded attackers.")
    classical = {2048: 112, 3072: 128, 4096: 152}.get(bits or 0)
    return _Spec(f"RSA-{bits}" if bits else "RSA", "RSA", primitive, "approved", parameter=b,
                 functions=["keygen", "sign", "encrypt"], quantum_vulnerable=True, nist_q=0, classical=classical,
                 reason="Classically secure but breakable by Shor's algorithm; plan migration to ML-KEM / ML-DSA (FIPS 203/204).")


def _ec(curve: str | None) -> _Spec:
    c = CURVES.get((curve or "").lower(), curve or "EC")
    weak = c in WEAK_CURVES
    prim = "signature" if c in ("Ed25519", "Ed448") else "key-agree" if c == "X25519" else "pke"
    return _Spec(f"ECC-{c}" if not c.startswith(("Ed", "X")) else c, "ECC", prim, "weak" if weak else "approved",
                 parameter=c, functions=["keygen", "sign", "keyexchange"], quantum_vulnerable=True, nist_q=0,
                 classical={"P-256": 128, "P-384": 192, "P-521": 256, "Ed25519": 128, "X25519": 128}.get(c),
                 rule="CRYPTO-WEAK-CURVE" if weak else None,
                 reason="Elliptic-curve cryptography is vulnerable to Shor's algorithm (quantum).")


def _pbkdf2(digest: str, iterations: int | None) -> _Spec:
    d = HASH_ALIASES.get(digest.lower(), digest.lower())
    low = iterations is not None and iterations < 100_000
    weak_hash = d in ("md5", "sha1")
    cls = "weak" if (low or weak_hash) else "approved"
    reason = (f"Only {iterations:,} iterations; OWASP recommends 600,000 for PBKDF2-HMAC-SHA256." if low else
              "PBKDF2 over a weak hash." if weak_hash else "")
    return _Spec(f"PBKDF2-HMAC-{HASHES.get(d, _Spec(d.upper(), '', '', '')).name}", "PBKDF2", "kdf", cls,
                 parameter=str(iterations) if iterations else None, functions=["keyderive"],
                 rule="CRYPTO-PBKDF2-WEAK" if cls == "weak" else None, cwe="CWE-916", reason=reason)


def _jwt(alg: str) -> _Spec:
    a = alg.strip().strip("'\"").upper()
    if a == "NONE":
        return _Spec("JWT-none", "JWT", "signature", "broken", parameter="none", functions=["verify"], rule="CRYPTO-JWT-NONE",
                     cwe="CWE-347", reason="The 'none' algorithm disables signature verification entirely.")
    qv = a.startswith(("RS", "PS", "ES", "ED"))
    prim = "mac" if a.startswith("HS") else "signature"
    return _Spec(f"JWT-{a}", "JWT", prim, "approved", parameter=a, functions=["sign", "verify"], quantum_vulnerable=qv,
                 nist_q=0 if qv else None)


TLS_LEGACY = {"PROTOCOL_SSLv2": "SSLv2", "PROTOCOL_SSLv3": "SSLv3", "PROTOCOL_TLSv1": "TLSv1.0", "PROTOCOL_TLSv1_1": "TLSv1.1",
              "PROTOCOL_SSLv23": "SSLv23 (negotiated)"}


def _tls_legacy(ver: str) -> _Spec:
    return _Spec(f"TLS-{ver}", "TLS", "protocol", "broken", asset_type="protocol", parameter=ver,
                 functions=["keyexchange", "encrypt"], rule="CRYPTO-TLS-LEGACY", cwe="CWE-326",
                 reason="SSL 3.0, TLS 1.0 and 1.1 are deprecated (RFC 8996) and vulnerable to POODLE/BEAST-class attacks.")


TLS_NOVERIFY = _Spec("TLS (certificate verification disabled)", "TLS", "protocol", "broken", asset_type="protocol",
                     parameter="verify=false", functions=["authenticate"], rule="CRYPTO-TLS-NOVERIFY", cwe="CWE-295",
                     reason="Without certificate validation, TLS provides encryption to whoever intercepts the connection.")
TLS_DEFAULT = _Spec("TLS (system default context)", "TLS", "protocol", "approved", asset_type="protocol",
                    parameter="default", functions=["keyexchange", "encrypt", "authenticate"])
PRNG_WEAK = _Spec("Mersenne Twister PRNG", "PRNG", "drbg", "weak", parameter="MT19937", functions=["generate"],
                  rule="CRYPTO-WEAK-PRNG", cwe="CWE-338", reason="Non-cryptographic generator used for a security value.")
PRNG_JS_WEAK = _Spec("Math.random (xorshift128+)", "PRNG", "drbg", "weak", parameter="xorshift128+", functions=["generate"],
                     rule="CRYPTO-WEAK-PRNG", cwe="CWE-338", reason="Non-cryptographic generator used for a security value.")
CSPRNG = _Spec("CSPRNG (OS entropy)", "CSPRNG", "drbg", "approved", functions=["generate"])
BCRYPT = _Spec("bcrypt", "bcrypt", "kdf", "approved", functions=["keyderive"], reason="Adaptive password hash.")
ARGON2 = _Spec("Argon2id", "Argon2", "kdf", "approved", functions=["keyderive"], reason="Memory-hard password hash (RFC 9106).")
SCRYPT = _Spec("scrypt", "scrypt", "kdf", "approved", functions=["keyderive"])
FERNET = _Spec("Fernet (AES-128-CBC + HMAC-SHA256)", "AES", "ae", "approved", mode="cbc", parameter="128",
               functions=["encrypt", "decrypt"], nist_q=1)
DSA = _Spec("DSA", "DSA", "signature", "weak", functions=["keygen", "sign"], quantum_vulnerable=True, nist_q=0,
            rule="CRYPTO-DSA", reason="DSA was removed from FIPS 186-5 for signature generation.")


def _asset(spec: _Spec, rel: str, line: int, lines: list[str], language: str, library: str | None,
           security_context: bool = False) -> CryptoAsset:
    return CryptoAsset(
        name=spec.name, family=spec.family, primitive=spec.primitive, asset_type=spec.asset_type,
        classification=spec.classification, file=rel, line=line, language=language, mode=spec.mode,
        parameter=spec.parameter, crypto_functions=list(spec.functions), quantum_vulnerable=spec.quantum_vulnerable,
        nist_quantum_level=spec.nist_q, classical_level=spec.classical, library=library, reason=spec.reason,
        security_context=security_context, snippet=make_snippet(lines, line, context=2),
    )


# ============================================================================ Python


def _const(node: ast.AST | None) -> Any:
    return node.value if isinstance(node, ast.Constant) else None


class _PyCrypto(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str]) -> None:
        self.rel, self.lines = rel, lines
        self.assets: list[tuple[CryptoAsset, _Spec]] = []
        self.aliases: dict[str, str] = {}
        self.func: list[str] = ["<module>"]
        self.targets: list[str] = []

    def add(self, spec: _Spec, node: ast.AST, library: str | None, ctx: bool = False) -> None:
        self.assets.append((_asset(spec, self.rel, getattr(node, "lineno", 1), self.lines, "python", library, ctx), spec))

    def dotted(self, node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        else:
            return ""
        return ".".join(reversed(parts))

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{node.module}.{a.name}" if node.module else a.name

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.func.append(node.name)
        self.generic_visit(node)
        self.func.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:
        self.targets = [n.id if isinstance(n, ast.Name) else n.attr for t in node.targets for n in ast.walk(t)
                        if isinstance(n, (ast.Name, ast.Attribute))]
        self.visit(node.value)
        self.targets = []

    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = self.dotted(node)
        if name.startswith("ssl.") and node.attr in TLS_LEGACY:
            self.add(_tls_legacy(TLS_LEGACY[node.attr]), node, "ssl")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self.dotted(node.func)
        method = name.rsplit(".", 1)[-1] if name else ""
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        args = node.args
        arg0 = args[0] if args else None
        if name.startswith("hashlib."):
            if method in HASHES:
                if _const(kw.get("usedforsecurity")) is not False:
                    self.add(HASHES[method], node, "hashlib")
            elif method == "new" and isinstance(_const(arg0), str):
                h = HASH_ALIASES.get(arg0.value.lower(), arg0.value.lower())  # type: ignore[union-attr]
                if h in HASHES:
                    self.add(HASHES[h], node, "hashlib")
            elif method == "pbkdf2_hmac":
                digest = _const(arg0) or "sha256"
                it = _const(args[3]) if len(args) > 3 else _const(kw.get("iterations"))
                self.add(_pbkdf2(str(digest), it if isinstance(it, int) else None), node, "hashlib")
            elif method == "scrypt":
                self.add(SCRYPT, node, "hashlib")
        elif name == "hmac.new":
            dm = args[2] if len(args) > 2 else kw.get("digestmod")
            dname = (self.dotted(dm).rsplit(".", 1)[-1] if dm is not None and not isinstance(dm, ast.Constant)
                     else str(_const(dm) or "md5")).lower()
            dname = HASH_ALIASES.get(dname, dname)
            base = HASHES.get(dname)
            if base:
                cls = "weak" if base.classification != "approved" else "approved"
                self.add(_Spec(f"HMAC-{base.name}", "HMAC", "mac", cls, functions=["tag"],
                               rule="CRYPTO-WEAK-HMAC" if cls == "weak" else None,
                               reason="HMAC over a deprecated hash." if cls == "weak" else ""), node, "hmac")
        elif name.startswith(("bcrypt.",)) and method in ("hashpw", "gensalt", "kdf"):
            if method != "gensalt":
                self.add(BCRYPT, node, "bcrypt")
        elif name.startswith(("argon2.",)) and method in ("PasswordHasher", "hash_password", "hash_secret"):
            self.add(ARGON2, node, "argon2-cffi")
        elif name.endswith("Fernet") and "fernet" in name.lower():
            self.add(FERNET, node, "cryptography")
        elif re.match(r"(Crypto|Cryptodome)\.Cipher\.(\w+)\.new$", name):
            algo = name.split(".")[2]
            mode_node = args[1] if len(args) > 1 else kw.get("mode")
            mode = self.dotted(mode_node).rsplit("MODE_", 1)[-1] if mode_node is not None else None
            if algo == "AES":
                self.add(_aes(mode), node, "pycryptodome")
            elif algo in SYMMETRIC:
                self.add(SYMMETRIC[algo], node, "pycryptodome")
        elif method == "Cipher" and "cipher" in name.lower() and args:
            alg = self.dotted(args[0].func) if isinstance(args[0], ast.Call) else ""
            alg_name = alg.rsplit(".", 1)[-1]
            mode_call = args[1] if len(args) > 1 else kw.get("mode")
            mode = (self.dotted(mode_call.func).rsplit(".", 1)[-1]
                    if isinstance(mode_call, ast.Call) else None)
            if alg_name == "AES":
                self.add(_aes(mode), node, "cryptography")
            elif alg_name in SYMMETRIC:
                self.add(SYMMETRIC[alg_name], node, "cryptography")
        elif re.match(r"(Crypto|Cryptodome)\.PublicKey\.RSA\.generate$", name) or name in ("rsa.newkeys",):
            bits = _const(arg0) if arg0 is not None else _const(kw.get("bits"))
            self.add(_rsa(bits if isinstance(bits, int) else None), node, "pycryptodome" if "Crypto" in name else "rsa")
        elif name.endswith("rsa.generate_private_key"):
            bits = _const(kw.get("key_size")) or (_const(args[1]) if len(args) > 1 else None)
            self.add(_rsa(bits if isinstance(bits, int) else None), node, "cryptography")
        elif name.endswith("dsa.generate_private_key") and "ec." not in name:
            self.add(DSA, node, "cryptography")
        elif name.endswith("ec.generate_private_key"):
            curve = self.dotted(arg0.func if isinstance(arg0, ast.Call) else arg0).rsplit(".", 1)[-1] if arg0 is not None else None
            self.add(_ec(curve), node, "cryptography")
        elif re.match(r"(Crypto|Cryptodome)\.PublicKey\.ECC\.generate$", name):
            self.add(_ec(str(_const(kw.get("curve")) or "P-256")), node, "pycryptodome")
        elif name.endswith(("Ed25519PrivateKey.generate", "X25519PrivateKey.generate")):
            self.add(_ec("ed25519" if "Ed25519" in name else "x25519"), node, "cryptography")
        elif name in ("ssl.create_default_context",):
            self.add(TLS_DEFAULT, node, "ssl")
        elif name == "ssl._create_unverified_context":
            self.add(TLS_NOVERIFY, node, "ssl")
        elif name.startswith("jwt.") and method in ("encode", "decode"):
            if method == "encode":
                alg = _const(kw.get("algorithm")) or "HS256"
                self.add(_jwt(str(alg)), node, "PyJWT")
            else:
                algs = kw.get("algorithms")
                if isinstance(algs, (ast.List, ast.Tuple)):
                    for e in algs.elts:
                        if isinstance(_const(e), str):
                            self.add(_jwt(e.value), node, "PyJWT")  # type: ignore[union-attr]
        elif name.startswith("random.") and method in ("random", "randint", "choice", "choices", "getrandbits",
                                                       "randrange", "sample", "randbytes"):
            if _has_word(self.targets + [self.func[-1]], SECURITY_WORDS):
                self.add(PRNG_WEAK, node, "random", ctx=True)
        elif name.startswith("secrets.") or name == "os.urandom":
            self.add(CSPRNG, node, "secrets" if name.startswith("secrets") else "os")
        v = kw.get("verify")
        if isinstance(v, ast.Constant) and v.value is False:
            self.add(TLS_NOVERIFY, node, name.split(".", 1)[0] or None)
        self.generic_visit(node)


def inventory_python(source: str, rel: str) -> list[tuple[CryptoAsset, _Spec]]:
    """Return crypto assets used in one Python file."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    v = _PyCrypto(rel, source.splitlines())
    v.visit(tree)
    return v.assets


# ============================================================================ JavaScript

JS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bcreateHash\s*\(\s*['\"`]([\w\-]+)['\"`]"), "hash"),
    (re.compile(r"\bcreateHmac\s*\(\s*['\"`]([\w\-]+)['\"`]"), "hmac"),
    (re.compile(r"\bcreateCipheriv\s*\(\s*['\"`]([\w\-]+)['\"`]"), "cipher"),
    (re.compile(r"\bcreateDecipheriv\s*\(\s*['\"`]([\w\-]+)['\"`]"), "cipher"),
    (re.compile(r"\bcreateCipher\s*\(\s*['\"`]([\w\-]+)['\"`]"), "legacy-cipher"),
    (re.compile(r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"`](rsa|rsa-pss|ec|ed25519|x25519|dsa)['\"`]\s*,\s*\{([^}]*)\}"), "keypair"),
    (re.compile(r"\bpbkdf2(?:Sync)?\s*\(\s*[^,]+,\s*[^,]+,\s*(\d[\d_]*)\s*,\s*\d+\s*,\s*['\"`]([\w\-]+)['\"`]"), "pbkdf2"),
    (re.compile(r"\b(?:crypto\.)?(randomBytes|randomUUID|getRandomValues|randomInt)\s*\("), "csprng"),
    (re.compile(r"\bbcrypt(?:js)?\s*\.\s*(?:hash|hashSync|genSalt)\s*\("), "bcrypt"),
    (re.compile(r"\bargon2\s*\.\s*hash\s*\("), "argon2"),
    (re.compile(r"algorithm\s*:\s*['\"`]((?:HS|RS|PS|ES)\d{3}|EdDSA|none)['\"`]", re.I), "jwt"),
    (re.compile(r"algorithms\s*:\s*\[([^\]]*)\]"), "jwt-list"),
    (re.compile(r"rejectUnauthorized\s*:\s*false"), "tls-noverify"),
    (re.compile(r"(?:minVersion|maxVersion)\s*:\s*['\"`](TLSv1(?:\.1)?)['\"`]|secureProtocol\s*:\s*['\"`](TLSv1(?:_1)?_method|SSLv3_method)['\"`]"), "tls-legacy"),
    (re.compile(r"\bMath\.random\s*\(\s*\)"), "math-random"),
]


def _js_cipher(name: str) -> _Spec:
    n = name.lower()
    m = re.match(r"aes-?(128|192|256)?-?(\w+)?", n)
    if n.startswith("aes") and m:
        return _aes((m.group(2) or "cbc").upper(), m.group(1))
    if n.startswith(("des-ede3", "des3", "des-ede")):
        return SYMMETRIC["DES3"]
    if n.startswith("des"):
        return SYMMETRIC["DES"]
    if n.startswith("rc4"):
        return SYMMETRIC["ARC4"]
    if n.startswith(("bf", "blowfish")):
        return SYMMETRIC["Blowfish"]
    if n.startswith("chacha20"):
        return SYMMETRIC["ChaCha20"]
    return _Spec(name.upper(), name.upper(), "block-cipher", "approved", functions=["encrypt", "decrypt"])


def inventory_js(source: str, rel: str) -> list[tuple[CryptoAsset, _Spec]]:
    """Return crypto assets used in one JS/TS file."""
    code = strip_comments(source)
    lines = source.splitlines()
    code_lines = code.splitlines()
    out: list[tuple[CryptoAsset, _Spec]] = []

    def add(spec: _Spec, offset: int, lib: str = "node:crypto", ctx: bool = False) -> None:
        ln = code.count("\n", 0, offset) + 1
        out.append((_asset(spec, rel, ln, lines, "javascript", lib, ctx), spec))

    for rx, kind in JS_PATTERNS:
        for m in rx.finditer(code):
            if kind == "hash":
                h = HASH_ALIASES.get(m.group(1).lower(), m.group(1).lower().replace("-", ""))
                if h in HASHES:
                    add(HASHES[h], m.start())
            elif kind == "hmac":
                h = HASH_ALIASES.get(m.group(1).lower(), m.group(1).lower().replace("-", ""))
                base = HASHES.get(h)
                if base:
                    cls = "weak" if base.classification != "approved" else "approved"
                    add(_Spec(f"HMAC-{base.name}", "HMAC", "mac", cls, functions=["tag"],
                              rule="CRYPTO-WEAK-HMAC" if cls == "weak" else None), m.start())
            elif kind == "cipher":
                add(_js_cipher(m.group(1)), m.start())
            elif kind == "legacy-cipher":
                add(_Spec(f"{m.group(1).upper()} via createCipher (MD5 key derivation)", "EVP_BytesToKey", "block-cipher",
                          "broken", functions=["encrypt"], rule="CRYPTO-LEGACY-CREATECIPHER",
                          reason="crypto.createCipher derives keys with a single MD5 round and no salt/IV; removed in Node 22."), m.start())
            elif kind == "keypair":
                typ, body = m.group(1), m.group(2)
                if typ.startswith("rsa"):
                    bits = re.search(r"modulusLength\s*:\s*(\d+)", body)
                    add(_rsa(int(bits.group(1)) if bits else None), m.start())
                elif typ == "ec":
                    curve = re.search(r"namedCurve\s*:\s*['\"`]([\w\-]+)['\"`]", body)
                    add(_ec(curve.group(1) if curve else None), m.start())
                elif typ in ("ed25519", "x25519"):
                    add(_ec(typ), m.start())
                else:
                    add(DSA, m.start())
            elif kind == "pbkdf2":
                add(_pbkdf2(m.group(2), int(m.group(1).replace("_", ""))), m.start())
            elif kind == "csprng":
                add(CSPRNG, m.start())
            elif kind == "bcrypt":
                add(BCRYPT, m.start(), "bcrypt")
            elif kind == "argon2":
                add(ARGON2, m.start(), "argon2")
            elif kind == "jwt":
                add(_jwt(m.group(1)), m.start(), "jsonwebtoken")
            elif kind == "jwt-list":
                for alg in re.findall(r"['\"`]([\w]+)['\"`]", m.group(1)):
                    add(_jwt(alg), m.start(), "jsonwebtoken")
            elif kind == "tls-noverify":
                add(TLS_NOVERIFY, m.start(), "node:tls")
            elif kind == "tls-legacy":
                ver = (m.group(1) or m.group(2) or "TLSv1").replace("_method", "").replace("_", ".")
                add(_tls_legacy(ver), m.start(), "node:tls")
            elif kind == "math-random":
                ln = code.count("\n", 0, m.start()) + 1
                window = code_lines[max(0, ln - 6):ln]
                idents = [i for w in window for i in re.findall(r"[A-Za-z_$][\w$]*", w)]
                if _has_word(idents, SECURITY_WORDS):
                    add(PRNG_JS_WEAK, m.start(), "V8", ctx=True)
    return out


# ============================================================================ driver

CRYPTO_REMEDIATION = {
    "CRYPTO-MD5": ("Replace MD5. For integrity use SHA-256; for passwords use Argon2id/bcrypt/scrypt.",
                   "import hashlib\ndigest = hashlib.sha256(data).hexdigest()"),
    "CRYPTO-SHA1": ("Move to SHA-256 or SHA-3.", "hashlib.sha256(data).hexdigest()"),
    "CRYPTO-AES-ECB": ("Use an authenticated mode such as AES-GCM with a unique 96-bit nonce per message.",
                       "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nkey = AESGCM.generate_key(bit_length=256)\nnonce = os.urandom(12)\nct = AESGCM(key).encrypt(nonce, plaintext, associated_data)"),
    "CRYPTO-DES": ("Replace DES with AES-256-GCM.", "AESGCM(key).encrypt(nonce, data, None)"),
    "CRYPTO-3DES": ("Replace 3DES with AES-256-GCM.", "AESGCM(key).encrypt(nonce, data, None)"),
    "CRYPTO-RC4": ("Replace RC4 with AES-GCM or ChaCha20-Poly1305.",
                   "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305"),
    "CRYPTO-BLOWFISH": ("Replace Blowfish with AES-GCM.", "AESGCM(key).encrypt(nonce, data, None)"),
    "CRYPTO-RSA-SHORT-KEY": ("Generate RSA keys of at least 3072 bits (or use Ed25519/ECDSA P-256), and plan a post-quantum migration path.",
                             "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=3072)"),
    "CRYPTO-TLS-LEGACY": ("Require TLS 1.2+ (prefer 1.3).",
                          "ctx = ssl.create_default_context()\nctx.minimum_version = ssl.TLSVersion.TLSv1_2"),
    "CRYPTO-TLS-NOVERIFY": ("Keep certificate verification on; trust a private CA explicitly if needed.",
                            "requests.get(url, verify='/etc/ssl/certs/corp-ca.pem')"),
    "CRYPTO-WEAK-PRNG": ("Use a CSPRNG for security values.", "import secrets\ntoken = secrets.token_urlsafe(32)"),
    "CRYPTO-JWT-NONE": ("Never accept 'none'. Pin the expected algorithm.", "jwt.verify(token, key, { algorithms: ['RS256'] })"),
    "CRYPTO-PBKDF2-WEAK": ("Use at least 600,000 iterations of PBKDF2-HMAC-SHA256, or switch to Argon2id.",
                           "hashlib.pbkdf2_hmac('sha256', password, salt, 600_000)"),
    "CRYPTO-WEAK-HMAC": ("Use HMAC-SHA256.", "hmac.new(key, msg, hashlib.sha256)"),
    "CRYPTO-WEAK-CURVE": ("Use P-256 or stronger (or X25519/Ed25519).", "ec.generate_private_key(ec.SECP256R1())"),
    "CRYPTO-DSA": ("Use Ed25519 or ECDSA P-256 for signatures.", "Ed25519PrivateKey.generate()"),
    "CRYPTO-LEGACY-CREATECIPHER": ("Use createCipheriv with a random key and IV (AES-256-GCM).",
                                   "const iv = crypto.randomBytes(12);\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);"),
}


def scan_crypto(root: Path, files: list[str]) -> tuple[list[CryptoAsset], list[Finding]]:
    """Build the crypto inventory and emit findings for weak/broken usage."""
    pairs: list[tuple[CryptoAsset, _Spec]] = []
    for rel in files:
        if rel.endswith(".py"):
            text = read_text(root / rel)
            if text:
                pairs += inventory_python(text, rel)
        elif rel.endswith(JS_EXTS) and not rel.endswith((".min.js", ".d.ts")):
            text = read_text(root / rel)
            if text:
                pairs += inventory_js(text, rel)
    assets = [a for a, _ in pairs]
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for asset, spec in pairs:
        if asset.classification == "approved" or not spec.rule:
            continue
        key = (spec.rule, asset.file, asset.line)
        if key in seen:
            continue
        seen.add(key)
        rem, example = CRYPTO_REMEDIATION.get(spec.rule, ("Replace with an approved algorithm.", ""))
        findings.append(Finding(
            module="crypto", rule_id=spec.rule,
            title=f"{'Broken' if asset.classification == 'broken' else 'Weak'} cryptography: {asset.name}",
            severity="high" if asset.classification == "broken" else "medium",
            file=asset.file, line=asset.line,
            description=(spec.reason or f"{asset.name} is classified {asset.classification}.") +
            (" This algorithm is also quantum-vulnerable." if asset.quantum_vulnerable else ""),
            remediation=rem, secure_example=example, cwe=spec.cwe, owasp="A02",
            snippet=make_snippet(read_text(root / asset.file).splitlines(), asset.line),  # type: ignore[union-attr]
            references=["https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
                        f"https://cwe.mitre.org/data/definitions/{spec.cwe.split('-')[1]}.html"],
            extra={"crypto_class": asset.classification, "algorithm": asset.name,
                   "quantum_vulnerable": asset.quantum_vulnerable, "language": asset.language},
        ))
    return assets, findings
