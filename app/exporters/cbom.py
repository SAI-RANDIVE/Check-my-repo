"""CycloneDX 1.6 cryptographic bill of materials (CBOM).

One ``cryptographic-asset`` component per distinct algorithm/protocol
configuration, with every place it is used listed under
``evidence.occurrences`` (file + line).
"""

from __future__ import annotations

import re
import uuid
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from app.exporters.sbom import _metadata
from app.scanners.base import CryptoAsset

if TYPE_CHECKING:
    from app.engine import ScanReport

VALID_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
                    "key-agree", "kem", "ae", "combiner", "other", "unknown"}
VALID_FUNCTIONS = {"generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify",
                   "encapsulate", "decapsulate", "other", "unknown"}
VALID_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _functions(fns: list[str]) -> list[str]:
    out = []
    for f in fns:
        v = f if f in VALID_FUNCTIONS else "other"
        if v not in out:
            out.append(v)
    return out


def build_cbom(report: ScanReport) -> dict[str, Any]:
    """Return a CycloneDX 1.6 CBOM dict."""
    groups: OrderedDict[str, list[CryptoAsset]] = OrderedDict()
    for a in sorted(report.crypto_assets, key=lambda a: ({"broken": 0, "weak": 1, "approved": 2}[a.classification], a.name)):
        groups.setdefault(f"{a.name}|{a.asset_type}|{a.mode}|{a.parameter}", []).append(a)
    components = []
    for key, items in groups.items():
        a = items[0]
        cp: dict[str, Any] = {"assetType": a.asset_type}
        if a.asset_type == "protocol":
            ver = (a.parameter or "").replace("TLSv", "").replace("SSLv", "")
            pp: dict[str, Any] = {"type": "tls"}
            if re.fullmatch(r"[0-9.]+", ver):
                pp["version"] = ver
            cp["protocolProperties"] = pp
        else:
            ap: dict[str, Any] = {
                "primitive": a.primitive if a.primitive in VALID_PRIMITIVES else "other",
                "executionEnvironment": "software-plain-ram",
                "implementationPlatform": "generic",
                "cryptoFunctions": _functions(a.crypto_functions),
            }
            if a.parameter:
                ap["parameterSetIdentifier"] = a.parameter
            if a.mode:
                ap["mode"] = a.mode if a.mode in VALID_MODES else "other"
            if a.classical_level is not None:
                ap["classicalSecurityLevel"] = a.classical_level
            if a.nist_quantum_level is not None:
                ap["nistQuantumSecurityLevel"] = a.nist_quantum_level
            cp["algorithmProperties"] = ap
        libraries = sorted({i.library for i in items if i.library})
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-{_slug(key)}",
            "name": a.name,
            "cryptoProperties": cp,
            "evidence": {"occurrences": [{"location": i.file, "line": i.line,
                                          "additionalContext": f"{i.language}{' / ' + i.library if i.library else ''}"}
                                         for i in items]},
            "properties": [
                {"name": "codesentinel:classification", "value": a.classification},
                {"name": "codesentinel:quantum_vulnerable", "value": str(a.quantum_vulnerable).lower()},
                {"name": "codesentinel:family", "value": a.family},
                {"name": "codesentinel:occurrences", "value": str(len(items))},
                *([{"name": "codesentinel:libraries", "value": ", ".join(libraries)}] if libraries else []),
                *([{"name": "codesentinel:reason", "value": a.reason}] if a.reason else []),
            ],
        })
    summary = {
        "approved": sum(1 for a in report.crypto_assets if a.classification == "approved"),
        "weak": sum(1 for a in report.crypto_assets if a.classification == "weak"),
        "broken": sum(1 for a in report.crypto_assets if a.classification == "broken"),
        "quantum_vulnerable": sum(1 for a in report.crypto_assets if a.quantum_vulnerable),
    }
    meta = _metadata(report, "cbom")
    meta["properties"] = [{"name": f"codesentinel:assets_{k}", "value": str(v)} for k, v in summary.items()]
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": meta,
        "components": components,
        "dependencies": [{"ref": "root-application", "dependsOn": [c["bom-ref"] for c in components]}],
    }
