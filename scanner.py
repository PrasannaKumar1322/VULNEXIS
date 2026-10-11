"""
Q-SHIELD scanning engine.

Performs robust cryptographic analysis across source-code files (Python, Java,
JavaScript, PHP, C/C++), configuration files, certificates, PEM/DER keys,
PDF encryption metadata, and ZIP archive encryption headers.

Distinguishes:
  - CONFIRMED: Parsed certificates/keys, PDF/ZIP encryption metadata, explicit keygen/cipher calls.
  - INFERRED: API calls, imports, and configuration directives.
  - TEXT_MATCH: Keyword occurrences in comments, strings, or documentation.

Nothing is executed and no cryptographic decryption is claimed or performed.
"""
from __future__ import annotations

import ast
import base64
import bisect
import io
import math
import os
import re
import struct
import tarfile
import time
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import migration_engine
import risk_engine
import risk_scoring

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import (
        dh, dsa, ec, ed448, ed25519, rsa, x448, x25519,
    )
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False

try:
    from pypdf import PdfReader
    HAVE_PYPDF = True
except Exception:  # pragma: no cover
    HAVE_PYPDF = False

# --------------------------------------------------------------------------
# Limits & Safety Boundaries
# --------------------------------------------------------------------------
MAX_FILE_BYTES = 5 * 1024 * 1024          # 5 MB per file (and per archive entry)
MAX_UPLOAD_FILES = 500                    # files in one upload request
MAX_SCANNED_FILES = 3000                  # after archives are opened
ARCHIVE_MAX_ENTRIES = 3000
ARCHIVE_MAX_TOTAL = 200 * 1024 * 1024     # 200 MB uncompressed bytes per archive
ZIP_BOMB_MAX_RATIO = 100                  # max decompression ratio for entries > 1 MB
MAX_OCCURRENCES = 25                      # stored per finding
SNIPPET_LEN = 160
MAX_SKIPPED_LISTED = 100

IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"}
KEYSTORE_EXT = (".jks", ".p12", ".pfx", ".keystore", ".bks")
DER_EXT = (".der", ".cer", ".crt")
TAR_EXT = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
CONFIG_EXT = (".conf", ".cnf", ".config", ".ini", ".yaml", ".yml", ".json", ".xml", ".properties", ".env", ".toml")
SOURCE_EXT = (
    ".py", ".pyw", ".java", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".php", ".go", ".rs", ".rb", ".cs", ".kt", ".swift"
)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

STATUS_LABELS = {
    "vulnerable": "Quantum-vulnerable",
    "weakened": "Quantum-weakened",
    "classical": "Unsafe today",
    "resistant": "Quantum-resistant",
    "pqc": "Post-quantum",
}

LEVEL_LABELS = {"none": "None found", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}

CONFIDENCE_ORDER = {"confirmed": 3, "inferred": 2, "text_match": 1}
CONFIDENCE_LABELS = {
    "confirmed": "Confirmed",
    "inferred": "Inferred",
    "text_match": "Text match",
}


class _Skip(Exception):
    pass


# --------------------------------------------------------------------------
# Rule Definitions
# --------------------------------------------------------------------------
class Rule:
    def __init__(self, id, name, category, severity, status, pattern, description,
                 recommendation, replacement, suppress_same_line=(), suppress_overlap=()):
        self.id = id
        self.name = name
        self.category = category
        self.severity = severity
        self.status = status
        self.regex = re.compile(pattern) if pattern else None
        self.description = description
        self.recommendation = recommendation
        self.replacement = replacement
        self.suppress_same_line = tuple(suppress_same_line)
        self.suppress_overlap = tuple(suppress_overlap)


_PQ_REC = ("Replace with a hybrid key exchange such as X25519MLKEM768, or ML-KEM-768 on its own once "
           "your peers support it.")

RULES = [
    Rule("rsa", "RSA", "Public-key", "critical", "vulnerable",
         r"(?:(?<![A-Za-z0-9])(?:RSA(?![a-z])|rsa(?![a-z])|Rsa(?=[A-Z]))|(?<=[wW]ith)RSA|genrsa)",
         "RSA relies on the difficulty of factoring large composite integers. Shor's algorithm solves this in "
         "polynomial time on a cryptographically relevant quantum computer. Traffic recorded today can be "
         "decrypted retroactively ('harvest now, decrypt later').",
         "Inventory all RSA usages. Move encryption and key exchange to ML-KEM (FIPS 203) first, then signatures "
         "to ML-DSA (FIPS 204). Use hybrid classical/PQC modes during transition.",
         "ML-KEM (FIPS 203) and ML-DSA (FIPS 204)"),
    Rule("dh", "Diffie-Hellman (DH/DHE)", "Public-key", "critical", "vulnerable",
         r"(?<![A-Za-z0-9])DHE?(?![A-Za-z0-9])|(?i:diffie[-_ ]?hellman|dhparam|(?<![a-z0-9])ffdhe)",
         "Finite-field Diffie-Hellman depends on the discrete logarithm problem, which Shor's algorithm "
         "solves efficiently. Handshakes recorded today will be readable once quantum hardware arrives.",
         _PQ_REC, "ML-KEM (FIPS 203), hybrid X25519MLKEM768"),
    Rule("ecdh", "ECDH / X25519 key exchange", "Public-key", "critical", "vulnerable",
         r"(?i:(?<![a-z0-9])(?:ecdhe?|ecies|x448|x25519(?!_?(?:ml|kyber))))",
         "Elliptic-curve Diffie-Hellman (including X25519 and X448) depends on the elliptic-curve discrete "
         "logarithm problem, which Shor's algorithm solves completely.",
         _PQ_REC, "ML-KEM (FIPS 203), hybrid X25519MLKEM768"),
    Rule("ecdsa", "ECDSA / EdDSA signatures", "Public-key", "high", "vulnerable",
         r"(?i:(?<![a-z0-9])(?:ecdsa|eddsa|ed25519|ed448))|(?<=[wW]ith)ECDSA",
         "ECDSA and EdDSA signatures depend on the elliptic-curve discrete logarithm problem. A quantum "
         "computer running Shor's algorithm can forge them, threatening identity, tokens, and code signing.",
         "Migrate to ML-DSA (FIPS 204). Use SLH-DSA (FIPS 205) for long-lived roots and firmware verification.",
         "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"),
    Rule("ecc_curve", "Elliptic-curve (ECC) keys and curves", "Public-key", "high", "vulnerable",
         r"(?i:(?<![a-z0-9])(?:secp(?:192|224|256|384|521)[rk]1|prime(?:192|239|256)v1|nistp(?:256|384|521)"
         r"|brainpool[pt]?\d{3}[rt]1|curve25519|p-(?:256|384|521)|elliptic[-_ ]curve))",
         "Elliptic-curve parameters were detected. Every standard curve (P-256, P-384, secp256k1, Curve25519) "
         "is vulnerable to Shor's algorithm.",
         "Migrate key exchange to ML-KEM and digital signatures to ML-DSA.",
         "ML-KEM (FIPS 203) or ML-DSA (FIPS 204)",
         suppress_same_line=("ecdsa", "ecdh")),
    Rule("dsa", "DSA", "Public-key", "high", "vulnerable",
         r"(?<![A-Za-z0-9])(?:DSA|dsa)(?![a-z])|ssh-dss|(?<=[wW]ith)DSA",
         "DSA depends on the discrete logarithm problem, solved by Shor's algorithm. FIPS 186-5 has deprecated "
         "DSA for new signatures.",
         "Replace with ML-DSA (FIPS 204). Transition via ECDSA or RSA-PSS only as temporary measures.",
         "ML-DSA (FIPS 204)",
         suppress_overlap=("pqc",)),
    Rule("elgamal", "ElGamal", "Public-key", "high", "vulnerable",
         r"(?i:el[-_ ]?gamal)",
         "ElGamal depends on the discrete logarithm problem, which Shor's algorithm solves.",
         "Replace with ML-KEM for encryption and key establishment.", "ML-KEM (FIPS 203)"),
    Rule("md5", "MD5", "Hash", "high", "classical",
         r"(?i:(?<![a-z0-9])md5)",
         "MD5 suffers from practical collision attacks and should never be used for digital signatures, "
         "certificates, or integrity verification.",
         "Use SHA-256 or SHA-3. For passwords use Argon2id, scrypt, or bcrypt.", "SHA-256 or SHA-3"),
    Rule("sha1", "SHA-1", "Hash", "high", "classical",
         r"(?i:(?<![a-z0-9])sha-?1(?![0-9]))",
         "SHA-1 has practical collision attacks (SHAttered, 2017) and is disallowed by NIST and CA/Browser forum.",
         "Use SHA-256 or SHA-3 for digital signatures and integrity checks.", "SHA-256 or SHA-3"),
    Rule("des", "DES", "Symmetric cipher", "critical", "classical",
         r"(?<![A-Za-z0-9])DES(?![A-Za-z0-9])|DESCryptoServiceProvider|(?i:(?<![a-z0-9])des[-_](?:cbc|ecb|cfb|ofb))",
         "DES uses a 56-bit key easily broken via brute force on commodity hardware within hours.",
         "Replace with AES-256-GCM or ChaCha20-Poly1305 and re-encrypt stored data.",
         "AES-256-GCM or ChaCha20-Poly1305",
         suppress_same_line=("tdes",)),
    Rule("tdes", "3DES / Triple DES", "Symmetric cipher", "high", "classical",
         r"(?i:(?<![a-z0-9])(?:3des|triple[-_ ]?des|des[-_ ]?ede3?|desede|des3))",
         "Triple DES has a 64-bit block size susceptible to Sweet32 birthday attacks, and was retired by NIST after 2023.",
         "Replace with AES-256-GCM or ChaCha20-Poly1305.", "AES-256-GCM or ChaCha20-Poly1305"),
    Rule("rc4", "RC4", "Symmetric cipher", "critical", "classical",
         r"(?i:(?<![a-z0-9])(?:rc4|arcfour))",
         "RC4 exhibits severe keystream biases and is prohibited in TLS (RFC 7465).",
         "Replace with AES-256-GCM or ChaCha20-Poly1305.", "AES-256-GCM or ChaCha20-Poly1305"),
    Rule("blowfish", "Blowfish", "Symmetric cipher", "medium", "classical",
         r"(?i:blowfish)",
         "Blowfish uses a 64-bit block size, rendering large-volume encryption vulnerable to Sweet32 attacks.",
         "Replace with AES-256-GCM or ChaCha20-Poly1305.", "AES-256-GCM or ChaCha20-Poly1305"),
    Rule("weak_tls", "Deprecated SSL/TLS version", "Protocol", "high", "classical",
         r"(?i:(?<![a-z0-9])(?:ssl[-_ ]?v?[23](?![0-9])|tls[-_ ]?v?1[._]?[01](?![0-9])|tls[-_ ]?v1(?![._0-9])))",
         "SSL 2.0/3.0 and TLS 1.0/1.1 are deprecated (RFC 8996) with known vulnerabilities (POODLE, BEAST).",
         "Require TLS 1.3, with TLS 1.2 as minimum where backwards compatibility demands.",
         "TLS 1.3"),
    Rule("aes_ecb", "AES in ECB mode", "Symmetric cipher", "critical", "classical",
         r"(?i:aes[-_ ]?(?:128|192|256)?[-_ ]?ecb|mode_ecb|\.ecb\(|cipher\.getinstance\([\"']aes/ecb)",
         "AES-ECB mode encrypts identical plaintext blocks into identical ciphertext blocks, leaking data structure.",
         "Switch immediately to an authenticated encryption mode such as AES-256-GCM or ChaCha20-Poly1305.",
         "AES-256-GCM"),
    Rule("aes128", "AES-128", "Symmetric cipher", "low", "weakened",
         r"(?i:(?<![a-z0-9])aes[-_ ]?128)",
         "Grover's algorithm theoretically halves effective key length to 64 bits. Practical quantum attacks "
         "remain distant, but AES-256 provides a robust safety margin for long-term secrets.",
         "Use AES-256-GCM for sensitive data with multi-decade confidentiality requirements.", "AES-256-GCM"),
    Rule("aes256", "AES-192 / AES-256", "Symmetric cipher", "info", "resistant",
         r"(?i:(?<![a-z0-9])aes[-_ ]?(?:192|256))",
         "AES with 192- or 256-bit keys maintains a 96- to 128-bit security margin under Grover's algorithm.",
         "Maintain standard configuration with authenticated encryption (GCM/CCM).", "Keep as is"),
    Rule("sha2", "SHA-2 / SHA-3", "Hash", "info", "resistant",
         r"(?i:(?<![a-z0-9])sha[-_]?(?:2(?![0-9])|224|256|384|512|3(?![0-9])))",
         "SHA-2 and SHA-3 with digests >= 256 bits are considered quantum-resistant against known quantum attacks.",
         "Maintain current configuration.", "Keep as is"),
    Rule("chacha", "ChaCha20", "Symmetric cipher", "info", "resistant",
         r"(?i:chacha20)",
         "ChaCha20 uses a 256-bit key and is considered secure against known quantum attacks.",
         "Maintain current configuration with Poly1305 authentication.", "Keep as is"),
    Rule("pqc", "Post-quantum algorithm", "Post-quantum", "info", "pqc",
         r"(?i:(?<![a-z])ml[-_ ]?(?:kem|dsa)|(?<![a-z])(?:slh[-_ ]?dsa|fn[-_ ]?dsa|kyber(?:512|768|1024)?|"
         r"dilithium[2-5]?|sphincs\+?|frodokem|classic[-_ ]?mceliece|liboqs))",
         "NIST-standardized or candidate post-quantum algorithm (e.g. ML-KEM, ML-DSA, SLH-DSA) is present.",
         "Ensure hybrid deployment modes during transition to maintain interoperability.",
         "Keep as is"),
    Rule("zip_crypto", "PKWARE ZipCrypto encryption", "Archive encryption", "critical", "classical",
         r"",
         "Traditional ZIP 2.0 PKWARE ZipCrypto stream cipher is cryptographically broken and trivially cracked.",
         "Use AES-256 WinZip encryption or encrypt archives with modern tools.",
         "WinZip AES-256"),
    Rule("pdf_crypto", "Legacy PDF encryption", "Document encryption", "high", "classical",
         r"",
         "Document uses legacy RC4 (40-bit or 128-bit) encryption handlers in PDF dictionary.",
         "Re-encrypt PDF using AES-256 (PDF 2.0 / Acrobat X standard handler).",
         "AES-256 PDF encryption"),
    Rule("private_key", "Embedded private key", "Key material", "critical", "classical",
         r"-----BEGIN (?:[A-Z0-9 ]+ )*PRIVATE KEY-----",
         "A private key is embedded directly in source or configuration files.",
         "Remove the key immediately, rotate certificates, and store keys in a KMS, HSM, or secrets manager.",
         "KMS, HSM, or Secrets Manager"),
]

RULES_BY_ID = {r.id: r for r in RULES}
PATTERN_RULES = [r for r in RULES if r.regex]

LABEL_RULE = {
    "RSA PRIVATE KEY": "rsa", "EC PRIVATE KEY": "ecc_curve", "DSA PRIVATE KEY": "dsa",
    "RSA PUBLIC KEY": "rsa", "EC PARAMETERS": "ecc_curve", "DH PARAMETERS": "dh", "DSA PARAMETERS": "dsa",
}

PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)
SSH_RE = re.compile(r"(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521))\s+([A-Za-z0-9+/=]{40,})")


# --------------------------------------------------------------------------
# Hit Representation
# --------------------------------------------------------------------------
class Hit:
    def __init__(self, rule_id: str, line: Optional[int], snippet: str,
                 source: str = "pattern", parsed: Optional[str] = None,
                 confidence: str = "inferred", key_size: Optional[int] = None,
                 mode: Optional[str] = None, evidence: Optional[str] = None,
                 location_meta: Optional[Dict[str, Any]] = None):
        self.rule_id = rule_id
        self.line = line
        self.snippet = snippet
        self.source = source
        self.parsed = parsed
        self.confidence = confidence  # "confirmed", "inferred", "text_match"
        self.key_size = key_size
        self.mode = mode
        self.evidence = evidence or snippet
        self.location_meta = location_meta or {}

    def to_legacy_tuple(self):
        return (self.rule_id, self.line, self.snippet, self.source, self.parsed)


# --------------------------------------------------------------------------
# Helper: Security & Quantum Assessment Knowledge Base
# --------------------------------------------------------------------------
def evaluate_security(rule_id: str, key_size: Optional[int] = None, mode: Optional[str] = None) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return (classical_security_assessment, quantum_risk_assessment)."""
    # 1. Classical Assessment
    c_status = "secure_standard"
    c_desc = "Algorithm meets current standard classical cryptographic recommendations."

    if rule_id in ("des", "rc4", "blowfish", "zip_crypto"):
        c_status = "broken"
        c_desc = f"{RULES_BY_ID[rule_id].name} has broken security and is susceptible to trivial brute force or known plaintext attacks."
    elif rule_id == "aes_ecb" or mode == "ECB":
        c_status = "broken"
        c_desc = "ECB mode does not provide semantic security; identical plaintext blocks result in identical ciphertext blocks."
    elif rule_id in ("md5", "sha1"):
        c_status = "broken"
        c_desc = f"{RULES_BY_ID[rule_id].name} has practical collision attacks demonstrated and is deprecated for security purposes."
    elif rule_id == "tdes":
        c_status = "deprecated"
        c_desc = "Triple-DES 64-bit block size allows Sweet32 collision attacks. Deprecated by NIST."
    elif rule_id == "weak_tls":
        c_status = "broken"
        c_desc = "Legacy TLS/SSL protocols are broken by design and deprecated by RFC 8996."
    elif rule_id == "private_key":
        c_status = "compromised_exposure"
        c_desc = "Hardcoded secret material exposed in files violates basic secrets hygiene."
    elif rule_id in ("rsa", "dh", "dsa"):
        if key_size and key_size < 2048:
            c_status = "broken"
            c_desc = f"Key size of {key_size} bits is below the modern 2048-bit minimum and insecure today."
        else:
            c_status = "legacy_acceptable"
            c_desc = "Key size >= 2048 bits provides ~112 bits of classical security, acceptable through ~2030."
    elif rule_id == "pdf_crypto":
        c_status = "broken" if (key_size and key_size < 128) else "legacy_acceptable"
        c_desc = "Legacy document encryption handler."

    # 2. Quantum Assessment
    rule = RULES_BY_ID.get(rule_id)
    q_status = rule.status if rule else "vulnerable"
    q_label = STATUS_LABELS.get(q_status, "Unknown")
    threat = "None"
    q_desc = rule.description if rule else ""

    if q_status == "vulnerable":
        threat = "Harvest Now, Decrypt Later (HNDL) via Shor's Algorithm"
        q_desc = "Shor's algorithm solves discrete logarithms and integer factorization in polynomial time on a CRQC."
    elif q_status == "weakened":
        threat = "Grover's Quantum Search"
        q_desc = "Grover's algorithm quadratically speeds up key search, halving the effective bit security margin."
    elif q_status == "resistant":
        threat = "Resistant"
        q_desc = "Key size and structure provide sufficient margin against known quantum algorithms."
    elif q_status == "pqc":
        threat = "Standardized Post-Quantum Primitive"
        q_desc = "Lattice-based or hash-based primitive resistant to Shor's and Grover's quantum attacks."
    elif q_status == "classical":
        threat = "Pre-Quantum Vulnerability"
        q_desc = "Algorithm is already insecure under classical computing capabilities regardless of quantum threats."

    return (
        {"status": c_status, "description": c_desc},
        {"status": q_status, "label": q_label, "threat_model": threat, "description": q_desc}
    )


def generate_limitations(confidence: str, source: str, rule_id: str) -> List[str]:
    """Generate explicit analysis limitations for findings."""
    lims = [
        "Static code analysis cannot determine if this cryptographic branch is executed during runtime.",
        "No cryptographic decryption of payload data, ciphertext, or private keys was performed.",
    ]
    if confidence == "text_match":
        lims.append("Detected via keyword match; does not confirm active cryptographic library invocation.")
    if confidence == "inferred":
        lims.append("Inferred from API/configuration reference; actual key strength depends on runtime inputs.")
    if rule_id == "private_key":
        lims.append("Key structure detected via PEM/DER header; passphrase protection or key usage was not decrypted.")
    if source in ("pdf_metadata", "zip_metadata"):
        lims.append("Encryption parameters extracted from file container headers without decrypting document payload.")
    return lims


# --------------------------------------------------------------------------
# Specialized Source Parsers
# --------------------------------------------------------------------------
def _line_no(nl: List[int], pos: int) -> int:
    return bisect.bisect_left(nl, pos) + 1


def _snippet(text: str, nl: List[int], line: int, pos: int) -> str:
    start = nl[line - 2] + 1 if line > 1 else 0
    end = nl[line - 1] if line - 1 < len(nl) else len(text)
    seg = text[start:end]
    rel = pos - start
    s = max(0, rel - 60)
    out = seg[s:s + SNIPPET_LEN].strip()
    return ("..." + out) if s > 0 else out


def _parse_python_ast(text: str, nl: List[int]) -> List[Hit]:
    """Parse Python code using AST to find concrete cryptographic calls."""
    hits: List[Hit] = []
    try:
        tree = ast.parse(text)
    except Exception:
        return hits

    class CryptoVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            call_line = node.lineno
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            # PyCryptodome RSA.generate(bits)
            if func_name == "generate" and isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", "") == "RSA":
                key_size = 2048
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
                    key_size = node.args[0].value
                hits.append(Hit("rsa", call_line, f"RSA.generate({key_size})", source="ast",
                                parsed=f"RSA-{key_size}", confidence="confirmed", key_size=key_size,
                                evidence=f"RSA.generate({key_size}) key generation call"))

            # cryptography rsa.generate_private_key(...)
            elif func_name == "generate_private_key":
                parent_mod = getattr(getattr(node.func, "value", None), "id", "")
                ksize = None
                for kw in node.keywords:
                    if kw.arg == "key_size" and isinstance(kw.value, ast.Constant) and isinstance(getattr(kw.value, 'value', None), int):
                        ksize = kw.value.value

                if parent_mod == "rsa" or ksize:
                    ksize = ksize or 2048
                    hits.append(Hit("rsa", call_line, f"rsa.generate_private_key(key_size={ksize})", source="ast",
                                    parsed=f"RSA-{ksize}", confidence="confirmed", key_size=ksize,
                                    evidence=f"rsa.generate_private_key call with key_size={ksize}"))
                elif parent_mod == "ec" or any("SECP" in ast.dump(node) or "P256" in ast.dump(node) or "curve" in (kw.arg or '') for kw in node.keywords):
                    curve_name = "ECC"
                    for a in node.args:
                        dump = ast.dump(a)
                        for c in ("SECP256R1", "SECP384R1", "SECP521R1", "secp256k1"):
                            if c in dump:
                                curve_name = f"ECC {c}"
                    hits.append(Hit("ecc_curve", call_line, f"ec.generate_private_key({curve_name})", source="ast",
                                    parsed=curve_name, confidence="confirmed", key_size=256 if "256" in curve_name else None,
                                    evidence="ec.generate_private_key call"))
                elif parent_mod == "dsa":
                    ksize = ksize or 2048
                    hits.append(Hit("dsa", call_line, f"dsa.generate_private_key(key_size={ksize})", source="ast",
                                    parsed=f"DSA-{ksize}", confidence="confirmed", key_size=ksize,
                                    evidence="dsa.generate_private_key call"))

            # Ciphers: AES.new(...) or Cipher(algorithms.AES(key), modes.GCM/CBC/ECB)
            elif func_name == "new" and isinstance(node.func, ast.Attribute):
                caller = getattr(node.func.value, "id", "")
                dump = ast.dump(node)
                if caller == "AES":
                    mode = "GCM" if "MODE_GCM" in dump else ("CBC" if "MODE_CBC" in dump else ("ECB" if "MODE_ECB" in dump else "CBC"))
                    rid = "aes_ecb" if mode == "ECB" else "aes256"
                    hits.append(Hit(rid, call_line, f"AES.new(..., MODE_{mode})", source="ast",
                                    parsed=f"AES-{mode}", confidence="confirmed", mode=mode,
                                    evidence=f"AES.new call with mode {mode}"))
                elif caller == "DES":
                    hits.append(Hit("des", call_line, "DES.new(...)", source="ast", parsed="DES",
                                    confidence="confirmed", key_size=56, evidence="DES.new initialization"))
                elif caller in ("DES3", "TripleDES"):
                    hits.append(Hit("tdes", call_line, "DES3.new(...)", source="ast", parsed="3DES",
                                    confidence="confirmed", key_size=168, evidence="DES3.new initialization"))
                elif caller in ("ARC4", "RC4"):
                    hits.append(Hit("rc4", call_line, "ARC4.new(...)", source="ast", parsed="RC4",
                                    confidence="confirmed", evidence="RC4.new initialization"))

            elif func_name == "Cipher":
                dump = ast.dump(node)
                mode = "GCM" if "GCM" in dump else ("CBC" if "CBC" in dump else ("ECB" if "ECB" in dump else None))
                if "AES" in dump:
                    rid = "aes_ecb" if mode == "ECB" else "aes256"
                    hits.append(Hit(rid, call_line, f"Cipher(algorithms.AES, modes.{mode or 'CBC'})", source="ast",
                                    parsed=f"AES-{mode or 'CBC'}", confidence="confirmed", mode=mode,
                                    evidence="cryptography Cipher(algorithms.AES) call"))

            # Hash calls
            elif func_name in ("md5", "sha1", "sha256", "sha512"):
                caller = getattr(getattr(node.func, "value", None), "id", "")
                if caller == "hashlib":
                    rid_map = {"md5": "md5", "sha1": "sha1", "sha256": "sha2", "sha512": "sha2"}
                    hits.append(Hit(rid_map[func_name], call_line, f"hashlib.{func_name}()", source="ast",
                                    parsed=func_name.upper(), confidence="confirmed",
                                    evidence=f"hashlib.{func_name}() invocation"))

            self.generic_visit(node)

    visitor = CryptoVisitor()
    visitor.visit(tree)
    return hits


def _parse_java(text: str, nl: List[int]) -> List[Hit]:
    """Inspect Java code for JCA / BouncyCastle crypto usage."""
    hits: List[Hit] = []
    for m in re.finditer(r'KeyPairGenerator\.getInstance\s*\(\s*["\'](RSA|DSA|EC|DiffieHellman|DH)["\']', text):
        line = _line_no(nl, m.start())
        algo = m.group(1)
        sub = text[m.end():m.end() + 200]
        init_m = re.search(r'\.initialize\s*\(\s*(\d+)\s*\)', sub)
        ksize = int(init_m.group(1)) if init_m else (2048 if algo == "RSA" else None)
        rid = "rsa" if algo == "RSA" else ("dsa" if algo == "DSA" else ("dh" if "DH" in algo else "ecc_curve"))
        hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                        parsed=f"{algo}-{ksize}" if ksize else algo, confidence="confirmed",
                        key_size=ksize, evidence=f'KeyPairGenerator.getInstance("{algo}")'))

    for m in re.finditer(r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']', text):
        line = _line_no(nl, m.start())
        trans = m.group(1)
        parts = trans.split('/')
        algo_name = parts[0].upper()
        mode = parts[1].upper() if len(parts) > 1 else None
        if "AES" in algo_name:
            rid = "aes_ecb" if mode == "ECB" else ("aes128" if "128" in algo_name else "aes256")
            hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=trans, confidence="confirmed", mode=mode,
                            evidence=f'Cipher.getInstance("{trans}")'))
        elif "DESEDE" in algo_name or "3DES" in algo_name:
            hits.append(Hit("tdes", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=trans, confidence="confirmed", mode=mode, evidence=f'Cipher.getInstance("{trans}")'))
        elif "DES" in algo_name:
            hits.append(Hit("des", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=trans, confidence="confirmed", mode=mode, evidence=f'Cipher.getInstance("{trans}")'))

    for m in re.finditer(r'Signature\.getInstance\s*\(\s*["\']([^"\']+)["\']', text):
        line = _line_no(nl, m.start())
        sig = m.group(1)
        upper = sig.upper()
        if "RSA" in upper:
            hits.append(Hit("rsa", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=sig, confidence="confirmed", evidence=f'Signature.getInstance("{sig}")'))
        elif "ECDSA" in upper or "ED25519" in upper:
            hits.append(Hit("ecdsa", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=sig, confidence="confirmed", evidence=f'Signature.getInstance("{sig}")'))
        elif "DSA" in upper:
            hits.append(Hit("dsa", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=sig, confidence="confirmed", evidence=f'Signature.getInstance("{sig}")'))
        elif "ML-DSA" in upper or "DILITHIUM" in upper:
            hits.append(Hit("pqc", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=sig, confidence="confirmed", evidence=f'Signature.getInstance("{sig}")'))

    for m in re.finditer(r'KeyAgreement\.getInstance\s*\(\s*["\'](ECDH|DH|DiffieHellman|X25519)["\']', text):
        line = _line_no(nl, m.start())
        proto = m.group(1)
        rid = "ecdh" if "EC" in proto or "X25519" in proto else "dh"
        hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                        parsed=proto, confidence="confirmed", evidence=f'KeyAgreement.getInstance("{proto}")'))

    return hits


def _parse_javascript(text: str, nl: List[int]) -> List[Hit]:
    """Inspect JavaScript / TypeScript code for Node.js crypto and WebCrypto usage."""
    hits: List[Hit] = []
    for m in re.finditer(r'generateKeyPair(?:Sync)?\s*\(\s*["\'](rsa|ec|dsa|ed25519|x25519)["\']', text, re.I):
        line = _line_no(nl, m.start())
        kind = m.group(1).lower()
        sub = text[m.end():m.end() + 200]
        len_m = re.search(r'modulusLength:\s*(\d+)', sub)
        ksize = int(len_m.group(1)) if len_m else None
        rid = "rsa" if kind == "rsa" else ("dsa" if kind == "dsa" else ("ecdh" if "x25519" in kind else "ecdsa"))
        hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                        parsed=f"{kind.upper()}-{ksize}" if ksize else kind.upper(),
                        confidence="confirmed", key_size=ksize, evidence=f"generateKeyPair({kind})"))

    for m in re.finditer(r'createCipher(?:iv)?\s*\(\s*["\']([a-zA-Z0-9_-]+)["\']', text):
        line = _line_no(nl, m.start())
        algo = m.group(1).lower()
        if "aes" in algo:
            mode = "ECB" if "ecb" in algo else ("GCM" if "gcm" in algo else "CBC")
            rid = "aes_ecb" if mode == "ECB" else ("aes128" if "128" in algo else "aes256")
            hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=algo, confidence="confirmed", mode=mode, evidence=f"createCipheriv({algo})"))
        elif "des-ede3" in algo or "3des" in algo:
            hits.append(Hit("tdes", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=algo, confidence="confirmed", evidence=f"createCipheriv({algo})"))
        elif "des" in algo:
            hits.append(Hit("des", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=algo, confidence="confirmed", evidence=f"createCipheriv({algo})"))

    for m in re.finditer(r'subtle\.generateKey\s*\(\s*\{[^}]*name:\s*["\']([^"\']+)["\']', text):
        line = _line_no(nl, m.start())
        name = m.group(1)
        sub = text[m.start():m.end() + 150]
        len_m = re.search(r'modulusLength:\s*(\d+)', sub)
        ksize = int(len_m.group(1)) if len_m else None
        upper = name.upper()
        rid = "rsa" if "RSA" in upper else ("ecdsa" if "ECDSA" in upper else ("ecdh" if "ECDH" in upper else "aes256"))
        hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                        parsed=name, confidence="confirmed", key_size=ksize, evidence=f"subtle.generateKey({name})"))

    return hits


def _parse_c_cpp(text: str, nl: List[int]) -> List[Hit]:
    """Inspect C and C++ code for OpenSSL / WolfSSL / Botan crypto usage."""
    hits: List[Hit] = []
    for m in re.finditer(r'(?:RSA_generate_key_ex\s*\([^,]+,\s*(\d+)|EVP_RSA_gen\s*\(\s*(\d+))', text):
        line = _line_no(nl, m.start())
        bits = int(m.group(1) or m.group(2))
        hits.append(Hit("rsa", line, _snippet(text, nl, line, m.start()), source="code_parser",
                        parsed=f"RSA-{bits}", confidence="confirmed", key_size=bits,
                        evidence="OpenSSL RSA key generation function"))

    for m in re.finditer(r'EVP_(aes_128_gcm|aes_256_gcm|aes_128_cbc|aes_256_cbc|aes_128_ecb|aes_256_ecb|des_ede3_cbc|des_cbc|rc4)\s*\(\s*\)', text):
        line = _line_no(nl, m.start())
        func = m.group(1)
        if "aes" in func:
            mode = "ECB" if "ecb" in func else ("GCM" if "gcm" in func else "CBC")
            rid = "aes_ecb" if mode == "ECB" else ("aes128" if "128" in func else "aes256")
            hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=func, confidence="confirmed", mode=mode, evidence=f"EVP_{func}()"))
        elif "des_ede3" in func:
            hits.append(Hit("tdes", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=func, confidence="confirmed", evidence="EVP_des_ede3_cbc()"))
        elif "des" in func:
            hits.append(Hit("des", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=func, confidence="confirmed", evidence="EVP_des_cbc()"))
        elif "rc4" in func:
            hits.append(Hit("rc4", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=func, confidence="confirmed", evidence="EVP_rc4()"))

    for m in re.finditer(r'EVP_PKEY_CTX_new_id\s*\(\s*(EVP_PKEY_[A-Z0-9_]+)', text):
        line = _line_no(nl, m.start())
        sym = m.group(1)
        if "RSA" in sym:
            hits.append(Hit("rsa", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed="RSA", confidence="confirmed", evidence=sym))
        elif "EC" in sym:
            hits.append(Hit("ecc_curve", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed="ECC", confidence="confirmed", evidence=sym))
        elif "DH" in sym:
            hits.append(Hit("dh", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed="DH", confidence="confirmed", evidence=sym))
        elif "DSA" in sym:
            hits.append(Hit("dsa", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed="DSA", confidence="confirmed", evidence=sym))
        elif "MLKEM" in sym or "KYBER" in sym or "MLDSA" in sym:
            hits.append(Hit("pqc", line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed="PQC", confidence="confirmed", evidence=sym))

    return hits


def _parse_php(text: str, nl: List[int]) -> List[Hit]:
    """Inspect PHP code for openssl and sodium crypto extensions."""
    hits: List[Hit] = []
    bits_m = re.search(r'["\']?private_key_bits["\']?\s*=>\s*(\d+)', text)
    bits = int(bits_m.group(1)) if bits_m else None
    for m in re.finditer(r'openssl_pkey_new\s*\(', text):
        line = _line_no(nl, m.start())
        hits.append(Hit("rsa", line, _snippet(text, nl, line, m.start()), source="code_parser",
                        parsed=f"RSA-{bits}" if bits else "RSA", confidence="confirmed", key_size=bits or 2048,
                        evidence="openssl_pkey_new key generation call"))

    for m in re.finditer(r'openssl_encrypt\s*\([^,]+,\s*["\']([a-zA-Z0-9_-]+)["\']', text):
        line = _line_no(nl, m.start())
        cipher = m.group(1).lower()
        if "aes" in cipher:
            mode = "ECB" if "ecb" in cipher else ("GCM" if "gcm" in cipher else "CBC")
            rid = "aes_ecb" if mode == "ECB" else ("aes128" if "128" in cipher else "aes256")
            hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=cipher, confidence="confirmed", mode=mode, evidence=f'openssl_encrypt("{cipher}")'))
        elif "des" in cipher:
            rid = "tdes" if "ede" in cipher or "3des" in cipher else "des"
            hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                            parsed=cipher, confidence="confirmed", evidence=f'openssl_encrypt("{cipher}")'))

    for m in re.finditer(r'sodium_crypto_(sign|box)_keypair\s*\(', text):
        line = _line_no(nl, m.start())
        kind = m.group(1)
        rid = "ecdsa" if kind == "sign" else "ecdh"
        curve = "Ed25519" if kind == "sign" else "X25519"
        hits.append(Hit(rid, line, _snippet(text, nl, line, m.start()), source="code_parser",
                        parsed=curve, confidence="confirmed", evidence=f"sodium_crypto_{kind}_keypair()"))

    return hits


def _parse_config(text: str, nl: List[int]) -> List[Hit]:
    """Inspect Nginx, Apache, TLS, and SSH configuration files."""
    hits: List[Hit] = []

    for m in re.finditer(r'(?:ssl_protocols|SSLProtocol)\s+([^;\n]+)', text, re.I):
        line = _line_no(nl, m.start())
        proto_str = m.group(1)
        for token in proto_str.replace('+', ' ').replace('-', ' ').split():
            clean = token.strip()
            if re.match(r'(?i)^(SSLv[23]|TLSv1(?:\.[01])?)$', clean):
                hits.append(Hit("weak_tls", line, _snippet(text, nl, line, m.start()), source="config",
                                parsed=clean, confidence="confirmed", evidence=f"Deprecated TLS directive: {clean}"))

    for m in re.finditer(r'(?:ssl_ciphers|SSLCipherSuite)\s+([^;\n]+)', text, re.I):
        line = _line_no(nl, m.start())
        ciphers_str = m.group(1)
        for cipher in re.split(r'[:,\s]+', ciphers_str):
            cipher = cipher.strip()
            if not cipher or cipher.startswith(('!', '@', '-')):
                continue
            cupper = cipher.upper()
            if "RC4" in cupper:
                hits.append(Hit("rc4", line, cipher, source="config", parsed=cipher, confidence="confirmed",
                                evidence=f"Configured cipher suite: {cipher}"))
            if "3DES" in cupper or "DES-CBC3" in cupper:
                hits.append(Hit("tdes", line, cipher, source="config", parsed=cipher, confidence="confirmed",
                                evidence=f"Configured cipher suite: {cipher}"))
            if "ECDHE" in cupper or "ECDH" in cupper:
                hits.append(Hit("ecdh", line, cipher, source="config", parsed=cipher, confidence="confirmed",
                                evidence=f"Configured cipher suite: {cipher}"))
            elif "DHE" in cupper or "EDH" in cupper:
                hits.append(Hit("dh", line, cipher, source="config", parsed=cipher, confidence="confirmed",
                                evidence=f"Configured cipher suite: {cipher}"))
            if "RSA" in cupper and ("ECDHE" in cupper or "DHE" in cupper or "WITH_RSA" in cupper):
                hits.append(Hit("rsa", line, cipher, source="config", parsed=cipher, confidence="confirmed",
                                evidence=f"Configured cipher suite: {cipher}"))
            if "AES128" in cupper or "AES-128" in cupper or "AES_128" in cupper:
                hits.append(Hit("aes128", line, cipher, source="config", parsed=cipher, confidence="confirmed",
                                key_size=128, evidence=f"Configured cipher suite: {cipher}"))
            elif "AES256" in cupper or "AES-256" in cupper or "AES_256" in cupper:
                hits.append(Hit("aes256", line, cipher, source="config", parsed=cipher, confidence="confirmed",
                                key_size=256, evidence=f"Configured cipher suite: {cipher}"))

    for m in re.finditer(r'ssl_dhparam\s+([^;\n]+);?', text, re.I):
        line = _line_no(nl, m.start())
        hits.append(Hit("dh", line, _snippet(text, nl, line, m.start()), source="config",
                        parsed="Diffie-Hellman parameters", confidence="confirmed",
                        evidence=f"Diffie-Hellman parameter file specified: {m.group(1).strip()}"))

    return hits


# --------------------------------------------------------------------------
# Cryptography Parsing Helpers (Certificates, PEM, DER, SSH)
# --------------------------------------------------------------------------
def _pub_info(pub):
    """Return (rule_id, label, below_minimum, key_size) for public key object."""
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa", f"RSA-{pub.key_size}", pub.key_size < 2048, pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ecc_curve", f"ECC {pub.curve.name}", False, pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "dsa", f"DSA-{pub.key_size}", pub.key_size < 2048, pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ecdsa", "Ed25519", False, 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "ecdsa", "Ed448", False, 448
    if isinstance(pub, x25519.X25519PublicKey):
        return "ecdh", "X25519", False, 256
    if isinstance(pub, x448.X448PublicKey):
        return "ecdh", "X448", False, 448
    if isinstance(pub, dh.DHPublicKey):
        return "dh", f"DH-{pub.key_size}", pub.key_size < 2048, pub.key_size
    return None


def _cert_hits(cert, line, kind="Certificate") -> List[Hit]:
    hits: List[Hit] = []
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = None
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"
    except Exception:
        sig = "n/a"
    try:
        try:
            end = cert.not_valid_after_utc
        except AttributeError:
            end = cert.not_valid_after.replace(tzinfo=timezone.utc)
        expiry = f"{'expired' if end < datetime.now(timezone.utc) else 'expires'} {end:%Y-%m-%d}"
    except Exception:
        expiry = "expiry unreadable"

    pub = cert.public_key()
    info = _pub_info(pub)
    label = info[1] if info else "unknown key type"
    who = f" CN={cn}" if cn else ""
    snippet = f"{kind}{who}: {label}, {sig} signature, {expiry}"

    if info:
        rid, lbl, weak, ksize = info
        hits.append(Hit(rid, line, snippet, source="parsed", parsed=lbl, confidence="confirmed",
                        key_size=ksize, evidence=f"X.509 Subject Public Key: {lbl}"))
    if sig in ("sha1", "md5"):
        hits.append(Hit(sig, line, f"{kind}{who} is signed with {sig.upper() if sig == 'md5' else 'SHA-1'}",
                        source="parsed", parsed=sig.upper(), confidence="confirmed",
                        evidence=f"X.509 Certificate Signature Algorithm: {sig.upper()}"))
    return hits


def _analyze_pem(label: str, block: str, line: int) -> List[Hit]:
    data = block.encode("utf-8", "ignore")
    hits: List[Hit] = []
    if label.endswith("PRIVATE KEY"):
        hits.append(Hit("private_key", line, f"-----BEGIN {label}----- block embedded in file",
                        source="parsed", confidence="confirmed", evidence=f"Embedded PEM private key: {label}"))
        key = None
        for loader in (lambda: serialization.load_pem_private_key(data, password=None),
                       lambda: serialization.load_ssh_private_key(data, password=None)):
            try:
                key = loader()
                break
            except Exception:
                continue
        if key is not None:
            info = _pub_info(key.public_key())
            if info:
                rid, lbl, weak, ksize = info
                note = " (below the 2048-bit minimum)" if weak else ""
                hits.append(Hit(rid, line, f"{lbl} private key{note}", source="parsed", parsed=lbl,
                                confidence="confirmed", key_size=ksize, evidence=f"Parsed {lbl} private key"))
        elif label in LABEL_RULE:
            hits.append(Hit(LABEL_RULE[label], line, f"{label} (encrypted or password-protected)",
                            source="parsed", confidence="confirmed", evidence=f"PEM block: {label}"))
    elif label in ("CERTIFICATE", "X509 CERTIFICATE"):
        hits += _cert_hits(x509.load_pem_x509_certificate(data), line)
    elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
        csr = x509.load_pem_x509_csr(data)
        info = _pub_info(csr.public_key())
        if info:
            rid, lbl, weak, ksize = info
            hits.append(Hit(rid, line, f"{lbl} certificate request", source="parsed", parsed=lbl,
                            confidence="confirmed", key_size=ksize, evidence=f"CSR Public Key: {lbl}"))
    elif label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
        pub = serialization.load_pem_public_key(data)
        info = _pub_info(pub)
        if info:
            rid, lbl, weak, ksize = info
            hits.append(Hit(rid, line, f"{lbl} public key", source="parsed", parsed=lbl,
                            confidence="confirmed", key_size=ksize, evidence=f"PEM Public Key: {lbl}"))
    elif label == "DH PARAMETERS":
        bits = serialization.load_pem_parameters(data).parameter_numbers().p.bit_length()
        weak = " (below the 2048-bit minimum)" if bits < 2048 else ""
        hits.append(Hit("dh", line, f"DH-{bits} parameters{weak}", source="parsed", parsed=f"DH-{bits}",
                        confidence="confirmed", key_size=bits, evidence=f"DH parameter file: {bits}-bit modulus"))
    elif label in LABEL_RULE:
        hits.append(Hit(LABEL_RULE[label], line, f"{label} block", source="parsed", confidence="confirmed",
                        evidence=f"PEM block: {label}"))
    return hits


def _ssh_hit(kind: str, b64: str, line: int) -> Optional[Hit]:
    try:
        raw = base64.b64decode(b64, validate=False)
        fields, i = [], 0
        while i + 4 <= len(raw) and len(fields) < 3:
            (n,) = struct.unpack(">I", raw[i:i + 4])
            i += 4
            fields.append(raw[i:i + n])
            i += n
        if kind == "ssh-rsa" and len(fields) >= 3:
            bits = int.from_bytes(fields[2], "big").bit_length()
            note = " (below the 2048-bit minimum)" if bits < 2048 else ""
            return Hit("rsa", line, f"ssh-rsa public key, {bits}-bit{note}", source="parsed",
                       parsed=f"RSA-{bits}", confidence="confirmed", key_size=bits,
                       evidence=f"OpenSSH RSA public key: {bits} bits")
        if kind == "ssh-ed25519":
            return Hit("ecdsa", line, "ssh-ed25519 public key", source="parsed", parsed="Ed25519",
                       confidence="confirmed", key_size=256, evidence="OpenSSH Ed25519 public key")
        if kind.startswith("ecdsa") and len(fields) >= 2:
            curve = fields[1].decode("ascii", "ignore")
            return Hit("ecdsa", line, f"ECDSA public key, curve {curve}", source="parsed", parsed=f"ECDSA {curve}",
                       confidence="confirmed", evidence=f"OpenSSH ECDSA public key on curve {curve}")
        if kind == "ssh-dss":
            return Hit("dsa", line, "ssh-dss public key", source="parsed", parsed="DSA",
                       confidence="confirmed", evidence="OpenSSH DSA public key")
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# Multi-Format Text & Code Scanner
# --------------------------------------------------------------------------
def _scan_text(text: str, filename: str) -> List[Hit]:
    nl = [m.start() for m in re.finditer("\n", text)]
    blocks = []

    def mask(m):
        blocks.append((m.group(1), m.group(0), m.start()))
        return re.sub(r"[^\n]", " ", m.group(0))

    masked = PEM_RE.sub(mask, text)
    hits: List[Hit] = []
    lower = filename.lower()

    if HAVE_CRYPTO:
        for label, block, start in blocks:
            line = _line_no(nl, start)
            try:
                hits += _analyze_pem(label, block, line)
            except Exception:
                if label.endswith("PRIVATE KEY"):
                    hits.append(Hit("private_key", line, f"-----BEGIN {label}----- block embedded in file",
                                    source="parsed", confidence="confirmed", evidence=label))
                elif label in LABEL_RULE:
                    hits.append(Hit(LABEL_RULE[label], line, f"{label} block (could not be parsed)",
                                    source="parsed", confidence="confirmed", evidence=label))
    else:
        for label, block, start in blocks:
            line = _line_no(nl, start)
            if label.endswith("PRIVATE KEY"):
                hits.append(Hit("private_key", line, f"-----BEGIN {label}----- block embedded in file",
                                source="pattern", confidence="confirmed", evidence=label))
            if label in LABEL_RULE:
                hits.append(Hit(LABEL_RULE[label], line, f"{label} block",
                                source="pattern", confidence="confirmed", evidence=label))

    for m in SSH_RE.finditer(masked):
        h = _ssh_hit(m.group(1), m.group(2), _line_no(nl, m.start()))
        if h:
            hits.append(h)

    if lower.endswith((".py", ".pyw")):
        hits += _parse_python_ast(text, nl)
    elif lower.endswith((".java", ".kt", ".scala")):
        hits += _parse_java(text, nl)
    elif lower.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        hits += _parse_javascript(text, nl)
    elif lower.endswith((".c", ".h", ".cpp", ".hpp", ".cc", ".cxx")):
        hits += _parse_c_cpp(text, nl)
    elif lower.endswith(".php"):
        hits += _parse_php(text, nl)
    elif lower.endswith(CONFIG_EXT) or "nginx" in lower or "apache" in lower:
        hits += _parse_config(text, nl)

    per_line = defaultdict(list)
    for rule in PATTERN_RULES:
        for m in rule.regex.finditer(masked):
            per_line[_line_no(nl, m.start())].append((rule, m.start(), m.end()))

    for line, matches in per_line.items():
        ids = {r.id for r, _, _ in matches}
        for rule, s, e in matches:
            if any(x in ids for x in rule.suppress_same_line):
                continue
            if any(r2.id in rule.suppress_overlap and s < e2 and s2 < e for r2, s2, e2 in matches):
                continue

            snip = _snippet(text, nl, line, s)
            line_str = snip.lstrip()
            is_comment = line_str.startswith(("#", "//", "/*", "*", "--", "<!--", ";", "rem "))
            is_import = line_str.startswith(("import ", "from ", "require(", "include ", "#include"))
            is_call_or_config = any(ch in snip for ch in ("(", "=", ":", "{"))

            confidence = "text_match"
            if is_call_or_config and not is_comment:
                confidence = "inferred"
            elif is_import:
                confidence = "inferred"

            hits.append(Hit(rule.id, line, snip, source="pattern", confidence=confidence, evidence=snip))

    return hits


# --------------------------------------------------------------------------
# PDF & Archive Inspection
# --------------------------------------------------------------------------
def _inspect_pdf(data: bytes, filename: str) -> List[Hit]:
    """Inspect PDF document text and encryption dictionary metadata."""
    if not HAVE_PYPDF:
        raise _Skip("PDF inspection requires pypdf; install requirements.txt")

    hits: List[Hit] = []
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
    except Exception:
        raise _Skip("PDF could not be parsed or is corrupted")

    if reader.is_encrypted:
        try:
            trailer = getattr(reader, "trailer", {}) or {}
            encrypt_dict = trailer.get("/Encrypt")
            if hasattr(encrypt_dict, "get_object"):
                encrypt_dict = encrypt_dict.get_object()

            v = encrypt_dict.get("/V") if encrypt_dict else None
            length = encrypt_dict.get("/Length", 40) if encrypt_dict else 40
            cf = encrypt_dict.get("/CF") if encrypt_dict else None

            if v == 1 or length == 40:
                hits.append(Hit("pdf_crypto", None, "PDF Encrypt dictionary: 40-bit RC4 handler (V=1)",
                                source="pdf_metadata", parsed="RC4-40", confidence="confirmed",
                                key_size=40, evidence="PDF /Encrypt dictionary: V=1, Length=40"))
            elif v == 2:
                hits.append(Hit("pdf_crypto", None, f"PDF Encrypt dictionary: {length}-bit RC4 handler (V=2)",
                                source="pdf_metadata", parsed=f"RC4-{length}", confidence="confirmed",
                                key_size=int(length), evidence=f"PDF /Encrypt dictionary: V=2, Length={length}"))
            elif v in (4, 5) or (cf and "AES" in str(cf)):
                ksize = int(length) if length in (128, 256) else (256 if v == 5 else 128)
                rid = "aes128" if ksize == 128 else "aes256"
                hits.append(Hit(rid, None, f"PDF Encrypt dictionary: AES-{ksize} handler (V={v})",
                                source="pdf_metadata", parsed=f"AES-{ksize}", confidence="confirmed",
                                key_size=ksize, evidence=f"PDF /Encrypt dictionary: V={v}, Length={ksize}"))
            else:
                hits.append(Hit("pdf_crypto", None, "Encrypted PDF document", source="pdf_metadata",
                                parsed="Encrypted PDF", confidence="confirmed",
                                evidence="PDF /Encrypt dictionary present"))
        except Exception:
            hits.append(Hit("pdf_crypto", None, "Encrypted PDF document (password protected)",
                            source="pdf_metadata", parsed="Encrypted PDF", confidence="confirmed",
                            evidence="reader.is_encrypted == True"))

    pages_text = []
    try:
        for page in reader.pages[:500]:
            extracted = page.extract_text()
            if extracted:
                pages_text.append(extracted)
    except Exception:
        pass

    full_text = "\n".join(pages_text).strip()
    if full_text:
        text_hits = _scan_text(full_text, filename)
        for th in text_hits:
            th.source = "pdf_text"
            if th.confidence == "inferred":
                th.confidence = "text_match"
        hits += text_hits
    elif not reader.is_encrypted:
        raise _Skip("PDF has no extractable text (image-only PDFs need OCR)")

    return hits


def _inspect_zip_metadata(zf: zipfile.ZipFile, name: str) -> List[Hit]:
    """Inspect ZIP file headers for encryption metadata (ZipCrypto vs WinZip AES)."""
    hits: List[Hit] = []
    encrypted_entries = [i for i in zf.infolist() if (i.flag_bits & 0x1)]
    if not encrypted_entries:
        return hits

    aes_entries = 0
    zipcrypto_entries = 0
    for info in encrypted_entries:
        has_aes = False
        extra = info.extra
        i = 0
        while i + 4 <= len(extra):
            header_id, data_size = struct.unpack('<HH', extra[i:i + 4])
            if header_id == 0x9901 and data_size >= 7:
                has_aes = True
                vendor_ver, vendor_id, aes_mode = struct.unpack('<H2sB', extra[i + 4:i + 9])
                ksize = 128 if aes_mode == 1 else (192 if aes_mode == 2 else 256)
                rid = "aes128" if ksize == 128 else "aes256"
                hits.append(Hit(rid, None, f"Entry '{info.filename}' encrypted with WinZip AES-{ksize}",
                                source="zip_metadata", parsed=f"AES-{ksize}", confidence="confirmed",
                                key_size=ksize, evidence=f"Extra field 0x9901: WinZip AES mode {aes_mode}"))
                aes_entries += 1
                break
            i += 4 + data_size

        if not has_aes:
            zipcrypto_entries += 1

    if zipcrypto_entries > 0:
        hits.append(Hit("zip_crypto", None,
                        f"{zipcrypto_entries} entry/entries encrypted with legacy PKWARE ZipCrypto",
                        source="zip_metadata", parsed="PKWARE ZipCrypto", confidence="confirmed",
                        evidence="ZIP General Purpose Bit Flag bit 0 set without 0x9901 AES header"))
    return hits


def _decode(data: bytes) -> Optional[str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _inspect(name: str, data: bytes) -> List[Hit]:
    lower = name.lower()

    if lower.endswith(".pdf") or data.startswith(b"%PDF-"):
        return _inspect_pdf(data, name)

    text = _decode(data)
    if text is None:
        if lower.endswith(KEYSTORE_EXT):
            raise _Skip("keystore needs a password to inspect")
        if HAVE_CRYPTO and lower.endswith(DER_EXT):
            try:
                cert = x509.load_der_x509_certificate(data)
            except Exception:
                raise _Skip("binary file")
            return _cert_hits(cert, None)
        raise _Skip("binary file")

    return _scan_text(text, name)


# --------------------------------------------------------------------------
# Archives and File Traversal
# --------------------------------------------------------------------------
def _clean_name(name: str) -> str:
    name = (name or "unnamed").replace("\\", "/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    return ("/".join(parts) or "unnamed")[:300]


def _ignored(name: str) -> bool:
    return any(p in IGNORED_DIRS for p in name.split("/")[:-1])


def _is_archive(name: str, data: bytes) -> Optional[str]:
    lower = name.lower()
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if lower.endswith(TAR_EXT):
        return "tar"
    return None


def _iter_archive(name: str, data: bytes, kind: str):
    """Yield (inner_name, data_or_None, skip_reason_or_None, hits_list)."""
    total = 0
    if kind == "zip":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            yield name, None, "archive could not be opened", []
            return

        zip_meta_hits = _inspect_zip_metadata(zf, name)

        infos = [i for i in zf.infolist() if not i.is_dir()]
        for idx, info in enumerate(infos[:ARCHIVE_MAX_ENTRIES]):
            inner = f"{name}!/{_clean_name(info.filename)}"
            meta_for_entry = zip_meta_hits if idx == 0 else []

            if info.flag_bits & 0x1:
                yield inner, None, "encrypted archive entry", meta_for_entry
                continue
            if info.file_size > MAX_FILE_BYTES:
                yield inner, None, "larger than 5 MB", meta_for_entry
                continue
            if info.compress_size > 0 and (info.file_size / info.compress_size > ZIP_BOMB_MAX_RATIO) and info.file_size > 10 * 1024 * 1024:
                yield inner, None, "abnormal compression ratio (possible zip bomb)", meta_for_entry
                continue

            total += info.file_size
            if total > ARCHIVE_MAX_TOTAL:
                yield name, None, "archive too large when unpacked, remaining entries not read", meta_for_entry
                return

            try:
                yield inner, zf.read(info), None, meta_for_entry
            except Exception:
                yield inner, None, "entry could not be read", meta_for_entry

        if len(infos) > ARCHIVE_MAX_ENTRIES:
            yield name, None, f"archive has {len(infos)} entries, only the first {ARCHIVE_MAX_ENTRIES} were read", []
    else:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data))
        except Exception:
            yield name, None, "archive could not be opened", []
            return
        with tf:
            count = 0
            for member in tf:
                if not member.isfile():
                    continue
                count += 1
                if count > ARCHIVE_MAX_ENTRIES:
                    yield name, None, f"only the first {ARCHIVE_MAX_ENTRIES} entries were read", []
                    return
                inner = f"{name}!/{_clean_name(member.name)}"
                if member.size > MAX_FILE_BYTES:
                    yield inner, None, "larger than 5 MB", []
                    continue
                total += member.size
                if total > ARCHIVE_MAX_TOTAL:
                    yield name, None, "archive too large when unpacked, remaining entries not read", []
                    return
                try:
                    yield inner, tf.extractfile(member).read(MAX_FILE_BYTES + 1), None, []
                except Exception:
                    yield inner, None, "entry could not be read", []


# --------------------------------------------------------------------------
# Scoring, Aggregation and Structured Findings Builder
# --------------------------------------------------------------------------
def _points(severity: str, count: int) -> float:
    return SEVERITY_WEIGHT[severity] * (1 + 0.1 * min(max(count - 1, 0), 5))


def risk_score(raw: float) -> int:
    return int(round(100 * (1 - math.exp(-raw / 30.0)))) if raw > 0 else 0


def risk_level(score: int) -> str:
    if score <= 0:
        return "none"
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def _build_findings(per_file_hits: Dict[str, List[Hit]], scan_context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    findings = []
    for fname, hits in per_file_hits.items():
        best: Dict[Tuple[str, Optional[int], str], Hit] = {}
        for h in hits:
            key = (h.rule_id, h.line, h.evidence)
            if key in best:
                if CONFIDENCE_ORDER.get(h.confidence, 0) > CONFIDENCE_ORDER.get(best[key].confidence, 0):
                    best[key] = h
            else:
                best[key] = h

        groups = defaultdict(list)
        for h in best.values():
            groups[h.rule_id].append(h)

        for rid, occ in groups.items():
            rule = RULES_BY_ID[rid]
            occ.sort(key=lambda o: (o.line is None, o.line or 0))

            key_sizes = [o.key_size for o in occ if o.key_size is not None]
            primary_key_size = key_sizes[0] if key_sizes else None
            modes = [o.mode for o in occ if o.mode is not None]
            primary_mode = modes[0] if modes else None

            confidence_ranks = [CONFIDENCE_ORDER.get(o.confidence, 1) for o in occ]
            max_rank = max(confidence_ranks) if confidence_ranks else 1
            confidence_level = "confirmed" if max_rank == 3 else ("inferred" if max_rank == 2 else "text_match")

            parsed_labels = []
            for o in occ:
                if o.parsed and o.parsed not in parsed_labels:
                    parsed_labels.append(o.parsed)

            first_occ = occ[0]
            evidence_str = first_occ.evidence
            loc_type = "source_code" if first_occ.line else ("binary" if "metadata" not in first_occ.source else first_occ.source)
            source_loc = {
                "type": loc_type,
                "line": first_occ.line,
                "file": fname,
            }

            # Call dedicated risk analysis engine
            risk_data = risk_engine.evaluate_risk(
                rule_id=rid,
                key_size=primary_key_size,
                mode=primary_mode,
                confidence=confidence_level,
                source=first_occ.source,
                evidence=evidence_str,
            )

            # Build backward-compatible assessments enriched with risk_engine insights
            classical_sec = {
                "status": risk_data["current_security_concerns"]["status"],
                "description": " ".join(risk_data["current_security_concerns"]["concerns"]),
                "exploitable_today": risk_data["current_security_concerns"]["exploitable_today"],
                "standards_reference": risk_data["current_security_concerns"]["standards_reference"],
            }
            quantum_risk = {
                "status": rule.status,
                "label": STATUS_LABELS.get(rule.status, "Unknown"),
                "threat_model": risk_data["quantum_threat_analysis"].get("quantum_algorithm_applicable", "Shor's / Grover's"),
                "description": risk_data["quantum_threat_analysis"]["why_vulnerable"],
                "quantum_classification": risk_data["quantum_threat_analysis"]["quantum_classification"],
                "breaks_security_assumptions": risk_data["quantum_threat_analysis"]["breaks_security_assumptions"],
                "theoretical_vs_active": risk_data["quantum_threat_analysis"]["theoretical_vs_active"],
            }
            limitations = generate_limitations(confidence_level, first_occ.source, rid)

            f_item = {
                "rule_id": rid,
                "filename": fname,
                "file": fname,
                "detected_algorithm": rule.name,
                "algorithm": rule.name,
                "category": rule.category,
                "severity": rule.severity,
                "quantum_status": rule.status,
                "quantum_label": STATUS_LABELS[rule.status],
                "confidence_level": confidence_level,
                "key_size": primary_key_size,
                "key_size_label": f"{primary_key_size}-bit" if primary_key_size else None,
                "mode": primary_mode,
                "evidence": evidence_str,
                "source_location": source_loc,
                "detected_parameters": risk_data["detected_parameters"],
                "current_security_concerns": risk_data["current_security_concerns"],
                "quantum_threat_analysis": risk_data["quantum_threat_analysis"],
                "quantum_classification": risk_data["quantum_threat_analysis"]["quantum_classification"],
                "breaks_security_assumptions": risk_data["quantum_threat_analysis"]["breaks_security_assumptions"],
                "why_vulnerable": risk_data["quantum_threat_analysis"]["why_vulnerable"],
                "theoretical_vs_active": risk_data["quantum_threat_analysis"]["theoretical_vs_active"],
                "harvest_now_decrypt_later": risk_data["harvest_now_decrypt_later"],
                "hndl_explanation": risk_data["harvest_now_decrypt_later"]["explanation"],
                "classical_concerns": risk_data["current_security_concerns"]["concerns"],
                "classical_security_assessment": classical_sec,
                "quantum_risk_assessment": quantum_risk,
                "remediation_guidance": risk_data["remediation_guidance"],
                "analysis_limitations": limitations,
                "count": len(occ),
                "occurrences": [
                    {
                        "line": o.line,
                        "snippet": o.snippet,
                        "source": o.source,
                        "confidence": o.confidence,
                        "evidence": o.evidence,
                        "key_size": o.key_size,
                        "mode": o.mode,
                    }
                    for o in occ[:MAX_OCCURRENCES]
                ],
                "parsed": parsed_labels[:6],
                "description": rule.description,
                "recommendation": rule.recommendation,
                "replacement": rule.replacement,
            }

            # Calculate transparent 6-factor risk prioritisation score
            score_data = risk_scoring.calculate_finding_risk(
                f_item,
                user_context=scan_context,
            )
            f_item.update({
                "risk_score": score_data["score"],
                "risk_level": score_data["level"],
                "risk_label": score_data["risk_label"],
                "priority": score_data["priority"],
                "timeframe": score_data["timeframe"],
                "remediation_timeframe": score_data["remediation_timeframe"],
                "is_provisional": score_data["is_provisional"],
                "confidence_flag": score_data["confidence_flag"],
                "score_explanation": score_data["explanation"],
                "contributing_factors": score_data["contributing_factors"],
                "factor_scores": score_data["factor_scores"],
                "is_long_lived_sensitive_pki": score_data["is_long_lived_sensitive_pki"],
                "highlight_callout": score_data["highlight_callout"],
                "score_disclaimer": score_data["disclaimer"],
                "user_context": score_data["user_context"],
                "weights_used": score_data["weights_used"],
                "scan_surface": "source_code",
            })
            # Generate structured PQC migration recommendation
            migration_rec = migration_engine.generate_migration_recommendation(
                f_item,
                scan_context=scan_context,
            )
            f_item["migration_recommendation"] = migration_rec
            findings.append(f_item)

    # Sort findings using documented tie-breakers: Risk Score desc, Confidentiality Lifetime desc, Exposure desc
    findings = risk_scoring.sort_remediation_queue(findings)
    for i, f in enumerate(findings, 1):
        f["id"] = i
    return findings


# --------------------------------------------------------------------------
# Migration Planning
# --------------------------------------------------------------------------
PHASES = [
    ("unsafe-today", "Remove what is already unsafe", "Immediate",
     "These items are weak with or without a quantum computer. Fix them before starting post-quantum work."),
    ("key-exchange", "Protect encryption and key exchange first", "High",
     "Traffic recorded today can be decrypted later once quantum computers mature, so key establishment has "
     "the earliest deadline."),
    ("signatures", "Replace signatures and certificates", "Medium",
     "Signatures cannot be attacked retroactively, but anything that must stay trustworthy for years "
     "(firmware, root certificates, long-lived documents) needs a plan now."),
    ("symmetric", "Strengthen symmetric crypto", "Low",
     "Symmetric algorithms need only larger keys, not new designs."),
    ("agility", "Build crypto-agility", "Ongoing",
     "Make the next algorithm change a configuration change, not a rewrite."),
]

ACTIONS = {
    "private_key": (0, "Remove embedded private keys",
                    "Treat any key stored in files as compromised: revoke or rotate it, then load keys at runtime "
                    "from a secrets manager, KMS or HSM."),
    "des": (0, "Retire DES", "Switch to AES-256-GCM or ChaCha20-Poly1305 and re-encrypt stored data."),
    "tdes": (0, "Retire Triple DES", "Switch to AES-256-GCM or ChaCha20-Poly1305 and re-encrypt stored data."),
    "rc4": (0, "Retire RC4", "Switch to AES-256-GCM or ChaCha20-Poly1305."),
    "blowfish": (0, "Retire Blowfish", "Switch to AES-256-GCM or ChaCha20-Poly1305."),
    "zip_crypto": (0, "Retire PKWARE ZipCrypto", "Use WinZip AES-256 or modern encrypted container formats."),
    "pdf_crypto": (0, "Upgrade PDF encryption", "Re-encrypt PDFs using AES-256 standard handlers."),
    "aes_ecb": (0, "Eliminate ECB mode", "Switch to AES-256-GCM or ChaCha20-Poly1305 with random unique IVs."),
    "md5": (0, "Replace MD5", "Use SHA-256 or SHA-3. Use Argon2id, scrypt or bcrypt for passwords."),
    "sha1": (0, "Replace SHA-1", "Use SHA-256 or SHA-3 for signatures and integrity checks."),
    "weak_tls": (0, "Disable SSL and TLS 1.0/1.1", "Require TLS 1.3, with TLS 1.2 as the minimum for older clients."),
    "rsa": (1, "Replace RSA encryption and key exchange",
            "Identify whether each RSA use is encryption or key exchange (migrate to ML-KEM first) or signing "
            "(covered in the signatures phase). Use hybrid modes during transition."),
    "dh": (1, "Replace Diffie-Hellman key exchange",
           "Use a hybrid key exchange such as X25519MLKEM768, or ML-KEM-768 once peers support it."),
    "ecdh": (1, "Replace ECDH and X25519 key exchange",
             "Use a hybrid key exchange such as X25519MLKEM768, or ML-KEM-768 once peers support it."),
    "elgamal": (1, "Replace ElGamal encryption", "Use ML-KEM for encryption and key establishment."),
    "ecdsa": (2, "Replace ECDSA and EdDSA signatures",
              "Use ML-DSA-65 (FIPS 204), or SLH-DSA (FIPS 205) for long-lived roots and firmware. Use hybrid or "
              "composite signatures where verifiers cannot all upgrade at once."),
    "dsa": (2, "Replace DSA signatures", "Use ML-DSA-65 (FIPS 204). DSA is no longer approved for new signatures."),
    "ecc_curve": (2, "Review elliptic-curve keys",
                  "Decide whether each key is used for key agreement (move to ML-KEM) or signing (move to ML-DSA). "
                  "Certificate chains depend on CA and PKI vendor support for post-quantum certificates."),
    "aes128": (3, "Move AES-128 to AES-256", "Use AES-256-GCM for data that must stay confidential for many years."),
}

REFERENCES = [
    "NIST published FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) in August 2024.",
    "NIST IR 8547 (draft) proposes deprecating RSA and elliptic-curve algorithms at 112-bit security by 2030 "
    "and disallowing them by 2035.",
]


def _build_plan(findings):
    buckets = defaultdict(lambda: defaultdict(list))
    for f in findings:
        rid = f["rule_id"]
        if rid in ACTIONS:
            buckets[ACTIONS[rid][0]][rid].append(f)
    phases = []
    for idx, (pid, title, priority, intro) in enumerate(PHASES):
        actions = []
        if idx in buckets:
            for rid, fs in sorted(buckets[idx].items(), key=lambda kv: -SEVERITY_ORDER[RULES_BY_ID[kv[0]].severity]):
                rule = RULES_BY_ID[rid]
                files = sorted({f["file"] for f in fs})
                rep_rec = (fs[0].get("migration_recommendation") or {}) if fs else {}
                actions.append({
                    "id": f"{pid}:{rid}",
                    "title": ACTIONS[rid][1],
                    "algorithm": rule.name,
                    "severity": rule.severity,
                    "replace_with": rep_rec.get("proposed_alternative") or rule.replacement,
                    "how": ACTIONS[rid][2],
                    "file_count": len(files),
                    "files": files[:8],
                    "uses": sum(f["count"] for f in fs),
                    "protocol_role": rep_rec.get("protocol_role"),
                    "reason": rep_rec.get("reason"),
                    "compatibility_considerations": rep_rec.get("compatibility_considerations"),
                    "implementation_steps": rep_rec.get("implementation_steps", []),
                    "testing_requirements": rep_rec.get("testing_requirements", []),
                    "tradeoff_analysis": rep_rec.get("tradeoff_analysis"),
                    "role_distinctions": rep_rec.get("role_distinctions"),
                    "assessment_factors": rep_rec.get("assessment_factors"),
                    "action_priority": rep_rec.get("priority", priority),
                })
        if pid == "agility" and phases:
            actions = [
                {"id": "agility:inventory", "title": "Keep a cryptographic inventory", "algorithm": None,
                 "severity": None, "replace_with": "A cryptographic bill of materials (CBOM)",
                 "how": "Record every algorithm, key size and library in use, and who owns it.",
                 "file_count": 0, "files": [], "uses": 0},
                {"id": "agility:config", "title": "Make algorithm choice configurable", "algorithm": None,
                 "severity": None, "replace_with": "Algorithm names in configuration, not hard-coded",
                 "how": "Wrap crypto calls behind one internal interface so a new algorithm needs one change.",
                 "file_count": 0, "files": [], "uses": 0},
                {"id": "agility:rescan", "title": "Scan again after each change", "algorithm": None,
                 "severity": None, "replace_with": "A new VULNEXIS scan after every migration step",
                 "how": "Compare risk scores in the scan history to confirm each step reduced exposure.",
                 "file_count": 0, "files": [], "uses": 0},
            ]
        if actions:
            phases.append({"id": pid, "title": title, "priority": priority, "intro": intro, "actions": actions})
    return {"references": REFERENCES, "phases": phases}


# --------------------------------------------------------------------------
# Public Entry Point
# --------------------------------------------------------------------------
def scan(items, scan_context: Optional[Dict[str, Any]] = None):
    """Scan an iterable of (filename, bytes) and return structured analysis result."""
    t0 = time.perf_counter()
    per_file_hits: Dict[str, List[Hit]] = defaultdict(list)
    sizes = {}
    skipped = []
    skipped_total = 0
    total_bytes = 0

    def skip(name, reason):
        nonlocal skipped_total
        skipped_total += 1
        if len(skipped) < MAX_SKIPPED_LISTED:
            skipped.append({"name": name, "reason": reason})

    def process(name: str, data: bytes, depth: int):
        nonlocal total_bytes
        if _ignored(name):
            skip(name, "ignored folder")
            return
        if len(data) > MAX_FILE_BYTES:
            skip(name, "larger than 5 MB")
            return

        kind = _is_archive(name, data)
        if kind:
            if depth > 0:
                skip(name, "nested archive")
                return
            for inner, d, reason, meta_hits in _iter_archive(name, data, kind):
                if meta_hits:
                    per_file_hits[name].extend(meta_hits)
                if reason:
                    skip(inner, reason)
                elif d is not None:
                    process(inner, d, depth + 1)
            return

        if len(per_file_hits) >= MAX_SCANNED_FILES:
            skip(name, "scan file limit reached")
            return

        try:
            hits = _inspect(name, data)
        except _Skip as why:
            skip(name, str(why))
            return
        except Exception as e:
            skip(name, f"parsing error: {str(e)[:100]}")
            return

        per_file_hits[name].extend(hits)
        sizes[name] = len(data)
        total_bytes += len(data)

    for raw_name, data in items:
        process(_clean_name(raw_name), data, 0)

    findings = _build_findings(per_file_hits, scan_context=scan_context)
    plan = _build_plan(findings)
    remediation_queue = risk_scoring.build_remediation_queue(findings)
    monday_morning_plan = risk_scoring.generate_monday_morning_plan(findings)
    dedup_data = risk_scoring.correlate_and_deduplicate_findings(findings)

    # Per-file ranking
    file_raw = defaultdict(float)
    file_info = {}
    for f in findings:
        file_raw[f["file"]] += _points(f["severity"], f["count"])
        info = file_info.setdefault(f["file"], {"findings": 0, "max": "info"})
        info["findings"] += 1
        if SEVERITY_ORDER[f["severity"]] > SEVERITY_ORDER[info["max"]]:
            info["max"] = f["severity"]

    files = []
    for name, raw in file_raw.items():
        sc = risk_score(raw)
        files.append({"name": name, "size": sizes.get(name, 0), "findings": file_info[name]["findings"],
                      "max_severity": file_info[name]["max"], "points": round(raw, 1),
                      "score": sc, "level": risk_level(sc)})
    files.sort(key=lambda x: (-x["points"], x["name"]))

    # Algorithm inventory
    algos = {}
    for f in findings:
        a = algos.setdefault(f["rule_id"], {
            "rule_id": f["rule_id"], "name": f["algorithm"], "category": f["category"],
            "severity": f["severity"], "quantum_status": f["quantum_status"],
            "quantum_label": f["quantum_label"], "findings": 0, "occurrences": 0, "files": set()})
        a["findings"] += 1
        a["occurrences"] += f["count"]
        a["files"].add(f["file"])

    algorithms = []
    for a in algos.values():
        a["files"] = len(a["files"])
        algorithms.append(a)
    algorithms.sort(key=lambda a: (-SEVERITY_ORDER[a["severity"]], -a["occurrences"], a["name"]))

    severity_counts = {k: 0 for k in SEVERITY_ORDER}
    status_counts = {k: 0 for k in STATUS_LABELS}
    confidence_counts = {k: 0 for k in CONFIDENCE_LABELS}
    for f in findings:
        severity_counts[f["severity"]] += 1
        status_counts[f["quantum_status"]] += 1
        confidence_counts[f.get("confidence_level", "text_match")] = confidence_counts.get(f.get("confidence_level", "text_match"), 0) + 1

    raw_total = sum(_points(f["severity"], f["count"]) for f in findings)
    score = risk_score(raw_total)
    vulnerable = status_counts["vulnerable"]
    pqc = status_counts["pqc"]
    readiness = round(100 * pqc / (pqc + vulnerable)) if (pqc + vulnerable) else None

    notes = []
    if not HAVE_CRYPTO:
        notes.append("Certificate and key parsing is disabled because the 'cryptography' package is not installed. "
                     "Key sizes and certificate metadata could not be fully parsed.")
    if not HAVE_PYPDF:
        notes.append("PDF text and encryption inspection is disabled because 'pypdf' is not installed.")

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": int((time.perf_counter() - t0) * 1000),
        "summary": {
            "files_scanned": len(per_file_hits),
            "bytes_scanned": total_bytes,
            "files_skipped": skipped_total,
            "files_with_findings": len(files),
            "findings_total": len(findings),
            "occurrences_total": sum(f["count"] for f in findings),
            "algorithms_detected": len(algorithms),
            "critical_findings": severity_counts["critical"],
            "quantum_vulnerable_assets": vulnerable,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "confidence_counts": confidence_counts,
            "risk_raw": round(raw_total, 1),
            "risk_score": score,
            "risk_level": risk_level(score),
            "risk_level_label": LEVEL_LABELS[risk_level(score)],
            "pqc_readiness": {"pqc": pqc, "vulnerable": vulnerable, "percent": readiness},
            "prioritisation_bands": {
                "critical": sum(1 for f in findings if f.get("risk_level") == "critical"),
                "high": sum(1 for f in findings if f.get("risk_level") == "high"),
                "medium": sum(1 for f in findings if f.get("risk_level") == "medium"),
                "low": sum(1 for f in findings if f.get("risk_level") == "low"),
            },
            "long_lived_sensitive_pki_count": sum(1 for f in findings if f.get("is_long_lived_sensitive_pki")),
        },
        "algorithms": algorithms,
        "files": files,
        "findings": findings,
        "plan": plan,
        "remediation_queue": remediation_queue,
        "monday_morning_plan": monday_morning_plan,
        "deduplicated_issues": dedup_data["deduplicated_issues"],
        "skipped": {"total": skipped_total, "items": skipped},
        "notes": notes,
    }
