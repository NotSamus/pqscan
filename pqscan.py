#!/usr/bin/env python3
"""Offline, dependency-free cryptographic inventory for Python 3.9+.

This is a static evidence scanner, not a proof of quantum readiness. No target
code is imported, built, or executed. Copy this file anywhere to use it.
"""

import argparse
import ast
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fnmatch
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tokenize
from typing import List, Optional, Tuple


VERSION = "1.0.0"
NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"
NIST_FAQ = NIST_PQC + "/faqs"
FIPS203 = "https://csrc.nist.gov/pubs/fips/203/final"
FIPS204 = "https://csrc.nist.gov/pubs/fips/204/final"
FIPS205 = "https://csrc.nist.gov/pubs/fips/205/final"
LIMITATIONS = [
    "Static evidence cannot certify quantum readiness or implementation correctness.",
    "Imports and dependencies show availability, not use. Dead code and reachability are not resolved.",
    "Python uses AST call/import analysis; other supported languages use lexical patterns, not type analysis.",
    "Custom crypto, dynamic algorithm selection, wrappers, reflection, and aliases outside Python may be missed.",
    "Transitive dependencies, binaries, remote services, negotiated TLS, certificates, and deployed settings are not inspected.",
    "PQC names do not verify parameter choices, provider versions, secure composition, fallback behavior, or key management.",
    "Test/example paths are inferred from filenames. Review findings against the actual deployment.",
]
DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "vendor",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "dist", "build", "target", "coverage", ".next", ".nuxt", ".idea", ".vscode",
}
SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go",
    ".rs", ".java", ".kt", ".kts", ".scala", ".c", ".h", ".cc", ".cpp",
    ".hpp", ".cxx", ".cs", ".rb", ".php", ".swift", ".sh", ".bash", ".zsh",
}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".tf"}
MANIFEST_NAMES = {
    "requirements.txt", "pyproject.toml", "pipfile", "setup.cfg", "package.json",
    "cargo.toml", "go.mod", "gemfile", "pom.xml", "build.gradle", "build.gradle.kts",
    "packages.config", "composer.json",
}
LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "cargo.lock", "go.sum", "pipfile.lock", "composer.lock", "gemfile.lock"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    algorithm: str
    category: str
    severity: str
    pattern: str
    recommendation: str
    reference: str


# Patterns intentionally name recognizable APIs and algorithm identifiers. They
# are not a list of words to search for in documentation or arbitrary strings.
RULES = (
    Rule("Q001", "RSA", "quantum_vulnerable", "high",
         r"(?<![\w])(?:rsa(?=[.:'\"\s/-]|$)|RSA(?:EncryptionPadding|SignaturePadding|Key|Parameters|_\w+)|EVP_PKEY_RSA(?:_PSS)?|(?:rsaEncryption|sha\d+WithRSA(?:Encryption)?)|(?:RS|PS)(?:256|384|512))(?!\w)",
         "Inventory RSA key transport and signatures. Plan protocol-supported ML-KEM key establishment and/or ML-DSA or SLH-DSA signatures; increasing RSA key size does not address Shor's algorithm.", NIST_PQC),
    Rule("Q002", "Elliptic-curve cryptography", "quantum_vulnerable", "high",
         r"(?<![\w])(?:ECDH\w*|ECDSA\w*|sha\d+withECDSA|ECC|EVP_PKEY_(?:EC|X25519|X448|ED25519|ED448)|X25519(?:PrivateKey|PublicKey|_dalek)?|X448(?:PrivateKey|PublicKey)?|Ed25519\w*|Ed448\w*|EdDSA|(?:ES)(?:256|384|512)|secp\w+|prime256v1|nistp(?:256|384|521)|P-(?:256|384|521)|ec\.(?:generate_private_key|derive_private_key|EllipticCurve\w*|SECP\w*)|(?<=['\"])ec(?=['\"]))(?!\w)",
         "Review elliptic-curve key agreement and signatures. Use a reviewed PQC-capable protocol/provider for the relevant role; retain classical components only as part of an explicitly reviewed hybrid design.", NIST_PQC),
    Rule("Q003", "Finite-field Diffie-Hellman", "quantum_vulnerable", "high",
         r"(?<![\w])(?:DiffieHellman\w*|(?:create|get)DiffieHellman|DHE|ffdhe\d*|DH_(?:new|generate_key|compute_key|generate_parameters\w*)|dh\.(?:generate_parameters|DHParameters|DHPrivateKey)|DH)(?!\w)",
         "Migrate finite-field DH key establishment to a protocol with ML-KEM or a reviewed hybrid KEM. Larger DH groups do not remove the quantum vulnerability.", FIPS203),
    Rule("Q004", "DSA", "quantum_vulnerable", "high",
         r"(?<![\w-])(?:DSA|sha\d+withDSA|DSA_(?:new|sign|verify|generate_key|generate_parameters\w*)|dsa\.(?:generate_private_key|generate_parameters|DSAPrivateKey))(?![\w-])",
         "Plan a protocol-compatible post-quantum signature migration using ML-DSA or SLH-DSA; DSA remains vulnerable to Shor's algorithm.", FIPS204),
    Rule("P001", "ML-KEM", "pqc", "info",
         r"(?<!\w)(?:OQS_KEM_alg_)?ml[_-]?kem(?:[_-]?(?:512|768|1024))?(?!\w)",
         "Confirm this is final FIPS 203 ML-KEM, with a maintained provider, validated parameter set, authenticated protocol, and no unintended classical-only fallback.", FIPS203),
    Rule("P002", "ML-DSA", "pqc", "info",
         r"(?<!\w)(?:OQS_SIG_alg_)?ml[_-]?dsa(?:[_-]?(?:44|65|87))?(?!\w)",
         "Confirm final FIPS 204 behavior, provider/version, parameter set, verification policy, and key lifecycle in deployed signing paths.", FIPS204),
    Rule("P003", "SLH-DSA", "pqc", "info",
         r"(?<!\w)(?:OQS_SIG_alg_)?slh[_-]?dsa(?:[_-](?:sha2|shake))?(?:[_-]?(?:128|192|256)[sf])?(?!\w)",
         "Confirm final FIPS 205 behavior and approved parameter set; test signing/verification performance and deployed verification policy.", FIPS205),
    Rule("P004", "Hybrid ML-KEM key establishment", "pqc", "info",
         r"(?<!\w)(?:X25519MLKEM768|X25519_ML_KEM_768|SecP256r1MLKEM768|SecP384r1MLKEM1024|XWing)(?!\w)",
         "A hybrid identifier is evidence of configuration or use, not negotiated protection. Verify peer support, combiner, downgrade/fallback policy, and authentication separately.", NIST_FAQ),
    Rule("R001", "Earlier PQC algorithm names", "review", "medium",
         r"(?<!\w)(?:kyber(?:[_-]?(?:512|768|1024))?|dilithium[235]?|sphincs(?:\+|plus)?(?:[_-][\w-]+)?|X25519Kyber768Draft00)(?!\w)",
         "Verify the exact implementation and version. Earlier Kyber, Dilithium, and SPHINCS+ names do not establish conformance to final ML-KEM, ML-DSA, or SLH-DSA standards.", NIST_PQC),
    Rule("R002", "Other PQC candidate or specialized scheme", "review", "medium",
         r"(?<!\w)(?:falcon(?:[_-](?:512|1024))?|fn[_-]?dsa|frodo(?:kem)?(?:[_-]?\d+)?|ntru(?:hps\w*|hrss\w*)?|hqc(?:[_-]?\d+)?|saber|mceliece\w*|xmss(?:mt)?|lms|hss)(?!\w)",
         "Review this scheme's current standardization status, parameter set, provider and use constraints. Stateful signatures additionally require safe persistent state management. This rule does not certify the scheme.", NIST_PQC),
    Rule("S001", "AES", "symmetric", "info",
         r"(?<!\w)(?:AES(?:[_-]?(?:128|192|256))?(?:[_-](?:GCM|CBC|CTR|CCM|ECB))?|AESGCM|AESCCM|AesGcm|aes\.NewCipher|EVP_aes_\w+)(?!\w)",
         "AES is not broken by Shor's algorithm. Review key size, authenticated mode, nonce handling and key establishment; AES alone does not make a protocol quantum-ready.", NIST_FAQ),
    Rule("S002", "ChaCha20", "symmetric", "info",
         r"(?<!\w)(?:ChaCha20(?:Poly1305)?|XChaCha20(?:Poly1305)?|chacha20[_-]poly1305)(?!\w)",
         "Review nonce handling and authentication, and independently check the public-key mechanism used to establish or wrap keys.", NIST_PQC),
    Rule("H001", "SHA-2 / SHA-3", "hash", "info",
         r"(?<!\w)(?:sha[_-]?(?:224|256|384|512)|sha3[_-]?(?:224|256|384|512)|shake[_-]?(?:128|256))(?!\w)",
         "A hash is not a post-quantum key exchange or signature. Review digest length and security role separately; do not infer repository readiness from hash usage.", NIST_FAQ),
    Rule("R003", "TLS configuration", "review", "low",
         r"(?<!\w)(?:ssl\.(?:create_default_context|SSLContext)|tls\.(?:Config|createServer|connect)|TLSv1[._]?[23]|TLS_AES_\w+|TLS_CHACHA20_\w+|PROTOCOL_TLS\w*|SSLContext\.getInstance)(?!\w)",
         "TLS version and symmetric cipher suite alone do not establish PQ protection. Inspect deployed key-exchange groups, peer negotiation, certificate signatures and fallback behavior.", NIST_FAQ),
    Rule("R004", "Cryptographic library", "review", "low",
         r"(?<!\w)(?:cryptography|pycryptodome|pycryptodomex|Crypto|Cryptodome|liboqs(?:-python)?|oqs|oqs-provider|pqcrypto|bouncycastle|bcprov[\w-]*|@noble/(?:post-quantum|curves|ciphers)|openssl|rustls|ring|circl)(?!\w)",
         "Inspect actual algorithm selection, provider version and deployed call paths. A crypto dependency or import alone is not evidence that PQC is in use.", NIST_PQC),
)
COMPILED_RULES = [(rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in RULES]
CRYPTO_CALL = re.compile(
    r"cryptography\.|Crypto(?:dome)?\.|pqcrypto\.|oqs\.|hashlib\.|ssl\.|jwt\.|nacl\.|OpenSSL\.|"
    r"(?:^|\.)(?:rsa|ec|dsa|dh|x25519|x448|ed25519|ed448)\.|"
    r"(?:generateKeyPair(?:Sync)?|create(?:Cipheriv|Decipheriv|Sign|Verify|ECDH|Hash)|"
    r"KeyEncapsulation|Signature|Cipher|KeyPairGenerator|KeyFactory|KeyAgreement)\b", re.I)
CONFIG_KEY = re.compile(r"alg(?:orithm)?|cipher|curve|group|signature|key_exchange|keyexchange|kem|tls|crypto", re.I)


@dataclass
class Unit:
    text: str
    line: int
    column: int
    kind: str
    confidence: str = "medium"


@dataclass
class Finding:
    rule_id: str
    algorithm: str
    category: str
    severity: str
    path: str
    line: int
    column: int
    evidence_kind: str
    context: str
    confidence: str
    evidence: str
    recommendation: str
    reference: str


def blank_span(chars, start, end):
    for index in range(start, end):
        if chars[index] not in "\r\n":
            chars[index] = " "


def strip_comments(source: str, suffix: str) -> str:
    """Preserve positions; retain strings, remove common line/block comments."""
    hash_comments = suffix in {".rb", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".tf"}
    slash_comments = suffix not in {".rb", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}
    chars = list(source)
    i = 0
    while i < len(source):
        if source[i] in "\"'`":
            quote = source[i]
            triple = source.startswith(quote * 3, i)
            delimiter = quote * (3 if triple else 1)
            i += len(delimiter)
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source.startswith(delimiter, i):
                    i += len(delimiter)
                    break
                else:
                    i += 1
        elif source.startswith("<!--", i):
            end = source.find("-->", i + 4)
            end = len(source) if end < 0 else end + 3
            blank_span(chars, i, end)
            i = end
        elif slash_comments and source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = len(source) if end < 0 else end + 2
            blank_span(chars, i, end)
            i = end
        elif (hash_comments and source[i] == "#") or (slash_comments and source.startswith("//", i)):
            end = source.find("\n", i)
            end = len(source) if end < 0 else end
            blank_span(chars, i, end)
            i = end
        else:
            i += 1
    return "".join(chars)


def dotted_name(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value, aliases)
        return parent + "." + node.attr if parent else node.attr
    return ""


def literal_strings(node):
    """Read literal selectors in containers, without traversing nested calls."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [text for item in node.elts for text in literal_strings(item)]
    if isinstance(node, ast.Dict):
        return [text for item in node.values for text in literal_strings(item)]
    return []


def python_units(source: str) -> List[Unit]:
    tree = ast.parse(source)
    aliases = {}
    units = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
                units.append(Unit(alias.name, node.lineno, node.col_offset + 1, "import"))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                full = (node.module + "." if node.module else "") + alias.name
                aliases[alias.asname or alias.name] = full
                units.append(Unit(full, node.lineno, node.col_offset + 1, "import"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func, aliases)
            # Analyze names and literal selectors only, never docstrings or logging prose.
            constants = [text for arg in node.args for text in literal_strings(arg)]
            constants.extend(text for kw in node.keywords for text in literal_strings(kw.value))
            name_has_crypto = any(pattern.search(name) for rule, pattern in COMPILED_RULES if rule.id != "R004")
            if CRYPTO_CALL.search(name) or name_has_crypto:
                units.append(Unit(name + " " + " ".join(repr(value) for value in constants), node.lineno, node.col_offset + 1, "usage", "high"))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, (ast.Constant, ast.List, ast.Tuple, ast.Set)) and any(CONFIG_KEY.search(dotted_name(t, {})) for t in targets):
                for child in ast.walk(value):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        units.append(Unit(repr(child.value), child.lineno, child.col_offset + 1, "configuration"))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and CONFIG_KEY.search(key.value):
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        units.append(Unit(repr(value.value), value.lineno, value.col_offset + 1, "configuration"))
    return units


def generic_units(source: str, suffix: str, manifest: bool) -> List[Unit]:
    clean = strip_comments(source, suffix)
    units = []
    in_import = False
    recent_code = []
    for lineno, line in enumerate(clean.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if manifest:
            kind = "dependency"
        elif (re.match(r"(?:import|from|use|require|#\s*include)\b", stripped)
              or (stripped.startswith("using ") and "(" not in stripped) or in_import):
            kind = "import"
            # Cover Go import blocks and JS/Rust multiline imports.
            in_import = (in_import or stripped.startswith("import (") or "{" in stripped) and not any(c in stripped for c in ");}")
        elif suffix in CONFIG_SUFFIXES:
            kind = "configuration"
        else:
            if re.match(r"(?:console\.(?:log|info|warn|error)|print(?:ln)?|logger?\.|System\.out\.)", stripped):
                continue
            # Selectors often sit on their own line inside a multiline API call.
            call_context = " ".join(recent_code[-5:])
            kind = "usage" if re.search(r"[(:=.]|\bnew\b", stripped) or CRYPTO_CALL.search(call_context) else "reference"
        units.append(Unit(line, lineno, 1, kind))
        recent_code.append(stripped)
    return units


def source_context(path: str) -> str:
    parts = Path(path).parts
    lower = [p.lower() for p in parts]
    if any(p in {"test", "tests", "__tests__", "testdata", "fixtures", "spec", "specs"} for p in lower[:-1]):
        return "test"
    name = lower[-1]
    if name.startswith("test_") or re.search(r"(?:_test\.|\.test\.|\.spec\.|_spec\.)", name) or name.endswith("test.java"):
        return "test"
    if any(p in {"example", "examples", "demo", "demos", "samples", "sample", "benchmark", "benchmarks"} for p in lower[:-1]):
        return "example"
    return "production"


def analyze_source(source: str, path: str) -> Tuple[List[Finding], List[str]]:
    filename = Path(path).name.lower()
    suffix = Path(path).suffix.lower()
    manifest = filename in MANIFEST_NAMES or filename.endswith(".csproj") or (filename.startswith("requirements") and suffix == ".txt")
    warnings = []
    if suffix in {".py", ".pyi"}:
        try:
            units = python_units(source)
        except (SyntaxError, ValueError, RecursionError) as exc:
            warnings.append(f"{path}: Python parse failed ({type(exc).__name__}); lexical fallback requires review.")
            # tokenize still handles comments/docstrings in some incomplete files.
            chars = list(source)
            offsets = [0]
            for line in source.splitlines(keepends=True):
                offsets.append(offsets[-1] + len(line))
            try:
                for token in tokenize.generate_tokens(io.StringIO(source).readline):
                    if token.type in {tokenize.COMMENT, tokenize.STRING}:
                        blank_span(chars, offsets[token.start[0] - 1] + token.start[1], offsets[token.end[0] - 1] + token.end[1])
            except (tokenize.TokenError, IndentationError, SyntaxError):
                pass
            units = generic_units("".join(chars), suffix, False)
            for unit in units:
                unit.kind = "reference"
                unit.confidence = "low"
    else:
        units = generic_units(source, suffix, manifest)
    context = source_context(path)
    findings = {}
    for unit in units:
        for rule, pattern in COMPILED_RULES:
            match = pattern.search(unit.text)
            if match is None:
                continue
            # A library name on a call is inventory, not a second migration issue.
            if rule.id == "R004" and unit.kind not in {"import", "dependency"}:
                continue
            kind = unit.kind
            severity = rule.severity if kind in {"usage", "configuration"} else "info"
            column = unit.column if suffix in {".py", ".pyi"} else match.start() + 1
            finding = Finding(rule.id, rule.algorithm, rule.category, severity, path,
                              unit.line, column, kind, context, unit.confidence,
                              match.group(0), rule.recommendation, rule.reference)
            key = (rule.id, unit.line, kind)
            findings.setdefault(key, finding)
    return list(findings.values()), warnings


def is_active(finding: Finding) -> bool:
    return finding.context == "production" and finding.evidence_kind in {"usage", "configuration"}


def assessment(findings: List[Finding], incomplete: bool):
    active = [finding for finding in findings if is_active(finding)]
    vulnerable = [f for f in active if f.category == "quantum_vulnerable"]
    pqc = [f for f in active if f.category == "pqc"]
    if vulnerable:
        status = "migration_needed"
        reason = "Quantum-vulnerable cryptography appears in production code/configuration. Review these paths and plan migration."
        if pqc:
            reason += " PQC evidence also exists; it does not cancel classical findings or prove a secure hybrid composition."
    elif incomplete:
        status = "review_required"
        reason = "Coverage is incomplete. Resolve scan warnings or skipped source files before assessing the implementation."
    elif pqc:
        status = "pqc_evidence_found"
        reason = "PQC identifiers appear in production calls/configuration; no recognized quantum-vulnerable usage was found in scanned files. Runtime protection and correctness still require verification."
    elif findings:
        status = "review_required"
        reason = "Crypto-related evidence was found, but there is insufficient evidence of production post-quantum protection."
    else:
        status = "no_crypto_evidence"
        reason = "No recognized cryptographic evidence was found. This is not a quantum-ready verdict; cryptography may be indirect or outside scan coverage."
    return {"status": status, "reason": reason, "certified_quantum_ready": False,
            "production_quantum_vulnerable": len(vulnerable), "production_pqc_evidence": len(pqc)}


def matches_exclude(path: str, patterns: List[str]) -> bool:
    # Deliberately simple shell globs, not an incomplete imitation of gitignore.
    parts = path.split("/")
    for pattern in patterns:
        pattern = pattern.rstrip("/")
        if not pattern:
            continue
        if "/" not in pattern and any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
        if fnmatch.fnmatchcase(path, pattern) or path.startswith(pattern + "/"):
            return True
    return False


def file_type(path: Path) -> Optional[str]:
    name = path.name.lower()
    if name in LOCK_NAMES or name.endswith(".min.js"):
        return None
    if (path.suffix.lower() in SOURCE_SUFFIXES | CONFIG_SUFFIXES | {".csproj"}
            or name in MANIFEST_NAMES or name in {"dockerfile", "makefile"}
            or (name.startswith("requirements") and name.endswith(".txt"))):
        return "source"
    return None


def read_regular_file(path: Path, limit: int) -> Tuple[Optional[bytes], Optional[str]]:
    # lstat plus O_NOFOLLOW avoids following file symlinks, including most races.
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        return None, "symlink" if stat.S_ISLNK(metadata.st_mode) else "non_regular"
    if metadata.st_size > limit:
        return None, "oversized"
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return None, "non_regular"
        data = handle.read(limit + 1)
    if len(data) > limit:
        return None, "oversized"
    return data, None


def scan_repository(root: Path, excludes=(), max_file_bytes=1024 * 1024, output_path=None):
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")
    patterns = list(excludes)
    errors, warnings, skipped, findings = [], [], [], []
    ignore_path = root / ".pqscanignore"
    if ignore_path.exists() and not ignore_path.is_symlink():
        try:
            data, skip = read_regular_file(ignore_path, 65536)
            if skip:
                errors.append(f"Cannot read .pqscanignore: {skip}")
            else:
                patterns.extend(line.strip() for line in data.decode("utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        except (OSError, UnicodeError) as exc:
            errors.append(f"Cannot read .pqscanignore: {exc}")
    scanned = 0
    scanned_bytes = 0
    incomplete = False

    def on_walk_error(exc):
        errors.append(f"Cannot traverse {exc.filename}: {exc.strerror}")

    for directory, dirs, files in os.walk(root, topdown=True, onerror=on_walk_error, followlinks=False):
        current = Path(directory)
        kept = []
        for dirname in sorted(dirs):
            path = current / dirname
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                skipped.append({"path": relative, "reason": "symlink"})
            elif dirname in DEFAULT_EXCLUDES or matches_exclude(relative, patterns):
                skipped.append({"path": relative + "/", "reason": "excluded_directory"})
            else:
                kept.append(dirname)
        dirs[:] = kept
        for filename in sorted(files):
            path = current / filename
            relative = path.relative_to(root).as_posix()
            if matches_exclude(relative, patterns) or (output_path is not None and path == output_path):
                skipped.append({"path": relative, "reason": "excluded_file"})
                continue
            if not file_type(path):
                skipped.append({"path": relative, "reason": "unsupported_or_generated"})
                continue
            try:
                data, reason = read_regular_file(path, max_file_bytes)
                if reason:
                    skipped.append({"path": relative, "reason": reason})
                    incomplete = True
                    continue
                if b"\x00" in data:
                    skipped.append({"path": relative, "reason": "binary"})
                    incomplete = True
                    continue
                if path.suffix.lower() in {".py", ".pyi"}:
                    encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
                else:
                    encoding = "utf-8-sig"
                source = data.decode(encoding)
            except (UnicodeError, SyntaxError, LookupError):
                skipped.append({"path": relative, "reason": "unsupported_encoding"})
                incomplete = True
                continue
            except OSError as exc:
                errors.append(f"Cannot read {relative}: {exc.strerror}")
                continue
            if path.suffix.lower() == ".json":
                try:
                    document = json.loads(source)
                except (ValueError, RecursionError):
                    document = None
                if (isinstance(document, dict) and document.get("tool") == "pqscan"
                        and document.get("schema_version") == "1.0"
                        and isinstance(document.get("findings"), list)
                        and isinstance(document.get("assessment"), dict)):
                    skipped.append({"path": relative, "reason": "generated_report"})
                    continue
            scanned += 1
            scanned_bytes += len(data)
            found, parse_warnings = analyze_source(source, relative)
            findings.extend(found)
            warnings.extend(parse_warnings)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.line, f.rule_id, f.evidence_kind))
    incomplete = incomplete or bool(errors) or bool(warnings) or any(s["reason"] == "symlink" for s in skipped)
    verdict = assessment(findings, incomplete)
    return {
        "schema_version": "1.0", "tool": "pqscan", "tool_version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(), "repository": str(root),
        "assessment": verdict,
        "summary": {"files_scanned": scanned, "bytes_scanned": scanned_bytes,
                    "files_or_directories_skipped": len(skipped), "findings": len(findings),
                    "by_category": dict(sorted(Counter(f.category for f in findings).items())),
                    "by_severity": dict(sorted(Counter(f.severity for f in findings).items())),
                    "by_context": dict(sorted(Counter(f.context for f in findings).items()))},
        "coverage": {"incomplete": incomplete, "max_file_bytes": max_file_bytes,
                     "default_excluded_directories": sorted(DEFAULT_EXCLUDES), "exclude_patterns": patterns,
                     "gitignore_respected": False, "skipped": skipped, "warnings": warnings, "errors": errors},
        "findings": [asdict(f) for f in findings], "limitations": LIMITATIONS,
    }


def terminal_safe(value) -> str:
    # Do not allow repository filenames or matched tokens to inject terminal controls.
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(value))


def render_text(report) -> str:
    summary = report["summary"]
    verdict = report["assessment"]
    lines = [f"PQScan {VERSION} | post-quantum repository analysis",
             f"Repository: {terminal_safe(report['repository'])}", "",
             f"Assessment: {verdict['status'].upper().replace('_', ' ')}", verdict["reason"],
             f"Scanned {summary['files_scanned']} files | {summary['findings']} findings | {summary['files_or_directories_skipped']} skipped files/directories",
             "Static evidence only; quantum readiness is not certified.", ""]
    for f in report["findings"]:
        lines.extend([
            f"[{f['severity'].upper()}] {f['rule_id']} {f['algorithm']} ({f['category']})",
            f"  {terminal_safe(f['path'])}:{f['line']}:{f['column']} | {f['context']} | {f['evidence_kind']} | confidence: {f['confidence']}",
            f"  Evidence: {terminal_safe(f['evidence'])}",
            f"  Next: {f['recommendation']}", "",
        ])
    if not report["findings"]:
        lines.append("No recognized cryptographic evidence found.\n")
    coverage = report["coverage"]
    if coverage["incomplete"]:
        lines.append("Coverage is INCOMPLETE; inspect skipped paths and warnings in the JSON report.")
    if coverage["skipped"]:
        counts = Counter(item["reason"] for item in coverage["skipped"])
        lines.append("Skipped: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())))
    for message in coverage["warnings"] + coverage["errors"]:
        lines.append("Warning: " + terminal_safe(message))
    lines.extend(["", "Review before claiming readiness:",
                  "  Confirm reachable production paths, deployed providers, negotiation and fallback.",
                  "  Review authentication, key management, dependencies and implementation correctness.",
                  "  Imports, tests, AES and hashes alone do not establish post-quantum protection.",
                  "  Run --format json for full coverage details and source references."])
    return "\n".join(lines) + "\n"


def exit_status(report, fail_on: str) -> int:
    if report["coverage"]["errors"]:
        return 2
    if fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[fail_on]
    for finding in report["findings"]:
        if (finding["context"] == "production" and finding["evidence_kind"] in {"usage", "configuration"}
                and SEVERITY_ORDER[finding["severity"]] <= threshold):
            return 1
    # A requested CI gate must not pass when scan coverage failed.
    return 2 if report["coverage"]["incomplete"] else 0


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Inspect a local repository for quantum-vulnerable cryptography and post-quantum evidence.",
                                     epilog="Offline static analysis. No target code is executed. A clean report is not certification.")
    parser.add_argument("repository", help="path to a local repository (no Git checkout required)")
    parser.add_argument("--version", action="version", version=f"pqscan {VERSION}")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="report format (default: text)")
    parser.add_argument("-o", "--output", type=Path, help="write report to a new file instead of stdout; never overwrites")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude a relative path or glob; repeatable")
    parser.add_argument("--max-file-bytes", type=positive_int, default=1024 * 1024, help="maximum input file size (default: 1048576)")
    parser.add_argument("--fail-on", choices=("none", "high", "medium", "low"), default="none", help="CI: exit 1 for production findings at or above severity; incomplete coverage exits 2 (default: none)")
    args = parser.parse_args(argv)
    try:
        output = args.output.expanduser().absolute() if args.output else None
        if output is not None and (output.exists() or output.is_symlink()):
            raise ValueError(f"Output already exists; choose a new report path: {output}")
        report = scan_repository(Path(args.repository), args.exclude, args.max_file_bytes, output)
        rendered = json.dumps(report, indent=2, ensure_ascii=True) + "\n" if args.format == "json" else render_text(report)
        if output:
            with output.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
            print(f"Report written to {terminal_safe(output)}", file=sys.stderr)
        else:
            sys.stdout.write(rendered)
        return exit_status(report, args.fail_on)
    except (OSError, ValueError) as exc:
        print(f"pqscan: {terminal_safe(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\npqscan: interrupted", file=sys.stderr)
        sys.exit(130)
