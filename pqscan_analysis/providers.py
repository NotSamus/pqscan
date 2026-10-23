"""Name-based provider boundaries, not provider implementation/API validation."""

import re

PROVIDERS = {
    "pqcrypto": {"distribution": "pqcrypto", "implementation": "external_or_native_uninspected"},
    "oqs": {"distribution": "liboqs-python", "implementation": "external_or_native_uninspected"},
}


def provider_boundary(name):
    root = name.split(".")[0]
    if root not in PROVIDERS:
        return None
    return dict(PROVIDERS[root], module=root, symbol=name, contract_status="not_verified")


def declared_dependencies(path, source):
    """Record simple requirements declarations only; never resolve/install them."""
    if not (path.rsplit("/", 1)[-1].lower().startswith("requirements") and path.endswith(".txt")):
        return []
    result = []
    for line, text in enumerate(source.splitlines(), 1):
        match = re.match(r"^\s*(pqcrypto|liboqs[-_]python|oqs)(\[[^\]]+\])?\s*([<>=!~][^;#]*)?", text, re.I)
        if match and re.match(r"(?:\s|[\[<>=!~;#]|$)", text[match.end(1):]):
            result.append({"path": path, "line": line, "distribution": match[1].lower().replace("_", "-"),
                           "constraint": (match[3] or "").strip()[:200], "status": "declared_only"})
    return result
