"""Versioned requirements and conservative report construction.

This milestone maps inventory to review targets, never to conformance results.
Catalogs and schemas are read only from the scanner distribution, not the target.
No target code, network access, or third-party packages are used.
"""

from copy import deepcopy
from datetime import date
import hashlib
import json
from pathlib import Path
import re


STANDARDS_DIR = Path(__file__).resolve().parent.parent / "standards"
CATALOG_FILE = "nist-pqc-v1.json"
SCHEMA_VERSION = "1.0"
FAMILY_RULES = {"ML-KEM": {"P001", "P004"}, "ML-DSA": {"P002"}, "SLH-DSA": {"P003"}}
BOUNDARY = (
    "Requirements are review targets, not executed checks. Inventory references do not "
    "establish applicability, reachable production use, correctness or exploitability. "
    "Missing evidence remains unknown; this partial catalog cannot certify compliance."
)


def _read_json(path):
    with path.open("rb") as stream:
        raw = stream.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError("Specification catalog/schema exceeds 256 KiB")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key in specification catalog/schema: " + key)
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique_object), raw


def _validate(value, schema, root, location="$"):
    """Validate the small JSON Schema subset used by our bundled contracts.

    Not a general-purpose JSON Schema API. Schemas are trusted distribution data;
    runtime data is checked against the same files consumers can independently use.
    """
    def fail(message):
        raise ValueError(f"Specification contract {location}: {message}")

    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            fail("only local definition references are supported")
        return _validate(value, root["$defs"][ref.split("/")[-1]], root, location)
    if "anyOf" in schema:
        for option in schema["anyOf"]:
            try:
                _validate(value, option, root, location)
                return
            except ValueError:
                pass
        fail("no permitted type matched")
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        fail("unexpected constant")
    if "enum" in schema and not any(type(value) is type(item) and value == item for item in schema["enum"]):
        fail("unexpected value")
    expected = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}
    if expected and type(value) is not types[expected]:
        fail("expected " + expected)
    if expected == "object":
        if set(schema.get("required", ())) - value.keys():
            fail("missing required fields")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and value.keys() - properties.keys():
            fail("unexpected fields")
        for key, item in value.items():
            if key in properties:
                _validate(item, properties[key], root, location + "." + key)
    elif expected == "array":
        if len(value) < schema.get("minItems", 0):
            fail("too few items")
        if len(value) > schema.get("maxItems", len(value)):
            fail("too many items")
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            fail("duplicate items")
        for i, item in enumerate(value):
            _validate(item, schema["items"], root, f"{location}[{i}]")
    elif expected == "string":
        if len(value.strip()) < schema.get("minLength", 0):
            fail("empty string")
        if len(value) > schema.get("maxLength", len(value)):
            fail("string too long")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            fail("invalid string format")
    elif expected == "integer" and value < schema.get("minimum", value):
        fail("integer below minimum")
    elif expected == "integer" and value > schema.get("maximum", value):
        fail("integer above maximum")


def _validate_contract(value, filename):
    schema, _ = _read_json(STANDARDS_DIR / filename)
    _validate(value, schema, schema)


def validate_catalog(catalog):
    """Enforce structure, unique IDs, source references, dates and provenance."""
    _validate_contract(catalog, "catalog.schema.json")
    sources = {s["id"]: s for s in catalog["sources"]}
    if len(sources) != len(catalog["sources"]):
        raise ValueError("Duplicate specification source ID")
    ids = [r["id"] for r in catalog["requirements"]]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate specification requirement ID")
    reviewed = date.fromisoformat(catalog["reviewed_on"])
    for source in sources.values():
        published = date.fromisoformat(source["publication_date"])
        checked = date.fromisoformat(source["reviewed_on"])
        errata = source["errata"]
        if not published <= checked <= reviewed or date.fromisoformat(errata["checked_on"]) > reviewed:
            raise ValueError("Inconsistent specification source review dates")
        if (errata["status"] == "reviewed") != (errata["url"] is not None and errata["sha256"] is not None):
            raise ValueError("Reviewed errata requires URL and SHA-256")
        if errata["status"] == "none_listed" and (errata["url"] is not None or errata["sha256"] is not None):
            raise ValueError("Unlisted errata must not supply an artifact")
    for requirement in catalog["requirements"]:
        if requirement["source_id"] not in sources:
            raise ValueError("Unknown specification source ID")
        if not date.fromisoformat(sources[requirement["source_id"]]["publication_date"]) <= date.fromisoformat(requirement["reviewed_on"]) <= reviewed:
            raise ValueError("Inconsistent requirement review date")
    return catalog


def load_catalog():
    """Return a validated fresh catalog and the hash of its exact JSON bytes."""
    catalog, raw = _read_json(STANDARDS_DIR / CATALOG_FILE)
    return validate_catalog(catalog), hashlib.sha256(raw).hexdigest()


def build_specification_review(report):
    catalog, digest = load_catalog()
    entries = []
    for requirement in catalog["requirements"]:
        # Family names only identify possible review targets. Generic provider
        # operations cannot select a family, and tests cannot establish production use.
        candidates = [f for f in report["findings"] if f["rule_id"] in FAMILY_RULES[requirement["algorithm"]]]
        entries.append({
            "requirement": deepcopy(requirement),
            "status": "not_assessed",
            "applicability_status": "unknown",
            "reason": "Applicability conditions and required behavior have not been checked; no conformance evaluator is implemented.",
            "evidence": {
                "kind": "inventory_only",
                "production_finding_ids": [f["finding_id"] for f in candidates if f["context"] == "production"],
                "nonproduction_finding_ids": [f["finding_id"] for f in candidates if f["context"] != "production"],
            },
            "exploitability": "not_assessed",
        })
    result = {
        "schema_version": SCHEMA_VERSION,
        "profile": "pqscan-specification-review-v1",
        "status": "requirements_not_assessed",
        "catalog": {"id": catalog["catalog_id"], "version": catalog["version"], "sha256": digest, "reviewed_on": catalog["reviewed_on"]},
        "sources": deepcopy(catalog["sources"]),
        "requirements": entries,
        "coverage": {
            "catalog_coverage": catalog["coverage"], "requirements_total": len(entries),
            "requirements_assessed": 0, "applicability_unknown": len(entries),
            "repository_coverage_incomplete": report["coverage"]["incomplete"],
            "excluded_topics": list(catalog["excluded_topics"]),
        },
        "basis": "current_catalog_and_inventory_only",
        "correctness_verified": False,
        "compliance_certified": False,
        "boundary": BOUNDARY,
    }
    _validate_contract(result, "specification-review.schema.json")
    return result
