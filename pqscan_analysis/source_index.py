"""Bounded Python source evidence. No imports, execution or filesystem traversal
of the target: the scanner passes the exact bytes it has already read.

Resolution is deliberately flow-insensitive. Rebinding, instance dispatch,
star imports and dynamic calls remain unknown. Local edges are candidates, not
proof of runtime reachability. Python root and src/ layouts are supported.
"""

import ast
from collections import defaultdict, deque
import hashlib
import json
from pathlib import PurePosixPath
import re

from .providers import declared_dependencies, provider_boundary

PROFILE = "pqscan-python-source-v1"
DEFAULT_LIMITS = {"max_files": 200, "max_bytes": 2 * 1024 * 1024,
                  "max_ast_nodes": 50000, "max_slices": 24,
                  "max_slice_chars": 4000, "max_source_chars": 24000, "max_hops": 3}
LIMITATIONS = [
    "Local call edges are static candidates, not demonstrated runtime reachability.",
    "Instance dispatch, closures with rebinding, wildcard imports, decorators, metaclasses and runtime import-path changes may be unresolved.",
    "Only Python modules at the repository root and src/ are resolved; other languages remain inventory-only.",
    "External dependencies and native code are not inspected. Provider contracts and installed versions are unverified.",
    "Requirements-file constraints are declarations only; lockfiles and transitive dependencies are not resolved.",
    "File hashes identify bytes read during this scan; the repository snapshot is not atomic and is not a Git commit attestation.",
    "Source excerpts may include literals and comments. They are stored locally and treated as untrusted data. Only explicit --ollama-source review sends excerpts to a local model; --ollama remains metadata-only.",
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest_id(files):
    return digest(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def source_lines(source):
    # Python physical lines do not split on Unicode separators inside strings.
    lines = re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", source)
    return lines[:-1] if lines and lines[-1] == "" else lines


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted(node.value)
        return prefix + "." + node.attr if prefix else ""
    return ""


def module_name(path):
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts and parts[0] == "src":
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


class Scope:
    def __init__(self, symbol, parent=None):
        self.symbol = symbol
        self.parent = parent
        self.bindings = defaultdict(list)
        self.wildcard = False


class Collector:
    def __init__(self, **limits):
        self.limits = dict(DEFAULT_LIMITS)
        if limits.keys() - self.limits.keys():
            raise ValueError("Unknown source review limit")
        for key, value in limits.items():
            if type(value) is not int or not 1 <= value <= DEFAULT_LIMITS[key]:
                raise ValueError("Source review limits must be positive and no larger than defaults")
        self.limits.update(limits)
        self.inputs = {}
        self.files = []
        self.gaps = []
        self.bytes = 0
        self.dependencies = []

    def observe(self, path, raw, source, context):
        """Capture only already-approved scanner input, preserving original bytes."""
        if len(self.files) >= self.limits["max_files"] or self.bytes + len(raw) > self.limits["max_bytes"]:
            self.gaps.append({"path": path, "reason": "snapshot_budget", "detail": "File omitted from source index."})
            return
        python = path.lower().endswith(".py")
        record = {"path": path, "sha256": digest(raw), "bytes": len(raw),
                  "lines": max(1, len(source_lines(source))), "language": "python" if python else "inventory_only"}
        self.files.append(record)
        self.bytes += len(raw)
        self.dependencies.extend(declared_dependencies(path, source))
        self.inputs[path] = (source, context, record)
        if not python:
            self.gaps.append({"path": path, "reason": "inventory_only", "detail": "No semantic analysis for this file type; Python stubs are not executable implementations."})

    def build(self, report):
        graph = Index(self)
        for path, (source, context, record) in sorted(self.inputs.items()):
            if record["language"] != "python":
                continue
            try:
                tree = ast.parse(source, filename=path)
                pending, count, depth_limit = [(tree, 0)], 0, False
                while pending:
                    node, depth = pending.pop()
                    count += 1
                    if depth > 100:
                        depth_limit = True
                        break
                    pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
                if depth_limit:
                    graph.gap(path, "ast_depth", "Python nesting exceeds supported depth.")
                    continue
                if graph.ast_nodes + count > self.limits["max_ast_nodes"]:
                    graph.gap(path, "ast_budget", "Python file omitted from semantic index.")
                    continue
                graph.ast_nodes += count
                graph.add_file(path, tree, context, record)
            except (SyntaxError, ValueError, RecursionError) as exc:
                # Never put exception source text in coverage messages.
                graph.gap(path, "parse_error", type(exc).__name__)
        return graph.finish(report)


class Index(ast.NodeVisitor):
    def __init__(self, collector):
        self.collector = collector
        self.scopes = {}
        self.modules = defaultdict(list)
        self.imports = []
        self.pending_calls = []
        self.ast_nodes = 0
        self.scope = None
        self.path = None
        self.record = None
        self.context = None
        self.conditional = 0

    def gap(self, path, reason, detail):
        self.collector.gaps.append({"path": path, "reason": reason, "detail": detail})

    def new_scope(self, name, kind, node, parent=None):
        line = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", None) or self.record["lines"] or 1
        decorators = getattr(node, "decorator_list", [])
        start = min([line] + [d.lineno for d in decorators])
        qualified = name if parent is None or parent.symbol["kind"] == "module" else parent.symbol["qualified_name"] + "." + name
        sid = f"{self.path}:{line}:{kind}:{qualified}"
        symbol = {"id": sid, "path": self.path, "qualified_name": qualified, "kind": kind,
                  "start_line": start, "end_line": end, "context": self.context,
                  "file_sha256": self.record["sha256"]}
        scope = Scope(symbol, parent)
        self.scopes[sid] = scope
        return scope

    def add_file(self, path, tree, context, record):
        self.path, self.context, self.record = path, context, record
        self.scope = self.new_scope("<module>", "module", tree)
        self.modules[module_name(path)].append(self.scope)
        self.conditional = 0
        self.visit(tree)

    def bind(self, name, binding):
        self.scope.bindings[name].append(("unknown", "conditional binding") if self.conditional else binding)

    def visit_Import(self, node):
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            value = alias.name if alias.asname else bound
            self.bind(bound, ("absolute", value))
            self.imports.append({"scope_id": self.scope.symbol["id"], "path": self.path, "line": node.lineno,
                                 "binding": bound, "target": alias.name})

    def visit_ImportFrom(self, node):
        base = node.module or ""
        if node.level:
            mod = module_name(self.path)
            package = mod if PurePosixPath(self.path).stem == "__init__" else mod.rpartition(".")[0]
            parts = package.split(".") if package else []
            if node.level > len(parts):
                base = ""
                self.gap(self.path, "relative_import", "Relative import escapes the indexed package.")
            else:
                base = ".".join(parts[:len(parts) - node.level + 1] + ([base] if base else []))
        for alias in node.names:
            target = ".".join(filter(None, [base, alias.name]))
            bound = alias.asname or alias.name
            if alias.name == "*":
                self.scope.wildcard = True
                self.gap(self.path, "wildcard_import", "Wildcard bindings are not resolved.")
            else:
                self.bind(bound, ("absolute", target) if base else ("unknown", "unresolved relative import"))
            self.imports.append({"scope_id": self.scope.symbol["id"], "path": self.path, "line": node.lineno,
                                 "binding": bound, "target": target})

    def function(self, node, kind):
        parent = self.scope
        child = self.new_scope(node.name, kind, node, parent)
        self.bind(node.name, ("symbol", child.symbol["id"]))
        # Decorators/defaults execute in the enclosing scope.
        for value in node.decorator_list + node.args.defaults + [v for v in node.args.kw_defaults if v is not None]:
            self.visit(value)
        if node.decorator_list:
            self.gap(self.path, "decorator", "Decorated definition has only a static candidate identity: " + child.symbol["id"])
        self.scope = child
        old_conditional, self.conditional = self.conditional, 0
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        args += [a for a in (node.args.vararg, node.args.kwarg) if a is not None]
        for arg in args:
            self.bind(arg.arg, ("unknown", "parameter or instance dispatch"))
        for statement in node.body:
            self.visit(statement)
        self.scope, self.conditional = parent, old_conditional

    def visit_FunctionDef(self, node):
        self.function(node, "function")

    def visit_AsyncFunctionDef(self, node):
        self.function(node, "async_function")

    def visit_ClassDef(self, node):
        parent = self.scope
        child = self.new_scope(node.name, "class", node, parent)
        self.bind(node.name, ("symbol", child.symbol["id"]))
        for value in node.decorator_list + node.bases + [kw.value for kw in node.keywords]:
            self.visit(value)
        self.scope = child
        for statement in node.body:
            self.visit(statement)
        self.scope = parent
        self.gap(self.path, "class_dispatch", "Descriptors, inheritance and instance dispatch are not resolved.")

    def assignment(self, node, targets, value):
        for target in targets:
            for name in ast.walk(target):
                if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store):
                    expression = dotted(value)
                    binding = ("alias", (self.scope.symbol["id"], expression)) if expression and isinstance(target, ast.Name) else ("unknown", "assigned or unpacked value")
                    self.bind(name.id, binding)
            if isinstance(target, ast.Attribute) and dotted(target):
                self.scope.bindings[dotted(target).split(".")[0]].append(("unknown", "attribute mutation"))
                self.gap(self.path, "attribute_mutation", "Attribute assignment can change dispatch.")
        if value is not None:
            self.visit(value)

    def visit_Assign(self, node):
        self.assignment(node, node.targets, node.value)

    def visit_AnnAssign(self, node):
        self.assignment(node, [node.target], node.value)

    def visit_NamedExpr(self, node):
        self.assignment(node, [node.target], node.value)

    def visit_AugAssign(self, node):
        self.assignment(node, [node.target], None)

    def visit_Name(self, node):
        # Loop, comprehension, with-as and other stores conservatively invalidate
        # a binding. Assignment targets are handled separately by assignment().
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.scope.bindings[node.id].append(("unknown", "additional binding"))

    def visit_Global(self, node):
        for name in node.names:
            self.scope.bindings[name].append(("unknown", "global/nonlocal mutation"))
        self.gap(self.path, "scope_mutation", "Global/nonlocal declarations require manual review.")

    visit_Nonlocal = visit_Global

    def visit_Lambda(self, node):
        self.gap(self.path, "lambda", "Lambda bodies and invocation are not resolved.")
        # Do not attribute deferred lambda calls to the enclosing function.

    def visit_ExceptHandler(self, node):
        if node.name:
            self.scope.bindings[node.name].append(("unknown", "exception binding"))
        self.generic_visit(node)

    def conditional_block(self, node):
        self.conditional += 1
        self.generic_visit(node)
        self.conditional -= 1

    visit_If = conditional_block
    visit_Try = conditional_block
    visit_For = conditional_block
    visit_AsyncFor = conditional_block
    visit_While = conditional_block
    visit_With = conditional_block
    visit_AsyncWith = conditional_block
    visit_Match = conditional_block

    def visit_Call(self, node):
        self.pending_calls.append((self.scope, node))
        self.generic_visit(node)

    def resolve(self, scope, expression, seen=frozenset()):
        if not expression:
            return "unresolved", None, "", "dynamic call expression"
        key = (scope.symbol["id"], expression)
        if key in seen or len(seen) >= 30:
            return "unresolved", None, expression, "alias cycle or resolution limit"
        seen = seen | {key}
        head, _, tail = expression.partition(".")
        if scope.wildcard:
            return "unresolved", None, expression, "wildcard import can change bindings"
        values = scope.bindings.get(head, [])
        if len(values) > 1:
            return "unresolved", None, expression, "shadowed or multiply assigned binding"
        if not values:
            parent = scope.parent
            # Class namespaces are not lexical parents of function bodies.
            if parent and parent.symbol["kind"] == "class":
                parent = parent.parent
            if parent:
                return self.resolve(parent, expression, seen)
            return "unresolved", None, expression, "name not bound in indexed scopes"
        kind, value = values[0]
        if kind == "unknown":
            return "unresolved", None, expression, value
        if kind == "alias":
            owner, target = value
            return self.resolve(self.scopes[owner], target + ("." + tail if tail else ""), seen)
        if kind == "symbol":
            if tail:
                target = self.scopes[value]
                if target.symbol["kind"] == "class":
                    return "unresolved", None, expression, "class/descriptor dispatch"
                return "unresolved", None, expression, "attribute of a local callable"
            return "local_candidate", value, expression, "lexical binding only; execution not established"
        absolute = value + ("." + tail if tail else "")
        # Find the longest indexed module prefix, then follow re-exports.
        parts = absolute.split(".")
        for end in range(len(parts), 0, -1):
            module = ".".join(parts[:end])
            matches = self.modules.get(module, [])
            if len(matches) > 1:
                return "unresolved", None, absolute, "ambiguous root/src module or duplicate module"
            if matches:
                remaining = ".".join(parts[end:])
                if not remaining:
                    return "unresolved", None, absolute, "module object is not a resolved callable"
                # A missing local member is unknown, never a guessed external API.
                return self.resolve(matches[0], remaining, seen)
        return "external_boundary", None, absolute, "dependency source not indexed; implementation and native code unverified"

    def finish(self, report):
        calls = []
        for sequence, (scope, node) in enumerate(self.pending_calls):
            expression = dotted(node.func)
            resolution, target, name, reason = self.resolve(scope, expression)
            path = scope.symbol["path"]
            source = source_lines(self.collector.inputs[path][0])
            # AST columns are UTF-8 byte offsets, not Unicode code-point offsets.
            line = source[node.lineno - 1]
            column = len(line.encode("utf-8")[:node.col_offset].decode("utf-8")) + 1
            end_line = node.end_lineno
            end_column = len(source[end_line - 1].encode("utf-8")[:node.end_col_offset].decode("utf-8")) + 1
            cid = f"{path}:{node.lineno}:{column}:call:{sequence}"
            calls.append({"id": cid, "caller_id": scope.symbol["id"], "path": path, "line": node.lineno,
                          "column": column, "end_line": end_line, "end_column": end_column,
                          "expression": expression or "<dynamic>", "resolved_name": name,
                          "resolution": resolution, "target_id": target, "reason": reason,
                          "provider": provider_boundary(name) if resolution == "external_boundary" else None})
        calls.sort(key=lambda c: (c["path"], c["line"], c["column"], c["caller_id"]))
        slices, selection = self.select_slices(report, calls)
        files = sorted(self.collector.files, key=lambda f: f["path"])
        local_targets = {c["target_id"] for c in calls if c["target_id"]}
        entrypoints = [s.symbol["id"] for s in self.scopes.values() if s.symbol["kind"] == "module" or (s.symbol["kind"] in {"function", "async_function"} and s.symbol["id"] not in local_targets)]
        gaps = sorted(self.collector.gaps, key=lambda g: (g["path"], g["reason"], g["detail"]))
        return {"schema_version": "1.0", "profile": PROFILE, "status": "collected", "origin": "live_scan",
                "snapshot": {"id": manifest_id(files), "atomic": False, "files": files},
                "symbols": [s.symbol for _, s in sorted(self.scopes.items())],
                "imports": sorted(self.imports, key=lambda i: (i["path"], i["line"], i["binding"])),
                "calls": calls, "potential_entrypoints": sorted(entrypoints),
                "dependencies": self.collector.dependencies, "source_slices": slices,
                "coverage": {"partial": True, "files_indexed": len(files), "ast_nodes": self.ast_nodes,
                             "unresolved_calls": sum(c["resolution"] == "unresolved" for c in calls),
                             "external_boundaries": sum(c["resolution"] == "external_boundary" for c in calls),
                             "gaps": gaps, "scanner_skipped": report["coverage"]["skipped"],
                             "scanner_warnings": report["coverage"]["warnings"], "scanner_errors": report["coverage"]["errors"],
                             **selection},
                "limits": dict(self.collector.limits), "limitations": list(LIMITATIONS),
                "evidence_policy": "Exact bounded source excerpts stored locally; --ollama remains metadata-only. Explicit --ollama-source opts in to local source model review.",
                "correctness_verified": False, "compliance_certified": False}

    def select_slices(self, report, calls):
        reasons, finding_ids = defaultdict(set), defaultdict(set)
        for finding in report["findings"]:
            candidates = [s.symbol for s in self.scopes.values() if s.symbol["path"] == finding["path"] and s.symbol["start_line"] <= finding["line"] <= s.symbol["end_line"]]
            if candidates:
                symbol = min(candidates, key=lambda s: s["end_line"] - s["start_line"])
                reasons[symbol["id"]].add("inventory_finding")
                finding_ids[symbol["id"]].add(finding["finding_id"])
        neighbors = defaultdict(set)
        for call in calls:
            if call["provider"]:
                reasons[call["caller_id"]].add("provider_boundary")
            if call["target_id"]:
                neighbors[call["caller_id"]].add(call["target_id"])
                neighbors[call["target_id"]].add(call["caller_id"])
        seeds = sorted(reasons)
        queue = deque((sid, 0) for sid in seeds)
        visited = set(seeds)
        while queue:
            sid, depth = queue.popleft()
            if depth >= self.collector.limits["max_hops"]:
                continue
            for other in sorted(neighbors[sid]):
                reasons[other].add("caller_or_callee")
                if other not in visited:
                    visited.add(other)
                    queue.append((other, depth + 1))
        # Independently index all functions/calls, including paths with no regex
        # finding. Include additional boundary/entry context when space permits.
        incoming = {c["target_id"] for c in calls if c["target_id"]}
        for sid, scope in self.scopes.items():
            if scope.symbol["kind"] == "module" or (sid not in incoming and scope.symbol["kind"] != "class"):
                reasons[sid].add("potential_entrypoint")
        ranked = sorted(reasons, key=lambda sid: (not bool(reasons[sid] & {"inventory_finding", "provider_boundary"}), "caller_or_callee" not in reasons[sid], self.scopes[sid].symbol["context"] != "production", sid))
        slices, omitted, total = [], [], 0
        for sid in ranked:
            symbol = self.scopes[sid].symbol
            lines = source_lines(self.collector.inputs[symbol["path"]][0])
            start, end = symbol["start_line"], symbol["end_line"]
            remaining = min(self.collector.limits["max_slice_chars"], self.collector.limits["max_source_chars"] - total)
            selected = []
            for line in lines[start - 1:end]:
                if len(line) > remaining:
                    break
                selected.append(line)
                remaining -= len(line)
            if len(slices) >= self.collector.limits["max_slices"] or not selected:
                omitted.append({"symbol_id": sid, "reason": "slice_budget", "omitted_lines": end - start + 1})
                continue
            text = "".join(selected)
            stop = start + len(selected) - 1
            slices.append({"id": f"{sid}:slice:{start}-{stop}", "symbol_id": sid, "path": symbol["path"],
                           "start_line": start, "end_line": stop, "text": text, "sha256": digest(text.encode("utf-8")),
                           "file_sha256": symbol["file_sha256"], "selection_reasons": sorted(reasons[sid]),
                           "finding_ids": sorted(finding_ids[sid])})
            total += len(text)
            if stop < end:
                omitted.append({"symbol_id": sid, "reason": "slice_truncated", "omitted_lines": end - stop})
        return slices, {"source_chars": total, "slices_selected": len(slices), "slices_omitted_or_truncated": omitted,
                        "symbols_outside_selection": len(set(self.scopes) - set(reasons))}


def validate_source_review(review, findings):
    """Validate saved evidence internally; never authenticate it or reread paths."""
    from .requirements import _validate_contract
    _validate_contract(review, "source-review.schema.json")
    limits = review["limits"]
    if any(not 1 <= limits[k] <= DEFAULT_LIMITS[k] for k in DEFAULT_LIMITS):
        raise ValueError("Source review exceeds supported limits")

    def indexed(items, key, label):
        result = {item[key]: item for item in items}
        if len(result) != len(items):
            raise ValueError("Duplicate source review " + label)
        return result

    files = indexed(review["snapshot"]["files"], "path", "file path")
    symbols = indexed(review["symbols"], "id", "symbol ID")
    calls = indexed(review["calls"], "id", "call ID")
    slices = indexed(review["source_slices"], "id", "slice ID")
    for path in files:
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts or str(pure) != path:
            raise ValueError("Invalid source review relative path")
    if (len(files) > limits["max_files"] or sum(f["bytes"] for f in files.values()) > limits["max_bytes"]
            or review["coverage"]["ast_nodes"] > limits["max_ast_nodes"]
            or review["snapshot"]["id"] != manifest_id(review["snapshot"]["files"])):
        raise ValueError("Invalid source snapshot manifest or budget")
    for symbol in symbols.values():
        file = files.get(symbol["path"])
        if not file or not 1 <= symbol["start_line"] <= symbol["end_line"] <= file["lines"] or symbol["file_sha256"] != file["sha256"]:
            raise ValueError("Source symbol has invalid location or file hash")
    for call in calls.values():
        caller = symbols.get(call["caller_id"])
        if (not caller or caller["path"] != call["path"]
                or not caller["start_line"] <= call["line"] <= call["end_line"] <= caller["end_line"]
                or (call["line"] == call["end_line"] and call["end_column"] <= call["column"])):
            raise ValueError("Source call has invalid location")
        if (call["resolution"] == "local_candidate") != (call["target_id"] in symbols):
            raise ValueError("Source call has invalid local target")
        if call["resolution"] != "local_candidate" and call["target_id"] is not None:
            raise ValueError("Unresolved source call cannot have a local target")
        if call["provider"] != (provider_boundary(call["resolved_name"]) if call["resolution"] == "external_boundary" else None):
            raise ValueError("Invalid source provider boundary")
    for item in review["imports"]:
        scope = symbols.get(item["scope_id"])
        if not scope or scope["path"] != item["path"] or not scope["start_line"] <= item["line"] <= scope["end_line"]:
            raise ValueError("Invalid source import location")
    for item in review["dependencies"]:
        if item["path"] not in files or not 1 <= item["line"] <= files[item["path"]]["lines"]:
            raise ValueError("Invalid dependency declaration location")
    if any(sid not in symbols for sid in review["potential_entrypoints"]):
        raise ValueError("Unknown potential entrypoint")
    by_finding = {f["finding_id"]: f for f in findings}
    for item in slices.values():
        symbol = symbols.get(item["symbol_id"])
        if (not symbol or symbol["path"] != item["path"] or item["file_sha256"] != symbol["file_sha256"]
                or not symbol["start_line"] <= item["start_line"] <= item["end_line"] <= symbol["end_line"]
                or len(source_lines(item["text"])) != item["end_line"] - item["start_line"] + 1
                or item["sha256"] != digest(item["text"].encode("utf-8"))):
            raise ValueError("Invalid source slice location or hash")
        if len(item["text"]) > limits["max_slice_chars"]:
            raise ValueError("Source slice exceeds character budget")
        for fid in item["finding_ids"]:
            f = by_finding.get(fid)
            # Finding can be outside a truncated excerpt but must be within its
            # full symbol. Consumers must inspect the recorded omission metadata.
            if not f or f["path"] != item["path"] or not symbol["start_line"] <= f["line"] <= symbol["end_line"]:
                raise ValueError("Source slice cites an unknown or unrelated finding")
    total_chars = sum(len(s["text"]) for s in slices.values())
    coverage = review["coverage"]
    if (len(slices) > limits["max_slices"] or total_chars > limits["max_source_chars"]
            or coverage["source_chars"] != total_chars or coverage["slices_selected"] != len(slices)
            or coverage["files_indexed"] != len(files)
            or coverage["unresolved_calls"] != sum(c["resolution"] == "unresolved" for c in calls.values())
            or coverage["external_boundaries"] != sum(c["resolution"] == "external_boundary" for c in calls.values())):
        raise ValueError("Inconsistent source review coverage")
    for omission in coverage["slices_omitted_or_truncated"]:
        if omission["symbol_id"] not in symbols:
            raise ValueError("Source omission references unknown symbol")
    return review


def build_source_evidence(report):
    """Validated local evidence bundle; this helper never invokes a model."""
    from copy import deepcopy
    if "source_review" not in report:
        return None
    review = validate_source_review(report["source_review"], report["findings"])
    return deepcopy({key: review[key] for key in (
        "profile", "origin", "snapshot", "source_slices", "symbols", "calls", "imports",
        "dependencies", "coverage", "limits", "limitations", "evidence_policy")})
