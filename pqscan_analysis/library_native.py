"""libclang index for selected translation units, inside the build container.

Compilation commands are data. Only a small allowlist of parse flags survives;
compiler plugins, response files and arbitrary command strings are never used.
"""
import hashlib
import json
from pathlib import Path
import sys

PREFIXES = ('crypto/ml_kem/', 'crypto/ml_dsa/', 'providers/implementations/kem/ml_kem',
            'providers/implementations/signature/ml_dsa', 'providers/implementations/keymgmt/ml_kem',
            'providers/implementations/keymgmt/ml_dsa', 'crypto/evp/kem.c', 'crypto/evp/m_sigver.c')
MAX_UNITS = 24
MAX_SYMBOLS = 1200
MAX_CALLS = 4000
MAX_SOURCE_CHARS = 24000


def parse_flags(arguments):
    result = ['-I/source/include', '-I/work/build/include', '-I/source', '-I/work/build']
    i = 0
    while i < len(arguments):
        arg = arguments[i]
        if arg in ('-I', '-D', '-U', '-isystem'):
            i += 1
            if i >= len(arguments): raise ValueError('Missing compiler option value')
            value = arguments[i]
            if arg in ('-I', '-isystem'):
                p = str((Path('/work/build') / value).resolve())
                if not p.startswith(('/source/', '/work/build/')) and p not in ('/source', '/work/build'):
                    raise ValueError('Include path outside captured source/build')
                result.append('-I' + p)
            else: result.append(arg + value)
        elif arg.startswith(('-I', '-D', '-U')) and len(arg) > 2:
            result.extend(parse_flags([arg[:2], arg[2:]])[4:])
        elif arg.startswith('-std=') or arg in ('-pthread', '-fPIC', '-fpic', '-fno-common'):
            result.append(arg)
        elif arg.startswith(('-O', '-g', '-W')) or arg in ('-c', '-o', '-MMD', '-MD', '-MP', '-MF', '-MT', '-MQ'):
            # Dependency/output flags do not change the parsed translation unit.
            if arg in ('-o', '-MF', '-MT', '-MQ'):
                i += 1
                if i >= len(arguments): raise ValueError('Missing compiler output option value')
        elif arg.endswith('.c'):
            pass
        else:
            raise ValueError('Unsupported compilation option: ' + arg[:150])
        i += 1
    return result


def build_index(snapshot):
    sys.path.append('/usr/lib/python3/dist-packages')
    from clang import cindex
    cindex.Config.set_library_file('/usr/lib/llvm-14/lib/libclang.so.1')
    index = cindex.Index.create()
    files = {f['path']: f for f in snapshot['files']}
    units, symbols, calls, slices, gaps = [], [], [], [], []
    seen_units, used_chars = set(), 0
    candidates = []
    for p in sorted(Path('/work/commands').glob('*.json')):
        value = json.loads(p.read_text())
        args = value['arguments']
        for arg in args:
            if arg.endswith('.c'):
                source = (Path(value['directory']) / arg).resolve()
                try: rel = source.relative_to('/source').as_posix()
                except ValueError: continue
                if rel.startswith(PREFIXES) and rel in files:
                    candidates.append((rel, args))
    def priority(candidate):
        rel = candidate[0]
        return (0 if rel in ('crypto/ml_kem/ml_kem.c', 'crypto/ml_dsa/ml_dsa_sign.c') else 1, rel)
    for rel, args in sorted(candidates, key=priority):
        if rel in seen_units: continue
        seen_units.add(rel)
        if len(units) >= MAX_UNITS:
            gaps.append({'path': rel, 'reason': 'translation_unit_budget'}); continue
        try:
            flags = parse_flags(args)
            tu = index.parse('/source/' + rel, args=flags, options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
            errors = [str(d)[:500] for d in tu.diagnostics if d.severity >= cindex.Diagnostic.Error]
            if errors:
                gaps.append({'path': rel, 'reason': 'parse_error', 'details': errors[:4]}); continue
        except Exception as exc:
            gaps.append({'path': rel, 'reason': 'unsupported_parse', 'details': [str(exc)[:500]]}); continue
        unit = {'path': rel, 'file_sha256': files[rel]['sha256'], 'arguments': flags,
                'macros_defined': 0, 'macro_expansions': 0}
        units.append(unit)
        raw = Path('/source', rel).read_bytes()
        text = raw.decode('utf-8')
        lines = text.splitlines(keepends=True)
        # Prefer interfaces/verification functions for excerpts; all definitions
        # remain indexed within the symbol budget regardless of snippet selection.
        functions, unit_chars = [], 0
        for cursor in tu.cursor.get_children():
            if not cursor.location.file or cursor.location.file.name != '/source/' + rel: continue
            if cursor.kind == cindex.CursorKind.MACRO_DEFINITION: unit['macros_defined'] += 1
            if cursor.kind == cindex.CursorKind.MACRO_INSTANTIATION: unit['macro_expansions'] += 1
            if cursor.kind == cindex.CursorKind.FUNCTION_DECL and cursor.is_definition(): functions.append(cursor)
        functions.sort(key=lambda c: (not any(w in c.spelling.lower() for w in ('decap', 'verify', 'import', 'parse')), c.location.line))
        for cursor in functions:
            if len(symbols) >= MAX_SYMBOLS:
                gaps.append({'path': rel, 'reason': 'symbol_budget'}); break
            usr = cursor.get_usr()
            sid = hashlib.sha256((rel + ':' + usr).encode()).hexdigest()[:24]
            start, end = cursor.extent.start.line, cursor.extent.end.line
            symbols.append({'id': sid, 'usr': usr, 'name': cursor.spelling, 'path': rel,
                            'start_line': start, 'end_line': end, 'file_sha256': files[rel]['sha256']})
            for child in cursor.walk_preorder():
                if child.kind != cindex.CursorKind.CALL_EXPR: continue
                if len(calls) >= MAX_CALLS: break
                ref = child.referenced
                direct = ref is not None and ref.kind == cindex.CursorKind.FUNCTION_DECL
                calls.append({'caller_id': sid, 'path': rel, 'line': child.location.line,
                              'callee': ref.spelling if ref else child.spelling,
                              'callee_usr': ref.get_usr() if direct else None,
                              'resolution': 'direct_declaration' if direct else 'indirect_unresolved'})
            excerpt, excerpt_end = '', start - 1
            for line_number in range(start, min(end, len(lines)) + 1):
                line = lines[line_number - 1]
                if (len(excerpt) + len(line) > 4000 or unit_chars + len(excerpt) + len(line) > 6000
                        or used_chars + len(excerpt) + len(line) > MAX_SOURCE_CHARS): break
                excerpt += line; excerpt_end = line_number
            if excerpt:
                slices.append({'id': sid + ':slice', 'symbol_id': sid, 'path': rel, 'start_line': start,
                               'end_line': excerpt_end, 'text': excerpt,
                               'sha256': hashlib.sha256(excerpt.encode()).hexdigest(), 'file_sha256': files[rel]['sha256']})
                used_chars += len(excerpt)
                unit_chars += len(excerpt)
            if excerpt_end < end: gaps.append({'path': rel, 'reason': 'excerpt_omitted_or_truncated', 'symbol_id': sid})
    by_usr = {}
    for symbol in symbols: by_usr.setdefault(symbol['usr'], []).append(symbol['id'])
    for call in calls:
        targets = by_usr.get(call.pop('callee_usr'), [])
        call['target_id'] = targets[0] if len(targets) == 1 else None
    return {'parser': 'libclang-14', 'translation_units': units, 'symbols': symbols, 'calls': calls,
            'source_slices': slices, 'source_chars': used_chars, 'coverage': {'partial': True, 'gaps': gaps,
            'selected_prefixes': list(PREFIXES), 'candidate_translation_units': len(seen_units),
            'call_budget_reached': len(calls) >= MAX_CALLS},
            'limitations': ['Only compiled C branches in the portable no-asm configuration are indexed.',
                           'Headers, other translation units, generated code and assembly are outside this source index.',
                           'Function-pointer dispatch is unresolved; direct declarations do not prove runtime reachability.',
                           'This is not dataflow, arithmetic equivalence or constant-time verification.']}
