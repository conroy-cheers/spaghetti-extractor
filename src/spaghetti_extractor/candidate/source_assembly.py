"""Explicit portable entry adapters shared by source assembly recipes.

Entries, replacement definitions and context lifetime are operator choices.
Comparison bindings are examples only; no ABI or lifecycle equivalence is inferred.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil

from ..components.source import _build_path


def _symbol(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
        raise ValueError('assembly entry requires a C symbol')
    return name


def assembly_binding(value, *, base: Path, operations=None):
    """Resolve ordinary adapter files independently of any comparison harness."""
    fields = {'entries', 'sources', 'headers', 'replacements', 'lifetime'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('assembly requires entries, sources, headers, replacements and lifetime')
    if not isinstance(value['entries'], dict) or not value['entries']:
        raise ValueError('assembly requires explicit native entry mappings')
    entries = {}
    for name, selected in value['entries'].items():
        _symbol(name)
        if (not isinstance(selected, list) or not selected or len(set(selected)) != len(selected)
                or any(not isinstance(op, str) or (operations is not None and op not in operations) for op in selected)):
            raise ValueError('assembly entry names an absent or repeated operation: '+name)
        entries[name] = list(selected)
    files = {}
    for field, suffix in [('sources', '.c'), ('headers', '.h')]:
        if not isinstance(value[field], dict) or (field == 'sources' and not value[field]):
            raise ValueError('assembly requires explicit C source/header mappings')
        files[field] = {}
        for name, path in value[field].items():
            if _build_path(name) != name or not name.endswith(suffix):
                raise ValueError('invalid assembly file: '+str(name))
            resolved = (base/path).resolve()
            if not resolved.is_file():
                raise ValueError('missing assembly file: '+str(resolved))
            files[field][name] = resolved
    replacements = value['replacements']
    if not isinstance(replacements, list):
        raise ValueError('assembly replacements must be a list')
    seen = set()
    for row in replacements:
        if not isinstance(row, dict) or set(row) != {'file', 'symbol'} or _build_path(row['file']) != row['file']:
            raise ValueError('assembly replacement requires a file and symbol')
        _symbol(row['symbol'])
        key = (row['file'], row['symbol'])
        if key in seen:
            raise ValueError('duplicate assembly replacement: '+str(key))
        seen.add(key)
    if not isinstance(value['lifetime'], str) or not value['lifetime'].strip():
        raise ValueError('assembly requires an explicit context/lifetime description')
    return dict(value, **files, entries=entries)


def retain_assembly_binding(binding, directory):
    """Make bindings reopenable in the delivered project, including local refresh."""
    return {**binding, **{field:{name:(Path(directory)/name).as_posix() for name in binding[field]}
                         for field in ('sources', 'headers')}}


def write_assembly_binding(binding, directory: Path):
    """Copy the reviewed adapter closure; caller's normal build compiles every C TU."""
    for field in ('sources', 'headers'):
        for name, origin in binding[field].items():
            destination = directory/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if origin.resolve() != destination.resolve():
                shutil.copyfile(origin, destination)
    return sorted(binding['sources'])


def check_native_entries(entries: dict, defined_symbols: list[str]):
    """Require each declared entry exactly once, including uncalled aliases."""
    owners = {}
    for component, symbols in entries.items():
        for symbol in [symbols] if isinstance(symbols, str) else symbols:
            _symbol(symbol)
            if symbol in owners:
                raise ValueError('multiple components provide native entry: '+symbol)
            owners[symbol] = component
            if defined_symbols.count(symbol) != 1:
                raise ValueError('selected native entry is missing or repeated: '+symbol)
    return owners


def assembly_delta(previous_entries, entries, previous_replacements, replacements):
    """Reconcile entry providers separately from retired backend definitions.

    Replacement maps contain component -> [{file, symbol}]. Several components
    may share a retired helper; its body returns only after the last owner leaves.
    This plans source assembly, never contract compatibility or qualification.
    """
    def providers(mapping):
        symbols = [symbol for values in mapping.values()
                   for symbol in ([values] if isinstance(values, str) else values)]
        return check_native_entries(mapping, sorted(set(symbols)))

    def bodies(mapping):
        result = {}
        for component, rows in mapping.items():
            seen = set()
            for row in rows:
                filename, symbol = _build_path(row['file']), _symbol(row['symbol'])
                key = (filename, symbol)
                if key in seen:
                    raise ValueError('duplicate replacement in '+component+': '+str(key))
                seen.add(key)
                result.setdefault(key, []).append(component)
        return result

    old, new = providers(previous_entries), providers(entries)
    old_bodies, new_bodies = bodies(previous_replacements), bodies(replacements)
    def rows(keys):
        return [dict(file=filename, symbol=symbol) for filename, symbol in sorted(keys)]
    return dict(
        added_components=sorted(entries.keys()-previous_entries.keys()),
        removed_components=sorted(previous_entries.keys()-entries.keys()),
        added_entries={name:new[name] for name in sorted(new.keys()-old.keys())},
        removed_entries={name:old[name] for name in sorted(old.keys()-new.keys())},
        moved_entries={name:dict(previous=old[name], desired=new[name])
                       for name in sorted(old.keys() & new.keys()) if old[name] != new[name]},
        retire=rows(new_bodies.keys()-old_bodies.keys()),
        restore=rows(old_bodies.keys()-new_bodies.keys()),
        retained_replacements=rows(old_bodies.keys() & new_bodies.keys()))


def definition_span(source, name):
    """Locate one explicitly named ordinary definition in reviewed backend C.

    This scans boundaries only; the C compiler remains responsible for types.
    Ambiguous, macro-generated and unsupported definitions require a source adapter.
    """
    _symbol(name)
    matches = list(re.finditer(r'^[A-Za-z_][A-Za-z0-9_ \t\n*]*\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{', source, re.M))
    if len(matches) != 1:
        raise ValueError('expected one reviewed C definition: '+name)
    begin, brace = matches[0].start(), matches[0].end()-1
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', source[brace:], re.S):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if depth == 0:
                return begin, brace+token.end()
    raise ValueError('unterminated reviewed C definition: '+name)
