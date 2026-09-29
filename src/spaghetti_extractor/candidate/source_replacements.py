"""Reversible, file-scoped retirement of explicitly selected ordinary C bodies."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from ..components.source import _build_path
from .source_assembly import definition_span


def _digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def retire_definition(source, symbol):
    """Keep the exact body and its replacement, including private declarations."""
    begin, end = definition_span(source, symbol)
    body = source[begin:end]
    declaration = body[:body.index('{')].strip()
    replacement = '/* '+symbol+' is supplied by the exported component binding. */'
    if re.match(r'static\s', declaration):
        replacement += '\n'+re.sub(r'^static\s+', '', declaration)+';'
    record = dict(symbol=symbol, body=body, body_sha256=_digest(body), replacement=replacement)
    return source[:begin]+replacement+source[end:], record


def reconcile_definitions(backend: Path, records: dict, delta: dict, *, restore_from: Path | None = None):
    """Return proposed backend text and records without changing input files.

    Legacy hash-only records can be restored from an explicit original source
    tree, checked against that hash. Surrounding operator C is never regenerated.
    Unrelated retired definitions (including target-specific partial bodies) stay.
    """
    retained = {}
    for name, value in records.items():
        row = dict(value, symbol=value.get('symbol', name))
        filename = _build_path(row['file'])
        key = filename+':'+row['symbol']
        if key in retained:
            raise ValueError('duplicate retired definition: '+key)
        retained[key] = row
    sources = {}

    def read(filename):
        filename = _build_path(filename)
        path = backend/filename
        if path.is_symlink() or not path.resolve().is_relative_to(backend.resolve()):
            raise ValueError('replacement requires an ordinary backend file: '+filename)
        if filename not in sources:
            sources[filename] = path.read_text()
        return filename, sources[filename]

    for row in delta['restore']:
        filename, source = read(row['file'])
        symbol = row['symbol']; key = filename+':'+symbol
        record = retained.get(key)
        if record is None or record.get('retained'):
            raise ValueError('no reversible retired definition: '+key)
        body = record.get('body')
        if body is None and restore_from is not None:
            original = (restore_from/filename).read_text()
            begin, end = definition_span(original, symbol)
            body = original[begin:end]
        if body is None:
            raise ValueError('legacy retirement retained only a hash for '+key+
                             '; supply --restore-from with the original backend source tree')
        if _digest(body) != record['body_sha256']:
            raise ValueError('retained original body hash mismatch: '+key)
        _, expected = retire_definition(body, symbol)
        replacement = record.get('replacement', expected['replacement'])
        if replacement != expected['replacement'] or source.count(replacement) != 1:
            raise ValueError('retired definition marker/declaration changed; reconcile '+key)
        sources[filename] = source.replace(replacement, body, 1)
        del retained[key]
    for row in delta['retire']:
        filename, source = read(row['file'])
        symbol = row['symbol']; key = filename+':'+symbol
        if key in retained:
            raise ValueError('definition already retired outside the selected owners: '+key)
        sources[filename], record = retire_definition(source, symbol)
        retained[key] = dict(record, file=filename)
    return sources, retained
