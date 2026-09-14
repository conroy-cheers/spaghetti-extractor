"""Compile exact ordinary source and inventoried proof marks in a bound workspace."""

import hashlib
import json
from pathlib import Path
import re
import shlex

from ..transfer.runtime_abi import exact_runtime_header
from .inductive_refinement import _write_cbmc_stdint
from .source_profile import _strip_comments_and_literals


def _require(condition, detail):
    if not condition:
        raise ValueError('source inventory: ' + detail)


def compile_source_inventory(*, package, source, headers, root, function, goto_cc,
                             goto_instrument, run, transform=None):
    """The caller retains and binds compiler logs; no proof is authorized here."""
    root.mkdir()
    include, inputs = root / 'include', root / 'inputs'
    include.mkdir()
    inputs.mkdir()
    _write_cbmc_stdint(include / 'stdint.h')
    (include / 'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
    (include / 'state-machine-runtime.h').write_text(exact_runtime_header())
    for name, contents in headers.items():
        (include / name).write_text(contents)
    rows = [*source['files'], *source['shared_inputs']]
    _require(all(v['path'].endswith(('.c', '.h')) for v in rows), 'unsupported source input')
    _require(not any(v['path'] in headers for v in source['files']), 'authored source shadows a generated header')
    for row in rows:
        content = (package / 'sources' / row['path']).read_bytes()
        _require(hashlib.sha256(content).hexdigest() == row['sha256'], 'source bytes changed during preparation')
        text = content.decode('utf-8')
        _require(not re.search(r'\b__(?:FILE|LINE|BASE_FILE|FILE_NAME|INCLUDE_LEVEL|DATE|TIME|TIMESTAMP|COUNTER)__\b',
                               _strip_comments_and_literals(text)),
                 'location or environment macro requires separate source-path correspondence')
        if row in source['shared_inputs']:
            _require(row['path'] in headers and headers[row['path']] == text,
                     'shared input differs from the generated interface')
        if transform is not None:
            text = transform(row['path'], text)
        destination = inputs / row['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    files = ['inputs/' + v['path'] for v in source['files'] if v['path'].endswith('.c')]
    prefix = [str(goto_cc), '--i386-win32', '-nostdinc', '-I', 'include', '-I', 'inputs']
    allowed = {v.resolve() for v in include.iterdir()} | {(inputs / v['path']).resolve() for v in rows}
    for i, file in enumerate(files):
        dependencies = run([*prefix, '-M', '-MT', 'spx_edit_dependencies', file], root, 'dependencies-' + str(i)).replace('\\\n', ' ').strip()
        _require(dependencies.startswith('spx_edit_dependencies:'), 'malformed include inventory')
        paths = set()
        for name in shlex.split(dependencies.removeprefix('spx_edit_dependencies:')):
            # Compiler paths are rooted in the existing virtual workspace.
            path = Path(name)
            if path.is_absolute():
                _require(path.is_relative_to('/tmp/spx-proof'), 'include escapes the virtual workspace')
                path = path.relative_to('/tmp/spx-proof')
            paths.add((root / path).resolve())
        _require((root / file).resolve() in paths and paths <= allowed, 'unbound source include')
    command = [*prefix, *files, '--function', function, '-o', 'model.goto']
    run(command, root, 'compile')
    inventory = {}
    for key, field, flag in [('functions', 'functions', '--show-goto-functions'), ('symbols', 'symbolTable', '--show-symbol-table')]:
        data = json.loads(run([str(goto_instrument), flag, '--json-ui', 'model.goto'], root, key, 'model'))
        records = [v[field] for v in data if field in v]
        _require(len(records) == 1, 'ambiguous compiled inventory')
        inventory[key] = {v['name']: v for v in records[0]} if key == 'functions' else records[0]
    return inventory, command
