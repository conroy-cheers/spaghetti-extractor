"""Compare the full retained quoting/free network in a finite service environment.

No Wine or pilot build is involved. The emitted record is diagnostic evidence,
not a contextual proof, checked representation adapter, or activation receipt.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent


def compare(authoring, retained, out, *, compiler, sanitize=False, mutation=None):
    started = time.monotonic()
    out.mkdir(parents=True)
    inputs = {}
    for dirname, count in [('exact', 40), ('rpl-free-exact', 10)]:
        path = retained/dirname
        manifest = json.loads((path/'component-exact-c-slice-v1.json').read_text())
        assert len(manifest['root_unit_ids']) == count
        assert manifest['root_unit_ids'] == manifest['root_context_unit_ids']
        for row in manifest['files']:
            source = path/row['path']
            assert sha256_file(source) == row['sha256'], str(source)
            inputs[str(source)] = row['sha256']
        inputs[str(path/'component-exact-c-slice-v1.json')] = sha256_file(path/'component-exact-c-slice-v1.json')
    child = retained/'rpl-free-authoring'
    child_headers = out/'release-headers'; child_headers.mkdir()
    intent = ComponentInterfaceIntentV1.parse(json.loads((child/'interface/component-interface-intent-v1.json').read_text()))
    for name, text in render_component_c_headers_v5(compile_component_interface_v5(intent), {'release': 'preserve_errno_free'}).items():
        (child_headers/name).write_text(text)
    quote_source = authoring/'source/sources/quote-slots.c'
    if mutation is not None:
        original = quote_source.read_text()
        before, after = {
            'no-elide-nul': ('options->flags | 1U', 'options->flags'),
            'late-size-store': ('slot->size = size;', '/* deliberately delayed until after services */'),
            'skip-clear': ('services->clear_slots(environment, slots, state->count,\n            new_count.value - state->count);',
                           '/* deliberately omitted clearing of new slots */'),
        }[mutation]
        assert original.count(before) == 1
        changed = original.replace(before, after)
        if mutation == 'late-size-store':
            changed = changed.replace('slot->buffer = buffer;', 'slot->buffer = buffer;\n        slot->size = size;')
        quote_source = out/'wrong-quote-slots.c'; quote_source.write_text(changed)
    for directory in (authoring/'headers', child_headers):
        for path in directory.glob('*.h'):
            inputs[str(path)] = sha256_file(path)
    for path in (HERE/'quote-objects.h', HERE/'growth-config.h', Path(__file__).resolve()):
        inputs[str(path)] = sha256_file(path)
    common = ['-std=c11', '-O1', '-Wall', '-Wextra', '-Werror']
    sanitizer = ['-fsanitize=undefined,address', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer'] if sanitize else []
    units = [
        (retained/'exact/behavioral-support.c', [retained/'exact']),
        (retained/'exact/behavioral-fn-00004eb3.c', [retained/'exact']),
        (retained/'rpl-free-exact/behavioral-fn-00001b34.c', [retained/'rpl-free-exact']),
        (quote_source, [authoring/'headers', HERE]),
        (authoring/'headers/component-conformance.c', [authoring/'headers']),
        (child/'preserve-errno-free.c', [child_headers]),
        (child_headers/'component-conformance.c', [child_headers]),
        (HERE/'release-bridge.c', [child_headers]),
        (HERE/'driver.c', [retained/'exact', authoring/'headers', HERE]),
    ]
    phases = [{'phase': 'preparation', 'seconds': time.monotonic()-started}]
    commands, objects = [], []
    for index, (source, includes) in enumerate(units):
        inputs[str(source)] = sha256_file(source)
        obj = out/f'unit-{index}.o'; objects.append(obj)
        command = [compiler, *common, *sanitizer, *[flag for p in includes for flag in ('-I', str(p))],
                   '-c', str(source), '-o', str(obj)]
        start = time.monotonic(); result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        commands.append(command); (out/f'compile-{index}.stderr').write_text(result.stderr)
        phases.append({'phase': 'compiler', 'source': str(source), 'seconds': time.monotonic()-start})
        if result.returncode:
            raise RuntimeError(f'compilation failed: {source}\n{result.stderr}')
    executable = out/'compare'
    command = [compiler, *sanitizer, *map(str, objects), '-o', str(executable)]
    start = time.monotonic(); result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    phases.append({'phase': 'link', 'seconds': time.monotonic()-start}); commands.append(command)
    (out/'link.stderr').write_text(result.stderr)
    if result.returncode: raise RuntimeError(result.stderr)
    start = time.monotonic(); result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
    phases.append({'phase': 'execution', 'seconds': time.monotonic()-start})
    (out/'stdout').write_text(result.stdout); (out/'stderr').write_text(result.stderr)
    record = {'status': 'matched' if result.returncode == 0 else 'mismatch' if result.returncode == 1 else 'fixture-error',
        'exit_code': result.returncode, 'mutation': mutation, 'sanitized': sanitize,
        'result': json.loads(result.stdout) if result.returncode == 0 else None,
        'original_equivalence': 'unverified', 'activation_authorized': False,
        'input_sha256s': inputs, 'commands': commands, 'compiler': compiler,
        'compiler_sha256': sha256_file(Path(compiler)),
        'phases': phases, 'model_generation': 0, 'solver_runs': 0,
        'executable_sha256': sha256_file(executable),
        'unproved': ['Fixture object/byte correspondence and scalar-to-reference release bridge.',
                    'Applicability of controlled allocation, quoting, errno, memory and terminal services.',
                    'Arbitrary aliasing, reentrancy/concurrency, allocation sizes and heap shapes.',
                    'Body-independent composition, native qualification and complete portable coverage.']}
    write_json(out/'validation.json', record)
    print(json.dumps({k: record[k] for k in ('status', 'exit_code', 'result', 'sanitized', 'mutation', 'phases')}), flush=True)
    if result.stderr: print(result.stderr, flush=True)
    return result.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('authoring', type=Path)
    parser.add_argument('retained', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--compiler', default=shutil.which('cc'))
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--mutation', choices=['no-elide-nul', 'late-size-store', 'skip-clear'])
    args = parser.parse_args()
    raise SystemExit(compare(args.authoring.resolve(), args.retained.resolve(), args.output.resolve(),
        compiler=args.compiler, sanitize=args.sanitize, mutation=args.mutation))
