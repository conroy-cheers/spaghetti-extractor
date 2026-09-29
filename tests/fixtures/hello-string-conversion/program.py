"""Ordinary target assembly adapter: add the checked string component to Hello.

Uses the existing program experiment, comparison readers, checked objects and PE
import helper. This is explicitly experimental; it does not alter admission.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import time

from spaghetti_extractor.components.comparison_build import observed_command
from spaghetti_extractor.components.comparison_package import copy_comparison, load_comparison_package, package_file
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.components.comparison_pe32_program import add_experimental_import

HERE = Path(__file__).resolve().parent


def helper(name):
    spec = importlib.util.spec_from_file_location('hello_program_'+name, HERE.parent/'hello-program'/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def prepare(connected, comparison, output, diagnostic=False):
    started = time.monotonic()
    result = load_comparison_result(comparison)
    if result['component_id'] != 'string-conversion' or result['target_id'] != 'gnu-hello':
        raise ValueError('requires the reviewed string component')
    if result['status'] != 'match' and not (diagnostic and result['status'] == 'mismatch'):
        raise ValueError('requires a match or explicit diagnostic mismatch')
    helper('prepare').prepare(connected, output, diagnostic=diagnostic)
    copy_comparison(comparison, output/'string-comparison')
    retained = output/'string-comparison'
    plan, _ = load_comparison_package(retained/'inputs')
    compilation = json.loads((retained/'build/compilation.json').read_text())
    selected = [row for row in compilation['units'] if row['source'] in ('source/string.c', 'adapters/bridge.c')]
    if {row['source'] for row in selected} != {'source/string.c', 'adapters/bridge.c'}:
        raise ValueError('missing reviewed component objects')
    objects = [package_file(retained/'build', row['object']) for row in selected]
    library = output/'runtime/hello-string.dll'
    timings = []
    linked = observed_command([plan['tools']['compiler']['path'], '-shared', *map(str, objects), '-o', str(library)],
        cwd=output, env=dict(os.environ), timeout=60, output=output/'string-link', phase='link', timings=timings)
    if linked['returncode'] or linked['timed_out']: raise ValueError('string DLL link failed; inspect string-link.stderr')
    for side in ('original', 'source'):
        directory = output/'runtime'/side
        shutil.copyfile(library, directory/library.name)
        # Keep the earlier import adapter as an exact retained input. The helper
        # preserves all its existing sections and the original entry/TLS data.
        previous = output/(side+'-before-string.exe')
        shutil.copyfile(directory/'hello.exe', previous)
        add_experimental_import(previous, library, 'spx_hello_string_anchor', directory/'hello.exe')
    description = json.loads((output/'program.json').read_text())
    description['source_selection'].append('string-conversion')
    description['objects'].update({str(p.relative_to(output)): sha256_file(p) for p in objects})
    description['runtime_files'] = {str(p.relative_to(output)): sha256_file(p) for p in (output/'runtime').rglob('*') if p.is_file()}
    description['string_comparison_receipt_sha256'] = result['receipt_sha256']
    description['string_comparison_status'] = result['status']
    description['string_preparation_seconds'] = time.monotonic()-started
    description['string_link_timings'] = timings
    write_json(output/'program.json', description)


def run(bundle, output, case=None):
    description = json.loads((bundle/'program.json').read_text())
    result = load_comparison_result(bundle/'string-comparison')
    if result['receipt_sha256'] != description['string_comparison_receipt_sha256']:
        raise ValueError('string comparison changed')
    status = helper('run').run(bundle, output, case)
    program = json.loads((output/'program-run.json').read_text())
    observations = []
    for row in program['cases']:
        states = {side: json.loads((output/(row['id']+'-'+side+'.state.json.string')).read_text())
                  for side in ('original', 'source')}
        if states['original']['source'] or not states['source']['source'] or states['original']['calls']:
            raise ValueError('incorrect string selection observation')
        expected = 1 if row['id'] in ('default', 'traditional', 'custom', 'empty', 'accent', 'quoted', 'long') else 0
        if states['source']['calls'] != expected: raise ValueError('string operation did not execute as expected')
        differences = [] if states['original']['implicit'] == states['source']['implicit'] else ['implicit']
        if differences: status = 'mismatch'
        observations.append(dict(id=row['id'], states=states, differences=differences))
    write_json(output/'string-program-run.json', dict(status=status, observations=observations,
        program_run_sha256=sha256_file(output/'program-run.json'), producer_sha256=sha256_file(Path(__file__)),
        string_comparison_receipt_sha256=result['receipt_sha256'], strong_qualification=False))
    return status


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare')
    for name in ('connected', 'comparison', 'output'): p.add_argument(name, type=Path)
    p.add_argument('--diagnostic', action='store_true')
    p = commands.add_parser('run')
    for name in ('bundle', 'output'): p.add_argument(name, type=Path)
    p.add_argument('--case')
    args = parser.parse_args()
    if args.command == 'prepare': prepare(args.connected.resolve(), args.comparison.resolve(), args.output.resolve(), args.diagnostic)
    else: raise SystemExit(0 if run(args.bundle.resolve(), args.output.resolve(), args.case) == 'match' else 1)
