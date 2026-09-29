"""Run the public edit, native consumer, discrepancy, replay and reuse loop."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import write_json


def run(packages, output):
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run inside spaghetti-headless-wayland')
    output.mkdir(parents=True, exist_ok=False)
    commands = []; results = {}

    def command(name, args, expected=0):
        args = list(map(str, args)); started = time.monotonic()
        ran = subprocess.run([sys.executable, '-m', 'spaghetti_extractor', *args],
            capture_output=True, text=True, timeout=180)
        (output/(name+'.stdout')).write_text(ran.stdout)
        (output/(name+'.stderr')).write_text(ran.stderr)
        commands.append(dict(name=name, arguments=args, exit_code=ran.returncode, seconds=time.monotonic()-started))
        write_json(output/'commands.json', commands)
        print(name, ran.returncode, round(commands[-1]['seconds'], 3), flush=True)
        if ran.returncode != expected: raise RuntimeError('inspect '+str(output/(name+'.stdout')))
        return ran.stdout

    def check(unit, name, previous=None, supplier=None, case=None, expected=0):
        args = ['component', 'check', 'dxball', 'cleanup-'+unit, '--comparison-package', output/unit,
                '--output', output/name]
        if previous: args += ['--reuse-comparison', output/previous]
        if supplier: args += ['--dependency-source', 'cleanup-dispose='+str(output/'dispose')]
        if case: args += ['--case', case]
        stdout = command(name, args, expected)
        result = load_comparison_result(output/name)
        phases = {}
        for row in result['timings']: phases[row['phase']] = phases.get(row['phase'], 0) + row['seconds']
        results[name] = dict(status=result['status'], work_counts=result['work_counts'],
            cases=len(result['cases']), timings=phases, receipt_sha256=result['receipt_sha256'])
        write_json(output/'results.json', results)
        return result, stdout

    for unit in ('select', 'dispose', 'clear'):
        command(unit+'-start', ['component', 'start', 'dxball', 'cleanup-'+unit,
            '--comparison-package', packages/('cleanup-'+unit), '--output', output/unit])
        check(unit, unit+'-baseline')
    # Export a baseline before the local edit; candidate apply updates this same
    # standalone source project after a matching consumer comparison.
    command('export-baseline', ['candidate', 'export', 'dxball', '--comparison', output/'clear-baseline',
        '--output', output/'program/lifted'])
    edit_started = time.monotonic()
    path = output/'dispose/source/dispose.c'; initial = path.read_text()
    # An implementation-only refactor under the established boundary.
    declaration = ('struct spx_opaque_cleanup_sprite_v5 *sprite =\n'
                   '        state->banks[state->current_bank].slots[slot];')
    assert initial.count(declaration) == 1
    revised = initial.replace(declaration,
        'struct cleanup_bank *initial_bank = &state->banks[state->current_bank];\n'
        '    struct spx_opaque_cleanup_sprite_v5 *sprite = initial_bank->slots[slot];')
    path.write_text(revised)
    local, _ = check('dispose', 'dispose-edited', 'dispose-baseline')
    assert local['work_counts']['compiler'] == 1
    neighbor, _ = check('select', 'select-reused', 'select-baseline')
    assert not any(neighbor['work_counts'].values())
    consumer, _ = check('clear', 'clear-edited', 'clear-baseline', supplier=True)
    assert consumer['work_counts']['compiler'] == 1
    write_json(output/'local-edit.json', dict(seconds=time.monotonic()-edit_started,
        boundary_changed=False, neighboring_local_evidence_reused=True, consumer_reran=True))

    # Deliberate plausible defect, clearly separated from the recovered code:
    # cache the sprite across release, losing the binary's post-service reload.
    wrong = revised.replace('state->banks[state->current_bank].slots[slot]->surface = 0;', 'sprite->surface = 0;')
    assert wrong != revised
    path.write_text(wrong)
    try:
        failed, stdout = check('dispose', 'dispose-wrong', 'dispose-edited', case='direct-kind-5', expected=2)
    finally:
        path.write_text(revised)
    assert failed['status'] == 'mismatch'
    replay = next(line.strip()[len('replay: '):] for line in stdout.splitlines() if line.strip().startswith('replay: '))
    command('replay', shlex.split(replay)[1:], expected=2)
    replayed = load_comparison_result(output/'dispose-wrong-replay')
    assert replayed['cases'][0]['first_difference'] == failed['cases'][0]['first_difference']
    repaired, _ = check('dispose', 'dispose-repaired', 'dispose-edited')
    assert not any(repaired['work_counts'].values())
    command('boundary-status', ['component', 'status', 'dxball', 'cleanup-dispose',
        '--comparison-package', output/'clear-edited/inputs'])
    write_json(output/'workflow.json', dict(status='complete', original_source_consulted=False,
        deliberate_defect=failed['cases'][0]['first_difference'],
        retained_replay=True, local_edit=json.loads((output/'local-edit.json').read_text()),
        per_component_tool_internal_changes=False, strong_qualification=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packages', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args(); run(args.packages.resolve(), args.output.resolve())
