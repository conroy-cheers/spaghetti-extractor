"""Edit/replay/reuse through actual native fatal diagnostics and child termination.

Prepare the native package with --terminal-failures. Supply local neighbor
comparisons using the same ID=PATH spelling as candidate build. All Wine execution
runs in one headless Wayland session; this recipe never rebuilds a target pilot.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.formats import EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT
from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.comparison_representation import representation_policy
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.util import sha256_file, write_json

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native_package', 'checked_package', 'output'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--component-comparison', action='append', default=[], metavar='ID=PATH')
    args = parser.parse_args()
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run inside spaghetti-headless-wayland')
    native, checked = args.native_package.resolve(), args.checked_package.resolve()
    plan, _ = load_comparison_package(native)
    if plan['observation_fields'] != ['terminal'] or len(plan['cases']) != 9:
        raise ValueError('requires the reviewed native terminal-failure package')
    neighbors = {}
    for value in args.component_comparison:
        name, separator, path = value.partition('=')
        if not separator or name in neighbors:
            raise ValueError('unique component comparisons must use ID=PATH')
        neighbors[name] = Path(path).resolve()
    if set(neighbors) != {u['id'] for u in plan['dependencies']} - {'checked-allocation'}:
        raise ValueError('supply the selected neighbor comparisons, excluding checked-allocation')
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    commands, results = [], {}; started = time.monotonic()

    def public(arguments, expected=0):
        command = [sys.executable, '-m', 'spaghetti_extractor', *map(str, arguments)]
        beginning = time.monotonic()
        ran = subprocess.run(command, capture_output=True, text=True, timeout=180)
        number = len(commands)
        (out/f'{number:02d}.stdout').write_text(ran.stdout)
        (out/f'{number:02d}.stderr').write_text(ran.stderr)
        commands.append(dict(command=command, exit_code=ran.returncode, seconds=time.monotonic()-beginning))
        write_json(out/'commands.json', commands)
        print(json.dumps(dict(command=number, exit_code=ran.returncode, seconds=commands[-1]['seconds'])), flush=True)
        if ran.returncode != expected:
            raise RuntimeError(f'command {number}: expected {expected}, got {ran.returncode}; inspect {out}')

    def check(identity, package, label, *, previous=None, replacement=None, case=None, expected=0):
        command = ['component', 'check', 'gnu-hello', identity, '--comparison-package', package,
                   '--output', out/label]
        if previous: command += ['--reuse-comparison', previous]
        if replacement: command += ['--dependency-package', 'checked-allocation='+str(replacement)]
        if case: command += ['--case', case]
        public(command, expected)
        result = load_comparison_result(out/label); results[label] = result
        return result

    draft = out/'checked-draft'
    public(['component', 'start', 'gnu-hello', 'checked-allocation', '--comparison-package', checked, '--output', draft])
    check('checked-allocation', draft, 'local-baseline')
    baseline = check('quote-slots', native, 'baseline', replacement=draft)
    for row in baseline['cases']:
        terminal = row['observations']['original']['terminal']
        status = int(row['arguments'][-1])
        assert terminal['exit_code'] == (status or 3)
        assert bytes(terminal['stderr']) == b'comparison.exe: memory exhausted\r\n'
        state = json.loads(bytes(terminal['stdout']))
        assert state['errno'] == 12 and all(b == 90 for b in state['old_prefix'])
    for name, previous in sorted(neighbors.items()):
        check(name, previous/'inputs', name+'-baseline', previous=previous)
    source = draft/'source/checked.c'; original = source.read_text()
    assert original.count('if (block == 0)') == 1
    edited = original.replace('if (block == 0)', 'if (!block)'); source.write_text(edited)
    check('checked-allocation', draft, 'local-compatible', previous=out/'local-baseline')
    changed = check('quote-slots', native, 'compatible', previous=out/'baseline', replacement=draft)
    assert changed['work_counts']['compiler'] == 1 and changed['work_counts']['execution'] == 18
    name = 'allocation-reallocate' if 'allocation-reallocate' in neighbors else sorted(neighbors)[0]
    reused = check(name, out/(name+'-baseline/inputs'), 'neighbor-reused', previous=out/(name+'-baseline'))
    assert not any(reused['work_counts'].values())

    failed_call = 'context->services->allocation_failed(context->services->context);'
    assert edited.count(failed_call) == 1
    source.write_text(edited.replace(failed_call, '(void)context;'))
    local_case = 'entry-6257-a-7-b-3-old-1-mode-2-seed-7'
    native_case = 'terminal-entry-2-status-37'
    try:
        wrong_local = check('checked-allocation', draft, 'local-wrong', previous=out/'local-compatible',
                            case=local_case, expected=2)
        wrong = check('quote-slots', native, 'wrong', previous=out/'compatible', replacement=draft,
                      case=native_case, expected=2)
    finally:
        source.write_text(edited)
    assert wrong_local['cases'][0]['status'] == wrong['cases'][0]['status'] == 'mismatch'
    assert wrong['cases'][0]['first_difference'] == dict(path='$.terminal.exit_code', kind='value', original=37, source=0)
    check('checked-allocation', out/'local-wrong/inputs', 'local-wrong-replay', case=local_case, expected=2)
    check('quote-slots', out/'wrong/inputs', 'wrong-replay', case=native_case, expected=2)
    local_repaired = check('checked-allocation', draft, 'local-repaired', previous=out/'local-compatible')
    repaired = check('quote-slots', native, 'repaired', previous=out/'compatible', replacement=draft)
    assert not any(local_repaired['work_counts'].values()) and not any(repaired['work_counts'].values())

    plan, _ = load_comparison_package(out/'repaired/inputs')
    units = {plan['component_id']: plan, **{row['id']: row for row in plan['dependencies']}}
    policy = dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT, target_id='gnu-hello',
        configuration_id='native-allocation-terminal', scope='component-network', required_components=sorted(units),
        accepted_assumptions={name: unit['assumptions'] for name, unit in units.items()},
        allowed_formal_statuses=['not-requested', 'unavailable', 'timeout', 'proved'],
        allow_original_runtime_dependencies=True,
        accepted_input_domains={name: unit.get('input_domain') for name, unit in units.items()},
        accepted_representations={name: representation_policy(unit.get('representation')) for name, unit in units.items()},
        accepted_service_catalogs={name: unit['service_catalog']['catalog_sha256'] if unit.get('service_catalog') else None for name, unit in units.items()},
        accepted_resource_checks={name: canonical_sha256_v3(unit['resource_checks']) if unit.get('resource_checks') else None for name, unit in units.items()})
    write_json(out/'policy.json', policy)
    command = ['candidate', 'build', 'gnu-hello', '--experimental-comparison', out/'repaired',
               '--experimental-policy', out/'policy.json', '--output', out/'experimental',
               '--component-comparison', 'checked-allocation='+str(out/'local-repaired')]
    for name in sorted(neighbors):
        command += ['--component-comparison', name+'='+str(out/(name+'-baseline'))]
    public(command)
    public(['candidate', 'test', 'gnu-hello', '--experimental-package', out/'experimental', '--output', out/'run'])
    assert all(r['formal_check']['status'] == 'not-requested' for r in results.values())
    write_json(out/'audit.json', dict(status='pass', authority='experimental-execution-only',
        commands=len(commands), comparisons=len(results), seconds=time.monotonic()-started, terminal_cases=9,
        results={name: dict(status=r['status'], receipt_sha256=r['receipt_sha256'],
            work_counts=r['work_counts'], timings=r['timings']) for name, r in results.items()},
        producers={p.name: sha256_file(p) for p in sorted(HERE.iterdir()) if p.is_file()},
        native_fatal_body_executed=True, original_startup=False, original_tls=False,
        whole_program_complete=False, strong_qualification=False))
    print(json.dumps(dict(status='pass', terminal_cases=9, comparisons=len(results), strong_authority=False)))


if __name__ == '__main__':
    main()
