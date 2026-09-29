"""Fresh public DX-Ball boundary/edit/compare/replay/reuse/assembly walkthrough.

This host-C experiment does not launch Wine. Command outcomes and observations
are checked by the existing public workflow, not a target-specific checker.
"""
import argparse
import json
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
    parser.add_argument('base', type=Path, nargs='?', help='optional retained initializer or package; omit for fresh recovery')
    for name in ('original_pe', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    packages = out/'packages'
    commands, results = [], {}
    started = time.monotonic()

    def run(arguments, expected=0):
        command = [sys.executable, *map(str, arguments)]
        start = time.monotonic()
        process = subprocess.run(command, capture_output=True, text=True)
        number = len(commands)
        (out/f'{number:02d}.stdout').write_text(process.stdout)
        (out/f'{number:02d}.stderr').write_text(process.stderr)
        commands.append(dict(command=command, exit_code=process.returncode,
                             seconds=time.monotonic()-start))
        write_json(out/'commands.json', commands)
        print(json.dumps(dict(command=number, exit_code=process.returncode,
                              seconds=commands[-1]['seconds'])), flush=True)
        if process.returncode != expected:
            raise RuntimeError(f'command {number}: expected {expected}, got {process.returncode}; inspect {out}')

    def public(arguments, expected=0):
        run(['-m', 'spaghetti_extractor', *arguments], expected)

    def check(name, package, label, *, previous=None, reset=None, case=None, expected=0):
        command = ['component', 'check', 'dxball', 'graphics-'+name,
                   '--comparison-package', package, '--output', out/label]
        if previous:
            command += ['--reuse-comparison', out/previous]
        if reset:
            command += ['--dependency-package', 'graphics-reset='+str(reset)]
        if case:
            command += ['--case', case]
        public(command, expected)
        result = load_comparison_result(out/label)
        results[label] = result
        return result

    run([HERE/'prepare.py', *([args.base.resolve()] if args.base else []), args.original_pe.resolve(), packages])
    for name in ('reset', 'initialize'):
        public(['component', 'start', 'dxball', 'graphics-'+name,
                '--comparison-package', packages/('graphics-'+name), '--output', out/(name+'-draft')])
    reset, network = out/'reset-draft', out/'initialize-draft'
    check('reset', reset, 'reset-baseline')
    check('bind', packages/'graphics-bind', 'bind-baseline')
    check('blit', packages/'graphics-blit', 'blit-baseline')
    check('initialize', network, 'baseline', reset=reset)

    source = reset/'source/reset.c'
    original = source.read_text()
    old = 'for (uint32_t slot = 0; slot < 255; ++slot)\n      state->banks[bank].slots[slot] = 0;'
    new = 'uint32_t remaining = 255;\n    while (remaining != 0)\n      state->banks[bank].slots[--remaining] = 0;'
    assert original.count(old) == 1
    compatible = original.replace(old, new); source.write_text(compatible)
    check('reset', reset, 'reset-compatible', previous='reset-baseline')
    changed = check('initialize', network, 'compatible', previous='baseline', reset=reset)
    assert changed['work_counts']['compiler'] == 1 and changed['work_counts']['execution'] == 74
    for name in ('bind', 'blit'):
        reused = check(name, packages/('graphics-'+name), name+'-reused', previous=name+'-baseline')
        assert not any(reused['work_counts'].values())

    # A bounded-memory error survives normal return and resource creation. The
    # shared bank observation, not a solver or a value-only test, catches it.
    source.write_text(compatible.replace('remaining = 255', 'remaining = 254'))
    try:
        wrong = check('reset', reset, 'wrong-reset', previous='reset-compatible', expected=2)
        wrong_network = check('initialize', network, 'wrong-reset-network', previous='compatible', reset=reset, expected=2)
    finally:
        source.write_text(compatible)
    for name, result in [('wrong-reset', wrong), ('wrong-reset-network', wrong_network)]:
        failed = next(row for row in result['cases'] if row['status'] == 'mismatch')
        assert failed['first_difference']['path'].startswith('$.banks[')
        check('reset' if name == 'wrong-reset' else 'initialize', out/name/'inputs',
              name+'-replay', case=failed['id'], expected=2)
    check('reset', reset, 'reset-repaired', previous='reset-compatible')
    check('initialize', network, 'reset-network-repaired', previous='compatible', reset=reset)

    # Preserve a service interaction bug whose final return remains zero.
    initialize = network/'source/initialize.c'; correct = initialize.read_text()
    first, rest = correct.split('\nuint32_t lifted_graphics_initialize', 1)
    faulty = first.replace('  /* The original', '  const uint32_t captured_window = state->window;\n  /* The original')
    marker = '  /* The original'
    before, after = faulty.split(marker, 1)
    faulty = before + marker + after.replace('state->window', 'captured_window')
    initialize.write_text(faulty+'\nuint32_t lifted_graphics_initialize'+rest)
    try:
        window = check('initialize', network, 'wrong-window', previous='compatible', reset=reset,
                       case='callback-3-3', expected=2)
    finally:
        initialize.write_text(correct)
    assert window['cases'][0]['status'] == 'mismatch'
    assert window['cases'][0]['observations']['original']['results'] == window['cases'][0]['observations']['source']['results']
    check('initialize', out/'wrong-window/inputs', 'wrong-window-replay', case='callback-3-3', expected=2)
    final = check('initialize', network, 'repaired', previous='compatible', reset=reset)
    for name in ('reset-repaired', 'reset-network-repaired', 'repaired'):
        assert not any(results[name]['work_counts'].values())

    # The public experimental policy admits sampled comparisons without silently
    # requesting a proof or granting any strong dispatch/link authority.
    plan, _ = load_comparison_package(out/'repaired/inputs')
    units = {plan['component_id']: plan, **{row['id']: row for row in plan['dependencies']}}
    checks = {'graphics-reset': out/'reset-repaired', 'graphics-bind': out/'bind-reused',
              'graphics-blit': out/'blit-reused', 'graphics-initialize': out/'repaired'}
    policy = dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT, target_id='dxball',
        configuration_id='authored-graphics-network', scope='component-network', required_components=sorted(units),
        accepted_assumptions={name: unit['assumptions'] for name, unit in units.items()},
        allowed_formal_statuses=['not-requested', 'unavailable', 'timeout', 'proved'],
        allow_original_runtime_dependencies=True,
        accepted_input_domains={name: unit.get('input_domain') for name, unit in units.items()},
        accepted_representations={name: representation_policy(unit.get('representation')) for name, unit in units.items()},
        accepted_service_catalogs={name: unit['service_catalog']['catalog_sha256'] if unit.get('service_catalog') else None for name, unit in units.items()},
        accepted_resource_checks={name: canonical_sha256_v3(unit['resource_checks']) if unit.get('resource_checks') else None for name, unit in units.items()})
    write_json(out/'policy.json', policy)
    command = ['candidate', 'build', 'dxball', '--experimental-comparison', out/'repaired',
               '--experimental-policy', out/'policy.json', '--output', out/'experimental']
    for name, path in sorted(checks.items()):
        if name != 'graphics-initialize':
            command += ['--component-comparison', name+'='+str(path)]
    public(command)
    public(['candidate', 'test', 'dxball', '--experimental-package', out/'experimental', '--output', out/'run'])
    assert final['status'] == 'match' and len(final['cases']) == 37
    assert all(result['formal_check']['status'] == 'not-requested' for result in results.values())
    write_json(out/'audit.json', dict(status='pass', authority='experimental-execution-only',
        seconds=time.monotonic()-started, comparisons=len(results), cases=37, commands=len(commands),
        producers={path.name: sha256_file(path) for path in sorted(HERE.iterdir()) if path.is_file()},
        checks={name: str(path) for name, path in checks.items()},
        results={name: dict(status=result['status'], receipt_sha256=result['receipt_sha256'],
            formal=result['formal_check']['status'], work_counts=result['work_counts'],
            timings=result['timings']) for name, result in results.items()},
        whole_program_complete=False, native_directdraw_execution=False, per_unit_tool_internal_changes=False))
    print(json.dumps(dict(status='pass', comparisons=len(results), connected_cases=37, strong_authority=False)))


if __name__ == '__main__':
    main()
