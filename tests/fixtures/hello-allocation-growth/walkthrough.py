"""Public growth/quoting edit, replay, neighbor reuse and experimental assembly."""
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
    for name in ('retained_quoting', 'growth_exact', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    packages = out/'packages'
    commands, results = [], {}
    started = time.monotonic()

    def run(arguments, expected=0):
        command = [sys.executable, *map(str, arguments)]
        start = time.monotonic()
        process = subprocess.run(command, capture_output=True, text=True, timeout=180)
        number = len(commands)
        (out/f'{number:02d}.stdout').write_text(process.stdout)
        (out/f'{number:02d}.stderr').write_text(process.stderr)
        commands.append(dict(command=command, exit_code=process.returncode, seconds=time.monotonic()-start))
        write_json(out/'commands.json', commands)
        print(json.dumps(dict(command=number, exit_code=process.returncode,
                              seconds=commands[-1]['seconds'])), flush=True)
        if process.returncode != expected:
            raise RuntimeError(f'command {number}: expected {expected}, got {process.returncode}; inspect {out}')

    def public(arguments, expected=0):
        run(['-m', 'spaghetti_extractor', *arguments], expected)

    def check(identity, package, label, *, previous=None, growth=None, case=None, expected=0):
        command = ['component', 'check', 'gnu-hello', identity,
                   '--comparison-package', package, '--output', out/label]
        if previous: command += ['--reuse-comparison', out/previous]
        if growth: command += ['--dependency-package', 'allocation-grow='+str(growth)]
        if case: command += ['--case', case]
        public(command, expected)
        result = load_comparison_result(out/label); results[label] = result
        return result

    run([HERE/'network.py', args.retained_quoting.resolve(), args.growth_exact.resolve(), packages])
    for identity in ('allocation-grow', 'quote-slots'):
        public(['component', 'start', 'gnu-hello', identity,
                '--comparison-package', packages/identity, '--output', out/(identity+'-draft')])
    growth, network = out/'allocation-grow-draft', out/'quote-slots-draft'
    release = packages/'preserve-errno-free'
    check('allocation-grow', growth, 'growth-baseline')
    check('preserve-errno-free', release, 'release-baseline')
    baseline = check('quote-slots', network, 'baseline', growth=growth)
    assert len(baseline['cases']) == 144
    uncalled = [c for c in baseline['cases'] if not any(
        row['calls'] for row in c['resources']['services']['coverage'].values())]
    assert len(uncalled) == 18 and all(c['resources']['status'] == 'satisfied' for c in uncalled)

    source = growth/'source/grow.c'; original = source.read_text()
    assert original.count('previous / 2U') == 1
    compatible = original.replace('previous / 2U', '(previous >> 1U)')
    source.write_text(compatible)
    local = check('allocation-grow', growth, 'growth-compatible', previous='growth-baseline')
    integrated = check('quote-slots', network, 'compatible', previous='baseline', growth=growth)
    assert local['work_counts']['compiler'] == integrated['work_counts']['compiler'] == 1
    assert integrated['work_counts']['execution'] == 288
    reused = check('preserve-errno-free', release, 'release-reused', previous='release-baseline')
    assert not any(reused['work_counts'].values())

    # Incorrect publication changes memory at failure even when final return and
    # failure class match. Retain both the local and consumer counterexamples.
    assert compatible.count('count->value = 0;') == 1
    source.write_text(compatible.replace('count->value = 0;', 'count->value = previous;'))
    try:
        wrong = check('allocation-grow', growth, 'wrong-publication', previous='growth-compatible',
                      case='edge-5-old-0-mode-2', expected=2)
        wrong_network = check('quote-slots', network, 'wrong-publication-network', previous='compatible',
                      growth=growth, case='scenario-104', expected=2)
    finally:
        source.write_text(compatible)
    assert wrong['cases'][0]['status'] == wrong_network['cases'][0]['status'] == 'mismatch'
    for identity, label, result in [('allocation-grow', 'wrong-publication', wrong),
                                    ('quote-slots', 'wrong-publication-network', wrong_network)]:
        case = result['cases'][0]
        if identity == 'allocation-grow':
            assert case['observations']['original']['outcome'] == case['observations']['source']['outcome'] == 2
        else:
            for side in ('original', 'source'):
                invocation = case['observations'][side]['invocations'][-1]
                assert invocation['outcome'] == 2 and invocation['result'] == 0
        check(identity, out/label/'inputs', label+'-replay', case=case['id'], expected=2)
    check('allocation-grow', growth, 'growth-repaired', previous='growth-compatible')
    final = check('quote-slots', network, 'repaired', previous='compatible', growth=growth)
    for label in ('growth-repaired', 'repaired'):
        assert not any(results[label]['work_counts'].values())

    plan, _ = load_comparison_package(out/'repaired/inputs')
    units = {plan['component_id']: plan, **{row['id']: row for row in plan['dependencies']}}
    checks = {'quote-slots': out/'repaired', 'allocation-grow': out/'growth-repaired',
              'preserve-errno-free': out/'release-reused'}
    policy = dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT, target_id='gnu-hello',
        configuration_id='authored-quoting-growth', scope='component-network', required_components=sorted(units),
        accepted_assumptions={name: unit['assumptions'] for name, unit in units.items()},
        allowed_formal_statuses=['not-requested', 'unavailable', 'timeout', 'proved'],
        allow_original_runtime_dependencies=True,
        accepted_input_domains={name: unit.get('input_domain') for name, unit in units.items()},
        accepted_representations={name: representation_policy(unit.get('representation')) for name, unit in units.items()},
        accepted_service_catalogs={name: unit['service_catalog']['catalog_sha256'] if unit.get('service_catalog') else None for name, unit in units.items()},
        accepted_resource_checks={name: canonical_sha256_v3(unit['resource_checks']) if unit.get('resource_checks') else None for name, unit in units.items()})
    write_json(out/'policy.json', policy)
    command = ['candidate', 'build', 'gnu-hello', '--experimental-comparison', out/'repaired',
               '--experimental-policy', out/'policy.json', '--output', out/'experimental']
    for name, path in sorted(checks.items()):
        if name != 'quote-slots': command += ['--component-comparison', name+'='+str(path)]
    public(command)
    public(['candidate', 'test', 'gnu-hello', '--experimental-package', out/'experimental', '--output', out/'run'])
    assert final['status'] == 'match'
    assert all(r['formal_check']['status'] == 'not-requested' for r in results.values())
    write_json(out/'audit.json', dict(status='pass', authority='experimental-execution-only',
        seconds=time.monotonic()-started, comparisons=len(results), connected_cases=144,
        growth_cases=len(local['cases']), release_cases=len(reused['cases']), uncalled_supplier_cases=len(uncalled),
        commands=len(commands), producers={p.name: sha256_file(p) for p in sorted(HERE.iterdir()) if p.is_file()},
        checks={name: str(path) for name, path in checks.items()},
        results={name: dict(status=r['status'], receipt_sha256=r['receipt_sha256'],
            work_counts=r['work_counts'], timings=r['timings']) for name, r in results.items()},
        whole_program_complete=False, native_execution=False, new_formal_rules=False,
        shared_runtime_fixes=['explicit nullable objects', 'uncalled supplier under completed handler']))
    print(json.dumps(dict(status='pass', comparisons=len(results), connected_cases=144, strong_authority=False)))


if __name__ == '__main__':
    main()
