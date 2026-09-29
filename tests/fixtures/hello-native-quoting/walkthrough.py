"""Public native-consumer comparison, C edit, replay, reuse and assembly.

Run this entire recipe inside spaghetti-headless-wayland. Source units and local
contracts come from the existing Hello allocation workflow; no new proof is used.
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
from prepare import package_paths

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base_workflow', 'environment_package', 'original_pe', 'output'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--component-packages', action='store_true',
                        help='start from fresh source/interface packages instead of a completed workflow')
    parser.add_argument('--cleanup-package', type=Path,
                        help='also lift and edit complete shared-cache cleanup')
    parser.add_argument('--reallocate-package', type=Path,
                        help='also lift and edit the complete lower realloc operation')
    parser.add_argument('--checked-allocation-package', type=Path,
                        help='also lift and edit the multi-operation allocation family')
    parser.add_argument('--quote-engine-package', type=Path,
                        help='also lift the complete quoting engine and reuse its controlled caller')
    parser.add_argument('--component-comparison',action='append',default=[],metavar='ID=PATH',
                        help='local checks for additional transitive selections, such as multibyte-conversion')
    args = parser.parse_args()
    if not os.environ.get('WAYLAND_DISPLAY'):
        raise ValueError('run the complete recipe inside spaghetti-headless-wayland')
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    base = args.base_workflow.resolve()
    inputs = package_paths(base, args.component_packages)
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

    def check(identity, package, label, *, previous=None, growth=None, cleanup=None, reallocate=None, checked=None, engine=None,
              case=None, expected=0):
        command = ['component', 'check', 'gnu-hello', identity,
                   '--comparison-package', package, '--output', out/label]
        if previous: command += ['--reuse-comparison', out/previous]
        if growth: command += ['--dependency-package', 'allocation-grow='+str(growth)]
        if cleanup: command += ['--dependency-package', 'quote-cleanup='+str(cleanup)]
        if reallocate: command += ['--dependency-package', 'allocation-reallocate='+str(reallocate)]
        if checked: command += ['--dependency-package', 'checked-allocation='+str(checked)]
        if engine: command += ['--dependency-package', 'quote-buffer='+str(engine)]
        if case: command += ['--case', case]
        public(command, expected)
        result = load_comparison_result(out/label); results[label] = result
        return result

    run([HERE/'prepare.py', base, args.environment_package.resolve(), args.original_pe.resolve(), out/'packages',
         *(['--component-packages'] if args.component_packages else []),
         *(['--cleanup-package', args.cleanup_package.resolve()] if args.cleanup_package else []),
         *(['--reallocate-package', args.reallocate_package.resolve()] if args.reallocate_package else []),
         *(['--checked-allocation-package', args.checked_allocation_package.resolve()] if args.checked_allocation_package else []),
         *(['--quote-engine-package', args.quote_engine_package.resolve()] if args.quote_engine_package else [])])
    native_plan, _ = load_comparison_package(out/'packages/quote-slots')
    native_cases = len(native_plan['cases'])
    for identity, package in [('quote-slots', out/'packages/quote-slots'),
                              ('allocation-grow', inputs['allocation-grow'])]:
        public(['component', 'start', 'gnu-hello', identity, '--comparison-package', package,
                '--output', out/(identity+'-draft')])
    network, growth = out/'quote-slots-draft', out/'allocation-grow-draft'
    release = inputs['preserve-errno-free']
    cleanup = None
    if args.cleanup_package:
        cleanup = out/'quote-cleanup-draft'
        public(['component', 'start', 'gnu-hello', 'quote-cleanup',
                '--comparison-package', args.cleanup_package.resolve(), '--output', cleanup])
        check('quote-cleanup', cleanup, 'cleanup-baseline')
    reallocate = None
    if args.reallocate_package:
        reallocate = out/'allocation-reallocate-draft'
        public(['component', 'start', 'gnu-hello', 'allocation-reallocate',
                '--comparison-package', args.reallocate_package.resolve(), '--output', reallocate])
        check('allocation-reallocate', reallocate, 'reallocate-baseline')
    checked = None
    if args.checked_allocation_package:
        checked = out/'checked-allocation-draft'
        public(['component', 'start', 'gnu-hello', 'checked-allocation',
                '--comparison-package', args.checked_allocation_package.resolve(), '--output', checked])
        check('checked-allocation', checked, 'checked-baseline')
    engine = None
    if args.quote_engine_package:
        engine = out/'quote-buffer-draft'
        public(['component', 'start', 'gnu-hello', 'quote-buffer',
                '--comparison-package', args.quote_engine_package.resolve(), '--output', engine])
        local_engine = check('quote-buffer', engine, 'engine-baseline')
        engine_plan, _ = load_comparison_package(engine)
        assert len(local_engine['cases']) == len(engine_plan['cases'])
        assert all(len(c['observations']['source']['samples']) == 112 for c in local_engine['cases'])
        controlled_plan, _ = load_comparison_package(inputs['quote-slots'])
        assert 'quote-buffer' not in {d['id'] for d in controlled_plan['dependencies']}
        check('quote-slots', inputs['quote-slots'], 'quote-caller-baseline')
    check('allocation-grow', growth, 'growth-baseline')
    check('preserve-errno-free', release, 'release-baseline')
    baseline = check('quote-slots', network, 'baseline', growth=growth)
    assert len(baseline['cases']) == native_cases
    assert all(len(c['observations']['source']['invocations']) == 6 for c in baseline['cases'])
    source = growth/'source/grow.c'; original = source.read_text()
    assert original.count('if (adjusted != 0U)') == 1
    source.write_text(original.replace('if (adjusted != 0U)', 'if (adjusted)'))
    check('allocation-grow', growth, 'growth-compatible', previous='growth-baseline')
    changed = check('quote-slots', network, 'compatible', previous='baseline', growth=growth)
    assert changed['work_counts']['compiler'] == 1 and changed['work_counts']['execution'] == 2*native_cases
    reused = check('preserve-errno-free', release, 'release-reused', previous='release-baseline')
    assert not any(reused['work_counts'].values())

    # The real style/memory caller supplies an embedded NUL. Losing the flag
    # changes the actual native quoting engine's output, without a fake oracle.
    quote_source = network/'source/quote-slots.c'; quote = quote_source.read_text()
    assert quote.count('options->flags | 1U') == 1
    quote_source.write_text(quote.replace('options->flags | 1U', 'options->flags'))
    try:
        wrong = check('quote-slots', network, 'wrong-nul', previous='compatible', growth=growth,
                      case='style-0-kind-1', expected=2)
    finally:
        quote_source.write_text(quote)
    assert wrong['cases'][0]['status'] == 'mismatch'
    check('quote-slots', out/'wrong-nul/inputs', 'wrong-nul-replay', case='style-0-kind-1', expected=2)
    repaired = check('quote-slots', network, 'repaired', previous='compatible', growth=growth)
    assert not any(repaired['work_counts'].values())

    final_network = out/'repaired'
    if cleanup:
        cleanup_source = cleanup/'source/cleanup.c'
        initial = cleanup_source.read_text()
        assert initial.count('= 256U;') == 1
        edited = initial.replace('= 256U;', '= UINT32_C(256);')
        cleanup_source.write_text(edited)
        check('quote-cleanup', cleanup, 'cleanup-compatible', previous='cleanup-baseline')
        connected = check('quote-slots', network, 'cleanup-network-compatible', previous='repaired',
                          growth=growth, cleanup=cleanup)
        assert connected['work_counts']['compiler'] == 1 and connected['work_counts']['execution'] == 2*native_cases
        neighbor = check('allocation-grow', growth, 'growth-reused', previous='growth-compatible')
        assert not any(neighbor['work_counts'].values())
        cleanup_source.write_text(edited.replace('= UINT32_C(256);', '= UINT32_C(255);'))
        try:
            local_wrong = check('quote-cleanup', cleanup, 'cleanup-wrong', previous='cleanup-compatible',
                                case='count-4-mode-3-seed-0', expected=2)
            consumer_wrong = check('quote-slots', network, 'cleanup-network-wrong',
                previous='cleanup-network-compatible', growth=growth, cleanup=cleanup,
                case='style-0-kind-1', expected=2)
        finally:
            cleanup_source.write_text(edited)
        assert local_wrong['cases'][0]['status'] == consumer_wrong['cases'][0]['status'] == 'mismatch'
        check('quote-cleanup', out/'cleanup-wrong/inputs', 'cleanup-wrong-replay',
              case='count-4-mode-3-seed-0', expected=2)
        check('quote-slots', out/'cleanup-network-wrong/inputs', 'cleanup-network-wrong-replay',
              case='style-0-kind-1', expected=2)
        local_repaired = check('quote-cleanup', cleanup, 'cleanup-repaired', previous='cleanup-compatible')
        repaired = check('quote-slots', network, 'cleanup-network-repaired',
                         previous='cleanup-network-compatible', growth=growth, cleanup=cleanup)
        assert not any(local_repaired['work_counts'].values()) and not any(repaired['work_counts'].values())
        final_network = out/'cleanup-network-repaired'

    if reallocate:
        reallocate_source = reallocate/'source/reallocate.c'
        initial = reallocate_source.read_text()
        assert initial.count('if (bytes == 0U)') == 1
        edited = initial.replace('if (bytes == 0U)', 'if (!bytes)')
        reallocate_source.write_text(edited)
        check('allocation-reallocate', reallocate, 'reallocate-compatible', previous='reallocate-baseline')
        integrated = final_network/'inputs'
        connected = check('quote-slots', integrated, 'reallocate-network-compatible',
            previous=final_network.name, reallocate=reallocate)
        assert connected['work_counts']['compiler'] == 1 and connected['work_counts']['execution'] == 2*native_cases
        neighbor = check('preserve-errno-free', release, 'release-reused-after-reallocate', previous='release-reused')
        assert not any(neighbor['work_counts'].values())
        assert edited.count('bytes = 1U;') == 1
        reallocate_source.write_text(edited.replace('bytes = 1U;', 'bytes = 2U;'))
        try:
            local_wrong = check('allocation-reallocate', reallocate, 'reallocate-wrong',
                previous='reallocate-compatible', case='bytes-0-old-1-mode-1-seed-7', expected=2)
            native_wrong = check('quote-slots', integrated, 'reallocate-network-wrong',
                previous='reallocate-network-compatible', reallocate=reallocate, case='style-0-kind-1', expected=2)
        finally:
            reallocate_source.write_text(edited)
        assert local_wrong['cases'][0]['status'] == native_wrong['cases'][0]['status'] == 'mismatch'
        check('allocation-reallocate', out/'reallocate-wrong/inputs', 'reallocate-wrong-replay',
              case='bytes-0-old-1-mode-1-seed-7', expected=2)
        check('quote-slots', out/'reallocate-network-wrong/inputs', 'reallocate-network-wrong-replay',
              case='style-0-kind-1', expected=2)
        local_repaired = check('allocation-reallocate', reallocate, 'reallocate-repaired', previous='reallocate-compatible')
        repaired = check('quote-slots', integrated, 'reallocate-network-repaired',
                         previous='reallocate-network-compatible', reallocate=reallocate)
        assert not any(local_repaired['work_counts'].values()) and not any(repaired['work_counts'].values())
        final_network = out/'reallocate-network-repaired'

    if checked:
        source = checked/'source/checked.c'; initial = source.read_text()
        assert initial.count('if (block == 0)') == 1
        edited = initial.replace('if (block == 0)', 'if (!block)'); source.write_text(edited)
        check('checked-allocation', checked, 'checked-compatible', previous='checked-baseline')
        integrated = final_network/'inputs'
        connected = check('quote-slots', integrated, 'checked-network-compatible',
            previous=final_network.name, checked=checked)
        assert connected['work_counts']['compiler'] == 1 and connected['work_counts']['execution'] == 2*native_cases
        neighbor = check('allocation-reallocate' if reallocate else 'preserve-errno-free',
            reallocate or release, 'checked-neighbor-reused',
            previous='reallocate-compatible' if reallocate else 'release-reused')
        assert not any(neighbor['work_counts'].values())
        resize = 'context->services->resize(context->services->context, block, bytes)'
        assert edited.count(resize) == 1
        source.write_text(edited.replace(resize, resize[:-1]+' + 1U)'))
        try:
            local_wrong = check('checked-allocation', checked, 'checked-wrong', previous='checked-compatible',
                case='entry-6257-a-7-b-3-old-1-mode-1-seed-7', expected=2)
            native_wrong = check('quote-slots', integrated, 'checked-network-wrong',
                previous='checked-network-compatible', checked=checked, case='style-0-kind-1', expected=2)
        finally:
            source.write_text(edited)
        assert local_wrong['cases'][0]['status'] == native_wrong['cases'][0]['status'] == 'mismatch'
        check('checked-allocation', out/'checked-wrong/inputs', 'checked-wrong-replay',
              case='entry-6257-a-7-b-3-old-1-mode-1-seed-7', expected=2)
        check('quote-slots', out/'checked-network-wrong/inputs', 'checked-network-wrong-replay',
              case='style-0-kind-1', expected=2)
        local_repaired = check('checked-allocation', checked, 'checked-repaired', previous='checked-compatible')
        repaired = check('quote-slots', integrated, 'checked-network-repaired',
                         previous='checked-network-compatible', checked=checked)
        assert not any(local_repaired['work_counts'].values()) and not any(repaired['work_counts'].values())
        final_network = out/'checked-network-repaired'

    if engine:
        source = engine/'source/quote-buffer.c'; initial = source.read_text()
        test = 'writer->length < writer->capacity'
        assert initial.count(test) == 1
        edited = initial.replace(test, 'writer->capacity > writer->length'); source.write_text(edited)
        local = check('quote-buffer', engine, 'engine-compatible', previous='engine-baseline')
        integrated = final_network/'inputs'
        connected = check('quote-slots', integrated, 'engine-network-compatible',
            previous=final_network.name, engine=engine)
        assert local['work_counts']['compiler'] == connected['work_counts']['compiler'] == 1
        assert connected['work_counts']['execution'] == 2*native_cases
        neighbor = check('quote-slots', inputs['quote-slots'], 'quote-caller-reused',
                         previous='quote-caller-baseline')
        assert not any(neighbor['work_counts'].values())
        # Defined C with deliberately wrong behavior: substitute rather than
        # elide embedded NULs. Both the local oracle and the real caller catch it.
        elision = '} else if (flags & ELIDE_NULLS) continue;'
        assert edited.count(elision) == 1
        source.write_text(edited.replace(elision, "} else if (flags & ELIDE_NULLS) c='?';"))
        local_case, native_case = 'style-0-flags-1-locale-0', 'style-0-kind-1'
        try:
            local_wrong = check('quote-buffer', engine, 'engine-wrong', previous='engine-compatible',
                                case=local_case, expected=2)
            native_wrong = check('quote-slots', integrated, 'engine-network-wrong',
                previous='engine-network-compatible', engine=engine, case=native_case, expected=2)
        finally:
            source.write_text(edited)
        assert local_wrong['cases'][0]['status'] == native_wrong['cases'][0]['status'] == 'mismatch'
        check('quote-buffer', out/'engine-wrong/inputs', 'engine-wrong-replay', case=local_case, expected=2)
        check('quote-slots', out/'engine-network-wrong/inputs', 'engine-network-wrong-replay',
              case=native_case, expected=2)
        local_repaired = check('quote-buffer', engine, 'engine-repaired', previous='engine-compatible')
        repaired = check('quote-slots', integrated, 'engine-network-repaired',
                         previous='engine-network-compatible', engine=engine)
        assert not any(local_repaired['work_counts'].values()) and not any(repaired['work_counts'].values())
        final_network = out/'engine-network-repaired'

    plan, _ = load_comparison_package(final_network/'inputs')
    units = {plan['component_id']: plan, **{row['id']: row for row in plan['dependencies']}}
    checks = {'allocation-grow': out/'growth-compatible', 'preserve-errno-free': out/'release-reused'}
    if cleanup: checks['quote-cleanup'] = out/'cleanup-repaired'
    if reallocate: checks['allocation-reallocate'] = out/'reallocate-repaired'
    if checked: checks['checked-allocation'] = out/'checked-repaired'
    if engine: checks['quote-buffer'] = out/'engine-repaired'
    for supplied in args.component_comparison:
        name, separator, path = supplied.partition('=')
        if not separator or name in checks or name not in units or name==plan['component_id']:
            raise ValueError('additional component checks must uniquely name selected dependencies as ID=PATH')
        checks[name] = Path(path).resolve()
    policy = dict(format=EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT, target_id='gnu-hello',
        configuration_id='native-quoting-consumers', scope='component-network', required_components=sorted(units),
        accepted_assumptions={name: unit['assumptions'] for name, unit in units.items()},
        allowed_formal_statuses=['not-requested', 'unavailable', 'timeout', 'proved'],
        allow_original_runtime_dependencies=True,
        accepted_input_domains={name: unit.get('input_domain') for name, unit in units.items()},
        accepted_representations={name: representation_policy(unit.get('representation')) for name, unit in units.items()},
        accepted_service_catalogs={name: unit['service_catalog']['catalog_sha256'] if unit.get('service_catalog') else None for name, unit in units.items()},
        accepted_resource_checks={name: canonical_sha256_v3(unit['resource_checks']) if unit.get('resource_checks') else None for name, unit in units.items()})
    write_json(out/'policy.json', policy)
    command = ['candidate', 'build', 'gnu-hello', '--experimental-comparison', final_network,
               '--experimental-policy', out/'policy.json', '--output', out/'experimental']
    for name, path in sorted(checks.items()):
        command += ['--component-comparison', name+'='+str(path)]
    public(command)
    public(['candidate', 'test', 'gnu-hello', '--experimental-package', out/'experimental', '--output', out/'run'])
    assert all(r['formal_check']['status'] == 'not-requested' for r in results.values())
    write_json(out/'audit.json', dict(status='pass', authority='experimental-execution-only',
        seconds=time.monotonic()-started, commands=len(commands), comparisons=len(results), native_cases=native_cases,
        native_consumer_calls=7*native_cases, original_bodies_removed=True, no_new_authored_units=not bool(cleanup or reallocate or checked or engine),
        selected_cleanup=bool(cleanup), local_cleanup_cases=len(results['cleanup-baseline']['cases']) if cleanup else 0,
        selected_reallocate=bool(reallocate), local_reallocate_cases=len(results['reallocate-baseline']['cases']) if reallocate else 0,
        selected_checked_allocation=bool(checked), local_checked_cases=len(results['checked-baseline']['cases']) if checked else 0,
        selected_quote_engine=bool(engine), local_engine_cases=len(results['engine-baseline']['cases']) if engine else 0,
        controlled_quote_caller_reused=bool(engine),
        fresh_component_packages=args.component_packages,
        results={name: dict(status=r['status'], receipt_sha256=r['receipt_sha256'],
            work_counts=r['work_counts'], timings=r['timings']) for name, r in results.items()},
        producers={p.name: sha256_file(p) for p in sorted(HERE.iterdir()) if p.is_file()},
        original_startup=False, original_tls=False, whole_program_complete=False, strong_qualification=False))
    print(json.dumps(dict(status='pass', native_cases=native_cases, comparisons=len(results), strong_authority=False)))


if __name__ == '__main__':
    main()
