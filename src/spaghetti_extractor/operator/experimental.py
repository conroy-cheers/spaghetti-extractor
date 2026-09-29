"""Explicit project policy admits scoped experimental candidate execution."""
from pathlib import Path
from copy import copy
import json
import shlex

from ..candidate.experimental_build import build_experimental_execution
from ..candidate.experimental_run import run_experimental_suite


def start_experimental_component(args) -> int:
    """Use retained named setups; do not invent an isolated fixture for a program unit."""
    from ..candidate.experimental_manifest import load_experimental_manifest
    from .comparison import start_component_comparison
    if args.output is None or args.apply:
        raise ValueError('experimental component preparation requires --output; it does not adopt a qualified source')
    package=args.experimental_package.resolve();output=args.output.resolve()
    if output.is_relative_to(package) or package.is_relative_to(output):
        raise ValueError('editable workspace and experimental package must be separate')
    manifest=load_experimental_manifest(package)
    if manifest['target_id']!=args.target:
        raise ValueError('experimental package belongs to another target')
    components=manifest['bindings']['components']
    if args.unit not in components:
        raise ValueError('component is absent from the experiment; selected: '+', '.join(sorted(components)))
    plan=json.loads((package/'comparison/inputs/comparison-plan.json').read_text())
    main=plan['component_id']
    selected=manifest['component_checks'].get(args.unit)
    if selected is None:
        print(args.unit+' has no retained independent comparison setup; opening its C in the existing '+main+' selection.')
    comparison=package/('comparison' if args.unit==main or selected is None else selected['path'])
    forwarded=copy(args);forwarded.comparison_package=comparison/'inputs'
    result=start_component_comparison(forwarded,reuse_comparison=comparison)
    print('reopened '+('main program/network' if args.unit==main or selected is None else 'component')+' setup from '+str(package))
    print('retained comparison: '+str(comparison))
    print('Editable draft; no compilation, execution or new qualification performed.')
    if args.unit!=main and selected is not None:
        program=output.with_name(output.name+'-program')
        command=['spaghetti-extractor','component','start',args.target,main,'--experimental-package',str(package),
            '--dependency-source',args.unit+'='+str(output),'--output',str(program)]
        print('After local edits, reopen the program with this selection: '+shlex.join(command))
    return result


def _component_comparisons(entries) -> dict:
    checks = {}
    for entry in entries or []:
        identity, separator, path = entry.partition('=')
        if not separator or not identity or not path or identity in checks:
            raise ValueError('--component-comparison requires unique COMPONENT=DIR entries')
        checks[identity] = Path(path)
    return checks


def prepare_candidate_policy(args) -> int:
    from ..candidate.experimental_policy import prepare_experimental_policy
    report=prepare_experimental_policy(comparison=args.comparison,
        component_checks=_component_comparisons(args.component_comparison),target_id=args.target,
        configuration_id=args.configuration,output=args.output,network_only=args.network_only)
    policy=report['policy']
    print('Prepared experimental policy: '+str(args.output/'experimental-policy.json'))
    print('selected components: '+', '.join(policy['required_components']))
    print('main network comparison: '+report['main_component'])
    print('original runtime dependencies allowed: '+str(policy['allow_original_runtime_dependencies']).lower())
    if args.network_only:print('Selected network evidence accepted without a separate check: '+', '.join(sorted(args.network_only)))
    if report['missing_checks']:print('Required component checks still missing: '+', '.join(report['missing_checks']))
    print('Review assumptions and declarations: '+str(args.output/'README.md'))
    print('Build after review: '+shlex.join(report['build_command']))
    print('No compilation, execution or qualification performed.')
    return 0


def build_candidate_experiment(args) -> int:
    reuse=getattr(args,'reuse_experimental',None)
    if args.configuration or not all((args.experimental_comparison, args.experimental_policy or reuse, args.output)):
        raise ValueError('experimental build requires --experimental-comparison, --experimental-policy or --reuse-experimental, and --output; '
                         '--configuration selects the qualified build workflow')
    checks=_component_comparisons(args.component_comparison)
    manifest = build_experimental_execution(comparison=args.experimental_comparison, component_checks=checks,
        policy_path=args.experimental_policy, output=args.output, target_id=args.target,reuse_experimental=reuse)
    print(f"{args.target}: experimental configuration={manifest['configuration_id']} scope={manifest['scope']}")
    print('selected components: ' + ', '.join(manifest['bindings']['components']))
    if reuse is not None:
        costs=json.loads((args.output/'experimental-build-costs.json').read_text())
        print('reused component receipts: '+(', '.join(costs['reused_component_checks']) or 'none'))
        print('reused experimental policy: '+str(costs['reused_policy']).lower())
    network_only=sorted(manifest['bindings']['components'].keys()-manifest['component_checks'].keys())
    if network_only:print('Selected network cases only; no separate component check: '+', '.join(network_only))
    print('bound binary: ' + manifest['bindings']['candidate_sha256'])
    if 'program' in manifest['bindings']:
        program=manifest['bindings']['program']
        print('authored library: '+program['driver']['library']+' '+program['library_sha256'])
    print('Reused comparison binary; no compiler, linker, model or solver invocation.')
    print(f"manifest: {args.output / 'experimental-execution.json'}")
    print('Experimental execution only; concrete comparisons do not establish strong qualification.')
    return 0


def test_candidate_experiment(args) -> int:
    if args.suite or not args.experimental_package or not args.output:
        raise ValueError('experimental test requires --experimental-package and --output; '
                         '--suite selects the qualified test workflow')
    result = run_experimental_suite(package=args.experimental_package, output=args.output, target_id=args.target,
        timeout=30 if args.experimental_timeout is None else args.experimental_timeout)
    print(f"{args.target}: experimental run={result['status']} scope={result['scope']}")
    for identity,program in result.get('programs',{}).items():
        if program['status']!='pass':
            difference=program.get('first_difference')
            print(f"  {identity}: program observations={program['status']}")
            if difference:
                from .comparison import _observation_excerpt
                print('  difference at '+difference['path']+': '+_observation_excerpt(difference))
            elif program.get('diagnostic'):print('  '+program['diagnostic'])
    if 'resources' in result:
        print('behavioral observations: '+result['behavioral_status'])
        for identity,resources in result['resources'].items():
            if resources['status']!='satisfied' or resources['diagnostics']:
                print(f"  {identity}: resource applicability={resources['status']}")
                for finding in resources['diagnostics'][:8]:
                    print('  '+finding['classification']+': '+finding.get('event',finding.get('detail','inspect resource report')))
    print(f"evidence: {args.output / 'experimental-run.json'}")
    return 0 if result['status'] == 'pass' else 2
