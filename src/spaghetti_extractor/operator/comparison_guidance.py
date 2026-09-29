"""Current workspace knowledge projected from existing comparison contracts.

These views are authoring aids. They are neither comparison receipts nor a new
boundary format, and inspecting one never compiles, executes or qualifies code.
"""
from __future__ import annotations

import json
import posixpath
from pathlib import Path
import shlex
from urllib.parse import quote

from ..components.comparison_package import load_comparison_package, package_file
from ..components.comparison_representation import validate_representation_selection
from ..components.interface_package_v5 import ComponentInterfaceIntentV1
from ..util import sha256_file


def workspace_view(root: Path, target: str, component: str) -> dict:
    plan, _ = load_comparison_package(root)
    root_id = plan['component_id']
    selected = [root_id, *[u['id'] for u in plan.get('dependencies', [])]]
    if plan['target_id'] != target or component not in selected:
        raise ValueError('comparison package has another target/component identity; selected components: '+', '.join(selected))
    files = {'comparison-plan.json': sha256_file(root/'comparison-plan.json')}
    units = []
    for identity, unit in [(root_id, plan), *[(u['id'], u) for u in plan.get('dependencies', [])]]:
        interface_path = package_file(root, unit['interface'])
        interface = ComponentInterfaceIntentV1.parse(json.loads(interface_path.read_text()))
        files[unit['interface']] = sha256_file(interface_path)
        shared = (unit.get('representation') or {}).get('inputs', {})
        for relative in shared.values():
            files[relative] = sha256_file(package_file(root, relative))
        units.append(dict(id=identity, interface_path=unit['interface'], interface=interface.to_payload(),
            sources=unit['sources'], adapters=unit['adapters'], operation_symbols=unit['operation_symbols'],
            private_headers=unit.get('private_headers',[]),state_owners=unit.get('state_owners'),
            include_directories=unit['include_directories'], assumptions=unit['assumptions'],
            input_domain=unit.get('input_domain'), representation=unit.get('representation'),
            resource_checks=unit.get('resource_checks'), service_catalog=unit.get('service_catalog'),
            service_bridge=unit.get('service_bridge'), requirements=unit.get('requirements', []),
            local_shared_contract=unit.get('local_shared_contract')))
    from .source_navigation import workspace_source_navigation
    files.update(workspace_source_navigation(root,units))
    for unit in units:
        unit['consumers'] = _consumers(units, unit['id'])
    return dict(target_id=target, component_id=root_id, selected_component_id=component, scope=plan['scope'],
        authority='authoring-guidance', assurance='not-evaluated', units=units,
        original=plan['original'], cases=plan['cases'], observation_fields=plan['observation_fields'],
        program_driver=plan.get('program_driver'),
        requires_wine_desktop=plan['tools']['server'] is not None,
        composition=plan.get('composition'), replacement_groups=validate_representation_selection(root, plan),
        knowledge_inputs_sha256=files)


def _consumers(units: list[dict], identity: str) -> list[dict]:
    return [dict(component_id=unit['id'], requirement=row['id'])
        for unit in units for row in unit.get('requirements', []) if row['supplier']==identity]


def list_component_comparison(args) -> int:
    if args.near is not None:
        raise ValueError('comparison workspace listing does not use --near; inspect selected components by name')
    plan, _ = load_comparison_package(args.comparison_package)
    if plan['target_id'] != args.target:
        raise ValueError('comparison package has another target identity')
    if getattr(args,'services',False) or getattr(args,'service',None):
        from .service_inventory import service_inventory, render_service_inventory
        view=service_inventory(args.comparison_package,args.target,queries=getattr(args,'service',None) or [])
        print(json.dumps(view,indent=2,sort_keys=True) if args.json else
              render_service_inventory(view,package=args.comparison_package))
        return 0
    units = [dict(id=plan['component_id'], **plan), *plan.get('dependencies', [])]
    view = dict(target_id=plan['target_id'], component_id=plan['component_id'],
        authority='authoring-guidance', assurance='not-evaluated', units=[dict(id=unit['id'],
            operation_symbols=unit['operation_symbols'], sources=unit['sources'],
            requirements=unit.get('requirements', []), consumers=_consumers(units, unit['id'])) for unit in units])
    if args.json:
        print(json.dumps(view, indent=2, sort_keys=True))
    else:
        print(f"{plan['component_id']}: {len(units)} selected components; assurance not evaluated")
        for unit in view['units']:
            print(f"  {unit['id']}"+(' (package entry)' if unit['id']==plan['component_id'] else '')+
                ': operations '+', '.join(unit['operation_symbols']))
            if unit['consumers']:
                print('    required by: '+', '.join(row['component_id']+'/'+row['requirement'] for row in unit['consumers']))
        print('inspect: '+shlex.join(['spaghetti-extractor','component','status',args.target,'COMPONENT',
            '--comparison-package',str(args.comparison_package.resolve())]))
    return 0


def _text(value) -> str:
    return str(value).replace('`', '\\`').replace('|', '\\|').replace('\n', ' ')


def render_workspace_summary(view: dict, *, package: Path) -> str:
    """Keep ordinary inspection local; full contracts/navigation remain explicit."""
    identity=view['selected_component_id']
    unit=next(row for row in view['units'] if row['id']==identity)
    package=package.resolve();interface=unit['interface']
    def link(path):return f'[{_text(path)}]({quote(str(package/path),safe="/")})'
    def values(rows):
        return ', '.join(_text(row['id'])+': '+_text(row['type_id'])+
            (' (nullable)' if row['nullable'] else '') for row in rows) or 'none'
    status=['spaghetti-extractor','component','status',view['target_id'],identity,
            '--comparison-package',str(package)]
    guide=('generated' if identity==view['component_id'] else 'dependencies/'+identity+'/generated')+'/workspace.md'
    lines=['# Component: '+_text(identity), '', *_workspace_previews(view),
        'Package entry: `'+_text(view['component_id'])+'`; '+str(len(view['units']))+
        ' selected components. Assurance not evaluated.',_text(view['scope']), '',
        'C to edit: '+', '.join(link(p) for p in unit['sources'])+'.',
        'Private headers: '+(', '.join(link(p) for p in unit['private_headers']) or 'none declared')+'.',
        'Interface: '+link(unit['interface_path'])+'. Boundary declarations: '+link('comparison-plan.json')+'.',
        'Shared headers/notes: '+', '.join(link(p) for p in unit['include_directories'])+'.',
        'Adapter files: '+', '.join(link(p) for p in unit['adapters'])+'.', '', '## Operations', '']
    signatures={row['id']:row for row in interface['schema']['signatures']}
    for operation in interface['operations']:
        signature=signatures[operation['signature_id']]
        lines.append('- `'+_text(operation['id'])+'` / `'+_text(unit['operation_symbols'][operation['id']])+
            '` — '+values(signature['parameters'])+' → '+values(signature['results'])+'.')
    representation=unit['representation']
    if representation:
        lines+=['', 'Shared representation: `'+_text(representation['group']['id'])+'`, revision `'+
            _text(representation['revision'])+'`.',
            *['- '+_text(name)+': '+link(path)+'.' for name,path in representation['inputs'].items()]]
    if unit['input_domain']:
        lines+=['', 'Input domain: `'+_text(json.dumps(unit['input_domain'],sort_keys=True))+'`.']
    lines+=['', '## Services and selected neighbors', '',
        '| Service | Declared supplier | C adapter | Outcomes |',
        '|---|---|---|---|']
    suppliers={row['service']:row['supplier'] for row in unit['requirements'] if row['kind']=='service'}
    adapters=(unit['service_bridge'] or {}).get('adapters',{})
    contracts={row['id']+':'+row['contract_sha256']:row for row in (unit['service_catalog'] or {}).get('contracts',[])}
    unobserved=set((unit['resource_checks'] or {}).get('unobserved',[]))
    for service in interface['services']:
        name=service['id'];subject=contracts.get(service['interaction_contract_id'],{}).get('subject',{})
        outcomes=', '.join(subject.get('outcomes',[])) or 'see declaration'
        if subject.get('nonlocal_outcomes'):outcomes+='; nonlocal '+', '.join(subject['nonlocal_outcomes'])
        lines.append('| `'+_text(name)+'` | '+_text(suppliers.get(name,'no authored supplier declared'))+
            ' | `'+_text(adapters.get(name,{}).get('symbol','inspect adapter C'))+'` | '+_text(outcomes)+' |')
        unobserved.update(subject.get('unobserved',[]))
    if not interface['services']:lines.append('| none | — | — | — |')
    if interface['services']:
        lines+=['', 'Browse reusable service declarations across this selection: `'+
            shlex.join(['spaghetti-extractor','component','list',view['target_id'],
                '--comparison-package',str(package),'--services'])+'` (add `--service QUERY` to inspect matches).']
    other=[row for row in unit['requirements'] if row['kind']!='service']
    if other:
        lines+=['', 'Other requirements: '+', '.join('`'+_text(row['id'])+'` → `'+_text(row['supplier'])+'`' for row in other)+'.']
    lines+=['', 'Required by: '+(', '.join('`'+_text(row['component_id']+'/'+row['requirement'])+'`'
        for row in unit['consumers']) or 'no caller requirements in this selection')+'.',
        'These are declared bindings, not checked compatibility. Full effects, lifecycle roles and contract identities use `--details`.',
        '', '## Assumptions and unobserved behavior', '']
    for assumption in unit['assumptions']:
        lines += ['> '+line for line in assumption.splitlines()]+['']
    if unit['local_shared_contract']:
        lines.append('Additional shared-memory/service premises are declared in '+link('comparison-plan.json')+'; inspect `--details --json`.')
    lines += ['- Unobserved: '+_text(gap) for gap in sorted(unobserved)]
    lines+=['', '## Checks and next actions', '',
        str(len(view['cases']))+' cases for package `'+_text(view['component_id'])+'`; oracle `'+_text(view['original']['kind'])+'`.',
        'Observed fields: '+_text(', '.join(view['observation_fields']))+'.']
    lines+=['- `'+_text(case['id'])+'`: `'+_text(shlex.join(case['arguments']))+'`.' for case in view['cases'][:3]]
    if len(view['cases'])>3:lines.append('All cases and arguments are available with `--details`.')
    if identity!=view['component_id']:
        lines+=['', 'The check below exercises the enclosing selection. An independent check needs this component\'s own reviewed local driver, oracle and cases.']
        recipe='dependencies/'+identity+'/prepare-local.py'
        if (package/recipe).is_file():
            lines+=['An editable local-check recipe is available at '+link(recipe)+'. Fill in its driver, original, cases and observations; current boundary/C/suppliers and execution tools are retained.']
    revision='revise-boundary.py' if identity==view['component_id'] else 'dependencies/'+identity+'/revise-boundary.py'
    if (package/revision).is_file():
        lines+=['', 'Boundary revision recipe: '+link(revision)+'. Edit its changes and name each reviewed caller requirement; omitted inputs and neighboring C are retained.']
    check=['spaghetti-extractor','component','check',view['target_id'],identity,
        '--comparison-package',str(package),'--history',str(package.with_name(package.name+'-checks'))]
    if view['requires_wine_desktop']:check.insert(0,'spaghetti-headless-wayland')
    lines+=['', '```sh',shlex.join(check),shlex.join([*status,'--details']),'```', '',
        'The full view reads current declarations; '+link(guide)+' is the generated snapshot. '
        'Use `--json` for the complete structured view, or `--reuse-comparison RESULT` for current edits and reuse eligibility.', '']
    return '\n'.join(lines)


def render_boundary(unit: dict, *, link, implementation, contract_path='comparison-plan.json',
                    adapter_note=None) -> list[str]:
    """Render the same declared operations, objects and services in both handoffs."""
    interface=unit['interface'];schema=interface['schema']
    signatures={row['id']:row for row in schema['signatures']}
    checks=unit['resource_checks']
    resource_rules={rule['operation_id']:rule for rule in checks['contracts']} if checks else {}

    def values(rows):
        return ', '.join('`'+_text(v['id'])+': '+_text(v['type_id'])+'`'+
            (' (nullable)' if v['nullable'] else '') for v in rows) or 'none'

    def roles(rows):
        return '; '.join(_text(row['path']['root']+'.'+row['path']['value_id']+
            ''.join('.'+x for x in row['path']['fields']))+': '+_text(row['transition'])+
            ' '+_text(row['resource_kind'])+' from '+_text(row['provider_domain'])+
            (' when '+_text(json.dumps(row['condition'],sort_keys=True)) if row['condition'] is not None else '')
            for row in rows) or 'none declared'

    lines=['## Operations and state', '']
    for op in interface['operations']:
        sig = signatures[op['signature_id']]
        lines += [f"- `{_text(op['id'])}` implemented by `{_text(unit['operation_symbols'][op['id']])}`: "+
            values(sig['parameters'])+' -> '+values(sig['results'])+'.',
            '  Allowed services: '+(', '.join('`'+_text(s)+'`' for s in op['allowed_service_ids']) or 'none')+'.']
        lines += implementation(unit['source_navigation']['operations'].get(op['id']))
        if op['lifecycle_bindings']:
            lines.append('  Interface lifecycle: '+roles(op['lifecycle_bindings'])+'.')
        rule = resource_rules.get(op['id'])
        if rule:
            lines += ['  Resource roles declared for comparison: '+roles(rule['lifecycle']['bindings'])+'.',
                '  Comparison allowances: untransferred '+str(rule['max_untransferred'])+
                ', retained '+str(rule['max_retained'])+'.']
            for outcome, limits in rule.get('nonlocal_allowances', {}).items():
                lines.append('  On `'+_text(outcome)+'`: untransferred '+str(limits['max_untransferred'])+
                    ', retained '+str(limits['max_retained'])+'.')
        if not op['lifecycle_bindings'] and not rule:
            lines.append('  No lifecycle roles declared in the interface or comparison settings.')
        memory = [v for v in (*sig['parameters'], *sig['results']) if v['access'] != 'none' or v['interpretation'] != 'value']
        for v in memory:
            lines.append('  Memory interpretation: `'+_text(v['id'])+'`: '+_text(json.dumps(v, sort_keys=True))+'.')
    lines += ['', 'State: '+_text(json.dumps(interface['state'], sort_keys=True))+'.',
        'Declared effects: '+_text(json.dumps(interface['effects'],sort_keys=True))+'.',
        'Protocol: '+_text(json.dumps(interface['protocol'],sort_keys=True))+'.', '',
        '## Shared types and objects', '']
    for row in schema['types']:
        kind=row['kind']
        if kind == 'function':
            continue
        if kind == 'integer':
            description=('signed' if row['signed'] else 'unsigned')+' '+str(row['width_bits'])+'-bit integer'
        elif kind == 'opaque':
            description='opaque C object, nominal identity `'+_text(row['nominal_id'])+'`'
        elif kind == 'record':
            description='record: '+', '.join('`'+_text(f['id'])+': '+_text(f['type_id'])+'`'+
                (' ('+str(f['bit_width'])+'-bit field)' if f['bit_width'] is not None else '') for f in row['fields'])
        else:
            description=_text(json.dumps({k:v for k,v in row.items() if k!='id'},sort_keys=True))
        lines.append('- `'+_text(row['id'])+'`: '+description+'.')
    lines += ['', 'Opaque pointers and layouts need the contents/lifetime premises below; a type declaration supplies neither.', '',
        '## Services, effects and outcomes', '']
    catalog = {r['id']+':'+r['contract_sha256']: r for r in (unit['service_catalog'] or {}).get('contracts', [])}
    bridge = unit['service_bridge'] or {}
    for service in interface['services']:
        name = service['id']; sig = signatures[service['signature_id']]
        contract = catalog.get(service['interaction_contract_id'])
        adapter = bridge.get('adapters', {}).get(name)
        lines += ['- `'+_text(name)+'`: '+values(sig['parameters'])+' -> '+values(sig['results'])+'.',
            '  Contract: `'+_text(service['interaction_contract_id'])+'`.',
            '  Executable adapter: '+(_text(json.dumps(adapter,sort_keys=True)) if adapter else adapter_note or 'not declared through the generated bridge; inspect adapter C')+'.']
        lines += implementation(unit['source_navigation']['services'].get(name))
        if contract:
            subject = contract['subject']
            lines += ['  Effects: '+_text(', '.join(e['primitive'] for e in contract['effects']))+'.',
                '  Outcomes: '+_text(', '.join(subject['outcomes']))+'; nonlocal: '+_text(', '.join(subject.get('nonlocal_outcomes', [])) or 'none declared')+'.',
                '  Protocol: '+_text(subject['protocol'])+'; lifecycle: '+roles(subject['lifecycle']['bindings'])+'.']
            lines += ['  Unobserved: '+_text(gap) for gap in subject['unobserved']]
    if not interface['services']:
        lines.append('No services declared.')
    if bridge.get('transports'):
        lines += ['', 'Live-value transports: '+_text(json.dumps(bridge['transports'],sort_keys=True))+'.']
    if checks:
        lines += ['', 'Resource instrumentation is configured for '+_text(', '.join(checks['instrumented_sides']))+
            '. The operation roles above come from '+link(contract_path)+'; they are declarations, not proved lifetimes.']
        lines += ['- Unobserved: '+_text(gap) for gap in checks['unobserved']]
    from ..components.state_ownership import state_owner_guidance
    lines += state_owner_guidance(unit.get('state_owners'))
    return lines


def render_workspace(view: dict, *, unit_id: str | None = None, directory: str = '',
                     package: Path | None = None) -> str:
    identity = unit_id or view.get('selected_component_id', view['component_id'])
    unit = next(row for row in view['units'] if row['id'] == identity)

    def link(path):
        return f'[{_text(path)}]({quote(posixpath.relpath(path, directory or "."), safe="/")})'

    def location(row):
        path=row['path'];line=row['line']
        return f'[{_text(path)}:{line}]({quote(posixpath.relpath(path,directory or "."),safe="/")}#L{line})'

    def implementation(record):
        if not record:return []
        if not record['definitions']:
            return ['  No definition found in the selected C/header files; inspect linked libraries, macros or callback bindings.']
        rows=[]
        for definition in record['definitions']:
            rows.append('  Source candidate: '+location(definition)+'.')
            if definition['calls']:
                calls=[]
                for call in definition['calls']:
                    text='`'+_text(call['expression'])+'`'
                    if call['definitions']:text+=' ('+', '.join(location(row) for row in call['definitions'])+')'
                    calls.append(text)
                rows.append('  Calls written here: '+', '.join(calls)+'.')
        return rows

    lines = [f'# Component workspace: {_text(identity)}', '', _text(view['scope']), '',
        'This guide describes declared boundaries and executable test setup. Assurance is not evaluated here.',
        'Establish or refine the boundary with surrounding-code analysis; ordinary implementation edits use these recorded dependencies.', '',
        '## Local implementation', '',
        'Authored C: '+', '.join(link(p) for p in unit['sources'])+'.',
        'Implementation-only headers: '+(', '.join(link(p) for p in unit.get('private_headers',[])) or 'none declared')+'.',
        'Adapters: '+', '.join(link(p) for p in unit['adapters'])+'.',
        'Interface: '+link(unit['interface_path'])+'.',
        'Shared headers and boundary notes: '+', '.join(link(p) for p in unit['include_directories'])+'.', '',
        'Source navigation reads C and headers without preprocessing. Definition candidates and written calls help investigation; macros, linkage and indirect dispatch still need inspection. This view does not establish dependency completeness or contract compatibility.', '',
        ]
    lines += render_boundary(unit,link=link,implementation=implementation)
    if identity!=view['component_id']:
        lines += ['', 'Selected inside `'+_text(view['component_id'])+'`. The driver, cases and observations below belong to that enclosing package.',
            'For an independent check, reuse this unit with '
            '`comparison_environment.retained_component_inputs(package, component_id='+repr(identity)+')` '
            'and supply a reviewed local driver, original oracle and cases to `prepare_comparison_package`. '
            'The helper retains the boundary, shared headers, C and supplier requirements; it supplies no local fixture or evidence. '
            'Pass `retain_dependencies=True` to keep the currently selected supplier implementations and their declared transitive requirements. '
            'See the component workflow guide for the network-to-local recipe.']
        recipe='dependencies/'+identity+'/prepare-local.py'
        if package and (package/recipe).is_file():
            lines+=['', 'Start that local setup with '+link(recipe)+'. Its `local_fixture()` keeps driver/oracle/case choices explicit while the existing helper carries this unit and its declared supplier closure. The recipe is editable and preserved when reopening the workspace.']
    if view.get('program_driver'):
        driver=view['program_driver']
        invocation=('The program receives its unchanged case arguments. The observer receives `SPX_COMPARISON_SIDE` and `SPX_COMPARISON_REPORT`; an untouched-original control checks instrumentation effects. '
                    if driver.get('process') else 'The process receives `original` or `source`, then the case arguments. ')
        lines += ['', 'Program driver: '+link(driver['image'])+' loads the compiled `'+_text(driver['library'])+
            '` through export `'+_text(driver['symbol'])+'`. '+invocation+
            'The C adapters determine entry redirection and observations; inspect the scope and assumptions below.']
        if driver.get('entries'):
            lines += ['Program entry components: '+_text(', '.join(driver['entries']))+
                '. The program may reach each independently; this selection does not declare calls between them. '
                'Changing any selected implementation invalidates the program comparison, while unchanged local evidence can still reuse.']
    lines += ['', '## Assumptions and admitted inputs', '']
    lines += ['- '+_text(s) for s in unit['assumptions']]
    if unit['input_domain']:
        lines += ['', 'Input domain: '+_text(json.dumps(unit['input_domain'],sort_keys=True))+'.']
    if unit['local_shared_contract']:
        lines += ['', 'Optional local shared-memory/service contract: declared in '+link('comparison-plan.json')+
            '; inspect the full projection with `--json`. Its premises are not discharged by this view.']
    lines += ['', '## Neighbors and replacement groups', '']
    for row in unit['requirements']:
        lines.append('- `'+_text(row['id'])+'` requires `'+_text(row['supplier'])+'` ('+_text(row['kind'])+
            '), contract `'+row['contract_sha256']+'`.')
    if not unit['requirements']:
        lines.append('No authored-neighbor requirements declared; native/controlled service dependencies above still apply.')
    consumers = _consumers(view['units'], identity)
    lines += ['', 'Required by: '+(', '.join('`'+_text(row['component_id']+'/'+row['requirement'])+'`'
        for row in consumers) or 'no caller requirements in this selection')+'.']
    for group_id, row in view['replacement_groups'].items():
        binding = row['binding']
        if identity in binding['group']['members']:
            lines.append('- Replacement group `'+_text(group_id)+'`, revision `'+_text(binding['revision'])+
                '; members '+_text(', '.join(binding['group']['members']))+
                '; missing '+_text(', '.join(row['missing_members']) or 'none')+'.')
    for name, path in (unit['representation'] or {}).get('inputs', {}).items():
        lines.append('- Shared representation input '+_text(name)+': '+link(path)+'.')
    for group in (view['composition'] or {}).get('recursion_groups', []):
        if identity in group['members']:
            lines.append('- Recursive group `'+_text(group['id'])+'`: '+_text(', '.join(group['members']))+'; progress unproved.')
    for neighbor in view['units']:
        if neighbor['id'] != identity:
            base = 'generated' if neighbor['id']==view['component_id'] else 'dependencies/'+neighbor['id']+'/generated'
            lines.append('- Neighbor `'+_text(neighbor['id'])+'`: '+link(base+'/workspace.md')+'.')
    lines += ['', 'Requirements freeze declared contracts. A matching signature alone is insufficient for a replacement.',
        'Boundary/shared-representation changes require explicit refinement and affected integration checks.', '',
        '## Examples and observations', '',
        'These cases exercise the selected package; they are not exhaustive admitted inputs or per-neighbor test evidence.',
        'Oracle: '+_text(view['original']['kind'])+'; '+', '.join(link(p) for p in view['original']['files'])+'.',
        'Compared observations: '+_text(', '.join(view['observation_fields']))+'.', '']
    lines += ['- `'+_text(row['id'])+'`: arguments `'+_text(shlex.join(row['arguments']))+'`.' for row in view['cases']]
    if package:
        package=package.resolve()
        revision='revise-boundary.py' if identity==view['component_id'] else 'dependencies/'+identity+'/revise-boundary.py'
        if (package/revision).is_file():
            lines+=['', 'Boundary revision recipe: '+link(revision)+'. Edit `boundary_changes(unit)` and run it with `--output NEW_PACKAGE`. '
                'Name each reviewed incoming contract with repeatable `--review-requirement CONSUMER/REQUIREMENT`; omitted inputs and neighboring C are retained. '
                'Review records are authoring decisions, not compatibility or behavior evidence. The recipe is editable and preserved when reopening this workspace.']
        if identity==view['component_id']:
            baseline=package.with_name(package.name+'-check')
            edited=package.with_name(package.name+'-edit-check')
            check=['spaghetti-extractor','component','check',view['target_id'],view['component_id'],
                   '--comparison-package',str(package)]
            lines += ['', '## Edit and check', '',
                'Edit the authored C linked above. Keep boundary/shared-layout changes explicit; ordinary implementation edits use the existing declarations.', '',
                'For repeated editing, run this same command after each change:', '', '```sh',
                shlex.join([*check,'--history',str(package.with_name(package.name+'-checks'))]), '```', '',
                'Each run retains a separate ordinary result and automatically reuses the last completed result. `latest` points to that result, including a mismatch or compiler failure; it does not mean passing. Use `CHECKS/latest` with status or source export, which still checks its actual status. Replay commands name the specific saved check, so later edits cannot retarget a discrepancy. `--history-baseline RESULT` seeds an empty history and is ignored once a completed check exists. `--reuse-comparison RESULT` overrides the automatic choice; `--rerun` forces execution while keeping eligible objects. Keep the history outside this editable package.', '',
                'First comparison (use a fresh output directory):', '', '```sh',
                shlex.join([*check,'--output',str(baseline)]), '```', '',
                'Try a driver-supported input with `--case NEW_NAME --case-arguments JSON`, where JSON is an array of argument strings. The result retains the new case in `inputs/` without changing this workspace. It executes as one case from fresh runtime state; existing names cannot silently change arguments. To collect these inputs for future checks, run `component start` from this current workspace with `--reuse-cases RESULT --output NEW_WORKSPACE`. Repeat `--reuse-cases` for several results or packages. A saved mismatch is also a useful input.', '',
                'For hand-written or generated inputs, use `component start --case-file FILE` with your comparison package or result and a new output directory. Each file contains a JSON list such as `[{"id":"new-input","arguments":["7"]}]`; use arguments supported by this driver. Repeat the option to append more lists. Imports preserve current C, neighbors and driver, append missing definitions in order, coalesce identical definitions and reject conflicting names. The workspace retains the arguments, so later checks need no original case file. Run the printed command to check the expanded suite, including any earlier setup cases. Imported definitions supply no observations or admission evidence.', '',
                'After an implementation edit, reuse the previous result and retain a new result:', '', '```sh',
                shlex.join([*check,'--reuse-comparison',str(baseline),'--output',str(edited)]), '```', '',
                'Preview current edits and eligible compiled-file reuse before checking:', '', '```sh',
                shlex.join(['spaghetti-extractor','component','status',view['target_id'],view['component_id'],
                    '--comparison-package',str(package),'--reuse-comparison',str(baseline)]), '```', '',
                'This reads the current selection and previous evidence without running tools. Use the same `--case` as the intended check; the default is all cases. Source validation and any selected formal checks still run when checking.', '',
                'Inspect that retained result without compiling or running a case:', '', '```sh',
                shlex.join(['spaghetti-extractor','component','status',view['target_id'],view['component_id'],
                    '--comparison-result',str(edited)]), '```', '',
                'Inspection shows the recorded result, nearby observation values and paths to full observations; it does not assess edits made since that result.', '',
                'A discrepancy prints its first differing observation and a replay command. Replay uses the retained failing inputs, even after the editable C has been repaired, and reruns the original case selection while reusing eligible compiled objects. Suite replay preserves case order and earlier runtime setup; a fresh single case may not reproduce a suite failure. Add `--rerun` to a reuse check whenever fresh execution is needed, including a previously passing case.', '',
                'After a matching comparison, export the selected C as a source library:', '', '```sh',
                shlex.join(['spaghetti-extractor','candidate','export',view['target_id'],'--comparison',str(edited),
                    '--output',str(package.with_name(package.name+'-source'))]), '```', '',
                'Add other checked selections with additional `--comparison` arguments. Existing program libraries use `--update`; run the affected program comparisons after integration. A source library still needs application/runtime bindings.']
            lines += ['', '## Revise the boundary', '',
                'For declaration-only edits, use `components.comparison_package.revise_comparison_package(package=..., output=..., assumptions=[...])`, or pass a reviewed interface as `interface=...`. It retains current C/fixtures and regenerates derived metadata; do not edit saved contract hashes or the composition graph. Start from its output to refresh this guide and editor commands. Supplier requirements stay frozen unless explicitly refined.', '',
                'After reviewing a changed supplier, pass `--refine-requirement CONSUMER/REQUIREMENT=SUPPLIER_PACKAGE` on start, or `refine_requirements={"CONSUMER/REQUIREMENT": Path("SUPPLIER_PACKAGE")}` to the revision helper. Bare requirement names refer to this package entry. Name every reviewed shared caller explicitly; unreviewed callers remain frozen and missing reviews are reported together. Caller C and neighbors with matching declared contracts remain in place. Check the new consumer before integration; this authoring decision is not a compatibility proof.', '',
                'Prepare the revised interface/adapters/cases with the existing authoring API, then carry this component\'s C and headers into a new workspace:', '', '```sh',
                shlex.join(['spaghetti-extractor','component','start',view['target_id'],view['component_id'],
                    '--comparison-package','REVISED_PACKAGE','--reuse-source',str(package),
                    '--output',str(package.with_name(package.name+'-revised'))]), '```', '',
                'The revised package supplies the boundary, adapters and selected neighbors. The handoff carries the declared authored file selection, including renamed, added or removed C files and private headers. Check the new workspace against the previous comparison to see invalidation and rerun affected cases. Carrying source does not establish contract compatibility.', '',
                'To retain an edited supplier before execution, add `--dependency-package COMPONENT=DIR` to start. DIR can be a comparison package or an exported source project; a source draft retains this consumer\'s adapters and neighboring selections. The existing contract and selection checks apply, and `--reuse-source` can preserve local caller C. The new workspace contains a snapshot of those suppliers; later edits need explicit reselection. Preparation does not check their behavior.']
            lines += ['',
                'For an ordinary supplier C edit, use `--dependency-source COMPONENT=DIR` on start, check or status. It reads only that named unit from a component workspace, another network workspace, a source project or a matching interface authoring workspace, retaining this consumer\'s adapters and other selected bodies. The file-editing commands below can declare local C file changes; the authoring API remains available for boundary refinement. Its contract and other authored headers must match. Changing an existing header\'s role requires explicit refinement. `--dependency-package` continues to select the complete supplied package, including its bundled suppliers.']
        else:
            lines += ['', '## Check through the selected consumer', '',
                'Edit the authored C linked above, then check using this component name:', '', '```sh',
                shlex.join(['spaghetti-extractor','component','check',view['target_id'],identity,
                    '--comparison-package',str(package),'--history',str(package.with_name(package.name+'-checks'))]),
                '```', '', 'The command runs the enclosing consumer '+_text(view['component_id'])+
                ' and keeps its receipt, replay and history identity. Independent component checking still needs the local setup described above.']
        lines += ['', 'Inspect this component\'s case inputs and recorded service scopes after checking:', '', '```sh',
            shlex.join(['spaghetti-extractor','component','status',view['target_id'],identity,
                '--comparison-result','RESULT','--details']), '```', '',
            'This reads the retained consumer result. Shared catalogs, missing instrumentation and incomplete traces are identified explicitly; scope observations do not establish branch coverage. Add `--case NAME` to focus the display. The printed replay command retains the original consumer, case selection and setup order.']
        lines += ['', '## Organize authored files', '',
            'Add helper C and a new private header without writing a preparation script:', '', '```sh',
            shlex.join(['spaghetti-extractor','component','start',view['target_id'],identity,
                '--comparison-package',str(package),'--source-file','source/helpers/helper.c=HELPER_C',
                '--source-file','source/helpers/helper.h=HELPER_H','--private-header','source/helpers/helper.h',
                '--output',str(package.with_name(package.name+'-files'))]), '```', '',
            'Names include `source/` and are relative to this component, without a `dependencies/COMPONENT/` prefix. '
            'Repeat `--source-file NAME=FILE` to add or replace C/header files. Rename a C file by supplying its new name and '
            '`--remove-source source/old.c`. Keep listed originals in the input workspace until the command retires them in the new draft. '
            'Other C, adapters, notes and neighbors remain. A new local file can be adopted by naming that exact file as its input; '
            'unlisted files are not picked automatically. Existing header roles and shared headers stay fixed. '
            'Check the new draft through the printed entry before publishing it.']
        if view['requires_wine_desktop']:
            lines += ['', 'These checks execute Wine and must run inside `spaghetti-headless-wayland`. Prefix a single check with that wrapper when needed. Keep an edit/reuse sequence in the same prepared environment: a new desktop/session currently invalidates cached execution evidence.']
        refresh = shlex.join(['spaghetti-extractor','component','status',view['target_id'],identity,
            '--comparison-package',str(package),'--details'])
        lines += ['', 'Refresh from current inputs with `'+refresh+'` (add `--json` for the full projection).']
    lines += ['', 'This generated snapshot is outside proof/comparison authority. Editing it does not change the boundary.',
        '<details><summary>Knowledge input fingerprints</summary>', '',
        '```json', json.dumps(view['knowledge_inputs_sha256'],indent=2,sort_keys=True), '```', '', '</details>', '']
    return '\n'.join(lines[:2]+_workspace_previews(view)+lines[2:])


def _workspace_previews(view: dict) -> list[str]:
    lines=[]
    if view.get('comparison_changes'):
        from .comparison_changes import render_change_preview
        lines+=['Edit/reuse preview for the enclosing `'+_text(view['component_id'])+'` selection.', '']+render_change_preview(view['comparison_changes'])
    if view.get('dependency_proposals'):
        from ..components.comparison_contract_diagnostics import describe_contract_changes
        preview=['## Proposed dependency contracts', '',
            'Read-only comparison of declarations and exact shared inputs. Compatibility, implementation correctness and evidence reuse are not evaluated. Consumer paths combine each proposal\'s requirements with current outer callers. Bundled defaults and explicit selections are listed separately; this does not resolve conflicting selections.', '']
        for row in view['dependency_proposals']:
            preview += ['- `'+_text(row['component_id'])+'`: contract '+row['status']+
                ' ('+('explicit' if row['explicit'] else 'bundled with '+_text(row['proposed_by']))+').',
                '  Proposed consumers: '+(', '.join(_text(c['component']+'/'+c['requirement']) for c in row['consumers']) or 'no explicit requirements recorded')+'.',
                '  Transitive consumers through this proposal: '+(', '.join(map(_text,row['transitive_consumers'])) or 'none recorded')+'.']
            if row.get('current_consumers',row['consumers'])!=row['consumers']:
                preview += ['  Current consumers: '+(', '.join(_text(c['component']+'/'+c['requirement'])
                    for c in row['current_consumers']) or 'none recorded')+'.']
            if row['status']=='added':
                preview += ['  New supplier in this proposal. Inspect its boundary, C adapters and assumptions before refinement:',
                    '', '```sh',shlex.join(['spaghetti-extractor','component','status',view['target_id'],row['component_id'],
                        '--comparison-package',row['package'],'--details']),'```', '']
            if row['changes']:
                preview += ['', '```text',describe_contract_changes(row['changes']),'```', '']
            if row.get('source_kind') in ('exported-c-draft','comparison-c-draft','interface-c-draft'):
                preview += ['  Component C draft; consumer adapters and neighboring selections retained.',
                    '  Changed authored files: '+(', '.join(map(_text,row['changed_sources'])) or 'none')+
                    '. Integration must be checked; no independent local fixture is supplied.']
                for key,label in [('added_sources','Added'),('removed_sources','Removed')]:
                    if row.get(key):preview.append('  '+label+': '+', '.join(map(_text,row[key]))+'.')
        preview += ['Review changed declarations and shared files before preparing a revised boundary. Use `component start --reuse-source` to preserve local C under that revised package, then run the affected component/integration checks. A comment-only shared-file edit still changes an exact input binding; this view does not infer semantic compatibility.', '']
        lines+=preview
    return lines


def write_workspace_guidance(root: Path, target: str, component: str) -> None:
    view = workspace_view(root, target, component)
    for unit in view['units']:
        directory = 'generated' if unit['id']==view['component_id'] else 'dependencies/'+unit['id']+'/generated'
        (root/directory/'workspace.md').write_text(render_workspace(view,unit_id=unit['id'],directory=directory,package=root),encoding='utf-8')


def status_component_comparison(args) -> int:
    if args.development or args.all or args.family or args.code or args.limit != 20:
        raise ValueError('comparison workspace status supports --comparison-package and --json, not provider-status filters')
    view = workspace_view(args.comparison_package, args.target, args.unit)
    if getattr(args,'case',None) is not None and getattr(args,'reuse_comparison',None) is None:
        raise ValueError('component status --case requires --reuse-comparison')
    from .comparison import dependency_selections
    dependencies=dependency_selections(args)
    if dependencies:
        from ..components.comparison_contract_diagnostics import dependency_contract_preview
        plan,_=load_comparison_package(args.comparison_package)
        view['dependency_proposals']=dependency_contract_preview(args.comparison_package,plan,
            dependencies)
    if getattr(args,'reuse_comparison',None) is not None:
        from .comparison_changes import comparison_change_preview
        view['comparison_changes']=comparison_change_preview(args.comparison_package,args.reuse_comparison,
            case_id=args.case,dependency_packages=dependencies)
    if args.json:print(json.dumps(view,indent=2,sort_keys=True))
    elif args.details:print(render_workspace(view,package=args.comparison_package))
    else:print(render_workspace_summary(view,package=args.comparison_package))
    return 0
