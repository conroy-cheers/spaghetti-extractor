"""Readable component boundaries beside exported C, using existing declarations."""
from __future__ import annotations

import json
from pathlib import Path
import posixpath
import shlex
from urllib.parse import quote

from ..components.source import load_component_source_package, load_component_source_workspace
from .comparison_guidance import _consumers, _text, render_boundary
from .source_navigation import workspace_source_navigation


def _source_export_units(root: Path, report: dict, *, draft_components: set[str] = frozenset()):
    """Share the existing boundary/source projection between guides and browsing."""
    units=[];sources={}
    for identity,record in sorted(report['components'].items()):
        directory=Path(record['source_package']).parent
        source=(load_component_source_workspace(root/record['source_package'],private_headers=record.get('private_headers'))[0] if identity in draft_components
            else load_component_source_package(root/record['source_package']))
        sources[identity]=source
        base=directory/'sources';contract=record['contract']
        units.append(dict(id=identity,guide=(directory/'README.md').as_posix(),
            interface_path=record['interface'],
            interface=json.loads((root/record['interface']).read_text()),
            sources=[(base/row['path']).as_posix() for row in source['files']],adapters=[],
            private_headers=[(base/name).as_posix() for name in record.get('private_headers',[])],
            include_directories=[base.as_posix()],operation_symbols=record['operation_symbols'],
            requirements=record.get('requirements', []),
            assumptions=record['assumptions'],input_domain=contract.get('input_domain'),
            representation=contract.get('representation'),local_shared_contract=record.get('local_shared_contract'),
            binding_references=record.get('comparison_binding_references',[]),
            unchecked_c_draft=identity in draft_components,
            resource_checks=contract.get('resource_checks'),service_catalog=contract.get('service_catalog'),
            state_owners=contract.get('state_owners'),service_bridge=None))
    inputs=workspace_source_navigation(root,units)
    return units,sources,inputs


def source_export_view(root: Path, target: str) -> dict:
    """Inspect existing source provenance and current C drafts without building."""
    from ..candidate.source_export_bindings import source_export_workspace
    from ..util import sha256_file

    report,drafts=source_export_workspace(root)
    if report.get('target_id')!=target:
        raise ValueError('source export has another target identity')
    draft_components={identity for identity,unit in report['components'].items()
        if any(path.startswith(str(Path(unit['source_package']).parent/'sources')+'/') for path in drafts)}
    units,_,inputs=_source_export_units(root,report,draft_components=draft_components)
    for unit in units:unit['consumers']=_consumers(units,unit['id'])
    return dict(target_id=target,component_id=None,origin='source-project',authority='authoring-guidance',
        assurance='not-evaluated',units=units,source_edits=drafts,
        knowledge_inputs_sha256={**report['files'],**inputs,**drafts,'source-export.json':sha256_file(root/'source-export.json')})


def list_component_source(args) -> int:
    if args.near is not None:
        raise ValueError('source project listing does not use --near; inspect exported components by name')
    if getattr(args,'services',False) or getattr(args,'service',None):
        from .service_inventory import service_inventory, render_service_inventory
        view=service_inventory(args.source_project,args.target,queries=getattr(args,'service',None) or [],source_project=True)
        print(json.dumps(view,indent=2,sort_keys=True) if args.json else
              render_service_inventory(view,package=args.source_project))
        return 0
    view=source_export_view(args.source_project,args.target)
    if args.json:
        print(json.dumps(view,indent=2,sort_keys=True))
    else:
        print(f"{args.target}: {len(view['units'])} exported components; assurance not evaluated")
        for unit in view['units']:
            print('  '+unit['id']+': operations '+', '.join(unit['operation_symbols'])+
                  ('; unchecked C draft' if unit['unchecked_c_draft'] else ''))
            if unit['consumers']:
                print('    required by: '+', '.join(row['component_id']+'/'+row['requirement'] for row in unit['consumers']))
            print('    boundary guide: '+str(args.source_project.resolve()/unit['guide']))
        print('services: '+shlex.join(['spaghetti-extractor','component','list',args.target,
            '--source-project',str(args.source_project.resolve()),'--services']))
    return 0


def write_source_export_guidance(root: Path, report: dict, *, draft_components: set[str] = frozenset()) -> None:
    """Project an already checked export into relocatable, non-authorizing guides."""
    units,sources,_=_source_export_units(root,report,draft_components=draft_components)
    guides={unit['id']:unit['guide'] for unit in units}
    receipts={r['receipt_sha256']:r for r in report['comparisons']}
    index=['## Component boundaries', '',
        'Open a component guide for its C, inputs, state, services, assumptions and recorded examples. '
        'These are generated snapshots of the exported selection; edits do not refresh assurance.', '']
    index+=['Browse reusable service declarations from this library directory: `'+shlex.join([
        'spaghetti-extractor','component','list',report['target_id'],'--source-project','.','--services'])+'`.',
        'Add `--service QUERY` for types, outcomes, ownership and recorded binding examples. '
        'Comparison adapters are examples; current backend choices remain explicit.', '']
    for unit in units:
        identity=unit['id'];record=report['components'][identity];source=sources[identity]
        directory=posixpath.dirname(unit['guide']);base=directory+'/sources/';contract=record['contract']
        def link(path, label=None):
            return f'[{_text(path if label is None else label)}]({quote(posixpath.relpath(path,directory),safe="/")})'
        def component_link(name):
            return (link(guides[name],name) if name in guides else '`'+_text(name)+'` (not exported)')
        def location(row):
            return f'[{_text(row["path"])}:{row["line"]}]({quote(posixpath.relpath(row["path"],directory),safe="/")}#L{row["line"]})'
        def implementation(info):
            lines=[]
            for definition in (info or {}).get('definitions',[]):
                lines.append('  Source candidate: '+location(definition)+'.')
                for call in definition['calls']:
                    lines.append('  Written call: `'+_text(call['expression'])+'`'+
                        ('; '+', '.join(location(row) for row in call['definitions']) if call['definitions'] else '')+'.')
            return lines
        lines=['# Component source: '+_text(identity), '',
            'This is a generated boundary snapshot for the exported C. It records declarations and comparison provenance; '
            'it does not assess subsequent edits or validate the application/backend.', '',
            '## Implementation', '',
            'Authored C and headers: '+', '.join(link(p) for p in unit['sources'])+'.',
            'Implementation-only headers: '+(', '.join(link(p) for p in unit['private_headers']) or 'none declared')+'.',
            'Interface: '+link(record['interface'])+'. Source inventory: '+link(record['source_package'])+'.',
            'Shared inputs and boundary notes: '+(', '.join(link(base+r['path']) for r in source['shared_inputs']) or 'none')+'.', '',
            'Source locations and written calls are lexical navigation aids; macros, linkage and indirect dispatch still need inspection.', '']
        if identity in draft_components:
            lines+=['**Unchecked C draft preserved.** The recorded comparisons below describe the previously published bytes. '
                'Compare this component before publishing its edits or assembling checked source.', '']
        lines+=render_boundary(unit,link=link,implementation=implementation,contract_path='source-export.json',
            adapter_note='supplied by the application/backend; recorded comparison bindings are listed below')
        lines+=['', '## Assumptions and admitted inputs', '',*['- '+_text(s) for s in record['assumptions']]]
        for label,value in [('Input domain',contract.get('input_domain')),
                            ('Local shared memory/service premises',record.get('local_shared_contract'))]:
            if value:lines+=['',label+':', '', '```json',json.dumps(value,indent=2,sort_keys=True),'```']
        lines+=['', '## Dependencies and shared representations', '']
        for requirement in record.get('requirements',[]):
            lines.append('- `'+_text(requirement['id'])+'` requires '+component_link(requirement['supplier'])+
                ' ('+_text(requirement['kind'])+'), contract `'+requirement['contract_sha256']+'`.')
        if not record.get('requirements'):lines.append('No authored-neighbor requirements recorded; the services above still need executable bindings.')
        consumers=_consumers(units,identity)
        lines+=['', 'Required by in this export: '+(', '.join(component_link(row['component_id'])+
            ' / `'+_text(row['requirement'])+'`' for row in consumers) or 'no declared consumers')+'.',
            'These are declared component requirements, not a complete application call graph. '
            'Ordinary implementation edits preserve them; a boundary change requires reviewing the affected requirements.']
        representation=contract.get('representation')
        if representation:
            lines+=['', 'Replacement group `'+_text(representation['group']['id'])+'`, revision `'+_text(representation['revision'])+
                '`; members '+', '.join(component_link(name) for name in representation['group']['members'])+'.']
            for name,digest in representation['inputs'].items():
                matching=[link(base+r['path']) for r in source['files']+source['shared_inputs'] if r['sha256']==digest]
                lines.append('- Shared input `'+_text(name)+'`, digest `'+digest+'`; exported files with this digest: '+(', '.join(matching) or 'not present')+'.')
        for group in record.get('recursion_groups',[]):
            lines.append('- Recursive group `'+_text(group['id'])+'`: '+', '.join(component_link(name) for name in group['members'])+'; progress is not established by this guide.')
        lines+=['', 'All exported components: '+link('README.md','library index')+'.',
            'A matching signature alone does not establish compatibility. Shared state or service changes require reviewing affected consumers.', '',
            '## Recorded comparisons and examples', '',
            'These cases exercised their recorded comparison selection. They are not exhaustive inputs or evidence that every selected component ran. '
            'Drivers, original runtime files and replay inputs remain in the separate comparison results.', '']
        references=record.get('comparison_binding_references',[])
        for reference in references:
            receipt=receipts[reference['comparison_receipt_sha256']]
            lines+=['- Receipt `'+receipt['receipt_sha256']+'`: '+_text(receipt['scope']),
                '  Comparison entry: '+('`'+_text(receipt['component_id'])+'`' if receipt.get('component_id') else 'not retained in this older export')+'.',
                '  Case names: '+_text(', '.join(receipt['cases']))+'.',
                '  Observations: '+_text(', '.join(receipt.get('observation_fields',[])) or 'not retained in this older export')+'.',
                '  Original kind: '+_text(receipt.get('original',{}).get('kind','not retained in this older export'))+'.',
                '  Formal check recorded: '+_text(json.dumps(receipt.get('formal_check'),sort_keys=True))+'.']
            if reference['service_bridge'] is not None:
                lines+=['', 'Comparison binding example (not a selected portable backend):', '',
                    '```json',json.dumps(reference['service_bridge'],indent=2,sort_keys=True),'```','']
        if not references:lines.append('This older export has no per-component comparison references; inspect the library provenance without assuming per-component coverage.')
        entries=sorted({receipts[r['comparison_receipt_sha256']]['component_id'] for r in references
            if receipts[r['comparison_receipt_sha256']].get('component_id')})
        entry=identity if identity in entries else entries[0] if entries else 'COMPARISON_ENTRY'
        lines+=['', 'Full provenance and binding references: '+link('source-export.json')+'.', '',
            '## Edit and compare', '',
            'Keep the local comparison result separately, including its inputs and build outputs. After editing C here, import it as an unverified draft:', '', '```sh',
            shlex.join(['spaghetti-extractor','component','start',report['target_id'],identity,'--comparison-result','LOCAL_CHECK',
                '--reuse-source','EXPORTED_LIBRARY','--output','DRAFT']),
            shlex.join(['spaghetti-headless-wayland','spaghetti-extractor','component','check',report['target_id'],entry,
                '--comparison-package','DRAFT','--history','CHECKS','--history-baseline','LOCAL_CHECK']),
            shlex.join(['spaghetti-extractor','candidate','export',report['target_id'],'--comparison','CHECKS/latest',
                '--output','EXPORTED_LIBRARY','--update-components','--component',identity]), '```', '',
            'Replace the uppercase paths with your directories. LOCAL_CHECK retains the native oracle, adapters and cases, '
            'plus reusable comparison work. Opening it does not execute code or assure edited C. '
            'Repeat the check command after edits: the first check uses LOCAL_CHECK, then subsequent checks reuse CHECKS/latest. '
            '`latest` can be a mismatch or failure; export still requires a matching result. '
            'If only a prepared package is available, start with `--comparison-package LOCAL_PACKAGE` and follow its printed check command; '
            'this source library alone supplies neither replay nor new assurance. The Wine wrapper is required for Wine comparisons.', '',
            ('Use a LOCAL_CHECK with comparison entry `'+_text(entry)+'` containing `'+_text(identity)+'`. '
             'Starting the workspace focuses this component; checking executes the enclosing comparison entry. '
             'If using a different caller setup, use the check command printed by `component start`.' if entries else
             'The older export does not record a comparison entry. Replace COMPARISON_ENTRY with the entry in the check command '
             'printed by `component start`; a supplier may be exercised through a caller rather than its own fixture.'), '',
            'The export input may instead be any matching consumer comparison containing this unit. '
            '`--component` publishes only this unit and preserves neighboring C drafts with their previous comparison records. '
            'It does not create an independent local check.', '',
            'For file splits/renames, open a local comparison draft with repeatable `--source-file source/NAME=FILE`, '
            '`--remove-source source/OLD_NAME` and `--private-header source/NEW_HEADER` options on `component start`. '
            'Combine these with `--reuse-source EXPORTED_LIBRARY` above to name files edited here; '
            'an explicitly retired implementation file may already have been removed from this project. '
            'Other authored files remain selected. Keep listed originals in comparison workspaces until the tools retire them. '
            'Boundary and shared-header changes use the authoring/refinement workflow and explicit export integration review. '
            'Rebuild and exercise affected program workloads after updating. Keep personal notes outside this generated README.', '']
        (root/unit['guide']).write_text('\n'.join(lines))
        index.append('- ['+_text(identity)+']('+quote(unit['guide'],safe='/')+')'+
            (' — unchecked C draft' if identity in draft_components else ''))
    readme=root/'README.md';text=readme.read_text();marker='\n## Component boundaries\n'
    if marker in text:text=text.split(marker,1)[0]+'\n'
    readme.write_text(text+'\n'+'\n'.join(index)+'\n')
