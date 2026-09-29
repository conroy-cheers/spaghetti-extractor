"""Shared source-handoff provenance and editable C under existing component contracts.

These readers grant no qualification or permission to activate a provider.
They require no candidate assembly, original runtime, compiler or comparison run.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .comparison_package import package_file
from .comparison_source_draft import DraftFiles, SourceDraft, checked_source_draft_inputs, edited_draft_files
from .formats import COMPONENT_SOURCE_PACKAGE_V3_FORMAT
from .interface_package_v5 import ComponentInterfaceIntentV1
from .service_authoring import ServiceDefinition, checked_service_catalog, service_catalog, services_from_interface, service_types
from .source import (load_component_source_package, load_component_source_workspace,
    _canonical_sha256, checked_private_headers, _build_path, checked_source_build)


def load_source_export(root: Path) -> dict:
    """Recheck listed source inputs and boundaries; ignore ordinary build outputs."""
    return _load_source_export(root, allow_c_drafts=False)[0]


def source_export_workspace(root: Path) -> tuple[dict, dict[str, str]]:
    """Inspect recorded export provenance and separately identify unchecked C edits."""
    return _load_source_export(root, allow_c_drafts=True)


def services_from_source_export(root: Path, *, names: dict[str, str]) -> dict[str, ServiceDefinition]:
    """Select exact declarations as LOCAL_NAME -> COMPONENT/SERVICE.

    Ordinary C drafts do not change these recorded boundaries. This imports no
    implementation, adapter, transport, comparison setup or evidence. The original
    comparison bindings in an export are examples, not current backend choices.
    """
    if not isinstance(names,dict) or not names or any(not isinstance(n,str) or not n for n in names):
        raise ValueError('source service selection needs nonempty local names')
    report,_=source_export_workspace(root)
    selected={};references={}
    for local,reference in names.items():
        if not isinstance(reference,str) or len(reference.split('/'))!=2 or not all(reference.split('/')):
            raise ValueError('source service reference must be COMPONENT/SERVICE: '+str(reference))
        owner,name=reference.split('/')
        if owner not in report['components']:
            raise ValueError('source export has no component: '+owner)
        references[local]=(owner,name)
        selected.setdefault(owner,set()).add(name)
    definitions={}
    for owner,needed in selected.items():
        unit=report['components'][owner]
        interface=ComponentInterfaceIntentV1.parse(json.loads(package_file(root,unit['interface']).read_text()))
        definitions[owner]=services_from_interface(interface,unit['contract'].get('service_catalog'),names=sorted(needed))
    services={local:definitions[owner][name] for local,(owner,name) in references.items()}
    service_types(services)  # Shared nominal and nested declarations must agree.
    service_catalog(services)  # Aliases may share an exact contract, not conflicting definitions.
    return services


def source_private_headers(unit: dict, source: dict) -> list[str]:
    """Read author-declared private headers; representation inputs remain shared."""
    shared=set(((unit.get('contract') or {}).get('representation') or {}).get('inputs',{}).values())
    return checked_private_headers(unit.get('private_headers'),[row['path'] for row in source['files']],
        protected=[row['path'] for row in source['files'] if row['sha256'] in shared])


def _load_source_export(root: Path, *, allow_c_drafts: bool) -> tuple[dict, dict[str, str]]:
    report = json.loads(package_file(root, 'source-export.json').read_text())
    if (not isinstance(report, dict) or report.get('version') != 1
            or report.get('authority') != 'source-provenance-only'
            or report.get('scope') != 'component-library'
            or report.get('qualification') is not False
            or report.get('whole_program_portable') is not False):
        raise ValueError('unsupported source export provenance or authority')
    files = report.get('files')
    if not isinstance(files, dict) or not files or 'source-export.json' in files:
        raise ValueError('source export requires its source file inventory')
    stale = {}; drafts = {}
    for name, digest in files.items():
        if (not isinstance(name, str) or _build_path(name) != name
                or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise ValueError('source export input is stale or invalid: '+str(name))
        actual = sha256_file(package_file(root, name))
        if actual != digest:
            if not allow_c_drafts:
                raise ValueError('source export input is stale or invalid: '+name)
            stale[name] = actual
    components = report.get('components')
    if not isinstance(components, dict) or not components:
        raise ValueError('source export requires a component selection')
    comparisons = report.get('comparisons')
    if (not isinstance(comparisons, list) or not comparisons
            or any(not isinstance(row, dict) or not isinstance(row.get('receipt_sha256'), str)
                or not re.fullmatch('[0-9a-f]{64}', row['receipt_sha256']) for row in comparisons)):
        raise ValueError('source export requires comparison provenance')
    receipts = {row['receipt_sha256'] for row in comparisons}
    for row in comparisons:
        if 'component_id' in row and (not isinstance(row['component_id'],str) or not row['component_id']):
            raise ValueError('source export comparison entry must be a nonempty component identity')
    for identity, unit in components.items():
        required = {'source_package', 'interface', 'implementation_sha256', 'operation_symbols',
                    'interface_sha256', 'contract', 'contract_sha256', 'assumptions', 'required_services'}
        if (not isinstance(identity, str) or not isinstance(unit, dict) or required - unit.keys()
                or not isinstance(unit.get('contract'), dict)):
            raise ValueError('source export component metadata is incomplete: '+str(identity))
        for role in ('source_package', 'interface'):
            if not isinstance(unit[role], str) or unit[role] not in files:
                raise ValueError('source export component input is not inventoried: '+identity)
        manifest = package_file(root, unit['source_package'])
        if allow_c_drafts:
            source, edits = load_component_source_workspace(manifest,private_headers=unit.get('private_headers'))
            base = Path(unit['source_package']).parent/'sources'
            drafts.update({(base/name).as_posix(): digest for name, digest in edits.items()})
            for row in source['files'] + source['shared_inputs']:
                name = (base/row['path']).as_posix()
                if files.get(name) != row['sha256']:
                    raise ValueError('source export recorded source binding is stale: '+name)
        else:
            source = load_component_source_package(manifest)
        source_private_headers(unit,source)
        if 'build' in unit:checked_source_build(unit['build'],source)
        interface = ComponentInterfaceIntentV1.parse(json.loads(package_file(root, unit['interface']).read_text()))
        if (source['lift_unit_id'] != identity or interface.component_id != identity
                or source['implementation_sha256'] != unit['implementation_sha256']
                or source['operation_symbols'] != unit['operation_symbols']
                or files[unit['interface']] != unit['interface_sha256']
                or unit['contract'].get('interface') != interface.intent_sha256
                or unit['contract'].get('operation_symbols') != unit['operation_symbols']
                or unit['contract'].get('assumptions') != unit['assumptions']
                or canonical_sha256_v3(unit['contract']) != unit['contract_sha256']
                or unit['required_services'] != interface.to_payload()['services']):
            raise ValueError('source export component identity or boundary is stale: '+identity)
        checked_service_catalog(unit['contract'].get('service_catalog'), interface)
        from .state_ownership import checked_state_owners
        checked_state_owners(unit['contract'].get('state_owners'),sources=[row['path'].removeprefix('source/') for row in source['files']])
        references = unit.get('comparison_binding_references', [])
        if not isinstance(references, list):
            raise ValueError('source export binding references must be a list: '+identity)
        for reference in references:
            if (not isinstance(reference, dict)
                    or set(reference) != {'comparison_receipt_sha256', 'service_bridge'}
                    or not isinstance(reference['comparison_receipt_sha256'], str)
                    or reference['comparison_receipt_sha256'] not in receipts
                    or (reference['service_bridge'] is not None and not isinstance(reference['service_bridge'], dict))):
                raise ValueError('source export binding reference is unbound: '+identity)
    from .state_ownership import check_state_owner_selection
    check_state_owner_selection({name:unit['contract'].get('state_owners') for name,unit in components.items()})
    if stale != drafts:
        raise ValueError('source export input is stale or invalid: '+', '.join(sorted(stale.keys() ^ drafts.keys())))
    return report, drafts


def source_export_draft(root: Path, *, package: Path, plan: dict,
                        component_id: str | None = None, selection: SourceDraft | None = None) -> DraftFiles:
    """Read this unit's edited C as a draft, never as matching source provenance.

    Other units may also be under edit. Explicit file edits can add or retire
    implementation files; the boundary and shared inputs must still match.
    A named supplier uses the existing consumer boundary and adapters. Returned
    paths belong to that workspace; no local oracle or supplier selection is made.
    """
    from .comparison_composition import contract_binding
    selection=selection or SourceDraft(root)
    replaced=set(selection.source_edits or {});removed=set(selection.remove_sources or [])
    whole_plan=plan
    target=plan['target_id'];identity=component_id or plan['component_id'];prefix=''
    if identity!=plan['component_id']:
        selected={row['id']:row for row in plan.get('dependencies',[])}
        if identity not in selected:
            raise ValueError('source draft names a dependency absent from this comparison: '+identity)
        plan=selected[identity];prefix='dependencies/'+identity+'/'
    report=json.loads(package_file(root,'source-export.json').read_text())
    if (not isinstance(report,dict) or report.get('version')!=1
            or report.get('authority')!='source-provenance-only'
            or report.get('scope')!='component-library' or report.get('qualification') is not False
            or report.get('whole_program_portable') is not False
            or report.get('target_id')!=target):
        raise ValueError('source draft requires a source export for the same target')
    unit=report.get('components',{}).get(identity)
    if not isinstance(unit,dict):raise ValueError('source export has no component '+identity)
    files=report.get('files',{})
    def bound(name):
        path=package_file(root,name)
        if not isinstance(files,dict) or files.get(name)!=sha256_file(path):
            raise ValueError('source draft boundary/metadata changed: '+name+'; review it in the comparison workspace')
        return path
    source=json.loads(bound(unit['source_package']).read_text())
    interface=ComponentInterfaceIntentV1.parse(json.loads(bound(unit['interface']).read_text()))
    core={key:value for key,value in source.items() if key!='implementation_sha256'}
    if (source.get('format')!=COMPONENT_SOURCE_PACKAGE_V3_FORMAT
            or source.get('implementation_sha256')!=_canonical_sha256(core)
            or source.get('implementation_sha256')!=unit.get('implementation_sha256')
            or source.get('lift_unit_id')!=identity
            or source.get('operation_symbols')!=plan['operation_symbols']):
        raise ValueError('source draft package identity is stale or belongs to another component')
    if (interface.intent_sha256!=unit['contract'].get('interface')
            or unit['contract']!=contract_binding(package,plan)
            or canonical_sha256_v3(unit['contract'])!=unit.get('contract_sha256')):
        raise ValueError('source export boundary differs from the comparison workspace; refine the boundary before importing C')
    authored=source.get('files',[]);shared=source.get('shared_inputs',[])
    if not isinstance(authored,list) or not isinstance(shared,list):
        raise ValueError('source draft requires authored and shared file inventories')
    private=source_private_headers(unit,source)
    base=Path(unit['source_package']).parent/'sources';carried={};listed=set();editable=set()
    for rows,role in ((authored,'source'),(shared,'shared_input')):
        for row in rows:
            name=_build_path(row['path']);relative=(base/name).as_posix()
            if name in listed or row.get('role')!=role or files.get(relative)!=row.get('sha256'):
                raise ValueError('source draft has inconsistent file roles or bindings: '+name)
            listed.add(name)
            if role=='source' and (name.endswith('.c') or name in private):
                editable.add(name)
                # An explicitly retired/replaced implementation need not survive
                # a physical rename. The placeholder is removed before checking.
                carried[prefix+name]=b'' if name in replaced|removed else package_file(root,relative).read_bytes()
            else:
                bound(relative)
                if ((role=='shared_input' or prefix+name in plan['sources'])
                        and sha256_file(package_file(package,prefix+name))!=row['sha256']):
                    raise ValueError('source draft shared/header input differs from the comparison workspace: '+name)
                if role=='source':carried[prefix+name]=package_file(root,relative).read_bytes()
    actual={p.relative_to(root/base).as_posix() for p in (root/base).rglob('*') if p.is_file()}
    unlisted=actual-listed-replaced;missing=listed-actual-((replaced|removed)&editable)
    if unlisted or missing:
        raise ValueError('source draft has undeclared file changes: missing='+str(sorted(missing))+
            ', unlisted='+str(sorted(unlisted))+'; name implementation changes with --source-file and --remove-source')
    draft=edited_draft_files(DraftFiles(carried,[prefix+name for name in private]),selection,prefix=prefix)
    if set(draft.files) & {prefix+row['path'] for row in shared}:
        raise ValueError('source draft shared inputs cannot become authored files')
    for row in authored:
        name=row['path']
        if not name.endswith('.c') and name not in private and (
                draft.files.get(prefix+name)!=carried[prefix+name] or prefix+name in draft.private_headers):
            raise ValueError('source draft authored header changed: '+name+'; review the boundary and shared inputs')
    return checked_source_draft_inputs(package,whole_plan,plan,draft.files,private_headers=draft.private_headers)
