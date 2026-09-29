"""Replacement-group consistency for concrete comparison selections.

A matching declaration is not a representation theorem. Exact shared input
agreement, local results and real integration remain separate requirements.
Incomplete groups can be checked locally but cannot authorize experimental runs.
"""
from __future__ import annotations

from pathlib import Path

from .lifting_intent import normalize_lifting_group
from ..util import sha256_file


def checked_representation(value: object, identity: str) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {'group', 'revision', 'inputs'}:
        raise ValueError('representation requires group, revision and shared inputs')
    group = normalize_lifting_group(value['group'], 0)
    if identity not in group['members'] or group['id'] in group['members']:
        raise ValueError('component is absent from its representation replacement group')
    if not isinstance(value['revision'], str) or not value['revision']:
        raise ValueError('representation revision must be explicit')
    inputs = value['inputs']
    if not isinstance(inputs, dict) or not inputs or any(
            not isinstance(k, str) or not k or not isinstance(v, str) or not v
            for k, v in inputs.items()):
        raise ValueError('representation shared inputs must be named paths')
    return {'group': group, 'revision': value['revision'], 'inputs': inputs}


def representation_binding(root: Path, row: dict) -> dict | None:
    from .comparison_package import package_file
    value = checked_representation(row.get('representation'), row.get('id', row.get('component_id')))
    if value is None:
        return None
    files = {}
    for name, relative in value['inputs'].items():
        path = package_file(root, relative)
        if not any(path.resolve().is_relative_to((root/d).resolve()) for d in row['include_directories']):
            raise ValueError('representation shared input is outside component include directories')
        files[name] = sha256_file(path)
    return {**value, 'inputs': files}


def validate_representation_selection(root: Path, plan: dict, *, complete: bool = False) -> dict:
    rows = {plan['component_id']: plan, **{r['id']: r for r in plan.get('dependencies', [])}}
    bindings = {identity: representation_binding(root, row) for identity, row in rows.items()}
    groups = {}
    for identity, binding in bindings.items():
        if binding is None:
            continue
        group = binding['group']
        for member in group['members']:
            if member in bindings and bindings[member] != binding:
                raise ValueError(f'incompatible representation selection in group {group["id"]}: {identity} and {member}')
        missing = sorted(set(group['members']) - rows.keys())
        if complete and missing:
            raise ValueError(f'incomplete representation replacement group {group["id"]}: missing {", ".join(missing)}')
        if group['id'] in groups and groups[group['id']]['binding'] != binding:
            raise ValueError('replacement group identity has conflicting representation meanings')
        groups[group['id']] = {'binding': binding, 'missing_members': missing}
    return groups


def representation_policy(binding: dict | None) -> dict | None:
    return None if binding is None else {k: binding[k] for k in ('group', 'revision')}


def revise_representation_inputs(root: Path, plan: dict, updates: dict) -> None:
    """Apply reviewed shared inputs inside the existing preparation transaction.

    Each group names a new revision, replacement input files and the exact
    consumer/requirement names reviewed for the changed supplier contracts.
    This changes declarations, never proves representation compatibility.
    """
    from .comparison_composition import contract_identity
    from .comparison_package import package_file

    if not isinstance(updates, dict) or not updates or any(not isinstance(group, str) or not group for group in updates):
        raise ValueError('representation updates must name reviewed replacement groups')
    units = {plan['component_id']: plan, **{row['id']: row for row in plan.get('dependencies', [])}}
    members = {}; contents = {}; declarations = {}; reviews = {}
    for identity, unit in units.items():
        representation = checked_representation(unit.get('representation'), identity)
        if representation is not None:
            members.setdefault(representation['group']['id'], []).append(identity)
    if updates.keys() - members.keys():
        raise ValueError('representation update names an absent group: '+', '.join(sorted(updates.keys()-members.keys())))
    for group, update in updates.items():
        if not isinstance(update, dict) or set(update) != {'revision', 'inputs', 'reviewed_requirements'}:
            raise ValueError('representation update requires revision, inputs and reviewed_requirements')
        revision = update['revision']; inputs = update['inputs']; reviewed = update['reviewed_requirements']
        if not isinstance(revision, str) or not revision:
            raise ValueError('representation update requires a new explicit revision')
        if not isinstance(inputs, dict) or not inputs or any(not isinstance(name, str) for name in inputs):
            raise ValueError('representation update inputs must map existing names to reviewed files')
        if (not isinstance(reviewed, list) or any(not isinstance(name, str) for name in reviewed)
                or len(reviewed) != len(set(reviewed))):
            raise ValueError('reviewed representation requirements must be unique consumer/requirement names')
        reviews[group] = set(reviewed)
        supplied = {name: Path(path).read_bytes() for name, path in inputs.items()}
        for identity in members[group]:
            representation = units[identity]['representation']
            if revision == representation['revision']:
                raise ValueError('representation update must change the revision: '+group)
            if inputs.keys() - representation['inputs'].keys():
                raise ValueError('representation update names an absent shared input in '+identity)
            declarations[identity] = {**representation, 'revision': revision}
            for name, data in supplied.items():
                relative = representation['inputs'][name]
                previous = package_file(root, relative).read_bytes()
                if relative in plan['original']['files'] and previous != data:
                    raise ValueError('representation update cannot rewrite an original oracle input: '+relative)
                if relative in contents and contents[relative] != data:
                    raise ValueError('representation updates disagree on shared input: '+relative)
                contents[relative] = data
    for relative, data in contents.items():
        package_file(root, relative).write_bytes(data)
    for identity, declaration in declarations.items():
        units[identity]['representation'] = declaration
    validate_representation_selection(root, plan)
    contracts = {identity: contract_identity(root, units[identity]) for identity in declarations}
    required = {group: set() for group in updates}
    for identity, unit in units.items():
        for requirement in unit.get('requirements', []):
            supplier = requirement['supplier']
            if supplier in contracts and requirement['contract_sha256'] != contracts[supplier]:
                group = declarations[supplier]['group']['id']
                required[group].add(identity+'/'+requirement['id'])
    for group in updates:
        missing = required[group] - reviews[group]; extra = reviews[group] - required[group]
        if missing:
            raise ValueError('representation '+group+' needs reviewed requirements: '+', '.join(sorted(missing)))
        if extra:
            raise ValueError('representation review names an unaffected or absent requirement: '+', '.join(sorted(extra)))
    for unit in units.values():
        if 'requirements' in unit:
            unit['requirements'] = [dict(row, contract_sha256=contracts[row['supplier']])
                if row['supplier'] in contracts else row for row in unit['requirements']]
