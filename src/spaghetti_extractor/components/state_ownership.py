"""Reviewed state ownership in practical component boundaries, never proof rules.

Declarations travel with existing comparison contracts and source exports. C and
its runtime retain initialization, thread storage and destruction; the workbench
does not reset, serialize or infer the meaning of OS objects.
"""
from __future__ import annotations

import copy
from pathlib import PurePosixPath
import re


def checked_state_owners(value, *, sources=None):
    if value is None:
        return None
    if not isinstance(value, list) or not value:
        raise ValueError('state_owners must declare a nonempty list of state owners')
    identities = set()
    covered = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {
                'id', 'scope', 'sources', 'thread_state', 'lifetime', 'reset'}:
            raise ValueError('state owner requires id, scope, sources, thread_state, lifetime and reset')
        identity = row['id']
        if (not isinstance(identity, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', identity)
                or identity in identities):
            raise ValueError('state owner identity is invalid or repeated')
        identities.add(identity)
        if row['scope'] not in ('process', 'module-instance'):
            raise ValueError('runtime state requires process or module-instance scope')
        if row['thread_state'] not in ('none', 'runtime-managed'):
            raise ValueError('thread_state must be none or runtime-managed')
        if row['reset'] != 'process-restart':
            raise ValueError('practical state reset requires process-restart; OS state cannot be zeroed or copied')
        if not isinstance(row['lifetime'], str) or not row['lifetime'].strip():
            raise ValueError('state owner requires an explicit initialization/sharing/cleanup description')
        names = row['sources']
        if not isinstance(names, list) or not names or any(not isinstance(n, str) for n in names):
            raise ValueError('state owner sources must name authored C translation units')
        for name in names:
            path = PurePosixPath(name)
            if (path.is_absolute() or '..' in path.parts or str(path) != name
                    or path.suffix != '.c' or name in covered):
                raise ValueError('state owner source is invalid or has multiple owners: '+name)
            if sources is not None and name not in sources:
                raise ValueError('state owner source is not an authored translation unit: '+name)
            covered.add(name)
    return copy.deepcopy(value)


def unit_state_owners(unit):
    """Names stay local to the component when it becomes a selected dependency."""
    identity = unit.get('component_id', unit.get('id'))
    prefix = '' if 'component_id' in unit else 'dependencies/'+identity+'/'
    names = [name.removeprefix(prefix+'source/') for name in unit['sources']]
    return checked_state_owners(unit.get('state_owners'), sources=names)


def check_state_owner_selection(declarations):
    """One selected implementation per declared state identity in an assembly.

    This catches duplicate providers. Ordinary C entry/service bindings still have
    to route consumers to that provider; a declaration is not an aliasing proof.
    """
    owners = {}
    for component, value in declarations.items():
        for row in checked_state_owners(value) or []:
            if row['id'] in owners:
                raise ValueError('shared runtime state '+row['id']+' has multiple providers: '+
                                 owners[row['id']]+' and '+component)
            owners[row['id']] = component
    return owners


def state_owner_guidance(value):
    rows = checked_state_owners(value)
    if rows is None:
        return []
    lines = ['','Shared runtime state (declared assumptions, not proved lifecycle rules):','']
    for row in rows:
        lines += ['- `'+row['id']+'`: '+row['scope']+'; thread state '+row['thread_state']+
                  '; reset by process restart. Authored storage: '+', '.join(row['sources'])+'.',
                  '  '+row['lifetime'].replace('\n', ' ')]
    return lines
