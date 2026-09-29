"""Practical C admission, separate from the unchanged formal source profile.

Storage is inspected in compiler output, not classified by spelling C types.
This is a toolchain observation, not a proof of effects or pointee immutability.
"""
from __future__ import annotations

from pathlib import Path
import os
import re
import shutil
import subprocess

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, sha256_text

PRACTICAL_PROFILE_ID = 'portable-component-c11-practical-v2'


def inspect_object_storage(compiler: Path, object_path: Path) -> dict:
    """Observe allocated data sections in the selected compiler's ordinary object."""
    environment = {**os.environ, 'LC_ALL': 'C'}
    try:
        name = subprocess.check_output([str(compiler), '-print-prog-name=objdump'],
                                      text=True, env=environment, timeout=15).strip()
        target = subprocess.check_output([str(compiler), '-dumpmachine'], text=True, env=environment, timeout=15).strip()
        executable = (shutil.which(target+'-objdump') if name == 'objdump' else None) or shutil.which(name)
        if executable is None:
            raise ValueError('compiler objdump is unavailable; use the lifting shell')
        text = subprocess.check_output([executable, '-h', '-t', str(object_path)],
                                       text=True, stderr=subprocess.STDOUT, env=environment, timeout=15)
        if not re.search(r'file format (?:elf\S*|pe\S*)', text) or 'Sections:' not in text:
            raise ValueError('storage inspection requires an ordinary ELF or COFF object')
        sections = []
        lines = text.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r'^\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+2\*\*\d+', line)
            if match is None:
                continue
            section, size = match[1], int(match[2], 16)
            flags = {flag.strip() for flag in lines[index+1].split(',')}
            if not size or 'ALLOC' not in flags or 'CODE' in flags:
                continue
            readonly = 'READONLY' in flags or section == '.data.rel.ro' or section.startswith('.data.rel.ro.')
            sections.append(dict(name=section, size=size, readonly=readonly, index=int(line.split()[0])))
        common = any('*COM*' in line for line in lines)
        writable = [row['name'] for row in sections if not row['readonly']]
        writable_indices = {row['index']+1 for row in sections if not row['readonly']}
        symbols = set()
        for line in text.partition('SYMBOL TABLE:')[2].splitlines():
            fields = line.split()
            coff = re.match(r'^\[\s*\d+\]\(sec\s+(\d+)\)', line)
            if fields and (coff and int(coff[1]) in writable_indices
                           or not coff and any(section in fields for section in writable)):
                if fields[-1] not in writable:
                    symbols.add(fields[-1])
        if common:
            writable.append('COMMON')
        return dict(status='satisfied' if not writable else 'incomplete', sections=sections,
                    writable_sections=writable, writable_symbols=sorted(symbols), object_sha256=sha256_file(object_path),
                    inspector=dict(path=executable, sha256=sha256_file(Path(executable))),
                    output_sha256=sha256_text(text),
                    scope='allocated object storage; referenced objects, lifetime compatibility and effects require boundary observations')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return dict(status='incomplete', diagnostic=str(error), object_sha256=sha256_file(object_path))


def practical_source_profile(proof_profile: dict, storage: list[dict] | None = None, *, state_owners=None) -> dict:
    """Admit compiled C independently of formal syntax; inspect every authored TU.

    Compilation/linking and executable boundary setup are checked by the caller.
    The unchanged formal profile is feedback, never a practical syntax gate.
    In particular, raw tokens cannot identify active calls or macro-defined state.
    """
    from .state_ownership import checked_state_owners
    state = checked_state_owners(state_owners)
    owners = {name:row['id'] for row in state or [] for name in row['sources']}
    issues = []
    if storage is not None:
        if not storage:
            issues.append(dict(status='incomplete', code='practical_storage_inspection_missing'))
        for row in storage:
            if row['status'] != 'satisfied':
                if (row.get('authored_source', row.get('source')) in owners
                        and row.get('writable_sections') and not row.get('diagnostic')):
                    continue
                issues.append(dict(status='incomplete', code='practical_persistent_storage_requires_context',
                    source=row.get('source'), diagnostic=row.get('diagnostic') or
                    'Writable persistent storage needs an explicit context or state_owners declaration '
                    '(component start --state-owners FILE): '+
                    ', '.join(row.get('writable_symbols') or row.get('writable_sections', []))))
    core = dict(profile_id=PRACTICAL_PROFILE_ID, component_id=proof_profile['component_id'],
                bindings=proof_profile['bindings'], issues=issues,
                status='incomplete' if issues else 'pending-storage' if storage is None else 'satisfied',
                storage_check=storage, proof_profile=proof_profile,
                policy=dict(formal_profile_required_for_execution=False, compiler_semantics_assumed_correct=True,
                            syntax_checked_by='selected C compiler', runtime_effects_checked=False,
                            immutable_storage_duration='C static lifetime', referenced_objects_implicitly_immutable=False))
    if state is not None:
        core.update(profile_id='portable-component-c11-practical-v3', state_owners=state)
        core['policy'].update(state_lifecycle_proved=False, state_reset='process-restart',
                              state_ownership='operator-declared; compiled storage inventoried')
    return {**core, 'receipt_sha256': canonical_sha256_v3(core)}
