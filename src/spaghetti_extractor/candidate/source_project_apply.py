"""Stage component export, target assembly and optional checks as one operation.

Target recipes remain ordinary programs. Commands run without a shell in a copied
project, with {project} expanded to that copy. Publication retains the entire old
tree for recovery; failed preparation never publishes a half-updated selection.
"""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time

from ..util import write_json
from .source_export import export_comparison_sources
from .source_export_update import _inventory


def apply_project_sources(*, project: Path, target_id: str, assembly_command: str,
                          comparisons=(), component_ids=None, remove_component_ids=None,
                          accept_boundary_changes=(), check_commands=()):
    """Apply a desired selection; matching comparisons authorize source export only."""
    project = Path(project)
    if project.is_symlink() or not project.is_dir():
        raise ValueError('candidate apply requires an existing ordinary project directory')
    project = project.resolve()
    if not assembly_command or not shlex.split(assembly_command):
        raise ValueError('candidate apply requires an assembly command')
    if not comparisons and (component_ids or remove_component_ids or accept_boundary_changes):
        raise ValueError('selection changes require a retained comparison; omit selection flags for binding-only changes')
    before = _inventory(project)
    for name, row in before.items():
        if row[0] == 'link' and (os.path.isabs(row[2]) or not (project/name).resolve().is_relative_to(project)):
            raise ValueError('staged assembly requires relative links within the project: '+name)
    started = time.monotonic()
    transaction = Path(tempfile.mkdtemp(prefix=project.name+'.apply-', dir=project.parent))
    staged = transaction/'proposed'
    backup = transaction/'previous'
    report = dict(version=1, authority='source-provenance-only', status='preparing',
                  project=str(project), transaction=str(transaction), commands=[],
                  program_validation_required=True, strong_qualification=False)
    phase = 'copy'
    try:
        shutil.copytree(project, staged, symlinks=True, copy_function=shutil.copy2)
        phase = 'export'
        if comparisons:
            export = export_comparison_sources(comparisons=list(comparisons), target_id=target_id,
                output=staged/'lifted', update_components=True,
                component_ids=component_ids, remove_component_ids=remove_component_ids,
                accept_boundary_changes=list(accept_boundary_changes))
            # The library backup travels with the project on publication. Bind
            # its final location before assembly hashes the export manifest.
            backup_relative = Path(export['update']['backup']).relative_to(staged)
            export['update']['backup'] = str(project/backup_relative)
            write_json(staged/'lifted/source-export.json', export)
            report['export'] = export.get('update', {})
        else:
            from .source_export_bindings import load_source_export
            if load_source_export(staged/'lifted')['target_id'] != target_id:
                raise ValueError('candidate apply requires a source export for the same target')
        report['preparation_seconds'] = time.monotonic()-started
        for index, command in enumerate([assembly_command, *check_commands]):
            phase = 'assembly' if index == 0 else 'check'
            argv = [word.replace('{project}', str(staged)) for word in shlex.split(command)]
            if not argv:
                raise ValueError('empty project command')
            log = transaction/f'{index}-{phase}.log'
            command_started = time.monotonic()
            with log.open('w') as stream:
                ran = subprocess.run(argv, cwd=staged, stdout=stream, stderr=subprocess.STDOUT, check=False)
            report['commands'].append(dict(phase=phase, argv=argv, log=str(log),
                returncode=ran.returncode, seconds=time.monotonic()-command_started))
            if ran.returncode:
                raise ValueError(phase+' command failed; see '+str(log))
        after = _inventory(staged)
        report.update(changed_files=sorted(name for name, row in after.items() if before.get(name) != row),
                      removed_files=sorted(before.keys()-after.keys()),
                      retained_files=sorted(name for name, row in before.items() if after.get(name) == row),
                      checks_passed=len(check_commands), backup=str(backup))
        phase = 'publish'
        if _inventory(project) != before:
            raise ValueError('working project changed during preparation; retry with the current edits')
        # Same filesystem renames preserve copied object/source mtimes. Recheck
        # after moving the original so a concurrent edit cannot silently vanish.
        project.rename(backup)
        try:
            if _inventory(backup) != before:
                raise ValueError('working project changed during publication; original restored')
            staged.rename(project)
        except BaseException:
            backup.rename(project)
            raise
        report.update(status='applied', seconds=time.monotonic()-started)
    except Exception as failure:
        report.update(status='failed', phase=phase, error=str(failure), seconds=time.monotonic()-started)
        write_json(transaction/'apply-result.json', report)
        raise ValueError(str(failure)+'; preparation retained at '+str(transaction)) from failure
    write_json(transaction/'apply-result.json', report)
    return report
