"""Reuse retained concrete observations, without claiming a fresh execution.

This is deliberately conservative about inputs and process environment. It does
not establish a deterministic fixture, infer contract compatibility, or upgrade
the authority of the evidence being reused.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import time

from ..util import sha256_file, sha256_text, write_json
from .comparison_package import package_file

REUSED_FIELDS = ('cases', 'status', 'binary_sha256', 'compiler_dependencies')
CONTEXT_FIELDS = ('input_sha256s', 'tools', 'case_selection', 'execution_context', 'runtime_state')


def comparison_execution_context() -> dict:
    from .comparison_capture import RESOURCES, SOURCES
    # Generated interfaces and current source-profile checks are bound separately.
    # Environment values may contain secrets: retain only an aggregate digest.
    return {
        'engine_sha256s': {p.name: sha256_file(p) for p in [*sorted(Path(__file__).parent.glob('comparison_*.py')), Path(__file__).parents[1]/'execution.py', Path(__file__).parent/'service_authoring.py', Path(__file__).parent/'service_c.py', Path(__file__).parent/'source_profile.py', Path(__file__).parent/'source_dialect.py', Path(__file__).parent/'state_ownership.py']},
        'python_sha256': sha256_file(Path(sys.executable)),
        'capture_sha256s': {name:sha256_file(RESOURCES/name) for name in SOURCES},
        'environment_sha256': sha256_text(json.dumps(dict(os.environ), sort_keys=True)),
    }


def comparison_runtime_state(plan: dict) -> dict:
    state=dict(process_scope='fresh-per-case',case_state='suite-shared',
        comparison_sides='private-working-directory-and-prefix',
        external_state='absolute-host-paths-and-external-services-not-isolated',
        explicit_server_persistence=plan['tools']['server'] is not None)
    if plan.get('program_driver',{}).get('process'):
        state.update(comparison_sides='private-files-and-prefixes-at-one-executable-path',
            untouched_original_control=True,program_arguments='case-arguments-without-side-prefix',
            observer_report='SPX_COMPARISON_REPORT',unexpected_working_directory_mutations='rejected')
        from .comparison_files import mutable_files
        files=mutable_files(plan['program_driver'])
        if files:
            state['mutable_files']=dict(names=files,initial_state='runtime-input-or-absent',
                persistence='suite-shared-per-side',observations='per-case-presence-and-exact-bytes')
    return state


def assess_comparison_reuse(*, previous: Path, prior: dict, package: Path,
                            current: dict, rerun: bool = False, plan: dict | None = None) -> dict:
    """Read the existing reuse conditions without retaining or executing evidence."""
    changed=sorted(name for name in prior['input_sha256s'].keys() | current['input_sha256s'].keys()
        if prior['input_sha256s'].get(name) != current['input_sha256s'].get(name))
    from .comparison_package import load_comparison_package
    from .comparison_compile_cache import irrelevant_header_changes
    if plan is None:plan,_=load_comparison_package(package)
    valid,ignored=irrelevant_header_changes(previous=previous,package=package,plan=plan,changed=changed)
    reasons = [field for field in CONTEXT_FIELDS if field!='input_sha256s' and prior.get(field) != current[field]]
    if set(changed)-set(ignored):reasons.append('input_sha256s')
    if not valid:reasons.append('compiler inputs or include resolution require revalidation')
    if prior['status'] != 'match':
        reasons.append('previous comparison did not match')
    if rerun:
        reasons.append('fresh execution requested')
    # Compiler-read system headers can live outside the explicit fixture package.
    # Recheck them rather than trusting a stable compiler executable alone.
    for name, digest in prior['compiler_dependencies'].items():
        relative=next((key for key in current['input_sha256s'] if name.endswith('/inputs/'+key)),None)
        path = package/relative if relative else Path(name)
        if not path.is_file() or sha256_file(path) != digest:
            reasons.append('compiler dependency: ' + name)
    return dict(receipt_sha256=prior['receipt_sha256'],reasons=reasons,
        changed_inputs=changed,ignored_unread_headers=ignored)


def try_reuse_comparison(*, previous: Path, output: Path, current: dict,
                         prior: dict, plan: dict, rerun: bool = False) -> bool:
    """Use the prior receipt and current plan validated by run_comparison."""
    started = time.monotonic()
    assessment=assess_comparison_reuse(previous=previous,prior=prior,package=output/'inputs',
        current=current,plan=plan,rerun=rerun)
    current['timings'].append({'phase': 'evidence-validation', 'seconds': time.monotonic() - started})
    current['reuse'] = {**assessment,'status':'invalidated' if assessment['reasons'] else 'reused'}
    if assessment['reasons']:
        return False
    started = time.monotonic()
    for name in prior['artifact_sha256s']:
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(package_file(previous, name), destination)
    archive = output / 'reuse/source-result.json'
    archive.parent.mkdir()
    write_json(archive, prior)
    for field in REUSED_FIELDS:
        current[field] = prior[field]
    current['timings'].append({'phase': 'evidence-retention', 'seconds': time.monotonic() - started})
    return True


def validate_reused_comparison(output: Path, current: dict) -> None:
    from .comparison_run import comparison_result_identity
    reuse = current.get('reuse')
    if not reuse or reuse['status'] != 'reused':
        return
    prior = json.loads(package_file(output, 'reuse/source-result.json').read_text())
    digest = comparison_result_identity({k: v for k, v in prior.items() if k != 'receipt_sha256'})
    if digest != prior.get('receipt_sha256') or digest != reuse['receipt_sha256']:
        raise ValueError('reused comparison source identity is stale')
    for field in (*REUSED_FIELDS, *CONTEXT_FIELDS, 'artifact_sha256s'):
        # Older receipts predate explicit runtime scope. They remain readable,
        # but try_reuse_comparison invalidates them against a new scoped run.
        observed = current.get(field) if field == 'runtime_state' else current[field]
        if field=='input_sha256s' and reuse.get('ignored_unread_headers'):
            from .comparison_package import load_comparison_package
            from .comparison_compile_cache import irrelevant_header_changes
            plan,_=load_comparison_package(output/'inputs')
            changed=sorted(k for k in prior[field].keys()|current[field].keys() if prior[field].get(k)!=current[field].get(k))
            valid,ignored=irrelevant_header_changes(previous=output,package=output/'inputs',plan=plan,changed=changed,check_configuration=False)
            if not valid or ignored!=changed or ignored!=reuse['ignored_unread_headers']:
                raise ValueError('reused comparison has unjustified unread-header changes')
        elif prior.get(field) != observed:
            raise ValueError(f'reused comparison changed retained {field}')
    if current['status'] != 'match' or reuse['reasons'] or any(current['work_counts'].values()):
        raise ValueError('reused comparison claims new execution or nonmatching evidence')
