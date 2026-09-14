"""Rebind suppliers of an unchanged local memory theorem without recompilation.

The consumer theorem is universal over the functional/frame dependency rule.
Supplier implementation evidence may change while that rule stays identical.
This transports auxiliary source guarantees, not binary equivalence or activation.
Original compiler/solver records and model bytes remain unchanged.
"""

import json
from pathlib import Path
import shutil
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_source_dependencies import READONLY_POLICY, MUTABLE_POLICY
from .machine_overlay_services_v5 import _c_identifier


def consumed_memory_contract(row):
    """Identify the actual auxiliary guarantee, not just its C signature.

Validation of the complete supplying certificate is a separate prerequisite.
Policies bind frame, opacity and input-dependence semantics. This deliberately
does not promise functional postconditions that the local checker never proves.
"""
    certificate = row['certificate']
    return {'symbol': row['symbol'], 'operation_id': row['operation_id'],
            'policy': certificate['policy'], 'model_policy': certificate['model_policy'],
            'interface_intent': certificate['interface_intent']}


def reuse_memory_consumer(*, previous, output, bundle, source, profile, headers,
                         dependencies, options, tools, mutable, shared_contract=None, timings=None):
    """Return a fully validated rebound certificate, or None for a changed use.

The caller has already copied and validated current supplier evidence. Validate
the previous consumer, preserve all its compiled artifacts, replace only supplier
evidence, and validate the resulting theorem with the current model renderer.
Unknown policy changes and changed consumer inputs take the normal checking path.
"""
    if previous is None or not dependencies:
        return None
    from .bisimulation_readonly_evidence import validate_readonly_source_contracts, validate_mutable_source_contracts
    from .bisimulation_readonly_evidence import validate_shared_source_contracts
    from .bisimulation_shared_model import SHARED_DEPENDENCY_POLICY

    started = time.monotonic()
    previous, output = Path(previous), Path(output)
    old = json.loads((previous / 'local-contract-result.json').read_text())
    if (old.get('policy') != (SHARED_DEPENDENCY_POLICY if shared_contract is not None else MUTABLE_POLICY if mutable else READONLY_POLICY)
            or old.get('shared_contract') != shared_contract
            or old.get('source_package') != source or old.get('source_profile') != profile
            or old.get('interface_intent') != bundle.intent.to_payload()
            or old.get('checker_options') != options
            or old.get('tools') != {name: sha256_file(path) for name, path in tools.items()}
            or old.get('headers_sha256') != canonical_sha256_v3(headers)):
        return None
    uses = [consumed_memory_contract(row) for row in dependencies]
    if uses != [consumed_memory_contract(row) for row in old['summary_dependencies']]:
        return None
    validator = (validate_shared_source_contracts if shared_contract is not None else
                 validate_mutable_source_contracts if mutable else validate_readonly_source_contracts)
    validator(old, artifacts=previous)
    # Only newly copied dependency directories may exist at this stage. No old
    # artifact or unrelated destination file may be overwritten by this path.
    expected = {f'dependency-{i:04d}' for i in range(len(dependencies))}
    if {path.name for path in output.iterdir()} != expected:
        raise ValueError('consumer reuse destination contains unexpected artifacts')
    for path in previous.iterdir():
        if path.name in expected:
            continue
        destination = output / path.name
        if path.is_dir():
            shutil.copytree(path, destination)
        else:
            shutil.copyfile(path, destination)
    core = {k: v for k, v in old.items() if k != 'receipt_sha256'}
    core['summary_dependencies'] = dependencies
    result = {**core, 'receipt_sha256': canonical_sha256_v3(core)}
    # This checks current generated C, headers, access rules, tool identities,
    # recorded inventories and complete solver outputs. It invokes no compiler
    # or solver and never rewrites an old model hash or query binding.
    validator(result, artifacts=output)
    for model in result['models']:
        name = _c_identifier(model['operation_id']) + '-' + model['kind']
        note = output / 'query-evidence' / name / 'reuse.json'
        # copytree preserves Nix store modes. Replace only the non-authorizing
        # reuse note in our owned copy; never chmod or edit retained input paths.
        note.parent.chmod(note.parent.stat().st_mode | 0o200)
        note.unlink(missing_ok=True)
        note.write_text(json.dumps({
            'authorizing': False, 'executed_queries': 0, 'reused_queries': 1,
            'previous_proof_receipt_sha256': old['receipt_sha256']}, sort_keys=True) + '\n')
    (output / 'local-contract-result.json').write_text(json.dumps(result, indent=2) + '\n')
    if timings is not None:
        timings.append({'phase': 'evidence-reuse', 'step': 'unchanged-consumer-contract-rebinding',
                        'seconds': time.monotonic() - started, 'executed_queries': 0,
                        'reused_queries': len(result['models']), 'compiler_runs': 0,
                        'consumer_models_rebuilt': 0,
                        'consumed_contract_sha256': canonical_sha256_v3(uses)})
    return result
