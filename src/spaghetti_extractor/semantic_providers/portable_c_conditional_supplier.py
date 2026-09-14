"""Load conditional shared suppliers without inventing native qualification.

This admits evidence into caller preparation. The caller still regenerates the
adapters and discharges the emitted entry, alias, memory and frame obligations.
"""
import json
from pathlib import Path

from ..util import sha256_file
from ..components.bisimulation_assurance import admitted_supplier_assurance
from ..components.conditional_check_result import checked_conditional_packet
from ..components.contextual_bisimulation import validate_complete_local_refinement
from ..components.bisimulation_readable_entry import checked_memory_summary_facts
from ..components.bisimulation_readonly_evidence import validate_shared_source_contracts
from ..components.bisimulation_shared_model import SHARED_CONTRACT_POLICY
from .portable_c_postconditions import normal_exit_intent


def load_conditional_supplier(*, paths, component_id, parent_assurance, bundle, contract, binding,
                              binding_model, operations, source_root, source, symbols, profile,
                              slice_id, transfer_plan_sha256):
    if 'qualification' in paths or 'contextual_refinement' in paths:
        raise ValueError('conditional supplier must not mix qualification and conditional evidence')
    path = Path(paths['conditional_refinement'])
    root = path.parent
    load = lambda name: json.loads((root/name).read_text())
    proof = json.loads(path.read_text())
    packet = load('conditional-engine-result.json')
    result, selection = checked_conditional_packet(packet, component_id)
    if (result.get('boundary_requirements') or result.get('selected_obligations')
            or contract.status != 'checked' or binding.status != 'checked'):
        raise ValueError('conditional supplier has unresolved boundary requirements')
    if admitted_supplier_assurance(proof, parent_assurance) != selection:
        raise ValueError('conditional supplier packet and theorem assumptions differ')
    system = {'proof': proof, 'proof_plan': load('component-proof-plan-v1.json'),
              'exact_c_slice': load('exact-c/component-exact-c-slice-v1.json')}
    validate_complete_local_refinement(system, runtime_assurance=selection)
    models = proof['models']
    if (proof['checker'] != result['checker'] or proof['shards'] != result['checks']
            or {k: v for k, v in models.items() if k != 'source_summary_contracts'} != result['bindings']
            or proof['status'] != result['status'] or proof['component_id'] != component_id):
        raise ValueError('conditional supplier theorem differs from its engine packet')
    expected = {'component_id': component_id, 'semantic_slice_sha256': slice_id,
                'binding_intent_sha256': binding_model.intent_sha256,
                'interface_sha256': bundle.interface.interface_sha256,
                'schema_sha256': bundle.interface.schema_sha256,
                'implementation_sha256': source['implementation_sha256'],
                'executable_transfer_plan_sha256': transfer_plan_sha256}
    if (any(packet['inputs'].get(k) != v for k, v in expected.items())
            or models['source_profile_sha256'] != profile['receipt_sha256']):
        raise ValueError('conditional supplier current source, interface, slice or transfer binding differs')
    summary = models.get('source_summary_contracts', {})
    certificate = summary.get('certificate', {})
    if certificate.get('policy') != SHARED_CONTRACT_POLICY:
        raise ValueError('conditional supplier requires a checked shared source contract')
    artifacts = root/'source-summary-contracts'
    if packet['inputs'].get('shared_source_contract_file_sha256') != sha256_file(artifacts/'local-contract-result.json'):
        raise ValueError('conditional supplier source contract request is stale')
    if json.loads((artifacts/'local-contract-result.json').read_text()) != certificate:
        raise ValueError('conditional supplier source certificate differs from its theorem')
    validate_shared_source_contracts(certificate, artifacts=artifacts)
    intent = normal_exit_intent(certificate['shared_contract']['relation_intent'], bundle=bundle)
    if intent is None or packet['inputs'].get('normal_exit_relation_intent_sha256') != intent.intent_sha256:
        raise ValueError('conditional supplier postcondition request differs')
    classification = str(paths.get('proof_classification', 'machine_overlay'))
    if classification not in {'machine_overlay', 'encapsulated_owned'}:
        raise ValueError('conditional supplier proof classification is unsupported')
    if packet['inputs'].get('proof_classification') != classification:
        raise ValueError('conditional supplier proof classification differs')
    return {
        'bundle': bundle, 'contract': contract, 'binding': binding, 'binding_model': binding_model,
        'operations': operations, 'source_root': source_root, 'source': source, 'symbols': symbols,
        'source_profile': profile, 'assurance': selection, 'authorizing': False,
        'qualification_sha256': None, 'contextual_refinement_sha256': proof['receipt_sha256'],
        'proof_receipt_sha256': proof['receipt_sha256'], 'proof_classification': classification,
        'proof_machine_overlay_sha256': models['machine_overlay_sha256'],
        'proof_overlay_sha256': models['proof_overlay_sha256'],
        'trusted_adapter_lowering': models.get('trusted_adapter_lowering'), 'relation_evidence': [],
        'normal_exit_postconditions': None, 'conditional_postcondition_intent': intent,
        'shared_source_contract_file_sha256': packet['inputs']['shared_source_contract_file_sha256'],
        'source_summary_contracts': summary, 'proof_system': system,
        'binding_intent': binding_model.to_payload(), 'proof_artifacts': root/'proof-diagnostics',
        'source_summary_artifacts': artifacts,
        **checked_memory_summary_facts(proof, artifacts=root/'proof-diagnostics', runtime_assurance=selection),
    }
