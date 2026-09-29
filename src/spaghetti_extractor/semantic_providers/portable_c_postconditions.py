"""Bind requested normal-return facts to the existing checked exit guards.

These facts live inside the contextual provider result. They grant no summary
substitution or activation authority independently of that enclosing proof.
"""

from ..components.normal_exit_postconditions import (
    shared_result_postcondition,
    checked_normal_exit_view_postconditions,
)
from ..components.relation_v5 import ComponentRelationIntentV1
from ..components.bisimulation_postconditions import (
    scalar_postcondition_requests, validate_scalar_postcondition_bindings,
)
from ..components.bisimulation_summary_contracts import (
    scalar_summary_operations, validate_scalar_summary_contracts,
)
from ..components.component_c_v5 import render_component_c_headers_v5
from ..components.contextual_bisimulation import validate_complete_local_refinement
from ..artifacts.artifact_set import canonical_sha256_v3


def normal_exit_intent(value, *, bundle):
    """Recognize the implemented all-normal-exit domain before proof work."""
    intent = ComponentRelationIntentV1.parse(value)
    requirements = [(operation['operation_id'], requirement)
                    for operation in intent.operations
                    for requirement in operation['requirements']]
    if not any(row['relation'] == 'normal_exit_postcondition' for _, row in requirements):
        return None
    if (intent.component_id != bundle.interface.identity or
            intent.status != 'ready_for_check' or intent.blockers or
            any(row['relation'] != 'normal_exit_postcondition' for _, row in requirements)):
        raise ValueError('provider normal-exit facts require a ready, unmixed postcondition intent')
    if scalar_summary_operations(bundle) is not None:
        scalar_postcondition_requests(bundle, intent)
    else:
        for operation_id, requirement in requirements:
            shared_result_postcondition(requirement['expression'], bundle=bundle, operation_id=operation_id)
    return intent


def checked_provider_postconditions(*, intent, **inputs):
    """Derive every requested fact from current, exactly regenerated adapters."""
    selected = normal_exit_intent(intent.to_payload(), bundle=inputs['bundle'])
    if selected is None:
        raise ValueError('provider postconditions lack requested normal-exit facts')
    facts = (_checked_scalar_postconditions(intent=selected, **inputs)
             if scalar_summary_operations(inputs['bundle']) is not None else
             checked_normal_exit_view_postconditions(intent=selected, **inputs))
    if len(facts) != sum(len(operation['requirements']) for operation in selected.operations):
        raise ValueError('provider postcondition coverage is incomplete')
    return {'authorizing': False, 'intent': selected.to_payload(), 'facts': facts}


def _checked_scalar_postconditions(*, intent, bundle, binding, proof_system,
                                  operation_symbols, runtime_assurance=None, **_):
    """Bind requested scalar exports to source theorems inside the local proof."""
    requested = scalar_postcondition_requests(bundle, intent)
    validate_complete_local_refinement(proof_system, runtime_assurance=runtime_assurance)
    proof = proof_system['proof']
    models = proof['models']
    world = proof['world']['bindings']
    if (binding.component_id != bundle.interface.identity or
            world['interface_sha256'] != bundle.interface.interface_sha256 or
            world['schema_sha256'] != bundle.interface.schema_sha256 or
            world['binding_intent_sha256'] != binding.intent_sha256):
        raise ValueError('scalar postcondition interface or binding is stale')
    bound = models.get('source_summary_contracts')
    if not isinstance(bound, dict) or not isinstance(bound.get('certificate'), dict):
        raise ValueError('scalar postcondition lacks its checked source summary')
    certificate = bound['certificate']
    validate_scalar_summary_contracts(certificate)
    if (certificate['status'] != 'satisfied' or
            certificate['interface_sha256'] != bundle.interface.interface_sha256 or
            certificate['operation_symbols'] != dict(operation_symbols) or
            certificate['headers_sha256'] != canonical_sha256_v3(
                render_component_c_headers_v5(bundle, operation_symbols)) or
            bound['implementation_sha256'] != proof['bindings']['implementation_sha256'] or
            bound['source_profile_sha256'] != proof['bindings']['source_profile_sha256']):
        raise ValueError('scalar postcondition source summary binding is stale or incomplete')
    facts = certificate['postconditions']
    validate_scalar_postcondition_bindings(facts, bundle=bundle, symbols=operation_symbols)
    expected = [{'operation_id': op, **fact} for op, rows in sorted(requested.items()) for fact in rows]
    if [{key: fact[key] for key in ('operation_id', 'id', 'expression')} for fact in facts] != expected:
        raise ValueError('scalar postcondition exports differ from the requested checked guarantees')
    return [{**fact, 'normal_exit_only': True, 'derivation': 'checked-scalar-source-postcondition-v1',
             'relation_intent_sha256': intent.intent_sha256,
             'proof_receipt_sha256': proof['receipt_sha256'],
             'source_summary_receipt_sha256': certificate['receipt_sha256'],
             'binding_intent_sha256': binding.intent_sha256,
             'interface_sha256': bundle.interface.interface_sha256,
             **({'assurance': runtime_assurance, 'authorizing': False} if runtime_assurance is not None else {})}
            for fact in expected]


def validate_provider_postconditions(value, **inputs):
    """A matching signature or a resealed wrapper cannot supply an alias fact."""
    if not isinstance(value, dict) or set(value) != {'authorizing', 'intent', 'facts'}:
        raise ValueError('provider normal-exit evidence fields differ')
    intent = ComponentRelationIntentV1.parse(value['intent'])
    expected = checked_provider_postconditions(intent=intent, **inputs)
    if value != expected:
        raise ValueError('provider normal-exit evidence differs from checked exit guards')


def validate_provider_postcondition_request(value, *, requested_sha256):
    """Require the exact request retained by the enclosing qualification input."""
    if requested_sha256 is None:
        if value is not None:
            raise ValueError('provider normal-exit evidence has no bound request')
        return
    if not isinstance(value, dict) or set(value) != {'authorizing', 'intent', 'facts'}:
        raise ValueError('provider normal-exit request lacks its evidence')
    if ComponentRelationIntentV1.parse(value['intent']).intent_sha256 != requested_sha256:
        raise ValueError('provider normal-exit request differs from qualification input')
