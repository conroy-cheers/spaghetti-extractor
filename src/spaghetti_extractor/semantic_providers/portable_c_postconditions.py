"""Bind requested normal-return facts to the existing checked exit guards.

These facts live inside the contextual provider result. They grant no summary
substitution or activation authority independently of that enclosing proof.
"""

from ..components.normal_exit_postconditions import (
    shared_result_postcondition,
    checked_normal_exit_view_postconditions,
)
from ..components.relation_v5 import ComponentRelationIntentV1


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
    for operation_id, requirement in requirements:
        shared_result_postcondition(requirement['expression'], bundle=bundle, operation_id=operation_id)
    return intent


def checked_provider_postconditions(*, intent, **inputs):
    """Derive every requested fact from current, exactly regenerated adapters."""
    selected = normal_exit_intent(intent.to_payload(), bundle=inputs['bundle'])
    if selected is None:
        raise ValueError('provider postconditions lack requested normal-exit facts')
    facts = checked_normal_exit_view_postconditions(intent=selected, **inputs)
    if len(facts) != sum(len(operation['requirements']) for operation in selected.operations):
        raise ValueError('provider postcondition coverage is incomplete')
    return {'authorizing': False, 'intent': selected.to_payload(), 'facts': facts}


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
