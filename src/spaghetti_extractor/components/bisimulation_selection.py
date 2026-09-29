"""Non-authorizing scheduling records within ordinary contextual receipts."""
from .conditional_check_result import checked_obligation_selection


def deferred_ordinary_obligation(task):
    return {**{key: task[key] for key in ('shard_id', 'operation_id', 'obligation_id',
                'proof_model_sha256', 'nonvacuity_proof_model_sha256',
                'property_checker_command_sha256', 'nonvacuity_checker_command_sha256')},
            'status': 'incomplete', 'code': 'proof_region_deferred',
            'detail': 'not selected for this diagnostic check',
            'goto_model_sha256': None, 'nonvacuity_goto_model_sha256': None,
            'execution_binding_sha256': None}


def diagnostic_selection(models, runtime_assurance):
    if 'diagnostic_selection' not in models:
        return None
    selection = checked_obligation_selection(models['diagnostic_selection'])
    if selection is None or selection != models['diagnostic_selection'] or runtime_assurance is not None:
        raise ValueError('ordinary diagnostic selection is malformed or mixed with conditional assurance')
    selected = {(row['operation_id'], row['obligation_id']) for row in selection}
    known = {(op['operation_id'], model['obligation_id'])
             for op in models['operation_models'] for model in op['obligation_models']}
    if not selected <= known:
        raise ValueError('ordinary diagnostic selection names unknown obligations')
    return selected


def validate_deferred_obligation(shard, model, key, selected):
    deferred = selected is not None and key not in selected
    if not deferred:
        if shard.get('code') == 'proof_region_deferred':
            raise ValueError('deferred proof region lacks a matching diagnostic selection')
        return False
    expected = deferred_ordinary_obligation({**model, 'operation_id': key[0],
        'obligation_id': key[1], 'shard_id': ':'.join(key)})
    if dict(shard) != expected or any(model.get(field) is not None for field in (
            'goto_model_sha256', 'nonvacuity_goto_model_sha256', 'execution_binding_sha256')):
        raise ValueError('deferred proof region claims execution evidence or has stale model bindings')
    return True
