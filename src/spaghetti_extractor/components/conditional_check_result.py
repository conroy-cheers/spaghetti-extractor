"""Validate conditional diagnostic packets for feedback and exact-query reuse.

Packet validation supplies no theorem, caller premise or activation authority.
Reusing a query also requires current compiled bytes, tools, arguments and the
retained process output to match, followed by the current result parser.
"""
import re

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_assurance import checked_implemented_runtime_assurance
from .formats import CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT


def checked_obligation_selection(value):
    if value is None:
        return None
    if (not isinstance(value, list) or not value or any(
            not isinstance(row, dict) or set(row) != {'operation_id', 'obligation_id'}
            or any(not isinstance(v, str) or not v for v in row.values()) for row in value)):
        raise ValueError('conditional region selection must name operation and obligation IDs')
    pairs = [(row['operation_id'], row['obligation_id']) for row in value]
    if len(pairs) != len(set(pairs)):
        raise ValueError('conditional region selection repeats an obligation')
    return [{'operation_id': operation, 'obligation_id': obligation} for operation, obligation in sorted(pairs)]


def deferred_obligation(task, assurance):
    """A scheduling record with no compiled or executed evidence."""
    return {**{key: task[key] for key in ('shard_id', 'operation_id', 'obligation_id',
                'proof_model_sha256', 'nonvacuity_proof_model_sha256',
                'property_checker_command_sha256', 'nonvacuity_checker_command_sha256')},
            'status': 'incomplete', 'code': 'conditional_region_deferred',
            'detail': 'not selected for this diagnostic check',
            'goto_model_sha256': None, 'nonvacuity_goto_model_sha256': None,
            'execution_binding_sha256': None, 'assurance': assurance, 'authorizing': False}


def conditional_packet_status(result):
    if result['status'] == 'satisfied' and (result.get('boundary_requirements') or result.get('selected_obligations')):
        return 'incomplete'
    return result['status']


def _check_entry_prefix(prefix, entry, model):
    base = {'policy', 'authorizing', 'status', 'original_goto_model_sha256',
            'entry_goto_model_sha256', 'entry_function'}
    if (not isinstance(prefix, dict) or prefix.get('policy') != 'compiled-entry-prefix-correspondence-v1'
            or prefix.get('authorizing') is not False or prefix.get('status') not in {'matched', 'incomplete'}
            or prefix.get('original_goto_model_sha256') != model.get('goto_model_sha256')
            or prefix.get('entry_goto_model_sha256') != entry.get('goto_model_sha256')
            or prefix.get('entry_function') != model.get('nonvacuity_function')
            or not isinstance(prefix.get('entry_function'), str)):
        raise ValueError('conditional entry prefix model or root binding differs')
    if prefix['status'] == 'incomplete':
        if set(prefix) != base | {'detail'} or not isinstance(prefix['detail'], str) or not prefix['detail']:
            raise ValueError('conditional entry prefix diagnostic differs')
        return
    counts = {'common_helpers', 'matched_instruction_pairs', 'unknown_branches',
              'false_assumption_exits', 'inventory_milliseconds', 'comparison_milliseconds'}
    manifest = {'required_assertion_descriptions', 'assertion_sites'} & prefix.keys()
    if (set(prefix) != base | counts | manifest | {'relation_sha256', 'frontier_properties', 'inventory_sha256'}
            or any(type(prefix.get(field)) is not int or prefix[field] < 0 for field in counts)
            or not isinstance(prefix.get('frontier_properties'), list) or not prefix['frontier_properties']
            or any(not isinstance(value, str) or not value for value in prefix['frontier_properties'])
            or prefix['frontier_properties'] != sorted(set(prefix['frontier_properties']))
            or not isinstance(prefix.get('inventory_sha256'), dict)
            or set(prefix['inventory_sha256']) != {'original_symbols', 'original_functions', 'entry_symbols', 'entry_functions'}
            or any(re.fullmatch('[0-9a-f]{64}', str(value)) is None for value in
                   [prefix.get('relation_sha256'), *prefix['inventory_sha256'].values()])):
        raise ValueError('conditional entry prefix inventory or relation differs')
    if manifest:
        if manifest != {'required_assertion_descriptions', 'assertion_sites'}:
            raise ValueError('conditional entry prefix lacks its complete assertion sites')
        descriptions = prefix['required_assertion_descriptions']
        if (not isinstance(descriptions, list) or not descriptions
                or any(not isinstance(value, str) or not value for value in descriptions)
                or descriptions != sorted(set(descriptions)) or 'spx-source-entry:escaped-cut' not in descriptions):
            raise ValueError('conditional entry prefix assertion manifest differs')
        sites = prefix['assertion_sites']
        if (not isinstance(sites, list) or not sites
                or any(not isinstance(row, dict) or set(row) != {'property_id', 'description', 'source_function'}
                       or any(not isinstance(value, str) or not value for value in row.values()) for row in sites)
                or [row['property_id'] for row in sites] != sorted({row['property_id'] for row in sites})):
            raise ValueError('conditional entry prefix assertion sites differ')


def _check_source_entry_preparation(preparation, entry, model, assurance, checker):
    """Separate preparation, guarded correspondence and complete entry checks."""
    policy = 'compiler-derived-first-begin-source-entry-v1'
    if preparation is None:
        if entry is not None:
            raise ValueError('conditional entry model lacks its preparation binding')
        return
    if (not isinstance(preparation, dict) or preparation.get('policy') != policy
            or preparation.get('authorizing') is not False
            or preparation.get('status') not in {'prepared', 'unsupported'}):
        raise ValueError('conditional source entry preparation is malformed')
    prepared = preparation['status'] == 'prepared'
    field = 'binding_sha256' if prepared else 'detail'
    if (set(preparation) != {'policy', 'authorizing', 'status', field}
            or not isinstance(preparation[field], str) or not preparation[field]
            or (prepared and re.fullmatch('[0-9a-f]{64}', preparation[field]) is None)):
        raise ValueError('conditional source entry preparation binding differs')
    if entry is None:
        return
    qualified = (isinstance(entry, dict) and isinstance(entry.get('entry_check'), dict)
                 and entry['entry_check'].get('status') == 'satisfied')
    base = {'preparation', 'authorizing', 'source_conformance_checked', 'entry_obligations_checked', 'status'}
    if (not isinstance(entry, dict) or entry.get('preparation') != preparation
            or entry.get('authorizing') is not False or entry.get('source_conformance_checked') is not qualified
            or entry.get('entry_obligations_checked') is not qualified
            or entry.get('status') not in ({'compiled', 'incomplete'} if prepared else {'unsupported'})):
        raise ValueError('conditional source entry preparation claims unchecked conformance or evidence')
    if entry['status'] == 'compiled':
        optional = {'prefix_correspondence', 'entry_check'} & entry.keys()
        if (set(entry) != base | optional | {'compiled_types_checked', 'goto_model_sha256', 'compile_milliseconds', 'type_inventory_milliseconds'}
                or entry.get('compiled_types_checked') is not True
                or re.fullmatch('[0-9a-f]{64}', str(entry.get('goto_model_sha256', ''))) is None
                or any(type(entry.get(field)) is not int
                       or entry[field] < 0 for field in ('compile_milliseconds', 'type_inventory_milliseconds'))):
            raise ValueError('conditional compiled entry model binding differs')
        if 'prefix_correspondence' in optional:
            _check_entry_prefix(entry['prefix_correspondence'], entry, model)
        if 'entry_check' in optional:
            from .bisimulation_entry_queries import validate_entry_check
            validate_entry_check(entry['entry_check'], entry=entry, model=model, assurance=assurance, checker=checker)
    elif set(entry) != base | {'detail'} or not isinstance(entry.get('detail'), str) or not entry['detail']:
        raise ValueError('conditional source entry preparation diagnostic differs')


def checked_conditional_packet(packet, component_id):
    if not isinstance(packet, dict) or set(packet) != {"format", "status", "inputs", "inputs_sha256", "result", "authorizing"}:
        raise ValueError("conditional check packet fields differ")
    inputs, result = packet['inputs'], packet['result']
    if not isinstance(inputs, dict) or not isinstance(result, dict) or not isinstance(result.get('bindings'), dict):
        raise ValueError("conditional check inputs, result or bindings are malformed")
    requirements = inputs.get('boundary_requirements', [])
    if (not isinstance(requirements, list)
            or any(not isinstance(row, dict) or not isinstance(row.get('code'), str) or not row['code'] for row in requirements)
            or result.get('boundary_requirements', []) != requirements):
        raise ValueError('conditional check boundary requirements are malformed or differ')
    if (packet['format'] != CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT or packet['status'] != conditional_packet_status(result)
            or packet['authorizing'] is not False
            or inputs.get('component_id') != component_id or result.get('component_id') != component_id
            or inputs.get('implementation_sha256') != result.get('bindings', {}).get('implementation_sha256')
            or packet['inputs_sha256'] != canonical_sha256_v3(inputs)
            or result.get('authorizing') is not False or result.get('activation_authorized') is not False
            or result.get('status') not in {'satisfied', 'incomplete', 'violated'}
            or result.get('receipt_sha256') != canonical_sha256_v3({k:v for k,v in result.items() if k != 'receipt_sha256'})):
        raise ValueError("conditional check identity, result or authority is stale")
    assurance = checked_implemented_runtime_assurance(result.get('assurance'))
    if assurance is None or inputs.get('runtime_assurance') != assurance or result.get('bindings', {}).get('assurance') != assurance:
        raise ValueError("conditional check needs its exact configured runtime contracts")
    checks = result.get('checks')
    if not isinstance(checks, list) or not checks or any(
            not isinstance(row, dict) or row.get('assurance') != assurance or row.get('authorizing') is not False
            or row.get('status') not in {'satisfied', 'incomplete', 'violated'} for row in checks):
        raise ValueError("conditional check has missing or mixed-assurance obligations")
    selection = checked_obligation_selection(inputs.get('selected_obligations'))
    if (inputs.get('selected_obligations') != selection
            or result.get('selected_obligations') != selection):
        raise ValueError('conditional region selection differs from its result')
    identities = [(row.get('operation_id'), row.get('obligation_id')) for row in checks]
    if len(identities) != len(set(identities)):
        raise ValueError('conditional check repeats an obligation')
    if selection is not None:
        selected = {(row['operation_id'], row['obligation_id']) for row in selection}
        if not selected <= set(identities):
            raise ValueError('conditional region selection names an unknown obligation')
        for row, identity in zip(checks, identities):
            deferred = row.get('code') == 'conditional_region_deferred'
            if deferred != (identity not in selected):
                raise ValueError('conditional deferred coverage disagrees with selection')
            if deferred and (row['status'] != 'incomplete' or any(row.get(key) is not None
                    for key in ('goto_model_sha256', 'nonvacuity_goto_model_sha256', 'execution_binding_sha256'))
                    or any(key in row for key in ('output_sha256', 'queries', 'partitioned_evidence', 'nonvacuity'))):
                raise ValueError('deferred conditional region claims execution evidence')
        models = result['bindings'].get('operation_models', [])
        model_ids = [(operation['operation_id'], model['obligation_id'])
                     for operation in models for model in operation['obligation_models']]
        if len(model_ids) != len(set(model_ids)) or set(model_ids) != set(identities):
            raise ValueError('conditional region coverage differs from prepared models')
    elif any(row.get('code') == 'conditional_region_deferred' for row in checks):
        raise ValueError('deferred conditional region lacks a bound selection')
    source_entries = {(operation['operation_id'], model['obligation_id']): model
                      for operation in result['bindings'].get('operation_models', [])
                      for model in operation.get('obligation_models', [])}
    for check, identity in zip(checks, identities):
        entry = check.get('source_entry_model')
        model = source_entries.get(identity, {})
        properties = check.get('property_result')
        if properties is not None:
            from .bisimulation_evidence import _validate_partitioned_property_evidence
            witness = check.get('nonvacuity')
            if (not isinstance(properties, dict) or not isinstance(witness, dict)
                    or properties.get('status') not in {'satisfied', 'violated', 'incomplete'}
                    or re.fullmatch('[0-9a-f]{64}', str(properties.get('output_sha256', ''))) is None):
                raise ValueError('conditional property result is malformed')
            _validate_partitioned_property_evidence(shard=properties, model=model)
            primary = properties if witness.get('status') == 'satisfied' or properties['status'] == 'violated' else witness
            if any(check.get(key) != value for key, value in primary.items()):
                raise ValueError('conditional property/coverage result selection differs')
        _check_source_entry_preparation(model.get('source_entry_preparation'), entry, model, assurance, result.get('checker', {}))
        if entry is not None and (check.get('code') == 'conditional_region_deferred'
                                  or check.get('goto_model_sha256') is None):
            raise ValueError('conditional uncompiled or deferred region claims entry preparation execution')
    statuses = {row['status'] for row in checks}
    expected = 'violated' if 'violated' in statuses else 'satisfied' if statuses == {'satisfied'} else 'incomplete'
    if result['status'] != expected:
        raise ValueError("conditional check aggregate disagrees with its obligations")
    return result, assurance
