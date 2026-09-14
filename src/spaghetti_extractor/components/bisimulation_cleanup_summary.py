"""Assemble a conditional paired-call contract from the checked cleanup network.

The public contract excludes authored bodies and regional proof identities.
Evidence binds those implementations separately. It is a relational substitution
rule, not an executable specification or permission for native activation.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import re

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_call_evidence import read_json
from .bisimulation_compaction_contract import require
from .bisimulation_cleanup_composition import _compact
from .bisimulation_cleanup_observations import _body
from .formats import COMPONENT_EXACT_C_SLICE_V1_FORMAT


def _manifest(root, component_id):
    root = Path(root); value = read_json(root/'component-exact-c-slice-v1.json')
    require(value['format'] == COMPONENT_EXACT_C_SLICE_V1_FORMAT and value['component_id'] == component_id
        and value['slice_sha256'] == canonical_sha256_v3({k: v for k, v in value.items() if k != 'slice_sha256'}),
        'cleanup original scope is stale or belongs to another component')
    paths = [row['path'] for row in value['files']]
    require(paths and len(paths) == len(set(paths)), 'cleanup original files are absent or duplicated')
    for row in value['files']:
        file = root/row['path']
        require(file.resolve().is_relative_to(root.resolve()) and sha256_file(file) == row['sha256'],
                'cleanup original source binding differs')
    return value


def checked_cleanup_original_cover(root, regions):
    require(set(regions) == {'entry', 'loop', 'tail'}, 'cleanup original cover needs all regions')
    all_slices = [root, *regions.values()]
    require(all(s['slice_sha256'] == canonical_sha256_v3({k: v for k, v in s.items() if k != 'slice_sha256'})
                for s in all_slices), 'cleanup original manifest changed')
    require(all(s['format'] == COMPONENT_EXACT_C_SLICE_V1_FORMAT and s['component_id'] == root['component_id']
                for s in all_slices), 'cleanup original component identity differs')
    require(len({s['bindings']['executable_transfer_plan_sha256'] for s in all_slices}) == 1,
            'cleanup original regions come from different transfer plans')
    require(root['root_entry_rvas'] == [0x55b7] and not root['forced_label_rvas']
        and not root['dependency_components'] and root['root_unit_ids'] == root['root_context_unit_ids'],
        'cleanup original root is not the complete production operation')
    owned = {n: set(s['root_unit_ids']) for n, s in regions.items()}
    require(set.union(*owned.values()) == set(root['root_unit_ids'])
        and len(set(root['root_unit_ids'])) == len(root['root_unit_ids']), 'cleanup original ownership has a hole or foreign unit')
    mapping = {r['unit_id']: r['rva'] for r in root['source_map']}
    require(len(mapping) == len(root['source_map']), 'cleanup original unit mapping is ambiguous')
    require(set(root['unit_ids']) == set(root['root_unit_ids'])
        and set(mapping) == set(root['unit_ids']) | set(root['internal_direct_call_closure']['unit_ids']), 'cleanup original source/closure inventory differs')
    for role, s in regions.items():
        require(all(mapping.get(r['unit_id']) == r['rva'] for r in s['source_map']),
                'cleanup original unit identity/entry differs: '+role)
    functions = [f for f in root['functions'] if f['entries'] == [0x55b7]]
    require(len(functions) == 1 and set(functions[0]['unit_rvas']) == {mapping[u] for u in root['root_unit_ids']},
            'cleanup original function coverage differs')
    edges = lambda s: {canonical_sha256_v3(e) for e in s['internal_direct_call_closure']['call_edges']}
    require(edges(root) == set.union(*(edges(s) for s in regions.values())), 'cleanup original dependency edges differ')
    runtime = lambda s: next(r['sha256'] for r in s['files'] if r['path'] == 'state-machine-runtime.h')
    require(len({runtime(s) for s in all_slices}) == 1, 'cleanup original runtime ABI differs')
    return {'entry_rva': 0x55b7, 'transfer_plan_sha256': root['bindings']['executable_transfer_plan_sha256'],
        'root_slice_sha256': root['slice_sha256'], 'root_unit_ids': sorted(root['root_unit_ids']),
        'regions': {n: sorted(ids) for n, ids in owned.items()},
        'shared_proof_units': sorted(u for u in mapping if sum(u in ids for ids in owned.values()) > 1),
        'internal_calls': root['internal_direct_call_closure']['call_edges']}


# These are proof observers, not application code. Their complete bodies include
# scalar equality at each source cut as well as the already checked full view.
OBSERVER_CONTRACTS = {'entry': 'a4db7c2d282563998c35e329511013893d78192caeb5ad91df274cc8e0f522c9', 'loop': 'f82c4fd06194adc02a48fcfd5b7c703ece409034051310e25e161eb375287036'}


def cleanup_operation_domain(domain, models, results, exact, component_id):
    original = _manifest(exact, component_id)
    regional = {n: _manifest(r['inputs']['exact'], component_id) for n, r in results.items()}
    cover = checked_cleanup_original_cover(original, regional)
    for role, name in [('entry', 'observe_entry'), ('loop', 'observe_loop')]:
        transport = results[role]['source_transport']
        require(transport['local_cut_observer_arguments_checked'] is True and transport['observer_function'] == name,
                'cleanup scalar observer invocation is not checked')
        require(hashlib.sha256(_compact(_body(models[role], name)).encode()).hexdigest() == OBSERVER_CONTRACTS[role],
                'cleanup scalar observer relation changed: '+role)
    # Only conjunctions present on all unconditional regional frames can pass
    # through arbitrary loop repetition. Saved registers have a separate checked
    # private-byte transport and terminal restoration proof.
    posts = domain['control_transport']['regional_postconditions']
    names = {'entry': 'entry-preserved-machine-frame', 'loop': 'loop-preserved-register-frame',
             'tail': 'tail-preserved-machine-state'}
    frames = []
    for role, name in names.items():
        clause = posts[role][name]
        require(clause['guards'] == [], 'cleanup persistent frame is outcome-dependent')
        atoms = clause['expression'].split('&&')
        require(all(re.fullmatch(r'state\.(.+)==initial\.\1', atom) for atom in atoms),
                'cleanup persistent frame has an unsupported relation')
        frames.append(set(atoms))
    preserved = set.intersection(*frames) | {'state.'+n+'==initial.'+n for n in ['esi', 'ebx', 'ebp']}
    source = results['entry']['proof_key']['bindings']
    views = results['tail']['inputs']['contract']['views']
    contract = {'profile': 'conditional-cleanup-paired-operation-v1', 'component_id': component_id,
        'operation_id': 'cleanup', 'original_entry_rva': cover['entry_rva'],
        'original_transfer_plan_sha256': cover['transfer_plan_sha256'],
        'interface_intent': source['interface_intent'],
        'native_projection': {'text': {'register': 'edi', 'extent': 'text_extent', 'permissions': 3},
            'image_views': {role: views[name] for role, name in [('suppress_notice', 'notice'),
                ('main_window', 'window'), ('edit_window', 'edit'), ('caption', 'caption')]},
            'call_entry_stack_delta': -4, 'normal_call_stack_delta': 0, 'return_word_offset': -4},
        'input_relation': {'native_flag_bounds': {'df': [0, 1]}, 'public_memory': 'The same current byte function at every admitted physical address; aliases share that function.',
            'views': 'The complete checked parameter reference/view relation, including current contents, permissions and live context storage.',
            'caller_requirements': {n: p for n, p in domain['additional_requirements'].items() if n.startswith('caller-')},
            'entry_admission': domain['regional_assumptions']['entry']},
        'runtime_requirements': {'regional': {n: r['proof_key']['bindings']['runtime_contract'] for n, r in results.items()},
            'allocator_requirements': {n: p for n, p in domain['additional_requirements'].items() if n.startswith('allocator-')},
            'named': {n: v['requirement'] for n, v in domain['descriptor_transport']['runtime_requirements'].items()},
            'accessors': domain['runtime_view_transport']['requires'],
            'observations': domain['observations']['requires'],
            'service_model_contracts': domain['observations']['helper_contracts']},
        'normal_return': {'result': {'kind': 'equal-u32', 'native_field': 'eax', 'excluded_values': [4294967295]},
            'stack_delta': 4, 'return_target': 'The incoming return word.',
            'preserved_equalities': sorted(preserved),
            'frame_quantifiers': {'continuation_slot': [0, 8], 'continuation_byte': [0, 10]}},
        'memory_fault': {'native_outcome': 'SPX_MEMORY_FAULT', 'source_result': 4294967295,
            'native_register_relation': 'Not exported; consumers must not assume a normal return frame on this exit.'},
        'all_outcomes': {'public_memory': {'kind': 'pointwise-byte-equality', 'address_width': 32,
            'scope': 'The admitted public world, separate from the disjoint callee-private frame; not the full physical process heap.'},
            'service_observations': domain['observations']['record_relation'], 'maximum_service_calls': 8},
        'private_frame': {'low': domain['private_transport']['low'], 'high': domain['private_transport']['high'],
            'scope': 'Checked private byte transport under the caller/allocator separation and physical-access premises.'},
        'termination': 'Finite under the regional/runtime premises when dependency invocations return; the checked rank handles repeated loop cuts.',
        'use': 'Paired caller equivalence only. Assert corresponding inputs before coupling the abstract results and post-memory.',
        'excluded': ['Concrete caller/adapter/service qualification.', 'Service invocation failures and nonreturning services.',
                     'Observable native fault-register context.', 'Native activation and strong contextual-bisimulation authority.']}
    return {'contract': contract, 'contract_sha256': canonical_sha256_v3(contract), 'original_cover': cover,
        'observer_contracts': dict(OBSERVER_CONTRACTS)}


def project_cleanup_summary(summary, export):
    """Conjunction elimination only: never add a guarantee or change premises.

    Called after the complete supplier evidence is checked. This export view is
    separate from the stronger proof domain, so weakening needs no new query.
    """
    if export is None:
        return summary
    require(summary['status'] == 'satisfied' and summary['contract_sha256'] == canonical_sha256_v3(summary['contract']),
            'cleanup export needs a complete bound summary')
    require(isinstance(export, dict) and set(export) == {'rule', 'preserved_equalities'}
            and export['rule'] == 'normal-frame-subset-v1', 'unsupported cleanup contract export rule')
    selected = export['preserved_equalities']
    require(isinstance(selected, list) and all(isinstance(v, str) for v in selected)
            and selected == sorted(set(selected))
            and set(selected) <= set(summary['contract']['normal_return']['preserved_equalities']),
            'cleanup export may only withdraw checked normal-frame guarantees')
    value = deepcopy(summary)
    value['contract']['normal_return']['preserved_equalities'] = selected.copy()
    value['contract_sha256'] = canonical_sha256_v3(value['contract'])
    value['evidence']['contract_projection'] = {'rule': export['rule'],
        'source_contract_sha256': summary['contract_sha256'],
        'exported_contract_sha256': value['contract_sha256'], 'preserved_equalities': selected.copy()}
    return value


def conditional_cleanup_summary(result):
    operation = result['proof_key']['domain'].get('operation')
    if operation is None:
        return {'status': 'incomplete', 'reason': 'Complete original operation scope was not supplied.', 'authorizing': False}
    expected = {'existing': 'violated', 'nonempty': 'violated', **{n: 'satisfied' for n in [
        'proposed', 'private_transport', 'public_transport', 'descriptor_transport', 'runtime_view_transport', 'control_transport', 'observations']}}
    require({n: r['query']['status'] for n, r in result['queries'].items()} == expected,
            'cleanup operation summary needs every composition obligation and nonempty admission')
    contract = operation['contract']
    require(operation['contract_sha256'] == canonical_sha256_v3(contract), 'cleanup operation contract changed')
    summary = {'status': 'satisfied', 'authorizing': False, 'activation_authorized': False,
        'runtime_compatibility': 'unverified', 'contract': contract, 'contract_sha256': operation['contract_sha256'],
        'evidence': {'composition_proof_key_sha256': result['proof_key_sha256'],
            'regional_receipts': {n: d['receipt_sha256'] for n, d in result['dependencies'].items()},
            'original_slice_sha256': operation['original_cover']['root_slice_sha256']}}
    return project_cleanup_summary(summary, result.get('summary_export'))
