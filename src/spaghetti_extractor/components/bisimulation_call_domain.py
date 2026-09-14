"""Admit a borrowed-view supplier at a manually defined caller continuation.

The domain describes a conditional proof region. It is not caller reachability,
service-table qualification, or permission to activate a replacement.
"""

from .bisimulation_clobber_frame import parse_clobbers
from .bisimulation_private_frame import parse_stack_writes
from .normal_exit_postconditions import shared_result_postcondition
from .relation_v5 import ComponentRelationIntentV1
from .binding_intent import ComponentMachineBindingIntentV1
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .machine_overlay_state_views import checked_state_view
from ..artifacts.artifact_set import canonical_sha256_v3


def require(condition, detail):
    if not condition:
        raise ValueError('caller contract: ' + detail)


def checked_call_domain(transition, projection, contract):
    """Return model inputs only after the supplying transition was validated."""
    require(set(contract) == {'region_index', 'entry_rva', 'instruction_rva', 'return_rva',
            'stack_delta', 'stack_words', 'private_stack', 'service_id', 'result_reference'}, 'fields differ')
    for key in ('region_index', 'entry_rva', 'instruction_rva', 'return_rva'):
        require(type(contract[key]) is int and 0 <= contract[key] < 2**32, 'invalid ' + key)
    require(projection['service_id'] == contract['service_id'] and len(projection['arguments']) == 1,
            'source service/argument binding differs')
    require(transition['authorizing'] is False and transition['runtime_compatibility'] == 'unverified'
            and transition['domain_sha256'] == canonical_sha256_v3(transition['domain']), 'unbound conditional transition')
    domain = transition['domain']
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(domain['interface_intent']))
    binding = ComponentMachineBindingIntentV1.parse(domain['binding_intent'])
    operation, = binding.operations
    require(operation.semantics.operation_id == transition['operation_id'] and len(operation.semantics.entry_rvas) == 1,
            'one checked supplier entry is required')
    machine = operation.semantics.machine_projection['operation']
    parameter, = machine['parameters']
    require(parameter['projection'] == {'kind': 'stack', 'at': 'entry', 'offset': 4, 'width': 32},
            'supplier requires a different call adapter')
    relation = ComponentRelationIntentV1.parse(domain['relation_intent'])
    requirement = next(row for row in relation.operations if row['operation_id'] == transition['operation_id'])['requirements'][0]
    _, alias, _ = shared_result_postcondition(requirement['expression'], bundle=bundle, operation_id=transition['operation_id'])
    states = {row['id']: row for row in machine['state']}
    views = {row.value.identity: checked_state_view(bundle, row, states[row.value.identity])[1:]
             for row in bundle.interface.state}
    require(alias in views and views[alias][1] == 3 and all(name == alias or permissions == 1
            for name, (_, permissions, _) in views.items()), 'one mutable returned image view is required')
    extent, _, address = views[alias]
    md = domain['machine_domain']
    accesses, writes = parse_stack_writes(md['private_accesses']), parse_stack_writes(md['private_writes'])
    clobbers = parse_clobbers(md['clobbers'])
    require(set(clobbers) <= {'cf','df','ecx','edx','eflags','of','pf','sf','zf'}, 'supplier destroys caller continuation storage')
    delta = contract['stack_delta']
    require(type(delta) is int and -256 <= delta <= 0, 'invalid caller stack delta')
    words = contract['stack_words']
    require(isinstance(words, list) and 1 <= len(words) <= 32, 'invalid caller word inventory')
    offsets = []
    for row in words:
        require(set(row) == {'offset', 'writable', 'exit'} and type(row['writable']) is bool
                and type(row['offset']) is int and -256 <= row['offset'] <= 256, 'invalid private word')
        offset, expected = row['offset'], row['exit']
        require(expected == {'kind': 'preserved'} or (set(expected) == {'kind', 'value'}
                and expected['kind'] == 'constant' and type(expected['value']) is int
                and 0 <= expected['value'] < 2**32), 'invalid continuation value')
        require(all(offset+4 <= other or other+4 <= offset for other in offsets), 'overlapping caller words')
        offsets.append(offset)
        # The call adapter materializes one return word at child entry. Neither
        # it nor the child's checked private writes may overwrite a live word.
        require(all(offset+4 <= delta-4+start or delta-4+start+count <= offset
                    for start, count in [(0,4), *writes]), 'child writes overlap live caller storage')
    require(delta in offsets, 'child argument is absent from caller storage')
    low = min([*offsets, *(delta-4+start for start, _ in accesses)])
    high = max([*(offset+4 for offset in offsets), *(delta-4+start+count for start,count in accesses)])
    private = contract['private_stack']
    require(set(private) == {'low','high'} and all(type(v) is int for v in private.values())
            and private['low'] <= low and high <= private['high'],
            'caller entry does not admit supplier private frame')
    low, high = private['low'], private['high']
    base, size = md['image_base'], md['image_size']
    require(high-low <= 1024 and (high-low <= base or base+size+high-low <= 2**32), 'empty or oversized stack domain')
    reference = contract['result_reference']
    require(set(reference) == {'domain','object','generation','offset','extent','permissions'}, 'reference fields differ')
    require(all(type(value) is int and 0 <= value < 2**64 for value in reference.values())
            and all(reference[key] > 0 for key in ('domain','object','generation'))
            and reference['permissions'] == 3 and reference['offset']+extent <= reference['extent'], 'invalid borrowed result reference')
    return {'entry': contract['entry_rva'], 'instruction': contract['instruction_rva'], 'successor': contract['return_rva'],
            'callee': operation.semantics.entry_rvas[0], 'stack_delta': delta, 'stack_words': words,
            'low': low, 'high': high, 'image_base': base, 'image_size': size, 'views': views,
            'result_address': address, 'result_extent': extent, 'result_reference': reference,
            'clobbers': sorted(clobbers), 'source': projection, 'runtime_contract': {
                'id': 'borrowed-image-single-call-region', 'revision': 1,
                'incoming': 'Arbitrary admitted machine stack/registers and related current image bytes; valid immutable source context/service table bound to the checked supplier.',
                'memory': 'Caller private accesses use the declared disjoint word inventory. Checked child private writes and the adapter return word cannot overwrite live caller words.',
                'calls': 'One direct internal cdecl word argument; checked normal borrowed-view supplier transition; exact argument/current-readable-memory correspondence and framed final writes.',
                'outgoing': 'Selected fallthrough successor, stack delta, live word values and preserved machine frame; source result is the complete live borrowed view.',
                'lifetime': 'Image and service context remain live; no callback, allocation, origin rebinding or nonlocal exit.',
                'scope': 'Conditional region only; surrounding caller coverage/progress and native compatibility are separate obligations.'}}
