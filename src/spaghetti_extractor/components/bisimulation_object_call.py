"""Checked live-object supplier inputs for body-independent caller composition.

Evidence is replayed by the existing original/source reader before facts escape
this module. Facts expose the checked frame and ABI, not the supplier algorithm.
They are conditional; the caller must prove object contents, aliases, lifetime,
private-frame separation and the actual call projection before using them.
"""

from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from .binding_intent import ComponentMachineBindingIntentV1
from .bisimulation_call_evidence import read_json
from .bisimulation_clobber_frame import parse_clobbers
from .bisimulation_private_frame import parse_stack_writes
from .bisimulation_shared_original_check import checked_object_original_transition
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .bisimulation_object_initialization import checked_object_parameter_projection, checked_initialization_requests
from .machine_overlay_state_views import checked_state_view

OBJECT_CALL_RULE = 'checked-live-object-paired-call-v1'


def checked_object_call_supplier(supplier):
    """Read complete current evidence; declarations or a stale model cannot bind."""
    supplier = Path(supplier)
    artifacts = supplier / 'original-comparison'
    transition = checked_object_original_transition(read_json(artifacts / 'result.json'),
        artifacts=artifacts, certificate=read_json(supplier / 'local-contract.json'),
        source_artifacts=supplier / 'local-contract-models')
    domain = transition['domain']
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(domain['interface_intent']))
    binding = ComponentMachineBindingIntentV1.parse(domain['binding_intent'])
    operation = binding.operations[0].semantics
    logical = next(op for op in bundle.interface.operations if op.identity == transition['operation_id'])
    signature = bundle.intent.schema.signature_index[logical.signature_id]
    projection = operation.machine_projection['operation']
    states = {row['id']: row for row in projection['state']}
    views = {}
    for state in bundle.interface.state:
        _, extent, permissions, address = checked_state_view(bundle, state, states[state.value.identity])
        views[state.value.identity] = {'address': address, 'extent': extent, 'permissions': permissions}
    parameters = {row['id']: row['projection'] for row in projection['parameters']}
    arguments = []
    for parameter in signature.parameters:
        projected = parameters[parameter.identity]
        row = {'id': parameter.identity, 'interpretation': parameter.interpretation}
        if parameter.interpretation == 'view':
            projected = checked_object_parameter_projection(parameter, projected)
            row.update(minimum_extent=projected['requested_extent']['value'], nullable=parameter.nullable,
                       permissions={'read': 1, 'write': 2, 'read_write': 3}[parameter.access])
            projected = projected['base']
        if projected['kind'] == 'register':
            row['entry_register'] = projected['register']
        else:
            row['entry_stack_offset'] = projected['offset']
        arguments.append(row)
    machine = domain['machine_domain']
    facts = {
        'rule': OBJECT_CALL_RULE, 'component_id': bundle.interface.identity,
        'operation_id': logical.identity, 'entry_rva': operation.entry_rvas[0],
        'arguments': arguments, 'shared_views': views, 'results': projection['results'],
        'private_accesses': [list(row) for row in parse_stack_writes(machine['private_accesses'])],
        'private_writes': [list(row) for row in parse_stack_writes(machine['private_writes'])],
        'clobbers': sorted(parse_clobbers(machine['clobbers'])), 'stack_delta': machine['stack_delta'],
        'image_base': machine['image_base'], 'runtime_contract': domain['runtime_contract'],
        'interface_intent': domain['interface_intent'], 'binding_intent': domain['binding_intent'],
    }
    initializes = checked_initialization_requests(machine.get('initializes', []), signature=signature)
    if initializes:
        facts['initializes'] = initializes
    if domain.get('terminal_services'):
        facts['terminal_services'] = domain['terminal_services']
    return {'authorizing': False, 'activation_authorized': False, 'runtime_compatibility': 'unverified',
            'contract': facts, 'contract_sha256': canonical_sha256_v3(facts), 'transition': transition}


def checked_object_supplier_facts(supplier, required_frame):
    """Adapt current live-object evidence to the existing public caller reader.

    The consumed frame is explicit. Stronger or changed evidence never silently
    supplies a requested register guarantee absent from the checked theorem.
    """
    from .bisimulation_clobber_frame import frame_equalities
    from .bisimulation_harness import _architectural_state_equalities
    from .bisimulation_native_calls import SCALAR_FIELDS, ARRAY_FIELDS, checked_return
    from .bisimulation_supplier_facts import require

    checked = checked_object_call_supplier(supplier)
    facts = dict(checked['contract']); transition = checked['transition']
    original = read_json(Path(supplier)/'original-comparison/result.json')['bindings']['exact_c_slice']
    require(original['slice_sha256'] == transition['domain']['exact_c_slice_sha256'],
            'object original identity differs')
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(facts['interface_intent']))
    operation = next(op for op in bundle.interface.operations if op.identity == facts['operation_id'])
    signature = bundle.intent.schema.signature_index[operation.signature_id].to_payload()
    require(len(facts['results']) == len(signature['results']) <= 1,
            'object caller requires a void or checked scalar result')
    result = facts['results'][0]['projection']['register'] if facts['results'] else None
    available = sorted(v.replace(' ', '') for v in frame_equalities(
        _architectural_state_equalities('state', 'initial'), [*facts['clobbers'], *([result] if result else []), 'esp']))
    require(isinstance(required_frame, list)
            and all(isinstance(v, str) and v in SCALAR_FIELDS | set(ARRAY_FIELDS) for v in required_frame)
            and required_frame == sorted(set(required_frame)), 'invalid requested object frame')
    required = ['state.'+v+'==initial.'+v for v in required_frame]
    missing = sorted(set(required)-set(available))
    entry = facts['entry_rva']
    facts.update(signature=signature, original_entry_rva=entry,
        original_transfer_plan_sha256=original['bindings']['executable_transfer_plan_sha256'],
        original_files={r['path']: r['sha256'] for r in original['files'] if r['path'] in
            {f'behavioral-fn-{entry:08x}.c', 'behavioral-support.c', 'state-machine-runtime.h'}},
        native_projection={'image_views': facts['shared_views'], 'call_entry_stack_delta': -4},
        normal_return=checked_return({'result_field': result, 'stack_delta': facts['stack_delta']-4,
            'preserved_fields': [v for v in required_frame if 'state.'+v+'==initial.'+v in available]}),
        entry_relations=[], normal_excludes=[])
    require(len(facts['original_files']) == 3, 'object original body/runtime binding is absent')
    requirements = {'rule': OBJECT_CALL_RULE, 'status': 'requires-recheck' if missing else 'compatible',
        'required_normal_frame': required, 'available_normal_frame': available, 'missing_guarantees': missing,
        'provided_contract_sha256': transition['domain_sha256'], 'consumed_contract_sha256': canonical_sha256_v3(facts)}
    return facts, {'contract_sha256': transition['domain_sha256'], 'consumer_requirements': requirements,
        'evidence': {k: transition[k] for k in ('supplier_receipt_sha256', 'source_certificate_sha256')}}
