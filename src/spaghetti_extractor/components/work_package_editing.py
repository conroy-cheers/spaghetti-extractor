"""Canonical editing inputs bound to an existing non-authorizing V6 package."""

import json

from .binding_intent import ComponentMachineBindingIntentV1
from .bisimulation import ComponentBisimulationIntentV1
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .relation_v5 import ComponentRelationIntentV1


def validate_editing_relation(value, binding):
    intent = ComponentRelationIntentV1.parse(value)
    operations = {op.semantics.operation_id for op in binding.operations}
    if (intent.component_id != binding.component_id or
            any(op['operation_id'] not in operations for op in intent.operations)):
        raise ValueError('editing relation names different component operations')
    return intent


def validate_editing_bisimulation(value, binding):
    intent = ComponentBisimulationIntentV1.parse(value)
    operations = {op.semantics.operation_id: op.semantics for op in binding.operations}
    if intent.component_id != binding.component_id or {op.operation_id for op in intent.operations} != set(operations):
        raise ValueError('editing bisimulation names different component operations')
    if any(cut.exact_unit_id not in operations[op.operation_id].unit_ids
           for op in intent.operations for cut in op.syncs):
        raise ValueError('editing bisimulation cut is outside the owned operation')
    return intent


def editing_input_texts(payload):
    """Reconstruct materialized originals; none of these declarations is proof."""
    inputs = payload['requirements'].get('editing_inputs')
    if inputs is None:
        return {}
    if (not isinstance(inputs, dict) or not {'interface', 'binding'} <= set(inputs)
            or set(inputs) - {'interface', 'binding', 'bisimulation', 'relation'}):
        raise ValueError('work-package editing inputs are malformed')
    interface = ComponentInterfaceIntentV1.parse(inputs['interface'])
    bundle = compile_component_interface_v5(interface)
    binding = ComponentMachineBindingIntentV1.parse(inputs['binding'])
    identities = payload['bindings']
    if (interface.component_id != payload['component_id'] or binding.component_id != payload['component_id']
            or bundle.interface.interface_sha256 != identities['interface_sha256']
            or bundle.interface.schema_sha256 != identities['schema_sha256']
            or binding.intent_sha256 != identities['binding_intent_sha256']):
        raise ValueError('work-package editing input identity differs')
    operations = {row['operation_id']: row for row in payload['operations']}
    if (set(operations) != {op.semantics.operation_id for op in binding.operations}
            or set(operations) != {op['id'] for op in interface.operations}):
        raise ValueError('work-package editing operation inventory differs')
    for op in binding.operations:
        semantics = op.semantics
        row = operations[semantics.operation_id]
        if (row['semantic_sha256'] != semantics.semantic_sha256
                or row['unit_ids'] != list(semantics.unit_ids)
                or row['context_transfer_ids'] != list(semantics.proof_context_transfer_ids)
                or row['entry_rvas'] != list(semantics.entry_rvas)
                or row['machine_projection'] != dict(semantics.machine_projection)):
            raise ValueError('work-package editing operation scope differs')
    if 'bisimulation' in inputs:
        validate_editing_bisimulation(inputs['bisimulation'], binding)
    if 'relation' in inputs:
        validate_editing_relation(inputs['relation'], binding)
    return {name + '.json': json.dumps(value, indent=2, sort_keys=True) + '\n'
            for name, value in inputs.items()}


def editing_input_inspection(payload):
    files = editing_input_texts(payload)
    if not files:
        return []
    inputs = payload['requirements']['editing_inputs']
    interface = inputs['interface']
    return [
        '  editable canonical inputs: ' + ', '.join(sorted(files)),
        '  declared interface: parameters/results, state, services, effects and lifecycle relations',
        f"  protocol: {interface['protocol']['initial_state']}; states: {', '.join(interface['protocol']['states'])}",
        '  edit the inputs and C, then boundary adopt --input DIR --output DIR',
        '  adoption normalizes declarations only; transport, coverage/progress and qualification remain required',
    ]
