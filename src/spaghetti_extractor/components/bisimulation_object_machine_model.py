"""Conditional leaf equivalence for live shared and nullable byte objects.

The original accesses the same current bytes as the authored C. Incoming storage
can belong to a caller; private callee bytes are separate and do not confer an
object lifetime. A caller must establish this domain before using the theorem.
This module supplies no native object authority or activation permission.
"""

from .binding_intent import ComponentMachineBindingIntentV1
from .bisimulation_clobber_frame import frame_equalities, parse_clobbers
from .bisimulation_harness import _architectural_state_equalities
from .bisimulation_object_model import _render_object_model, object_source_shape
from .bisimulation_private_frame import parse_stack_writes
from .component_c_v5 import _parameter_type, _result_type
from .bisimulation_object_initialization import checked_object_parameter_projection, checked_initialization_requests
from .machine_overlay_services_v5 import _c_identifier
from .machine_overlay_state_views import checked_state_view


def object_machine_runtime_contract(*, terminal_services=()):
    contract = {
        "id": "live-object-original-source-domain", "revision": 1,
        "inputs": "Related current bytes, logical origins, aliases and nullable byte views; fixed shared views.",
        "memory": "Successful little-endian one-to-four-byte accesses in declared readable/writable views or private callee ranges.",
        "private": "Nonwrapping callee stack ranges disjoint from every visible view; arbitrary initial private bytes with exact entry arguments and return word.",
        "lifetime": "Incoming objects remain live throughout the operation; caller ownership, creation, expiration and escape are separate composition premises.",
        "outcomes": "Normal return with checked target, stack delta, result and undeclared architectural clobbers; no services, callbacks or nonlocal exits.",
        "progress": "Every safety, frame and unwinding assertion must pass; finite model capacities are asserted, never input assumptions.",
    }
    if terminal_services:
        contract.update(revision=2,
            outcomes='Checked normal return or the exact declared terminal service occurrence with equal public current memory before invocation; no continuation after a terminal service.',
            terminal_services=list(terminal_services))
    return contract


def render_object_machine_model(*, bundle, operation_id, symbol, binding_intent, machine_domain,
                                terminal_services=(), service_bindings=()):
    """Instantiate existing projections and memory semantics, never target logic."""
    operations = object_source_shape(bundle, terminal_services=terminal_services)
    if service_bindings and not terminal_services:
        raise ValueError('object machine services require explicit terminal premises')
    binding = ComponentMachineBindingIntentV1.parse(binding_intent)
    if (operations is None or operation_id not in operations or binding.component_id != bundle.interface.identity
            or len(binding.operations) != 1 or binding.operations[0].semantics.operation_id != operation_id):
        raise ValueError("object machine comparison requires one bound object-view operation")
    operation = binding.operations[0].semantics
    if terminal_services and (set(operation.service_ids) != {row['service_id'] for row in terminal_services}
            or operation.machine_projection['service_bindings']):
        raise ValueError('object terminal service coverage must match its explicit event bindings')
    logical = next(op for op in bundle.interface.operations if op.identity == operation_id)
    signature = bundle.intent.schema.signature_index[logical.signature_id]
    types = bundle.intent.schema.type_index
    scalars = [v for v in (*signature.parameters, *signature.results) if v.interpretation != "view"]
    if (len(operation.entry_rvas) != 1 or any(types[v.type_id].kind != "integer"
            or types[v.type_id].body != {"signed": False, "width_bits": 32} for v in scalars)
            or set(machine_domain)-{'initializes'} != {"image_base", "private_accesses", "private_writes", "clobbers", "stack_delta"}):
        raise ValueError("object machine comparison needs unsigned words and an explicit private/return frame")
    accesses = parse_stack_writes(machine_domain["private_accesses"])
    writes = parse_stack_writes(machine_domain["private_writes"])
    clobbers = parse_clobbers(machine_domain["clobbers"])
    low = min((offset for offset, _ in accesses), default=0)
    high = max((offset+size for offset, size in accesses), default=0)
    image, delta = machine_domain["image_base"], machine_domain["stack_delta"]
    if (type(image) is not int or not 0 <= image < 2**32 or type(delta) is not int or not 4 <= delta <= 256
            or not low <= 0 < 4 <= high or high-low > 256
            or any(offset+size > 0 or not any(a <= offset and offset+size <= a+n for a, n in accesses)
                   for offset, size in writes)):
        raise ValueError("object machine private/return frame is unsupported")
    projection = operation.machine_projection["operation"]
    states = {row["id"]: row for row in projection["state"]}
    state_views = {item.value.identity: checked_state_view(bundle, item, states[item.value.identity])[1:]
                   for item in bundle.interface.state}
    parameters = {row["id"]: row["projection"] for row in projection["parameters"]}
    initializes = checked_initialization_requests(machine_domain.get('initializes', []), signature=signature)
    requested, input_values, occupied = {}, [(0, "return_target")], set(range(4))
    register_inputs = {}
    view_index = len(state_views)
    for index, value in enumerate(signature.parameters):
        projected = parameters[value.identity]
        if value.interpretation == "view":
            projected = checked_object_parameter_projection(value, projected)
            requested[value.identity] = projected["requested_extent"]["value"]
            projected = projected["base"]
            expression = f"env->inputs[{view_index}].address"
            view_index += 1
        else:
            expression = f"parameter_{index}"
        if projected.get('kind') == 'register':
            if (set(projected) != {'kind', 'at', 'register', 'width'} or projected['at'] != 'entry'
                    or projected['width'] != 32 or projected['register'] not in {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp'}
                    or projected['register'] in register_inputs):
                raise ValueError('object machine arguments require distinct entry word registers')
            register_inputs[projected['register']] = expression
            continue
        if (set(projected) != {"kind", "at", "offset", "width"} or projected["kind"] != "stack"
                or projected["at"] != "entry" or projected["width"] != 32
                or type(projected["offset"]) is not int or projected["offset"] < 4
                or not any(a <= projected["offset"] and projected["offset"]+4 <= a+n for a, n in accesses)
                or occupied.intersection(range(projected["offset"], projected["offset"]+4))):
            raise ValueError("object machine arguments require distinct admitted entry-stack words")
        occupied.update(range(projected["offset"], projected["offset"]+4))
        input_values.append((projected["offset"], expression))
    results = {row["id"]: row["projection"] for row in projection["results"]}
    result_register = None
    if signature.results:
        result = results[signature.results[0].identity]
        if (set(result) != {"kind", "at", "register", "width"} or result["kind"] != "register"
                or result["at"] != "exit" or result["width"] != 32
                or result["register"] not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}
                or result["register"] in clobbers):
            raise ValueError("object machine result requires a separately checked word register")
        result_register = result["register"]
    result_type = _result_type(types, signature)
    params = [f"{_parameter_type(types, v)} parameter_{i}" for i, v in enumerate(signature.parameters)]
    context_type = f"spx_{_c_identifier(bundle.interface.identity)}_context_v5"
    def ranges(items):
        return " || ".join(
            f"((int64_t)address >= (int64_t)m->entry+INT64_C({offset}) && "
            f"(int64_t)address+width <= (int64_t)m->entry+INT64_C({offset+size}))" for offset, size in items) or "0U"
    from .bisimulation_object_terminal import terminal_machine_dispatch
    dispatch = (terminal_machine_dispatch(terminal_services, service_bindings) if terminal_services else [
        "spx_call_status spx_invoke_call(spx_runtime *rt,const spx_call_event *event,",
        "    const spx_machine_state *input,spx_machine_state *output) {",
        "  (void)rt;(void)event;(void)input;(void)output;",
        '  __CPROVER_assert(0,"spx-object-machine-unmodeled-call");return SPX_CALL_UNIMPLEMENTED;', "}"])
    lines = ["#include \"behavioral-c.h\"",
        f"struct spx_object_machine {{ struct spx_object_environment *env; uint32_t entry; uint8_t stack[{high-low}]; }};",
        "static uint32_t spx_object_machine_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault) {",
        "  struct spx_object_machine *m=opaque;",
        '  __CPROVER_assert(width>=1U && width<=4U,"spx-object-machine-access-width");',
        f"  if({ranges(accesses)}) {{ uint32_t result=0U;",
        f"    for(uint32_t i=0;i<width;i++) result|=(uint32_t)m->stack[address-m->entry+{-low}U+i]<<(8U*i);",
        "    *fault=0U; return result; }",
        "  return spx_object_read(m->env,address,width,fault);", "}",
        "static void spx_object_machine_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {",
        "  struct spx_object_machine *m=opaque;",
        '  __CPROVER_assert(width>=1U && width<=4U,"spx-object-machine-access-width");',
        f"  if({ranges(writes)}) {{",
        f"    for(uint32_t i=0;i<width;i++) m->stack[address-m->entry+{-low}U+i]=(uint8_t)(value>>(8U*i));",
        "    *fault=0U; return; }",
        "  spx_object_write(m->env,address,width,value,fault);", "}",
        *dispatch,
        f"static {result_type} spx_object_original(struct spx_object_environment *env,{context_type} *context"+
        (","+",".join(params) if params else "")+") {", "  (void)context;",
        "  spx_machine_state initial,state; uint32_t return_target; struct spx_object_machine m;",
        f"  __CPROVER_assume(initial.esp>={-low}U && (uint64_t)initial.esp+{high}U<=UINT64_C(4294967296) &&",
        f"      (uint64_t)initial.esp+{delta}U<=UINT32_MAX);",
        "  m.env=env;m.entry=initial.esp;"]
    lines += [f'  initial.{register}={value};' for register, value in sorted(register_inputs.items())]
    for i in range(view_index):
        lines += [f"  __CPROVER_assume(env->inputs[{i}].reference.object==0U ||",
            f"      (uint64_t)env->inputs[{i}].address+env->inputs[{i}].extent<=(uint64_t)initial.esp+INT64_C({low}) ||",
            f"      (uint64_t)initial.esp+{high}U<=env->inputs[{i}].address);"]
    for offset, expression in input_values:
        lines += [f"  for(uint32_t i=0;i<4U;i++)m.stack[{offset-low}U+i]=(uint8_t)(({expression})>>(8U*i));"]
    lines += ["  spx_runtime rt={.context=&m,.read=spx_object_machine_read,.write=spx_object_machine_write,",
        f"    .image_base=UINT32_C({image})}};state=initial;",
        f"  spx_step_result result=spx_sub_{operation.entry_rvas[0]:08x}(&rt,&state,UINT32_C({operation.entry_rvas[0]}));"]
    if terminal_services:
        lines += ['  if(env->terminal){',
            '    __CPROVER_assert(result.kind==SPX_NONLOCAL,"spx-object-machine-terminal-outcome");',
            '    return;' if result_type == 'void' else '    return 0U;', '  }']
    lines += [f"  __CPROVER_assert(result.kind==SPX_RETURN && result.value==return_target && state.esp==initial.esp+{delta}U,",
        '      "spx-object-machine-normal-return");', "  uint32_t continuation_slot,continuation_byte;",
        "  __CPROVER_assume(continuation_slot<8U && continuation_byte<10U);"]
    preserved = frame_equalities(_architectural_state_equalities("state", "initial"),
                                [*clobbers, "esp", *([result_register] if result_register else [])])
    lines += ['  __CPROVER_assert('+" && ".join(preserved)+',"spx-object-machine-register-frame");']
    if result_register:
        lines.append(f"  return state.{result_register};")
    lines.append("}")
    return _render_object_model(bundle=bundle, operation_id=operation_id, symbol=symbol, kind="original_equivalence",
        terminal_services=terminal_services,
        original_adapter={"source": lines, "state_addresses": {name: row[2] for name, row in state_views.items()},
                          "requested_extents": requested, 'initializes': initializes})
