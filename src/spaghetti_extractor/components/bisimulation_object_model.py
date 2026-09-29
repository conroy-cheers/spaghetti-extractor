"""Local frames and dependence for shared objects and nullable byte views.

This source theorem does not establish machine entry, object lifetime or a
connected summary. It uses the production reference accessors and sparse current
memory. The event capacity is asserted, never assumed as an input restriction.
"""

from .bisimulation_mutable_memory import sparse_mutable_memory_runtime
from .component_c_v5 import _parameter_type, _result_type
from .machine_overlay_result_views import result_view_runtime_helpers
from .machine_overlay_services_v5 import _c_identifier


OBJECT_CONTRACT_POLICY = "object-view-source-frame-dependence-v1"
OBJECT_MODEL_POLICY = "object-view-sparse-current-memory-v1"
OBJECT_EVENT_CAPACITY = 8


def object_source_shape(bundle, *, terminal_services=()):
    """Recognize a local theorem domain, without granting composition authority."""
    interface = bundle.interface
    if ((interface.services and not terminal_services) or interface.effects or not interface.operations
            or len(bundle.intent.protocol_states) != 1):
        return None
    if terminal_services:
        from .bisimulation_object_terminal import checked_terminal_services
        checked_terminal_services(bundle, terminal_services)
    types = bundle.intent.schema.type_index

    def scalar(value):
        return (value.interpretation == "value" and value.access == "none"
                and not value.nullable and types[value.type_id].kind in {"integer", "bool", "enum"})

    def view(value, *, state=False):
        typ = types[value.type_id]
        if (value.interpretation != "view" or value.access not in {"read", "write", "read_write"}
                or typ.kind != "pointer"):
            return False
        element = types[typ.body["pointee_type_id"]]
        if element.kind != "integer" or element.body["width_bits"] != 8:
            return False
        if state:
            return (value.access != 'write' and not value.nullable and value.extent.get("kind") == "fixed"
                    and type(value.extent.get("bytes")) is int
                    and 0 < value.extent["bytes"] <= 0xffffffff)
        return (value.nullable and value.extent.get("kind") == "none" or
                not value.nullable and value.extent.get("kind") == "fixed"
                and type(value.extent.get("bytes")) is int and 0 < value.extent['bytes'] <= 0xffffffff)

    if any(item.initial is not None or not view(item.value, state=True) for item in interface.state):
        return None
    has_view = bool(interface.state)
    for operation in interface.operations:
        if (set(operation.pre_states) != {bundle.intent.initial_protocol_state}
                or set(operation.post_states) != {bundle.intent.initial_protocol_state}):
            return None
        signature = bundle.intent.schema.signature_index[operation.signature_id]
        if len(signature.results) > 1 or not all(scalar(value) for value in signature.results):
            return None
        if not all(scalar(value) or view(value) for value in signature.parameters):
            return None
        has_view |= any(value.interpretation == "view" for value in signature.parameters)
    return tuple(sorted(op.identity for op in interface.operations)) if has_view else None


def _runtime(count, *, terminal=False):
    return f'''
struct spx_object_input {{ spx_ref_v5 reference; uint32_t address, permissions; uint64_t extent; }};
struct spx_object_environment {{ struct spx_mutable_world *world; struct spx_object_input inputs[{count}];{' uint32_t terminal;' if terminal else ''} }};
static uint32_t spx_object_access(const struct spx_object_environment *env,
    uint32_t address, uint32_t width, uint32_t permissions) {{
  uint32_t admitted=0U;
  for (uint32_t i=0U;i<{count}U;++i) {{
    const struct spx_object_input *input=&env->inputs[i];
    if (input->reference.object != 0U && (input->permissions & permissions)==permissions &&
        address>=input->address && (uint64_t)address+width<=(uint64_t)input->address+input->extent)
      admitted=1U;
  }}
  return admitted;
}}
static uint32_t spx_object_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault) {{
  struct spx_object_environment *env=opaque;
  __CPROVER_assert(width>=1U && width<=4U && spx_object_access(env,address,width,1U),
      "spx-object-readable-frame");
  uint32_t result=0U;
  for(uint32_t i=0U;i<width;++i) result|=(uint32_t)spx_mutable_byte(env->world,address+i)<<(8U*i);
  *fault=0U; return result;
}}
static void spx_object_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {{
  struct spx_object_environment *env=opaque;
  __CPROVER_assert(width>=1U && width<=4U && spx_object_access(env,address,width,2U),
      "spx-object-writable-frame");
  spx_mutable_event(env->world,address,width,value,0U,0U); *fault=0U;
}}
static spx_boundary_status spx_object_realize(void *opaque,const spx_machine_reference_v1 *ref,
    uint32_t permissions,uint32_t nullable,uint32_t one_past,uint32_t *address) {{
  const struct spx_object_environment *env=opaque;
  (void)nullable;
  if(ref==0 || address==0 || ref->object==0U || ref->offset>ref->extent ||
      (ref->offset==ref->extent && !one_past) || (ref->permissions & permissions)!=permissions)
    return SPX_BOUNDARY_MEMORY_FAULT;
  for(uint32_t i=0U;i<{count}U;++i) {{
    const struct spx_object_input *input=&env->inputs[i];
    const spx_ref_v5 *known=&input->reference;
    if(ref->domain==known->domain && ref->object==known->object && ref->generation==known->generation &&
        ref->extent==known->extent && ref->permissions==known->permissions) {{
      uint64_t actual=(uint64_t)input->address-known->offset+ref->offset;
      if(actual>UINT32_MAX) return SPX_BOUNDARY_MEMORY_FAULT;
      *address=(uint32_t)actual; return SPX_BOUNDARY_OK;
    }}
  }}
  return SPX_BOUNDARY_MEMORY_FAULT;
}}
'''.splitlines()


def render_object_source_model(*, bundle, operation_id, symbol, kind, summary_dependencies=(), terminal_services=(), event_capacity=None):
    return _render_object_model(bundle=bundle, operation_id=operation_id, symbol=symbol,
        kind=kind, summary_dependencies=summary_dependencies, terminal_services=terminal_services, event_capacity=event_capacity)


def _render_object_model(*, bundle, operation_id, symbol, kind, summary_dependencies=(), original_adapter=None,
                         terminal_services=(), event_capacity=None):
    operations = object_source_shape(bundle, terminal_services=terminal_services)
    kinds = {"original_equivalence"} if original_adapter is not None else {"frame", "input_dependence"}
    if (operations is None or operation_id not in operations or kind not in kinds
            or not symbol or symbol != _c_identifier(symbol) or summary_dependencies):
        raise ValueError("object source model requires its service-free object-view domain")
    operation = next(op for op in bundle.interface.operations if op.identity == operation_id)
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    types = bundle.intent.schema.type_index
    component = _c_identifier(bundle.interface.identity)
    context_type = f"spx_{component}_context_v5"
    result_type = _result_type(types, signature)
    views = [("state", item.value) for item in bundle.interface.state]
    views += [("parameter", value) for value in signature.parameters if value.interpretation == "view"]
    # This is an asserted storage budget, not an assumption about the input or
    # a guarantee of full writes. Larger/repeated writes still fail capacity.
    capacity = max(OBJECT_EVENT_CAPACITY, min(64, sum(v.extent['bytes'] for root, v in views
        if root == 'parameter' and v.access in {'write', 'read_write'} and v.extent.get('kind') == 'fixed')))
    if event_capacity is not None:
        if type(event_capacity) is not int or not 1 <= event_capacity <= 64:
            raise ValueError('object event capacity must be an explicit checked budget between 1 and 64')
        capacity = event_capacity
    from .bisimulation_object_initialization import checked_initialization_requests, initialization_checks
    initializes = checked_initialization_requests(
        original_adapter.get('initializes', []) if original_adapter is not None else [], signature=signature)
    sides = ("left",) if kind == "frame" else ("left", "right")
    entry = f"spx_object_{kind}_{_c_identifier(operation_id)}"
    parameters = [f"{context_type} *context"] + [
        f"{_parameter_type(types, value)} parameter_{i}" for i, value in enumerate(signature.parameters)]
    lines = ['#include "state-machine-runtime.h"', '#include "portable-component-implementation.h"',
        *sparse_mutable_memory_runtime(capacity, observed_byte=kind != 'frame'),
        *_runtime(len(views), terminal=bool(terminal_services)),
        *result_view_runtime_helpers(),
        f"{result_type} {symbol}({', '.join(parameters)})",
        "__CPROVER_requires(1)", "__CPROVER_ensures(1)",
        "__CPROVER_assigns(__CPROVER_object_whole(spx_mutable_frame));"]
    if terminal_services:
        from .bisimulation_object_terminal import terminal_model_runtime, terminal_model_setup
        lines += terminal_model_runtime(bundle=bundle, signature=signature, symbol=symbol, kind=kind, services=terminal_services)
    if original_adapter is not None:
        lines.extend(original_adapter["source"])
    lines.append(f"void {entry}(void) {{")
    if kind != 'frame':
        lines.append('  uint32_t observed_address;')
    for i, value in enumerate(signature.parameters):
        if value.interpretation != "view":
            lines.append(f"  {_parameter_type(types, value)} parameter_{i};")
    for side in sides:
        lines += [f"  {context_type} context_{side}={{0}};",
            (f"  struct spx_mutable_world world_{side}={{0}};" if kind == 'frame' else
             f"  struct spx_mutable_world world_{side}={{.observed_address=observed_address,"
             ".observed_byte=__CPROVER_uninterpreted_readonly_byte(observed_address)};"),
            f"  struct spx_object_environment env_{side}={{.world=&world_{side}}};",
            f"  spx_runtime runtime_{side}={{.context=&env_{side},.read=spx_object_read,",
            "    .write=spx_object_write,.realize_reference=spx_object_realize};"]
    for i, (root, value) in enumerate(views):
        name = _c_identifier(value.identity)
        permissions = {'read': 1, 'write': 2, 'read_write': 3}[value.access]
        lines += [f"  struct spx_object_input input_{i};",
            f"  __CPROVER_assume(input_{i}.reference.object!=0U && input_{i}.address!=0U &&",
            f"      input_{i}.reference.offset<=input_{i}.address &&",
            f"      input_{i}.reference.offset<input_{i}.reference.extent &&",
            f"      input_{i}.reference.extent<=UINT32_MAX &&",
            f"      (input_{i}.reference.permissions & {permissions}U)=={permissions}U &&",
            f"      (uint64_t)input_{i}.address-input_{i}.reference.offset+input_{i}.reference.extent<=UINT64_C(4294967296));",
            f"  input_{i}.permissions={permissions}U;"]
        if root == "state" or value.extent.get('kind') == 'fixed':
            lines += [f"  input_{i}.extent=UINT64_C({value.extent['bytes']});",
                f"  __CPROVER_assume(input_{i}.extent<=input_{i}.reference.extent-input_{i}.reference.offset);"]
        else:
            lines += [f"  input_{i}.extent=input_{i}.reference.extent-input_{i}.reference.offset;",
                f"  uint8_t null_{i}; __CPROVER_assume(null_{i}<=1U);",
                f"  if(null_{i}) input_{i}=(struct spx_object_input){{0}};"]
        if original_adapter is not None:
            if root == "state":
                lines.append(f"  __CPROVER_assume(input_{i}.address==UINT32_C({original_adapter['state_addresses'][value.identity]}));")
            else:
                minimum = original_adapter["requested_extents"][value.identity]
                lines.append(f"  __CPROVER_assume(input_{i}.reference.object==0U || input_{i}.extent>=UINT64_C({minimum}));")
        for prior in range(i):
            # Identical live logical origins cannot name conflicting physical
            # storage. Different origins may overlap; bytes remain shared.
            lines += [f"  __CPROVER_assume(input_{i}.reference.object==0U || input_{prior}.reference.object==0U ||",
                f"      input_{i}.reference.domain!=input_{prior}.reference.domain ||",
                f"      input_{i}.reference.object!=input_{prior}.reference.object ||",
                f"      input_{i}.reference.generation!=input_{prior}.reference.generation ||",
                f"      (input_{i}.reference.extent==input_{prior}.reference.extent &&",
                f"       input_{i}.reference.permissions==input_{prior}.reference.permissions &&",
                f"       (uint64_t)input_{i}.address-input_{i}.reference.offset==",
                f"       (uint64_t)input_{prior}.address-input_{prior}.reference.offset));"]
        for side in sides:
            target = f"context_{side}.state.{name}" if root == "state" else f"view_{i}_{side}"
            lines += [f"  env_{side}.inputs[{i}]=input_{i};"]
            if root != "state":
                lines.append(f"  spx_view_v5 {target};")
            lines += [f"  {target}=(spx_view_v5){{0}};",
                f"  if(input_{i}.reference.object!=0U) {target}=(spx_view_v5){{",
                f"    .base=input_{i}.reference,.extent=input_{i}.extent,.element_width=1U,",
                f"    .access_context=&runtime_{side}" +
                (",.read=spx_component_result_view_read" if permissions & 1 else "") +
                (",.write=spx_component_result_view_write" if permissions & 2 else "") + "};"]
    if terminal_services:
        lines += terminal_model_setup(bundle=bundle, signature=signature, views=views, sides=sides, services=terminal_services)
    for side in sides:
        args = [f"&context_{side}"]
        for i, value in enumerate(signature.parameters):
            index = next((j for j, (root, item) in enumerate(views)
                          if root == "parameter" and item.identity == value.identity), None)
            args.append(f"&view_{index}_{side}" if index is not None else f"parameter_{i}")
        lines.append(f"  spx_mutable_frame=&world_{side};")
        call = (f"spx_object_original(&env_left, {', '.join(args)})"
                if original_adapter is not None and side == "left" else f"{symbol}({', '.join(args)})")
        if terminal_services and side == 'right':
            lines.append('  spx_object_terminal_run_right();')
            if result_type != 'void':
                lines.append(f'  {result_type} result_right=spx_object_terminal.result_right;')
        else:
            lines.append(f"  {result_type} result_{side}={call};" if result_type != "void" else f"  {call};")
        if terminal_services and original_adapter is not None and side == 'left':
            lines += ['  spx_object_terminal.left_service=env_left.terminal;', '  if(!env_left.terminal){',
                *initialization_checks(initializes, views=views, side=side), '  }']
        else:
            lines += initialization_checks(initializes, views=views, side=side)
    if kind in {"input_dependence", "original_equivalence"}:
        observation = "equivalence" if original_adapter is not None else "dependence"
        if result_type != "void":
            lines.append(f'  __CPROVER_assert(result_left==result_right,"spx-object-result-{observation}");')
        lines += ['  __CPROVER_assert(world_left.observed_byte==world_right.observed_byte,',
            f'      "spx-object-current-memory-{observation}");']
    lines += [f'  __CPROVER_assert(1,"spx-object-{kind}:{operation_id}");', "}"]
    return "\n".join(lines) + "\n", entry
