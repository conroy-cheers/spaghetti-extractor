"""Current-memory suffix facts with matched construction and observation.

The first range form is a constant-filled suffix of a captured allocation view.
Coordinates may use registers or checked private stack reads. Heap facts cannot
change a private coordinate retroactively; other prior observations still block
installation.
"""

import json
from collections.abc import Mapping

from .bisimulation_support import BisimulationRefinementError

POLICY = "allocation-current-filled-suffix-v1"


def parse_facts(values, captures, history):
    from .bisimulation import _c_identifier, _invariant_expression

    if not isinstance(values, list):
        raise ValueError("memory_facts must be a list")
    by_id = {capture.identity: capture for capture in captures}
    result = []
    for value in values:
        if not isinstance(value, Mapping) or set(value) != {"id", "kind", "view", "start", "byte"}:
            raise ValueError("memory fact requires id, kind, view, start and byte")
        identity = _c_identifier(value["id"], "memory fact id")
        capture = by_id.get(_c_identifier(value["view"], "memory fact view"))
        if (value["kind"] != "filled_suffix" or capture is None or capture.mode != "native_view"
                or history is None or capture.projection.payload["authority"]["lifetime"] != "allocation"
                or capture.projection.payload["base"].get("kind") not in {"register", "stack"}
                or capture.projection.payload["base"].get("width") != 32
                or capture.projection.payload["extent"] != {"kind": "origin_remainder"}
                or capture.projection.payload["requested_extent"] != {"kind": "constant", "value": 1, "width": 32}
                or capture.encoding["access"] not in {"read", "read_write"}):
            raise ValueError("filled suffix needs a readable allocation view with register/private-stack base and origin remainder")
        byte = value["byte"]
        if type(byte) is not int or not 0 <= byte <= 255:
            raise ValueError("filled suffix byte must be an integer in 0..255")
        start, sort, refs = _invariant_expression(value["start"], "filled suffix start")
        if start["op"] == "const":
            valid = start["width"] <= 32
        elif start["op"] == "state_input" and refs <= set(by_id):
            scalar = by_id[start["name"]]
            valid = (scalar.mode == "machine_codec" and scalar.kind == "source_state"
                and scalar.projection.payload.get("kind") in {"register", "stack"}
                and scalar.projection.payload.get("width") == 32
                and scalar.encoding == start and scalar.decoding == {"op": "projected_value"})
        else:
            valid = False
        if sort != "word" or not valid:
            raise ValueError("filled suffix start needs a uint32 constant or an identity register/private-stack capture")
        result.append({"id": identity, "kind": "filled_suffix", "view": value["view"], "start": start, "byte": byte})
    ids = [row["id"] for row in result]
    if ids != sorted(set(ids)):
        raise ValueError("memory facts must be ordered and unique")
    return tuple(result)


def capacity(operation):
    return max((len(sync.memory_facts) for sync in operation.syncs), default=0)


def coordinate_phases(sync, fact):
    view = next(row for row in sync.captures if row.identity == fact['view'])
    if view.projection.payload['base']['kind'] == 'stack':
        return ('coordinate-private', 'coordinate-readable')
    if fact['start']['op'] == 'state_input':
        capture = next(row for row in sync.captures if row.identity == fact['start']['name'])
        if capture.projection.payload['kind'] == 'stack':
            return ('coordinate-private', 'coordinate-readable')
    return ()


def metadata(operation):
    return {"memory_fact_policy": POLICY} if capacity(operation) else {}


def validate_model(planned, model):
    from .bisimulation import BisimulationSyncV1
    syncs = [BisimulationSyncV1.parse(sync, "memory-fact sync") for sync in planned["source"]["syncs"]
             if "memory_facts" in sync]
    present = any(sync.memory_facts for sync in syncs)
    if ("memory_fact_policy" in model) != present or (present and model["memory_fact_policy"] != POLICY):
        raise ValueError("current-memory fact transport differs from the proof plan")
    if present and "obligation_id" in model:
        targets = {edge["target_unit_id"] for edge in planned["exact"]["control_edges"]
                   if edge["source_unit_id"] in model["selected_unit_ids"]}
        for sync in syncs:
            phases = (("construction-order", "input-domain") if model["obligation_id"] == f"sync:{sync.identity}" else ())
            phases += ("output-domain", "contents") if sync.exact_unit_id in targets else ()
            for fact in sync.memory_facts:
                required = phases + (coordinate_phases(sync, fact) if phases else ())
                if any(description(sync, fact, phase) not in model["required_assertion_descriptions"] for phase in required):
                    raise ValueError("current-memory fact omits its construction or successor checks")
    return {"memory_fact_policy"} if present else set()


def description(sync, fact, phase):
    return f"spx-bisimulation-memory-fact-{phase}:{sync.identity}:{fact['id']}"


def world_fragments(count):
    if type(count) is not int or count < 0:
        raise BisimulationRefinementError("memory fact capacity must be a nonnegative integer")
    if not count:
        return {"declarations": "", "read": "", "reset": ""}
    rows = '\n'.join(f'''  if (spx_initial_fill_count > UINT32_C({i}) &&
      (uint64_t)address >= spx_initial_fills[{i}].begin &&
      (uint64_t)address < spx_initial_fills[{i}].end)
    return spx_initial_fills[{i}].byte;''' for i in range(count))
    return {"declarations": f'''typedef struct {{ uint64_t begin, end; uint8_t byte; }} spx_initial_fill;
static spx_initial_fill spx_initial_fills[{count}];
static uint32_t spx_initial_fill_count, spx_initial_fill_observed;
''', "read": "  spx_initial_fill_observed = 1U;\n" + rows + "\n",
        "reset": "  spx_initial_fill_count = spx_initial_fill_observed = 0U;\n"}


def symbols(sync, fact):
    return f"spx_memory_fact_{len(sync.identity)}_{sync.identity}_{fact['id']}"


def declarations(operation):
    return [f"void {symbols(sync, fact)}_check(const spx_machine_state *);"
            for sync in operation.syncs for fact in sync.memory_facts]


def initialization(sync):
    return ([f"  {symbols(sync, fact)}_initialize(&initial_state);" for fact in sync.memory_facts]
            if sync is not None else [])


def outgoing(sync):
    return [f"    {symbols(sync, fact)}_check(&spx_proof_exact_output);" for fact in sync.memory_facts]


def source(operation, specs, authority, *, runtime_assurance=None):
    from .bisimulation_projection import _projection_expression

    from .bisimulation_assurance import runtime_contract_selected

    projected = runtime_contract_selected(runtime_assurance, "world-reference-summary")
    context_declaration = "" if projected else "  spx_proof_authority_context context;\n"
    context_check = ("spx_proof_authority_world_context_status(&spx_exact_world)" if projected else
                     "spx_proof_allocation_authority_context(&spx_exact_world, &context)")
    lookup = ("spx_proof_authority_world_resolve_reference(&spx_exact_world," if projected else
              "spx_proof_authority_resolve_reference(&context,")
    if not capacity(operation):
        return ""
    if specs is None:
        raise BisimulationRefinementError("memory facts require checked native view codecs")
    result = []
    for sync in operation.syncs:
        captures = {capture.identity: capture for capture in sync.captures}
        for fact in sync.memory_facts:
            view = captures[fact["view"]]
            spec = specs["captures"][(sync.identity, view.identity)]
            selector = json.loads(spec["selector"])
            rule_selector = next(index + 1 for index, rule in enumerate(authority["rules"])
                                 if rule["id"] == selector)
            name = symbols(sync, fact)
            base = _projection_expression(view.projection.payload["base"], state="(*state)", read=f"{name}_coordinate_read")
            offset = (f"UINT32_C({fact['start']['value']})" if fact["start"]["op"] == "const" else
                _projection_expression(captures[fact["start"]["name"]].projection, state="(*state)", read=f"{name}_coordinate_read"))
            if base is None or offset is None:
                raise BisimulationRefinementError("memory fact coordinates lack checked transport")
            if coordinate_phases(sync, fact):
                result.append(f'''
static uint32_t {name}_coordinate_read(uint32_t address, uint32_t width) {{
  uint32_t private_span = width == 4U && address >= spx_exact_world.private_low &&
      (uint64_t)address + width <= spx_exact_world.private_high;
  __CPROVER_assert(private_span, "{description(sync, fact, 'coordinate-private')}");
  __CPROVER_assume(private_span);
  /* Every installed fill belongs to an allocation disjoint from this private
     frame. Preserve the observation flag only for this proved private read;
     never clear an observation that preceded coordinate evaluation. */
  uint32_t observed = spx_initial_fill_observed, fault = 0U;
  uint32_t value = spx_proof_exact_read(0, address, width, &fault);
  __CPROVER_assert(fault == 0U, "{description(sync, fact, 'coordinate-readable')}");
  spx_initial_fill_observed = observed;
  return value;
}}
''')
            conflicts = '\n'.join(f'''  if (spx_initial_fill_count > UINT32_C({i}))
    __CPROVER_assume(end <= spx_initial_fills[{i}].begin || begin >= spx_initial_fills[{i}].end ||
        spx_initial_fills[{i}].byte == UINT32_C({fact['byte']}));''' for i in range(capacity(operation)))
            result.append(f'''
static uint32_t {name}_domain(const spx_machine_state *state, uint64_t *begin, uint64_t *end) {{
  const uint32_t base = (uint32_t)({base});
  if (base == 0U && UINT32_C({spec['nullable']})) {{ *begin = *end = 0U; return 1U; }}
  spx_machine_reference_v1 reference = {{0}};
{context_declaration}  if (!spx_proof_allocation_class_locally_born(&spx_exact_world, UINT32_C({rule_selector})) ||
      {context_check} != SPX_BOUNDARY_OK) return 0U;
  spx_boundary_status status = {lookup}
      base, 1U, UINT32_C({spec['permissions']}), {spec['selector']}, 0U, 0U, &reference);
  if (status != SPX_BOUNDARY_OK || reference.offset > reference.extent) return 0U;
  const uint32_t offset = (uint32_t)({offset});
  uint64_t remaining = reference.extent - reference.offset;
  if ((uint64_t)offset > remaining || (uint64_t)base + remaining > UINT64_C(4294967296)) return 0U;
  *begin = (uint64_t)base + offset; *end = (uint64_t)base + remaining;
  return 1U;
}}
static void {name}_initialize(const spx_machine_state *state) {{
  uint64_t begin, end;
  __CPROVER_assert(!spx_initial_fill_observed && spx_initial_fill_count < UINT32_C({capacity(operation)}),
      "{description(sync, fact, 'construction-order')}");
  __CPROVER_assume({name}_domain(state, &begin, &end));
{conflicts}
  spx_initial_fills[spx_initial_fill_count++] = (spx_initial_fill){{begin, end, UINT32_C({fact['byte']})}};
  __CPROVER_assert({name}_domain(state, &begin, &end), "{description(sync, fact, 'input-domain')}");
}}
void {name}_check(const spx_machine_state *state) {{
  uint64_t begin, end;
  uint32_t admitted = {name}_domain(state, &begin, &end);
  __CPROVER_assert(admitted, "{description(sync, fact, 'output-domain')}");
  __CPROVER_assume(admitted);
  uint32_t probe = spx_nondet_u32();
  __CPROVER_assert((uint64_t)probe < begin || (uint64_t)probe >= end ||
      spx_proof_exact_byte(probe) == UINT32_C({fact['byte']}), "{description(sync, fact, 'contents')}");
}}
''')
    return '\n'.join(result)
