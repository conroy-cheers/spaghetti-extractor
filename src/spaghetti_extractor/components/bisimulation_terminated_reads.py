"""Checked current-memory result constraints for a terminated byte span.

The span comes from an entry NUL view AND an already issued readable origin.
No origin is created here. Its last byte is rechecked at the call, providing a
nonvacuity witness for the response constraint. Replay checks the recorded
response against current memory in addition to the independent call snapshot.
"""

from pathlib import Path

from ..external.terminated_reads import RELATION, WRITTEN_RELATION, checked_terminated_read, checked_terminated_write
from .bisimulation_support import BisimulationRefinementError


def uses_terminated_reads(bindings):
    return any(row.get("relation") == RELATION for binding in bindings
               for row in (binding.get("external_effect_contract") or {}).get("result_register_relations", []))


def uses_terminated_results(bindings):
    return any(row.get("relation") in {RELATION, WRITTEN_RELATION} for binding in bindings
               for row in (binding.get("external_effect_contract") or {}).get("result_register_relations", []))


def borrowed_memory_implementation_paths():
    # Borrowed references still depend on current memory and lifetime even when
    # the service has no terminated-string result relation.
    return [Path(__file__).with_name(name) for name in (
        "bisimulation_call_memory.py", "bisimulation_world.py", "bisimulation_world_memory.py",
        "bisimulation_reference_origins.py", "bisimulation_allocation_lifetime.py")]


def terminated_read_implementation_paths():
    return [*borrowed_memory_implementation_paths(), Path(__file__),
            Path(__file__).with_name("bisimulation_image_frame.py"),
            Path(__file__).parents[1]/"external"/"terminated_reads.py"]


def with_terminated_reads(fragments, *, specs, reference_capacity, max_nul_views, max_calls=0, access_check="", max_zero_writes=0):
    selected = []
    for spec in specs:
        row = checked_terminated_read(spec.get("external_effect_contract") or {},
                                      argument_words=len(spec["offsets"]))
        if row is None:
            continue
        if spec["cell_inputs"] or spec["outputs"] or row["base_argument"] not in spec["raw_indices"]:
            raise BisimulationRefinementError("terminated byte offset requires direct raw input without local cells")
        selected.append((spec, row, spec["raw_indices"].index(row["base_argument"])))
    written = []
    for spec in specs:
        row = checked_terminated_write(spec.get("external_effect_contract") or {},
                                       argument_words=len(spec["offsets"]))
        if row is not None:
            written.append((spec["spec_id"], spec["raw_indices"].index(row["base_argument"]),
                            spec["raw_indices"].index(row["capacity_argument"])))
    if written and (type(max_calls) is not int or max_calls < 1):
        raise BisimulationRefinementError("written termination requires checked call history capacity")
    # Call snapshots still admit dependence on all public memory. An auxiliary
    # image/private locality theorem must reject this service until a checked
    # read-footprint composition rule narrows that dependence. The caller passes
    # the active probe's rejecting guard; ordinary paired checks remain enabled.
    origin_cases = "\n".join(f'''
  if (origins->count > UINT32_C({i})) {{
    const spx_proof_origin *origin = &origins->entries[{i}];
    if (base >= origin->base && (origin->permissions & 1U) != 0U &&
        (uint64_t)base - origin->base <= origin->extent &&
        extent <= origin->extent - ((uint64_t)base - origin->base) &&
        spx_proof_allocation_reference_live(world, origin->base, origin->extent,
            origin->lifetime_generation, 0U)) return 1U;
  }}''' for i in range(reference_capacity))
    def span_cases(admission):
        return "\n".join(f'''
  if (world->nul_view_count > UINT32_C({i})) {{
    uint32_t start = world->nul_view_bases[{i}], size = world->nul_view_extents[{i}];
    if (base >= start && (uint64_t)base - start < size &&
        (uint64_t)start + size <= UINT64_C(4294967296)) {{
      uint32_t extent = size - (base - start);
      if (spx_proof_private_bytes(world, base, extent) == 0U &&
          {admission} &&
          (world == &spx_exact_world ? spx_proof_exact_byte(start + size - 1U) :
                                      spx_proof_source_byte(start + size - 1U)) == 0U &&
          (bound == 0U || extent < bound)) bound = extent;
    }}
  }}''' for i in range(max_nul_views))
    def written_span_cases(admission):
        # A historical service result supplies a candidate address, never a
        # preserved-content or lifetime claim. Recheck the zero now; callers of
        # this search separately establish current readable authority.
        return "\n".join(f'''
  if (world->call_count > UINT32_C({i})) {{
    spx_proof_call call = spx_exact_world.calls[{i}];
    if (call.spec == UINT32_C({spec_id}) && call.response_eax < call.arguments[{capacity}]) {{
      uint32_t start = call.arguments[{argument}];
      uint64_t end = (uint64_t)start + call.response_eax + UINT64_C(1);
      if (start != 0U && base >= start && (uint64_t)base < end && end <= UINT64_C(4294967296)) {{
        uint32_t extent = (uint32_t)(end - base);
        if (spx_proof_private_bytes(world, base, extent) == 0U &&
            {admission} &&
            (world == &spx_exact_world ? spx_proof_exact_byte((uint32_t)(end - 1U)) :
                                        spx_proof_source_byte((uint32_t)(end - 1U))) == 0U &&
            (bound == 0U || extent < bound)) bound = extent;
      }}
    }}
  }}''' for i in range(max_calls) for spec_id, argument, capacity in written)
    def zero_store_cases(admission):
        # Summary stores are replayed in the same public effect interval. Their
        # addresses are candidate witnesses only: overwritten bytes and dead
        # origins still fail. No origin or lifetime is minted by this search.
        # Any current zero is sufficient; prefer recent writes and stop once
        # one is found instead of computing an unneeded minimum prefix.
        return "\n".join(f'''
  if (world->write_count > UINT32_C({i}) && world->writes[{i}].call_range == 0U &&
      world->writes[{i}].width == 1U && (uint8_t)world->writes[{i}].value == 0U) {{
    uint32_t last = world->writes[{i}].address;
    if (base != 0U && last >= base) {{
      uint32_t extent = last - base + 1U;
      if (spx_proof_private_bytes(world, base, extent) == 0U && {admission} &&
          (world == &spx_exact_world ? spx_proof_exact_byte(last) : spx_proof_source_byte(last)) == 0U)
        return extent;
    }}
  }}''' for i in reversed(range(max_zero_writes)))
    cases = []
    for spec, row, index in selected:
        cases.append(f'''
  if (call->spec == UINT32_C({spec['spec_id']})) {{
    uint32_t base = call->arguments[{index}];
    if ({int(row['nullable'])}U && base == 0U) {{
      if (recording) __CPROVER_assume(call->response_eax == 0U);
      else __CPROVER_assert(call->response_eax == 0U, "spx-bisimulation-terminated-read-result");
      return;
    }}
    uint32_t extent = base == 0U ? 0U : spx_proof_terminated_read_span(world, base);
    /* Distinct assertion sites let the normal inventory scheduler check and
       retain recording and replay separately. Both remain mandatory; replay
       must establish its own current span after the portable execution. */
    if (recording) {{
      __CPROVER_assert(extent != 0U, "spx-bisimulation-terminated-read-current-span");
    }} else {{
      __CPROVER_assert(extent != 0U, "spx-bisimulation-terminated-read-current-span");
    }}
    __CPROVER_assume(extent != 0U);
{access_check}
    /* The checked final byte witnesses at least one possible response. */
    if (recording) __CPROVER_assume(call->response_eax < extent);
    else {{
      __CPROVER_assert(call->response_eax < extent, "spx-bisimulation-terminated-read-result");
      __CPROVER_assume(call->response_eax < extent);
    }}
    uint32_t address = base + call->response_eax;
    uint32_t byte = world == &spx_exact_world ? spx_proof_exact_byte(address) : spx_proof_source_byte(address);
    if (recording) __CPROVER_assume(byte == 0U);
    else __CPROVER_assert(byte == 0U, "spx-bisimulation-terminated-read-result");
    return;
  }}''')
    helpers = '''
static uint32_t spx_proof_terminated_read_origin(spx_proof_world *world, uint32_t base, uint32_t extent) {
  const spx_proof_origins *origins = spx_proof_origins_for(world);
''' + origin_cases + '''
  return 0U;
}
static uint32_t spx_proof_terminated_read_span(spx_proof_world *world, uint32_t base) {
  uint32_t bound = 0U;
''' + zero_store_cases("spx_proof_terminated_read_origin(world, base, extent)") + span_cases(
    "spx_proof_terminated_read_origin(world, base, extent)") + written_span_cases(
    "spx_proof_terminated_read_origin(world, base, extent)") + '''
  return bound;
}
uint64_t spx_proof_borrowed_nul_extent(void *context, uint32_t base, uint64_t visible) {
  /* Called after the adapter realizes the exact borrowed reference and checks
     its visible bounds. That check supplies identity, permission and lifetime;
     a fitting prefix need not search the origin registry a second time. */
  if (context == &spx_exact_world || context == &spx_source_world) {
    spx_proof_world *world = (spx_proof_world *)context;
    uint32_t bound = 0U;
''' + zero_store_cases("extent <= visible") + span_cases("extent <= visible") + written_span_cases("extent <= visible") + '''
    if (bound != 0U) return bound;
  }
  /* A view's own current final byte remains a sufficient alternative witness.
     The generated adapter reads it through the actual runtime and checks zero. */
  return visible;
}
'''
    if not selected:
        return {**fragments, "helpers": fragments["helpers"] + "\n" + helpers}
    helpers += '''
static void spx_proof_apply_terminated_read(spx_proof_world *world, const spx_proof_call *call, uint32_t recording) {
''' + "\n".join(cases) + '''
}
static void spx_proof_typed_apply_terminated_read(void) {
  if (spx_proof_typed_terminated_read_applied) return;
  if (!spx_proof_typed_recording) {
    __CPROVER_assert(spx_proof_typed_call_matches, "spx-bisimulation-terminated-read-arguments");
    __CPROVER_assume(spx_proof_typed_call_matches);
  }
  spx_proof_apply_terminated_read(spx_proof_typed_recording ? &spx_exact_world : &spx_source_world,
      &spx_exact_world.calls[spx_proof_typed_call_position], spx_proof_typed_recording);
  spx_proof_typed_terminated_read_applied = 1U;
}
'''
    additions = {"helpers": helpers,
        "declarations": "static uint32_t spx_proof_typed_terminated_read_applied;\nstatic void spx_proof_typed_apply_terminated_read(void);",
        "typed_reset": "  spx_proof_typed_terminated_read_applied = 0U;",
        "typed_apply": "  spx_proof_typed_apply_terminated_read();",
        "exact_apply": "    spx_proof_apply_terminated_read(&spx_exact_world, call, 1U);",
        "source_apply": "    spx_proof_apply_terminated_read(&spx_source_world, call, 0U);"}
    return {**fragments, **{key: fragments[key] + "\n" + value for key, value in additions.items()}}
