"""Checked public image and allocation-buffer ranges in the paired call oracle.

Each call supplies an arbitrary final byte function over its declared writable
ranges. The same call and physical address select the same byte on replay,
including overlapping footprints. A range occupies one chronological write
event; its size does not expand the model. This is an environment abstraction,
not evidence that an external implementation satisfies a declared footprint.
"""

from collections.abc import Mapping
from pathlib import Path

from .bisimulation_support import BisimulationRefinementError
from ..external.argument_domains import checked_argument_domain, word_in_domain
from ..external.terminated_reads import checked_terminated_write


def uses_call_ranges(bindings):
    return any(isinstance(row.get("external_effect_contract"), Mapping) and
               (row["external_effect_contract"].get("memory_effect") == "argumentRanges" or
                (row["external_effect_contract"].get("memory_effect") == "readOnly" and
                 bool(row["external_effect_contract"].get("memory_footprints"))) or
                bool(row["external_effect_contract"].get("argument_domain"))) for row in bindings)


def call_range_implementation_paths():
    return [*(Path(__file__).with_name(name) for name in (
        "bisimulation_call_ranges.py", "bisimulation_call_memory.py",
        "bisimulation_world.py", "bisimulation_world_memory.py",
        "bisimulation_reference_authority.py", "bisimulation_reference_origins.py",
        "bisimulation_allocation_lifetime.py", "bisimulation_exact_frame.py",
        "bisimulation_mutable_frame.py", "bisimulation_private_frame.py")),
        Path(__file__).parents[1]/"external"/"argument_domains.py"]


def _reject(detail):
    raise BisimulationRefinementError(f"proof_service_buffer_effect_unsupported: {detail}")


def _word(value, *, positive=False):
    return type(value) is int and int(positive) <= value <= 0xffffffff


def checked_call_ranges(spec):
    payload = spec.get("external_effect_contract") or {}
    readonly = payload.get('memory_effect') == 'readOnly'
    if payload.get("memory_effect") != "argumentRanges" and not readonly:
        return ()
    footprints = payload.get('memory_footprints', [])
    if readonly and footprints == []:
        return ()
    if readonly and (spec.get('outputs') != [] or spec.get('cell_inputs') != []):
        _reject('readOnly footprints require empty local-cell inputs and outputs')
    if (payload.get("world_effect") not in {"none", "opaqueResources"} or
            spec.get("outputs") or spec.get("cell_inputs")):
        _reject("buffer ranges cannot yet combine with lifetime or local-cell outputs")
    if not isinstance(footprints, list) or not footprints:
        _reject(f"{payload.get('memory_effect')} requires explicit footprints")
    raw = spec["raw_indices"]

    def argument(index):
        if not _word(index) or index not in raw:
            _reject("footprint argument is absent from the checked raw transcript")
        return raw.index(index)

    result = []
    for row in footprints:
        if (not isinstance(row, Mapping) or set(row) != {
                "access", "base_argument", "offset", "size", "nullable"} or
                row["access"] not in {"read", "write", "read_write"} or
                not _word(row["offset"]) or type(row["nullable"]) is not bool):
            _reject("footprint shape is unsupported")
        if readonly and row['access'] != 'read':
            _reject('readOnly footprints must have read access')
        base = argument(row["base_argument"])
        size = row["size"]
        if not isinstance(size, Mapping):
            _reject("footprint size is malformed")
        terminated = None
        if set(size) == {"kind", "bytes"} and size["kind"] == "fixed" and _word(size["bytes"], positive=True):
            extent = f'UINT64_C({size["bytes"]})'
        elif (set(size) == {"kind", "argument", "scale"} and size["kind"] == "argument" and
                _word(size["scale"], positive=True)):
            extent = f'(uint64_t)call->arguments[{argument(size["argument"])}] * UINT64_C({size["scale"]})'
        elif (set(size) == {"kind", "source_argument", "source_offset", "unit_bytes", "sentinel", "max_units"}
              and size["kind"] == "bounded_terminated" and type(size["unit_bytes"]) is int
              and size["unit_bytes"] == 1 and size["sentinel"] == [0]
              and all(type(value) is int for value in size["sentinel"])
              and _word(size["source_offset"]) and _word(size["max_units"], positive=True)):
            terminated = (argument(size["source_argument"]), size["source_offset"], size["max_units"])
            extent = None
        else:
            _reject("only fixed, argument-scaled and bounded NUL byte extents are implemented")
        result.append({"base": base, "extent": extent, "offset": row["offset"],
                       "nullable": row["nullable"], "access": row["access"], "terminated": terminated})
    return tuple(result)


def readable_range_descriptions(specs):
    """Bind each declared read span to an explicit consumer proof obligation."""
    return sorted({f"spx-bisimulation-call-readable-range:{spec['spec_id']}:{index}"
        for spec in specs if (spec.get('external_effect_contract') or {}).get('memory_effect') == 'readOnly'
        for index, _ in enumerate(checked_call_ranges(spec))})


def validate_readable_range_guards(specs, models):
    required = set(readable_range_descriptions(specs))
    if not required:
        return
    operations = models.get('operation_models')
    if (not isinstance(operations, list) or not operations or any(
            not isinstance(operation, Mapping) or not operation.get('obligation_models') or any(
                not isinstance(segment, Mapping) or not required.issubset(
                    segment.get('required_assertion_descriptions', []))
                for segment in operation['obligation_models']) for operation in operations)):
        _reject('explicit readOnly footprints lack their checked consumer guards')


def call_range_write_capacity(specs):
    """Reserve chronological range events in both the world and its consumers."""
    return max((sum(row["access"] != "read" for row in checked_call_ranges(spec)) +
                int(checked_terminated_write(spec.get("external_effect_contract") or {},
                                            argument_words=len(spec["offsets"])) is not None)
                for spec in specs), default=0)


def call_range_fragments(*, specs, authority, image_size, private_ranges, frame_check,
                        summary_ranges=False, reference_capacity=0):
    empty = {key: "" for key in ("declarations", "helpers", "typed_reset", "typed_apply",
                                "exact_apply", "source_apply")}
    empty["writes_per_call"] = 0
    selected = [(spec, checked_call_ranges(spec), checked_argument_domain(
        (spec.get("external_effect_contract") or {}).get("argument_domain", []), argument_words=len(spec["offsets"])))
        for spec in specs]
    selected = [(spec, ranges, domain) for spec, ranges, domain in selected if ranges or domain]
    if not selected and not summary_ranges:
        return empty
    terminated_ranges = any(row["terminated"] is not None for _, ranges, _ in selected for row in ranges)
    if terminated_ranges and (type(reference_capacity) is not int or reference_capacity <= 0):
        _reject("terminated footprints require the checked origin capacity")
    has_ranges = summary_ranges or any(ranges for _, ranges, _ in selected)
    if has_ranges and authority is None:
        _reject("buffer footprints require canonical object authority")
    if has_ranges and not _word(image_size, positive=True):
        _reject("buffer footprints require the checked image extent")
    rules = [rule for rule in (authority.rules if has_ranges else ()) if rule.locator.kind == "image_rva" and
             rule.kind == "image" and rule.lifetime == "image" and rule.extent_mode == "fixed" and
             rule.locator.offset + rule.extent <= image_size]
    allocated = [rule for rule in (authority.rules if has_ranges else ())
                 if rule.locator.kind == "external_allocation" and rule.kind == "external" and
                 rule.lifetime == "allocation" and rule.extent_mode == "instance_remainder"]
    if has_ranges and not rules and not allocated:
        _reject("buffer footprints require fixed image objects or checked allocation origins")
    if allocated and (type(reference_capacity) is not int or reference_capacity <= 0):
        _reject("allocation footprints require the checked origin capacity")
    guards = []
    for rule in rules:
        comparison = ">=" if rule.interior_pointers else "=="
        guards.append(f'''(base {comparison} (uint64_t)SPX_PROOF_IMAGE_BASE + UINT64_C({rule.locator.offset}) &&
          end <= (uint64_t)SPX_PROOF_IMAGE_BASE + UINT64_C({rule.locator.offset + rule.extent}) &&
          (UINT32_C({rule.permissions}) & permissions) == permissions)''')
    private = "\n".join(f'''  if (base < UINT64_C({start + size}) && UINT64_C({start}) < end)
    return UINT32_C(0);''' for start, size in private_ranges)
    allocation_guards = " ||\n          ".join(f'''(origin.domain == UINT64_C({rule.domain}) &&
          origin.object == UINT64_C({rule.object_id}) &&
          base {">=" if rule.interior_pointers else "=="} origin.base &&
          (UINT32_C({rule.permissions}) & permissions) == permissions)''' for rule in allocated)
    # A raw address or historical allocation is insufficient. Use an origin
    # issued by the existing checked adapter and recheck its current lifetime.
    # Copy rows by value, avoiding symbolic pointers retained into the registry.
    allocation_guards = ('''
  const spx_proof_origins *origins = spx_proof_origins_for(world);
  if (origins == 0) return UINT32_C(0);
''' + "\n".join(f'''
  if (origins->count > UINT32_C({i})) {{
    spx_proof_origin origin = origins->entries[{i}];
    if (origin.lifetime_generation > UINT64_C(1) &&
        (origin.permissions & permissions) == permissions &&
        base >= origin.base && base - origin.base <= origin.extent &&
        extent <= origin.extent - (base - origin.base) &&
        ({allocation_guards}) &&
        spx_proof_allocation_reference_live(world, origin.base, origin.extent,
            origin.lifetime_generation, 0U)) return UINT32_C(1);
  }}''' for i in range(reference_capacity))) if allocated else ""
    cases = []
    for spec, ranges, domain in selected:
        lines = [f'  if (call->spec == UINT32_C({spec["spec_id"]})) {{']
        written = checked_terminated_write(spec.get("external_effect_contract") or {},
                                           argument_words=len(spec["offsets"]))
        if written is not None:
            capacity = spec["raw_indices"].index(written["capacity_argument"])
            lines += [f'    uint32_t capacity = call->arguments[{capacity}];',
                '    __CPROVER_assert(capacity != 0U, "spx-bisimulation-written-termination-capacity");',
                '    __CPROVER_assume(capacity != 0U);',
                '    if (world == &spx_source_world)',
                '      __CPROVER_assert(call->response_eax < capacity, "spx-bisimulation-written-termination-result");',
                '    __CPROVER_assume(call->response_eax < capacity);']
        for constraint in domain:
            index = constraint["argument_index"]
            if index not in spec["raw_indices"]:
                _reject("argument domain requires a checked raw argument")
            condition = word_in_domain(f'call->arguments[{spec["raw_indices"].index(index)}]', constraint)
            lines += [f'    __CPROVER_assert({condition}, "spx-bisimulation-call-argument-domain");',
                      f'    __CPROVER_assume({condition});']
        # Resolve memory-dependent extents in the call-entry world. Applying a
        # preceding writable footprint must not change a later source bound.
        for index, row in enumerate(ranges):
            if row["terminated"] is not None:
                source, offset, maximum = row["terminated"]
                lines += [f'    uint64_t extent_{index} = 0U;',
                    f'    if ({int(not row["nullable"])}U || call->arguments[{row["base"]}] != 0U) {{',
                    f'      extent_{index} = spx_proof_call_terminated_extent(world,',
                    f'          (uint64_t)call->arguments[{source}] + UINT64_C({offset}), UINT32_C({maximum}));',
                    f'      __CPROVER_assert(extent_{index} != 0U, "spx-bisimulation-call-terminated-current-span");',
                    f'      __CPROVER_assume(extent_{index} != 0U);', '    }']
        for index, row in enumerate(ranges):
            permissions = {"read": 1, "write": 2, "read_write": 3}[row["access"]]
            description = (f"spx-bisimulation-call-readable-range:{spec['spec_id']}:{index}"
                if (spec.get('external_effect_contract') or {}).get('memory_effect') == 'readOnly'
                else 'spx-bisimulation-call-buffer-authority')
            lines += [f'    if ({int(not row["nullable"])}U || call->arguments[{row["base"]}] != 0U) {{',
                      f'      uint64_t base = (uint64_t)call->arguments[{row["base"]}] + UINT64_C({row["offset"]});',
                      f'      uint64_t extent = {row["extent"] if row["terminated"] is None else f"extent_{index}"};',
                      f'      uint32_t admitted = spx_proof_call_range_admitted(world, base, extent, UINT32_C({permissions}));',
                      f'      __CPROVER_assert(admitted, "{description}");',
                      '      __CPROVER_assume(admitted);']
            if permissions & 2:
                lines += ['      if (extent != 0U) {',
                          '        spx_proof_append_call_range(world, (uint32_t)base, (uint32_t)extent, position);',
                          '      }']
            lines += ['    }']
        if written is not None:
            base = spec["raw_indices"].index(written["base_argument"])
            lines += [
                '    /* Construct the promised byte after the arbitrary range. Every',
                '       admitted positive capacity permits every count below capacity.',
                '       Authority and frame were checked for the enclosing range. */',
                f'    spx_proof_append_write(world, call->arguments[{base}] + call->response_eax, 1U, 0U);']
        cases.append("\n".join([*lines, '    return;', '  }']))
    terminated_helpers = ''
    if terminated_ranges:
        terminated_helpers = '''
static uint32_t spx_proof_terminated_read_span(spx_proof_world *world, uint32_t base);
static uint32_t spx_proof_call_terminated_extent(
    spx_proof_world *world, uint64_t wide_base, uint32_t maximum) {
  if (wide_base == 0U || wide_base > UINT32_MAX) return 0U;
  uint32_t base = (uint32_t)wide_base;
  uint32_t bound = spx_proof_terminated_read_span(world, base);
  if (bound > maximum) bound = 0U;
  const spx_proof_origins *origins = spx_proof_origins_for(world);
  if (origins == 0) return bound;
''' + "\n".join(f'''
  if (origins->count > UINT32_C({i})) {{
    spx_proof_origin origin = origins->entries[{i}];
    if (base >= origin.base && (uint64_t)base - origin.base < origin.extent &&
        origin.extent <= UINT64_C(4294967296) - origin.base &&
        (origin.permissions & 1U) != 0U &&
        spx_proof_allocation_reference_live(world, origin.base, origin.extent,
            origin.lifetime_generation, 0U)) {{
      uint64_t extent = origin.extent - ((uint64_t)base - origin.base);
      if (extent <= maximum && (bound == 0U || extent < bound) &&
          spx_proof_private_bytes(world, base, (uint32_t)extent) == 0U &&
          (world == &spx_exact_world ? spx_proof_exact_byte(base + (uint32_t)extent - 1U) :
                                      spx_proof_source_byte(base + (uint32_t)extent - 1U)) == 0U)
        bound = (uint32_t)extent;
    }}
  }}''' for i in range(reference_capacity)) + '''
  return bound;
}
'''
    helpers = terminated_helpers + '''
static uint32_t spx_proof_call_range_admitted(
    spx_proof_world *world, uint64_t base, uint64_t extent, uint32_t permissions) {
  if (base == 0U || base > UINT32_MAX || extent > UINT32_MAX ||
      extent > UINT64_C(4294967296) - base) return UINT32_C(0);
  uint64_t end = base + extent;
  if (extent == 0U) return UINT32_C(1);
  if (base < world->private_high && world->private_low < end) return UINT32_C(0);
''' + private + allocation_guards + '''
  if (!spx_proof_allocation_reference_live(world, (uint32_t)base, extent, UINT64_C(1), 0U))
    return UINT32_C(0);
  return ''' + (" ||\n      ".join(guards) or "UINT32_C(0)") + ''';
}

static void spx_proof_append_call_range(
    spx_proof_world *world, uint32_t base, uint32_t extent, uint32_t call_position) {
  /* This independent witness checks every byte against the enclosing frame.
     It does not choose or constrain the service's output bytes. */
  uint32_t address = spx_nondet_u32(), width = UINT32_C(1);
  (void)width;
  if (address >= base && (uint64_t)address - base < extent) {
''' + frame_check + '''
  }
  uint32_t position = world->write_count;
  spx_proof_append_write(world, base, extent, call_position);
  world->writes[position].call_range = UINT32_C(1);
}

static void spx_proof_apply_call_ranges(
    spx_proof_world *world, const spx_proof_call *call, uint32_t position) {
''' + "\n".join(cases) + '''
}

static void spx_proof_typed_apply_ranges(void) {
  if (spx_proof_typed_ranges_applied) return;
  if (!spx_proof_typed_recording) {
    __CPROVER_assert(spx_proof_typed_call_matches, "spx-bisimulation-buffer-typed-arguments");
    __CPROVER_assume(spx_proof_typed_call_matches);
  }
  spx_proof_apply_call_ranges(spx_proof_typed_recording ? &spx_exact_world : &spx_source_world,
      &spx_exact_world.calls[spx_proof_typed_call_position], spx_proof_typed_call_position);
  spx_proof_typed_ranges_applied = UINT32_C(1);
}
'''
    if summary_ranges:
        helpers += '''
static void spx_proof_append_summary_range(
    spx_proof_world *world, uint32_t base, uint32_t extent, uint32_t token) {
  uint32_t admitted = spx_proof_call_range_admitted(world, base, extent, 2U);
  __CPROVER_assert(admitted, "spx-bisimulation-summary-range-authority");
  __CPROVER_assume(admitted);
  uint32_t position = world->write_count;
  spx_proof_append_call_range(world, base, extent, token);
  world->writes[position].call_range = UINT32_C(2);
}
'''
    return {"helpers": helpers,
            "writes_per_call": call_range_write_capacity(specs),
            "declarations": '''static uint32_t spx_proof_typed_ranges_applied;
static void spx_proof_typed_apply_ranges(void);''',
            "typed_reset": "  spx_proof_typed_ranges_applied = UINT32_C(0);",
            "typed_apply": "  spx_proof_typed_apply_ranges();",
            "exact_apply": "    spx_proof_apply_call_ranges(&spx_exact_world, call, position);",
            "source_apply": "    spx_proof_apply_call_ranges(&spx_source_world, call, exact_position);"}
