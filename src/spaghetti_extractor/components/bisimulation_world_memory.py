"""Sparse memory, private-frame cache, and immutable-byte proof fragments."""

from __future__ import annotations

from typing import Sequence
from ..artifacts.artifact_set import canonical_sha256_v3

from .bisimulation_support import (
    BisimulationRefinementError,
    PROOF_PRIVATE_STACK_ABOVE,
    PROOF_PRIVATE_STACK_BELOW,
)


def allocation_byte_projection_contract():
    return {
        "id": "allocation-byte-projection", "revision": 2,
        "semantics": [
            "Select the newest matching allocation once per byte lookup using the existing world selector.",
            "Private writes retain their original precedence and do not acquire public lifetime filtering.",
            "Public writes and shadow bytes retain newest-first order, current lifetime and their separate history floors.",
            "An address without an allocation uses the original initial byte.",
            "Released storage retains the original dead-byte result.",
            "Imported allocation contents remain arbitrary current input bytes even if the birth was zero-initialized.",
            "Fresh live storage retains zero initialization or its generation-indexed arbitrary initial byte.",
            "Call-range and component-summary bytes retain their original oracle identities.",
            "The projection has no writes or observable effects and grants no address validity or lifetime authority.",
        ],
        "authority": "Experimental model projection; evidence remains explicitly conditional.",
    }


def allocation_byte_projection_assurance():
    contract = allocation_byte_projection_contract()
    return {"kind": "conditional-runtime-contracts", "contracts": [{
        "id": contract["id"], "revision": contract["revision"],
        "contract_sha256": canonical_sha256_v3(contract),
    }]}


def allocation_byte_projection_fragments(enabled):
    if type(enabled) is not bool:
        raise BisimulationRefinementError("allocation byte projection selection must be boolean")
    if not enabled:
        return "", "  return spx_proof_allocation_initial_byte(SPX_WORLD, address);"
    digest = allocation_byte_projection_assurance()["contracts"][0]["contract_sha256"]
    prefix = f'''#ifndef SPX_CONDITIONAL_RUNTIME_CONTRACT_{digest}
#error "allocation byte projection requires explicitly conditional obligation execution"
#endif
  const uint32_t selected = spx_proof_allocation_at(SPX_WORLD, address);
  spx_proof_allocation object = {{0}};
  uint32_t visible = UINT32_C(1), write_floor = UINT32_C(0), shadow_floor = UINT32_C(0);
  if (selected != UINT32_MAX) {{
    object = spx_proof_allocation_snapshot(SPX_WORLD, selected);
    visible = object.live;
    write_floor = object.write_floor;
    shadow_floor = object.shadow_floor;
  }}
'''
    initial = '''  if (selected == UINT32_MAX) return spx_proof_initial_byte(address);
  if (!object.live) return UINT8_C(0);
  if (selected < world->input_allocation_count) return spx_proof_initial_byte(address);
  if (object.zero_initialized) return UINT8_C(0);
  return __CPROVER_uninterpreted_spx_allocation_byte(object.generation, address - object.base);'''
    return prefix, initial


def fixed_index_stores(table: str, capacity: int, fields: Sequence[tuple[str, str]]) -> str:
    """Lower a bounded append after its existing capacity assertion/assumption.

    Each branch writes exactly one constant-index record. The caller retains
    counter updates and capacity checks; this does not truncate a full log.
    """
    return '\n'.join(
        f'  if (position == UINT32_C({index})) {{\n'
        + '\n'.join(f'    {table}[{index}].{field} = {value};' for field, value in fields)
        + '\n    return;\n  }' for index in range(capacity))


def exposed_stack_fragments(
    *, capacity: int, private_ranges: Sequence[tuple[int, int]],
) -> dict[str, str]:
    """Freeze shared stack spans before either paired execution has effects.

    The spans change observation visibility, not byte values or permissions.
    Fixed private objects remain private even when a proposed span aliases them.
    """
    if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 0:
        raise BisimulationRefinementError("exposed stack-view capacity is malformed")
    if capacity == 0:
        return {key: "" for key in ("declarations", "private", "helpers", "reset")}
    membership = "\n".join(
        f"    if (spx_proof_exposed_count > UINT32_C({index}) &&\n"
        f"        address >= spx_proof_exposed[{index}].base &&\n"
        f"        (uint64_t)address < spx_proof_exposed[{index}].end)\n"
        "      return UINT32_C(0);"
        for index in range(capacity)
    )
    exposed_address = " ||\n      ".join(
        f"(spx_proof_exposed_count > UINT32_C({index}) && address >= spx_proof_exposed[{index}].base && "
        f"(uint64_t)address < spx_proof_exposed[{index}].end)" for index in range(capacity))
    protected = "\n".join(
        f"  if ((uint64_t)address < UINT64_C({base + extent}) &&\n"
        f"      UINT64_C({base}) < end) return UINT32_C(0);"
        for base, extent in private_ranges
    )
    protected_bytes = "\n".join(
        f"  if (address >= UINT32_C({base}) &&\n"
        f"      (uint64_t)address < UINT64_C({base + extent})) return UINT32_C(1);"
        for base, extent in private_ranges
    )
    # At most capacity intervals can extend a connected covering prefix. Scan
    # all intervals that many times so input order and overlap cannot affect it.
    covering = "\n".join(
        f"  if (spx_proof_exposed_count > UINT32_C({index}) &&\n"
        f"      spx_proof_exposed[{index}].base <= covered &&\n"
        f"      spx_proof_exposed[{index}].end > covered)\n"
        f"    covered = spx_proof_exposed[{index}].end;"
        for _ in range(capacity) for index in range(capacity)
    )
    return {
        "declarations": f"""
static uint32_t spx_proof_exposed_count;
static struct {{ uint32_t base; uint64_t end; }} spx_proof_exposed[{capacity}];
""",
        "private": protected_bytes + "\n" + f"""
  if (world != 0 && address >= world->private_low && address < world->private_high) {{
{membership}
  }}
""",
        "helpers": f"""
static uint32_t spx_proof_address_exposed(uint32_t address) {{
  return {exposed_address};
}}

static void spx_proof_expose_stack_view(uint32_t address, uint32_t extent) {{
  uint32_t position = spx_proof_exposed_count;
  uint32_t valid_range = address != UINT32_C(0) &&
      (uint64_t)address + extent <= UINT64_C(4294967296);
  uint32_t before_effects =
      spx_exact_world.write_count == 0U && spx_source_world.write_count == 0U &&
      spx_exact_world.private_write_count == 0U && spx_source_world.private_write_count == 0U &&
      spx_exact_world.shadow_count == 0U && spx_source_world.shadow_count == 0U &&
      spx_exact_world.call_count == 0U && spx_source_world.call_count == 0U &&
      spx_exact_world.atomic_count == 0U && spx_source_world.atomic_count == 0U;
  __CPROVER_assert(valid_range, "spx-bisimulation-exposed-stack-range");
  __CPROVER_assert(before_effects, "spx-bisimulation-exposed-stack-before-effects");
  __CPROVER_assert(position < UINT32_C({capacity}), "spx-bisimulation-exposed-stack-capacity");
  __CPROVER_assume(valid_range && before_effects && position < UINT32_C({capacity}));
  spx_proof_exposed[position].base = address;
  spx_proof_exposed[position].end = (uint64_t)address + extent;
  spx_proof_exposed_count = position + UINT32_C(1);
}}

static uint32_t spx_proof_range_is_public(
    const spx_proof_world *world, uint32_t address, uint64_t extent) {{
  uint64_t end, covered, required_end;
  if (world == 0 || extent > UINT64_C(4294967296) - address)
    return UINT32_C(0);
  if (extent == UINT64_C(0)) return UINT32_C(1);
  end = (uint64_t)address + extent;
{protected}
  covered = address > world->private_low ? address : world->private_low;
  required_end = end < world->private_high ? end : world->private_high;
{covering}
  return covered >= required_end;
}}
""",
        "reset": "  spx_proof_exposed_count = UINT32_C(0);",
    }


def memory_fragments(
    *,
    max_writes: int,
    max_private_writes: int,
    max_shadow_bytes: int,
    max_nul_views: int,
    private_ranges: Sequence[tuple[int, int]],
    immutable_bytes: Sequence[tuple[int, int]],
    exact_stack_accesses: Sequence[tuple[int, int]],
    defer_initial_reads: bool = False,
    summary_ranges: bool = False,
    allocation_byte_projection: bool = False,
) -> dict[str, str]:
    prefix, initial = allocation_byte_projection_fragments(allocation_byte_projection)
    def history(index, shadow):
        if allocation_byte_projection:
            return f'(visible && UINT32_C({index}) >= {"shadow_floor" if shadow else "write_floor"})'
        return f'spx_proof_allocation_history_visible(SPX_WORLD, UINT32_C({index}), address, UINT32_C({int(shadow)}))'
    private_index_lines: list[str] = []
    for start, width in private_ranges:
        private_index_lines.extend(
            [
                f"  if (address >= UINT32_C({start}) && "
                f"address < UINT32_C({start + width})) {{",
                "    return UINT32_C(1);",
                "  }",
            ]
        )
    private_index_cases = "\n".join(private_index_lines)
    byte_cases = "\n".join(
        f"  if (world->write_count > UINT32_C({index}) &&\n"
        f"      {history(index, False)} &&\n"
        f"      address >= world->writes[{index}].address &&\n"
        f"      address - world->writes[{index}].address <\n"
        f"          world->writes[{index}].width)\n"
        "    return " + (f"world->writes[{index}].call_range == UINT32_C(2) ?\n"
        f"        __CPROVER_uninterpreted_spx_summary_byte(world->writes[{index}].value, address) :\n        "
        if summary_ranges else "") + f"world->writes[{index}].call_range ?\n"
        f"        __CPROVER_uninterpreted_spx_call_byte(world->writes[{index}].value, address) :\n"
        f"        (uint8_t)(spx_proof_word_suffix(\n"
        f"        world->writes[{index}].value,\n"
        f"        address - world->writes[{index}].address) & UINT32_C(255));"
        for index in reversed(range(max_writes))
    )
    shadow_cases = "\n".join(
        f"  if (world->shadow_count > UINT32_C({index}) && "
        f"world->shadow[{index}].address == address &&\n"
        f"      {history(index, True)})\n"
        f"    return world->shadow[{index}].value;"
        for index in reversed(range(max_shadow_bytes))
    )
    private_byte_cases = "\n".join(
        f"  if (world->private_write_count > UINT32_C({index}) &&\n"
        f"      address >= world->private_writes[{index}].address &&\n"
        f"      address - world->private_writes[{index}].address <\n"
        f"          world->private_writes[{index}].width)\n"
        f"    return (uint8_t)(spx_proof_word_suffix(\n"
        f"        world->private_writes[{index}].value,\n"
        f"        address - world->private_writes[{index}].address) & "
        "UINT32_C(255));"
        for index in reversed(range(max_private_writes))
    )
    private_read_cases = "\n".join(
        f"  if (world->private_write_count > UINT32_C({index}) &&\n"
        f"      (uint64_t)address < (uint64_t)world->private_writes[{index}].address +\n"
        f"          (uint64_t)world->private_writes[{index}].width &&\n"
        f"      (uint64_t)world->private_writes[{index}].address <\n"
        "          (uint64_t)address + (uint64_t)width) {\n"
        f"    if (address >= world->private_writes[{index}].address &&\n"
        "        (uint64_t)address + (uint64_t)width <=\n"
        f"            (uint64_t)world->private_writes[{index}].address +\n"
        f"                (uint64_t)world->private_writes[{index}].width) {{\n"
        f"      uint32_t result = spx_proof_word_suffix(\n"
        f"          world->private_writes[{index}].value,\n"
        f"          address - world->private_writes[{index}].address);\n"
        "      *matched = UINT32_C(1);\n"
        "      if (width == UINT32_C(1)) return result & UINT32_C(255);\n"
        "      if (width == UINT32_C(2)) return result & UINT32_C(65535);\n"
        "      if (width == UINT32_C(3)) return result & UINT32_C(16777215);\n"
        "      return result;\n"
        "    }\n"
        "    return UINT32_C(0);\n"
        "  }"
        for index in reversed(range(max_private_writes))
    )
    normalized_immutable_bytes = sorted(set(immutable_bytes))
    if (
        len(normalized_immutable_bytes) != len(immutable_bytes)
        or any(
            address < 0
            or address > 0xFFFFFFFF
            or value < 0
            or value > 0xFF
            for address, value in normalized_immutable_bytes
        )
        or len({address for address, _value in normalized_immutable_bytes})
        != len(normalized_immutable_bytes)
    ):
        raise BisimulationRefinementError(
            "immutable proof bytes are malformed or ambiguous"
        )
    immutable_byte_cases = "\n".join(
        f"  if (address == UINT32_C({address})) return UINT8_C({value});"
        for address, value in normalized_immutable_bytes
    )
    normalized_stack_accesses = sorted(set(exact_stack_accesses))
    if (
        len(normalized_stack_accesses) != len(exact_stack_accesses)
        or any(
            not -PROOF_PRIVATE_STACK_BELOW <= offset
            or width != 4
            or offset % 4 != 0
            or offset + width > PROOF_PRIVATE_STACK_ABOVE
            for offset, width in normalized_stack_accesses
        )
    ):
        raise BisimulationRefinementError(
            "exact stack-cache access inventory is malformed"
        )
    def stack_address(offset: int) -> str:
        operator = "+" if offset >= 0 else "-"
        return (
            "spx_exact_world.private_anchor "
            f"{operator} UINT32_C({abs(offset)})"
        )

    exact_stack_declarations = "\n".join(
        f"static uint32_t spx_proof_exact_stack_word_{index:04d};\n"
        f"static uint32_t spx_proof_exact_stack_valid_{index:04d};"
        for index in range(len(normalized_stack_accesses))
    )
    exact_stack_reset = "\n".join(
        f"  spx_proof_exact_stack_valid_{index:04d} = UINT32_C(1);\n"
        f"  spx_proof_exact_stack_word_{index:04d} =\n"
        f"      (uint32_t)spx_proof_initial_byte({stack_address(offset)}) |\n"
        f"      ((uint32_t)spx_proof_initial_byte({stack_address(offset + 1)})) << 8U |\n"
        f"      ((uint32_t)spx_proof_initial_byte({stack_address(offset + 2)})) << 16U |\n"
        f"      ((uint32_t)spx_proof_initial_byte({stack_address(offset + 3)})) << 24U;"
        for index, (offset, _width) in enumerate(normalized_stack_accesses)
    )
    if defer_initial_reads:
        # Initial-memory facts are installed after resetting the worlds. Eager
        # cache population would observe those bytes before construction and
        # retain values from the old initial-memory function. Leave entries
        # empty: normal reads use the authoritative byte log, while complete
        # stores populate the existing cache and partial aliases invalidate it.
        exact_stack_reset = "\n".join(
            f"  spx_proof_exact_stack_valid_{index:04d} = UINT32_C(0);"
            for index in range(len(normalized_stack_accesses))
        )
    # Partial aliases invalidate the optimization; the chronological byte log
    # remains authoritative. A later full-word store can populate it again.
    exact_stack_updates = "\n".join(
        f"    if (width == UINT32_C(4) && address == {stack_address(offset)}) {{\n"
        f"      spx_proof_exact_stack_word_{index:04d} = value;\n"
        f"      spx_proof_exact_stack_valid_{index:04d} = UINT32_C(1);\n"
        "    } else if ((uint64_t)address <\n"
        f"        (uint64_t)({stack_address(offset)}) + UINT64_C(4) &&\n"
        f"        (uint64_t)({stack_address(offset)}) <\n"
        "            (uint64_t)address + (uint64_t)width) {\n"
        f"      spx_proof_exact_stack_valid_{index:04d} = UINT32_C(0);\n"
        "    }"
        for index, (offset, _width) in enumerate(normalized_stack_accesses)
    )
    exact_stack_read_cases = "\n".join(
        f"  if (spx_proof_exact_stack_valid_{index:04d} != UINT32_C(0) &&\n"
        f"      width == UINT32_C(4) && address == {stack_address(offset)}) {{\n"
        "    *matched = UINT32_C(1);\n"
        f"    return spx_proof_exact_stack_word_{index:04d};\n"
        "  }"
        for index, (offset, _width) in enumerate(normalized_stack_accesses)
    )
    private_byte_count = """
static uint32_t spx_proof_private_bytes(
    const spx_proof_world *world, uint32_t address, uint32_t width) {
  uint32_t count = spx_proof_is_private(world, address);
  if (width > UINT32_C(1))
    count += spx_proof_is_private(world, address + UINT32_C(1));
  if (width > UINT32_C(2))
    count += spx_proof_is_private(world, address + UINT32_C(2));
  if (width > UINT32_C(3))
    count += spx_proof_is_private(world, address + UINT32_C(3));
  return count;
}
"""
    exact_private_byte_cases = private_byte_cases.replace(
        "world->", "spx_exact_world."
    )
    exact_byte_cases = byte_cases.replace("world->", "spx_exact_world.").replace("SPX_WORLD", "&spx_exact_world")
    exact_shadow_cases = shadow_cases.replace("world->", "spx_exact_world.").replace("SPX_WORLD", "&spx_exact_world")
    source_private_byte_cases = private_byte_cases.replace(
        "world->", "spx_source_world."
    )
    source_byte_cases = byte_cases.replace("world->", "spx_source_world.").replace("SPX_WORLD", "&spx_source_world")
    source_shadow_cases = shadow_cases.replace("world->", "spx_source_world.").replace("SPX_WORLD", "&spx_source_world")
    exact_private_read_cases = private_read_cases.replace(
        "world->", "spx_exact_world."
    )
    source_private_read_cases = private_read_cases.replace(
        "world->", "spx_source_world."
    )
    nul_extent_cases = "\n".join(
        f"  if (world != 0 && world->nul_view_count > UINT32_C({index}) && "
        f"world->nul_view_bases[{index}] == address)\n"
        f"    if (extent < world->nul_view_extents[{index}])\n"
        f"      extent = world->nul_view_extents[{index}];"
        for index in range(max_nul_views)
    )

    return {
        "exact_byte_cases": exact_byte_cases,
        "exact_private_byte_cases": exact_private_byte_cases,
        "exact_private_read_cases": exact_private_read_cases,
        "exact_shadow_cases": exact_shadow_cases,
        "exact_stack_declarations": exact_stack_declarations,
        "exact_stack_read_cases": exact_stack_read_cases,
        "exact_stack_reset": exact_stack_reset,
        "exact_stack_updates": exact_stack_updates,
        "immutable_byte_cases": immutable_byte_cases,
        "nul_extent_cases": nul_extent_cases,
        "private_index_cases": private_index_cases,
        "private_byte_count": private_byte_count,
        "source_byte_cases": source_byte_cases,
        "source_private_byte_cases": source_private_byte_cases,
        "source_private_read_cases": source_private_read_cases,
        "source_shadow_cases": source_shadow_cases,
        **{f"{side}_byte_{kind}": value.replace("world->", f"spx_{side}_world.").replace("SPX_WORLD", f"&spx_{side}_world")
           for side in ("exact", "source") for kind, value in (("prefix", prefix), ("initial", initial))},
    }
