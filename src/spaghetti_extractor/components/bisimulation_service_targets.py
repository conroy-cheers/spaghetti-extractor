"""Checked image-slot transport for indirect external service targets.

The ordinary overlay reads the same current slot. A paired target check proves
that this word matches the original call, including when the original retained
an earlier load in a register. The selected native import still supplies code
capability authorization; a slot address alone does not identify a DLL export.
"""

from pathlib import Path

from .bisimulation_support import BisimulationRefinementError
from .machine_binding import MachineProjectionV1


def checked_typed_external_target(binding):
    value = binding.get("captured_target_projection")
    if binding.get("provider_kind") != "external_call" or value is None:
        return None
    try:
        projection = MachineProjectionV1.parse(value, "typed external target")
        if (projection.kind != "static_slot" or projection.payload["width"] != 32 or
                projection.payload["at"] != "entry" or projection.payload["rva"] > 0xfffffffc):
            raise ValueError("only a complete 32-bit entry image slot has checked typed transport")
    except ValueError as exc:
        raise BisimulationRefinementError(f"proof_service_captured_target_unsupported: {exc}") from exc
    return dict(projection.payload)


def uses_external_target_slots(bindings):
    return any(binding.get("provider_kind") == "external_call" and
               binding.get("captured_target_projection") is not None for binding in bindings)


def external_target_implementation_paths():
    return [Path(__file__), Path(__file__).with_name("machine_binding.py")]


def typed_external_target_lines(binding, *, zero_result):
    projection = checked_typed_external_target(binding)
    if projection is None:
        return [], None
    rva = projection["rva"]
    return [
        "  uint64_t spx_typed_target_address = (uint64_t)spx_typed_service->runtime->image_base +",
        f"      UINT64_C({rva});",
        "  if (spx_typed_target_address > UINT64_C(4294967292) ||",
        "      !spx_proof_typed_service_public_range((uint32_t)spx_typed_target_address, UINT32_C(4))) {",
        '    __CPROVER_assert(0, "spx-bisimulation-typed-target-slot-address");',
        "    *spx_typed_service->memory_fault = UINT32_C(1);",
        f"    {zero_result}",
        "  }",
        "  uint32_t spx_typed_target = spx_component_read(spx_typed_service->runtime,",
        "      (uint32_t)spx_typed_target_address, UINT32_C(4), &spx_typed_fault);",
        "  if (spx_typed_fault != UINT32_C(0) || spx_typed_target == UINT32_C(0)) {",
        '    __CPROVER_assert(0, "spx-bisimulation-typed-target-slot-readable-nonnull");',
        "    *(spx_typed_fault != UINT32_C(0) ? spx_typed_service->memory_fault :",
        "        spx_typed_service->service_fault) = UINT32_C(1);",
        f"    {zero_result}",
        "  }",
    ], "spx_typed_target"
