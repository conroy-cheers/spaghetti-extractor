"""Checked image-slot and entry-register transport for external service targets.

Sampling defaults to each service call. Explicit operation_entry sampling uses
the ordinary overlay's per-invocation capture, including its read fault. A paired
target check still proves that the saved word matches each actual original call.
The selected native import supplies code capability authorization; a slot address
alone does not identify a DLL export.
"""

from pathlib import Path

from .bisimulation_support import BisimulationRefinementError
from .machine_binding import MachineProjectionV1, external_target_sampling


def checked_typed_external_target(binding):
    value = binding.get("captured_target_projection")
    try:
        external_target_sampling(binding.get("target_sampling", "service_call"), has_target=value is not None)
        if "target_sampling" in binding and (value is None or binding.get("provider_kind") != "external_call"):
            raise ValueError("target sampling requires a captured external target")
    except ValueError as exc:
        raise BisimulationRefinementError(f"proof_service_captured_target_unsupported: {exc}") from exc
    if binding.get("provider_kind") != "external_call" or value is None:
        return None
    try:
        projection = MachineProjectionV1.parse(value, "typed external target")
        if (projection.kind not in {"static_slot", "register"} or
                projection.payload["width"] != 32 or projection.payload["at"] != "entry" or
                (projection.kind == "register" and projection.payload["register"] not in
                 {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}) or
                (projection.kind == "static_slot" and projection.payload["rva"] > 0xfffffffc)):
            raise ValueError("only a complete 32-bit entry register or image slot has checked typed transport")
    except ValueError as exc:
        raise BisimulationRefinementError(f"proof_service_captured_target_unsupported: {exc}") from exc
    return dict(projection.payload)


def uses_external_target_slots(bindings):
    return any(binding.get("provider_kind") == "external_call" and
               binding.get("captured_target_projection") is not None for binding in bindings)


def external_target_implementation_paths():
    return [Path(__file__), Path(__file__).with_name("machine_binding.py")]


def typed_external_target_lines(binding, *, zero_result, entry_index=None):
    projection = checked_typed_external_target(binding)
    if projection is None:
        return [], None
    if binding.get("target_sampling") == "operation_entry":
        if type(entry_index) is not int or entry_index < 0:
            raise BisimulationRefinementError("operation-entry target requires a checked service index")
        return [
            f"  uint32_t spx_typed_target = spx_typed_service->entry_targets[{entry_index}].value;",
            f"  if (spx_typed_service->entry_targets[{entry_index}].fault != UINT32_C(0)) {{",
            '    __CPROVER_assert(0, "spx-bisimulation-typed-target-entry-readable");',
            "    *spx_typed_service->memory_fault = UINT32_C(1);", f"    {zero_result}", "  }",
            "  if (spx_typed_target == UINT32_C(0)) {",
            '    __CPROVER_assert(0, "spx-bisimulation-typed-target-entry-nonnull");',
            "    *spx_typed_service->service_fault = UINT32_C(1);", f"    {zero_result}", "  }",
        ], "spx_typed_target"
    if projection["kind"] == "register":
        # Match the production thunk's service context. This is the selected
        # overlay entry state, not a register sampled from the original after
        # the call. Paired call checking still compares the actual target word.
        register = projection["register"]
        return [
            f"  uint32_t spx_typed_target = spx_typed_service->state->{register};",
            "  if (spx_typed_target == UINT32_C(0)) {",
            '    __CPROVER_assert(0, "spx-bisimulation-typed-target-register-nonnull");',
            "    *spx_typed_service->service_fault = UINT32_C(1);",
            f"    {zero_result}",
            "  }",
        ], "spx_typed_target"
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
