"""Call-time checks for borrowed logical inputs to proof service adapters."""

from __future__ import annotations

from .bisimulation_support import BisimulationRefinementError


def borrowed_input_checks(*, logical: str, logical_type, parameter, type_index,
                          symbol: str, parameter_index: int, zero_result: str) -> list[str]:
    """Realize an existing origin; never issue a fresh origin to admit an input.

    NUL views admit a checked registered prefix within the visible extent, or
    their own current final byte as a sufficient termination witness. Neither
    computes the first NUL nor infers lifetime from an address. Wider strings need their
    own checked element/termination model before this adapter can admit them.
    """
    view = logical_type.kind in {"view", "bytes"}
    base = f"{logical}->base" if view else logical
    permissions = {"none": 0, "read": 1, "write": 2, "read_write": 3}.get(parameter.access)
    if permissions is None or (view and permissions == 0):
        raise BisimulationRefinementError("typed proof borrowed input access is unsupported")
    nul = view and logical_type.nul_terminated
    if nul:
        element = type_index.get(logical_type.element_type_id)
        if logical_type.kind != "bytes" and (
            getattr(element, "kind", None) != "scalar"
            or getattr(element, "c_type", None) not in {"uint8_t", "int8_t"}
        ):
            raise BisimulationRefinementError("typed proof NUL service input requires byte elements")
        if not permissions & 1:
            raise BisimulationRefinementError("typed proof NUL service input requires read access")
    reference = f"spx_typed_input_{parameter_index}_reference"
    address = f"spx_typed_input_{parameter_index}_address"
    diagnostic = f"{symbol}:{parameter_index}"

    def reject(reason: str) -> list[str]:
        return [f'    __CPROVER_assert(0, "spx-bisimulation-typed-service-{reason}:{diagnostic}");',
                "    *spx_typed_service->service_fault = UINT32_C(1);",
                f"    {zero_result}", "  }"]

    lines = []
    if view:
        lines += [f"  if ({logical} == 0 ||",
                  f"      {base}.offset > {base}.extent ||",
                  f"      {logical}->extent > {base}.extent - {base}.offset) {{"]
        lines += reject("reference")
    # Production view lowering requires a nonnull, non-one-past reference.
    nullable = 0 if view else int(parameter.nullable)
    lines += [f"  spx_machine_reference_v1 {reference} = {{",
              f"    {base}.domain, {base}.object, {base}.generation,",
              f"    {base}.offset, {base}.extent, {base}.permissions",
              "  };",
              f"  uint32_t {address} = UINT32_C(0);",
              "  if (spx_typed_service->runtime->realize_reference == 0 ||",
              "      spx_typed_service->runtime->realize_reference(",
              "          spx_typed_service->runtime->context,",
              f"          &{reference}, UINT32_C({permissions}), UINT32_C({nullable}),",
              f"          UINT32_C(0), &{address}) != SPX_BOUNDARY_OK) {{"]
    lines += reject("reference")
    if nul:
        lines += [f"  if ({logical}->element_width != UINT32_C(1) ||",
                  f"      {logical}->extent == UINT64_C(0) ||",
                  f"      {logical}->extent > UINT64_C(4294967296) - {address}) {{"]
        lines += reject("termination")
        lines += ["  extern uint64_t spx_proof_borrowed_nul_extent(void *, uint32_t, uint64_t);",
                  f"  uint64_t spx_typed_nul_extent_{parameter_index} = spx_proof_borrowed_nul_extent(",
                  f"      spx_typed_service->runtime->context, {address}, {logical}->extent);",
                  "  if (spx_component_read(spx_typed_service->runtime,",
                  f"          (uint32_t)((uint64_t){address} + spx_typed_nul_extent_{parameter_index} - UINT64_C(1)),",
                  "          UINT32_C(1), &spx_typed_fault) != UINT32_C(0) ||",
                  "      spx_typed_fault != UINT32_C(0)) {"]
        lines += reject("termination")
    return lines
