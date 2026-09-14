"""Checked exact continuation context; never a register-deadness waiver."""

from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_support import BisimulationRefinementError, mapping, rows, strings


def continuation_model(operation: Mapping[str, object]) -> dict | None:
    identities = strings(operation.get("continuation_unit_ids", []), "continuation units")
    units = rows(operation.get("continuation_units", []), "continuation semantics")
    if not identities:
        if units:
            raise BisimulationRefinementError("continuation semantics have no selected units")
        return None
    if len(identities) != len(set(identities)) or identities != sorted(identities):
        raise BisimulationRefinementError("continuation units must be unique and ordered")
    if len(identities) > 256:
        raise BisimulationRefinementError("continuation exceeds the bounded context inventory")
    owned = {str(row.get("id")) for row in rows(operation.get("units"), "operation units")}
    index = {str(row.get("id")): row for row in units}
    if len(index) != len(units) or set(index) != set(identities) or set(identities) & owned:
        raise BisimulationRefinementError("continuation context is missing, duplicated or overlaps the operation")
    rvas = []
    for identity in identities:
        row = index[identity]
        if row.get("status") != "qualified":
            raise BisimulationRefinementError("continuation requires qualified exact machine units")
        original = mapping(mapping(row.get("source"), "continuation source").get("original"), "continuation original")
        rva = original.get("rva_start")
        if type(rva) is not int or not 0 <= rva <= 0xffffffff:
            raise BisimulationRefinementError("continuation unit RVA is malformed")
        semantics = mapping(row.get("semantics"), "continuation semantics")
        calls = semantics.get("external_events")
        if not isinstance(calls, list) or calls:
            raise BisimulationRefinementError("continuation calls require checked context call contracts")
        rvas.append(rva)
    if len(set(rvas)) != len(rvas):
        raise BisimulationRefinementError("continuation unit RVAs are duplicated")
    return {
        "unit_ids": identities,
        "unit_rvas": rvas,
        "units_sha256": canonical_sha256_v3([index[identity] for identity in identities]),
        # Every acyclic path fits. Cyclic execution must also prove it leaves
        # this finite prefix within this bound; no path enumeration is used.
        "maximum_steps": len(identities),
        "requires_exact_selection": True,
    }


def continuation_assertions(operation_id: str, proof_function: str) -> list[str]:
    return [f"spx-bisimulation-continuation-{kind}:{operation_id}:{proof_function}"
            for kind in ("bound", "implemented", "control", "target", "value", "calls", "atomics", "memory")]


def render_continuation(model: Mapping, *, operation_id: str, proof_function: str) -> list[str]:
    def active(result):
        kinds = " || ".join(f"{result}.kind == {kind}" for kind in
                             ("SPX_FALLTHROUGH", "SPX_JUMP", "SPX_BRANCH", "SPX_INDIRECT_JUMP"))
        targets = " || ".join(f"{result}.target_rva == UINT32_C({rva})" for rva in model["unit_rvas"])
        return f"(({kinds}) && ({targets}))"

    lines = [f"  const uint32_t continuation_active = {active('source_result')};",
             "  uint32_t continuation_implemented = UINT32_C(1);"]
    for result, state, runtime in (
        ("spx_proof_exact_result", "spx_proof_exact_output", "exact_runtime"),
        ("source_result", "source_state", "source_runtime"),
    ):
        for _ in range(model["maximum_steps"]):
            lines.extend([
                f"  if ({active(result)}) {{",
                f"    {result} = spx_behavioral_step(&{runtime}, &{state}, {result}.target_rva);",
                f"    continuation_implemented &= ({result}.kind != SPX_UNIMPLEMENTED);",
                "  }",
            ])
    predicates = [
        f"!{active('source_result')} && !{active('spx_proof_exact_result')}",
        "continuation_implemented != UINT32_C(0)",
        "source_result.kind == spx_proof_exact_result.kind",
        "source_result.target_rva == spx_proof_exact_result.target_rva",
        "source_result.value == spx_proof_exact_result.value",
        "spx_proof_world_calls_equal()", "spx_proof_world_atomics_equal()", "spx_proof_world_public_memory_equal()",
    ]
    for predicate, description in zip(predicates, continuation_assertions(operation_id, proof_function)):
        lines.append(f'  __CPROVER_assert({predicate}, "{description}");')
    return lines
