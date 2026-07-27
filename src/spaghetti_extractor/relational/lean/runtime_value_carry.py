"""Emit compact Lean data for checked runtime value-carry routes."""

from __future__ import annotations

from pathlib import Path

from ...util import write_json
from ..runtime_value_carry_ir import RuntimeValueCarryIR


STRUCTURE_MODULE = "GeneratedRelationalRuntimeValueCarryStructure"
BINDING_MODULE = "GeneratedRelationalRuntimeValueCarryBinding"
CONTEXT_MODULE = (
    "GeneratedRelationalInterpreterMixedOriginalBaseCarrierData"
)
CONTEXT_NAME = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
    "generatedOriginalStaticContext"
)

_REGISTERS = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
}
_TRANSFER_KINDS = {
    "finite_origin_call_result": "finiteOriginCallResult",
    "direct_call_register_preserve": "directCallRegisterPreserve",
    "decoded_preserve": "decodedPreserve",
    "decoded_register_to_frame": "decodedRegisterToFrame",
    "call_frame_word_preserve": "callFrameWordPreserve",
}


def _nat_list(values: list[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _location(kind: str, register: str, offset: int) -> str:
    if register not in _REGISTERS:
        raise ValueError(f"unsupported runtime value-carry register {register}")
    if kind == "register":
        if offset != 0:
            raise ValueError("register value-carry location has an offset")
        return f".inRegister .{register}"
    if kind == "frame_word":
        adjustment = ".identity" if offset == 0 else f"(.add {offset})"
        return f".inFrameWord .{register} {adjustment}"
    raise ValueError(f"unsupported runtime value-carry location {kind}")


def _fact(target_id: int, location_id: int) -> str:
    return (
        "{ targetId := "
        f"{target_id}, locationId := {location_id}"
        " }"
    )


def _transfer(route, transfer) -> str:
    kind = _TRANSFER_KINDS.get(transfer.kind)
    if kind is None:
        raise ValueError(
            f"unsupported runtime value-carry transfer {transfer.kind}"
        )
    source = (
        "none"
        if transfer.source_location_id is None
        else f"some {transfer.source_location_id}"
    )
    return (
        "{ edgeId := "
        f"{transfer.edge_index}, "
        f"sourceTargetId := {transfer.source_target_id}, "
        f"targetTargetId := {transfer.target_target_id}, "
        f"kind := .{kind}, "
        f"sourceLocationId := {source}, "
        f"targetLocationId := {transfer.target_location_id}"
        " }"
    )


def _structure_source(value: RuntimeValueCarryIR) -> str:
    definitions: list[str] = []
    theorems: list[str] = []
    for index, route in enumerate(value.routes):
        target_ids = sorted({
            route.origin.target_id,
            *(fact.target_id for fact in route.facts),
            *(transfer.source_target_id for transfer in route.transfers),
            *(transfer.target_target_id for transfer in route.transfers),
        })
        edges = [
            (
                "{ edgeId := "
                f"{transfer.edge_index}, "
                f"sourceTargetId := {transfer.source_target_id}, "
                f"targetTargetId := {transfer.target_target_id}"
                " }"
            )
            for transfer in route.transfers
        ]
        locations = [
            _location(
                location.kind,
                location.register,
                location.offset,
            )
            for location in route.locations
        ]
        facts = [
            _fact(fact.target_id, fact.location_id)
            for fact in route.facts
        ]
        transfers = [
            _transfer(route, transfer)
            for transfer in route.transfers
        ]
        prefix = f"generatedRuntimeValueCarryRoute{index}"
        definitions.extend([
            f"""def {prefix}Graph : CutpointGraph := {{
  targetIds := {_nat_list(target_ids)}
  edges := [{", ".join(edges)}]
}}""",
            f"""def {prefix} : Route := {{
  originTargetId := {route.origin.target_id}
  locations := [{", ".join(locations)}]
  facts := [{", ".join(facts)}]
  transfers := [{", ".join(transfers)}]
  targetFact := {_fact(
      route.target_fact.target_id,
      route.target_fact.location_id,
  )}
}}""",
        ])
        theorems.append(
            f"""theorem {prefix}StructureChecked :
    {prefix}.structureChecked {prefix}Graph = true := by
  native_decide"""
        )
    return f"""import StageA.RelationalRuntimeValueCarry

namespace StageA.GeneratedRelational.RuntimeValueCarry

open StageA.Relational.RuntimeValueCarry

{"\n\n".join(definitions)}

{"\n\n".join(theorems)}

end StageA.GeneratedRelational.RuntimeValueCarry
"""


def _binding_source(value: RuntimeValueCarryIR) -> str:
    theorems: list[str] = []
    for index, _route in enumerate(value.routes):
        prefix = f"generatedRuntimeValueCarryRoute{index}"
        theorems.append(
            f"""theorem {prefix}OriginChecked :
    {prefix}.originChecked {CONTEXT_NAME} = true := by
  native_decide

theorem {prefix}StaticChecked :
    {prefix}.checked {CONTEXT_NAME} {prefix}Graph = true := by
  simp only [Route.checked, Bool.and_eq_true]
  exact ⟨{prefix}StructureChecked, {prefix}OriginChecked⟩"""
        )
    return f"""import StageA.{STRUCTURE_MODULE}
import StageA.{CONTEXT_MODULE}

namespace StageA.GeneratedRelational.RuntimeValueCarry

open StageA.Relational.RuntimeValueCarry

{"\n\n".join(theorems)}

end StageA.GeneratedRelational.RuntimeValueCarry
"""


def write_runtime_value_carry_lean(
    out: Path,
    value: RuntimeValueCarryIR,
) -> tuple[Path, Path, Path]:
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    structure = stage_a / f"{STRUCTURE_MODULE}.lean"
    binding = stage_a / f"{BINDING_MODULE}.lean"
    structure.write_text(_structure_source(value), encoding="utf-8")
    binding.write_text(_binding_source(value), encoding="utf-8")
    report = out / "runtime-value-carry-lean.json"
    write_json(
        report,
        {
            "format": "stage-a-runtime-value-carry-lean-v1",
            "modules": [STRUCTURE_MODULE, BINDING_MODULE],
            "routes": [
                {
                    "stable_id": route.stable_id,
                    "proof_ready": route.proof_ready,
                    "structure_theorem": (
                        "StageA.GeneratedRelational.RuntimeValueCarry."
                        f"generatedRuntimeValueCarryRoute{index}"
                        "StructureChecked"
                    ),
                    "static_theorem": (
                        "StageA.GeneratedRelational.RuntimeValueCarry."
                        f"generatedRuntimeValueCarryRoute{index}"
                        "StaticChecked"
                    ),
                    "semantic_authority": None,
                }
                for index, route in enumerate(value.routes)
            ],
            "proof_authority": False,
            "semantic_authority_complete": value.proof_ready,
        },
    )
    return structure, binding, report


__all__ = [
    "BINDING_MODULE",
    "CONTEXT_MODULE",
    "CONTEXT_NAME",
    "STRUCTURE_MODULE",
    "write_runtime_value_carry_lean",
]
