"""Emit compact Lean data for checked runtime value-carry routes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from ...util import write_json
from ..original_cutpoint_graph_ir import OriginalCutpointGraphIR
from ..runtime_value_carry_ir import RuntimeValueCarryIR, RuntimeValueTransfer


STRUCTURE_MODULE = "GeneratedRelationalRuntimeValueCarryStructure"
BINDING_MODULE = "GeneratedRelationalRuntimeValueCarryBinding"
SEMANTICS_MODULE = "GeneratedRelationalRuntimeValueCarrySemantics"
CONTEXT_MODULE = (
    "GeneratedRelationalInterpreterMixedOriginalBaseCarrierData"
)
CONTEXT_NAME = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
    "generatedOriginalStaticContext"
)
CARRIER_CONTEXT_NAME = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
    "generatedOriginalCarrierContext"
)
ORIGINAL_AUTHORITY_NAME = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
    "generatedExactOriginalDecodedAuthority"
)
ORIGINAL_PROGRAM_NAME = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
    "generatedOriginalDecodedProgram"
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
        return f".inFrameWord .{register} (.add {offset})"
    raise ValueError(f"unsupported runtime value-carry location {kind}")


def _control_value_location(kind: str, register: str, offset: int) -> str:
    """Render the corresponding original-only provenance location."""

    if register not in _REGISTERS:
        raise ValueError(f"unsupported runtime value-carry register {register}")
    if kind == "register":
        if offset != 0:
            raise ValueError("register value-carry location has an offset")
        return f".register .{register}"
    if kind == "frame_word":
        return f".frameWord .{register} (.add {offset})"
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


def _structure_source(
    value: RuntimeValueCarryIR,
    graph: OriginalCutpointGraphIR | None,
) -> str:
    definitions: list[str] = []
    theorems: list[str] = []
    for index, route in enumerate(value.routes):
        tracked_target_ids = {fact.target_id for fact in route.facts}
        transfer_edge_ids = {
            transfer.edge_index for transfer in route.transfers
        }
        if graph is None:
            graph_edges = [
                (
                    transfer.edge_index,
                    transfer.source_target_id,
                    transfer.target_target_id,
                    True,
                )
                for transfer in route.transfers
            ]
        else:
            graph_edges = [
                (
                    edge.edge_index,
                    edge.source_target_id,
                    edge.target_target_id,
                    edge.transition_role != "dataflow",
                )
                for edge in graph.edges
                if (
                    edge.edge_index in transfer_edge_ids
                    or (
                        edge.target_target_id in tracked_target_ids
                        and edge.transition_role != "dataflow"
                    )
                )
            ]
        target_ids = sorted({
            route.origin.target_id,
            *(fact.target_id for fact in route.facts),
            *(transfer.source_target_id for transfer in route.transfers),
            *(transfer.target_target_id for transfer in route.transfers),
            *(source for _edge, source, _target, _decoded in graph_edges),
            *(target for _edge, _source, target, _decoded in graph_edges),
        })
        edges = [
            (
                "{ edgeId := "
                f"{edge_index}, "
                f"sourceTargetId := {source_target_id}, "
                f"targetTargetId := {target_target_id}, "
                f"decodedIncoming := {str(decoded_incoming).lower()}"
                " }"
            )
            for (
                edge_index,
                source_target_id,
                target_target_id,
                decoded_incoming,
            ) in graph_edges
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
  stableId := "{route.stable_id}"
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

theorem {prefix}StructuralStaticChecked :
    {prefix}.checked {CONTEXT_NAME} {prefix}Graph = true := by
  simp only [Route.checked, Bool.and_eq_true]
  exact ⟨{prefix}StructureChecked, {prefix}OriginChecked⟩

theorem {prefix}ExactIncomingChecked :
    {prefix}.exactIncomingChecked {CONTEXT_NAME} {prefix}Graph = true := by
  native_decide

theorem {prefix}StaticChecked :
    {prefix}.exactChecked {CONTEXT_NAME} {prefix}Graph = true := by
  simp only [Route.exactChecked, Bool.and_eq_true]
  exact ⟨⟨by native_decide, {prefix}StructuralStaticChecked⟩,
    {prefix}ExactIncomingChecked⟩

def {prefix}Authority : CheckedRoute {CONTEXT_NAME} := {{
  decodedAuthority := {ORIGINAL_AUTHORITY_NAME}
  graph := {prefix}Graph
  route := {prefix}
  checked := {prefix}StaticChecked
}}"""
        )
    return f"""import StageA.{STRUCTURE_MODULE}
import StageA.{CONTEXT_MODULE}

namespace StageA.GeneratedRelational.RuntimeValueCarry

open StageA.Relational.RuntimeValueCarry

{"\n\n".join(theorems)}

end StageA.GeneratedRelational.RuntimeValueCarry
"""


def _frame_transfer_authority(
    route,
    route_index: int,
    transfer: RuntimeValueTransfer,
) -> tuple[str, str] | None:
    if (
        transfer.kind != "call_frame_word_preserve"
        or transfer.authority_status != "checked_dependency"
        or transfer.source_location_id is None
        or transfer.authority_lean_term is None
        or transfer.authority_callee_target_id is None
    ):
        return None
    source = route.locations[transfer.source_location_id]
    target = route.locations[transfer.target_location_id]
    if (
        source.kind != "frame_word"
        or target.kind != "frame_word"
        or source.register != "esp"
        or target.register != "esp"
        or source.offset != target.offset
    ):
        raise ValueError(
            "checked caller-frame transfer has invalid semantic locations"
        )
    prefix = (
        f"generatedRuntimeValueCarryRoute{route_index}"
        f"Transfer{transfer.transfer_id}"
    )
    route_name = f"generatedRuntimeValueCarryRoute{route_index}"
    term = transfer.authority_lean_term.qualified
    common = f"""  transfer := {_transfer(route, transfer)}
  transferMember := by decide +kernel
  sourceLocationId := {transfer.source_location_id}
  sourceLocation := {_location(source.kind, source.register, source.offset)}
  targetLocation := {_location(target.kind, target.register, target.offset)}
  callerFrameWordOffset := {target.offset}
  transferKind := rfl
  transferSourceLocation := rfl
  sourceLocationExact := by decide +kernel
  targetLocationExact := by decide +kernel
  sourceLocationShape := rfl
  targetLocationShape := rfl
  sourceTargetExact := by decide +kernel
  continuationTargetExact := by decide +kernel"""
    if transfer.authority_origin == (
        "checked_finite_origin_call_caller_frame_word_summary"
    ):
        authority_type = (
            "CheckedFiniteOriginCallCallerFrameWordRouteTransfer"
        )
        exact = f"""  requestedWord := {{
    originalOffset := {target.offset}
    candidateOffset := {target.offset}
  }}
  requestedWordExact := rfl
  requestedWordMember := by decide +kernel"""
    elif transfer.authority_origin == (
        "checked_direct_call_caller_frame_word_summary"
    ):
        authority_type = "CheckedDirectCallCallerFrameWordRouteTransfer"
        exact = f"""  requestedWord := {{
    originalOffset := {target.offset}
    candidateOffset := {target.offset}
  }}
  requestedWordExact := rfl
  requestedWordMember := by decide +kernel"""
    else:
        raise ValueError(
            "checked caller-frame transfer has an unsupported authority origin"
        )
    source_text = f"""def {prefix}Authority :
    {authority_type} {route_name} {term} := {{
{common}
{exact}
}}

#print axioms {prefix}Authority"""
    return prefix, source_text


def _local_transfer_authority(
    route,
    route_index: int,
    transfer: RuntimeValueTransfer,
    graph: OriginalCutpointGraphIR,
) -> tuple[str, str] | None:
    if (
        transfer.kind
        not in {"decoded_preserve", "decoded_register_to_frame"}
        or transfer.authority_status != "checked_dependency"
        or transfer.source_location_id is None
    ):
        return None
    regions = {region.target_id: region for region in graph.regions}
    source_region = regions.get(transfer.source_target_id)
    if source_region is None:
        raise ValueError(
            "checked local value transfer has no cutpoint-graph source"
        )
    source = route.locations[transfer.source_location_id]
    target = route.locations[transfer.target_location_id]
    prefix = (
        f"generatedRuntimeValueCarryRoute{route_index}"
        f"Transfer{transfer.transfer_id}"
    )
    route_name = f"generatedRuntimeValueCarryRoute{route_index}"
    targets = ", ".join(
        (
            f"(generatedCarrierContext.codeMap.get? {target_id}).get "
            "(by decide +kernel)"
        )
        for target_id in source_region.successor_target_ids
    )
    local_kind = {
        "decoded_preserve": "Or.inl rfl",
        "decoded_register_to_frame": "Or.inr rfl",
    }[transfer.kind]
    source_text = f"""def {prefix}SourceRegion : RegionRelation := {{
  id := {source_region.target_id}
  original := {{ start := {source_region.rva}, size := {source_region.size} }}
  candidate := {{ start := {source_region.rva}, size := {source_region.size} }}
  root := false
  inputs := []
  outputs := []
  inputRelations := []
  targets := [{targets}]
}}

def {prefix}SourceTarget : CodeTargetPair :=
  (generatedCarrierContext.codeMap.get? {source_region.target_id}).get
    (by decide +kernel)

def {prefix}DecodedBehavior : SymbolicBehavior :=
  (regionBehaviorWithMachineCallContracts
    generatedCarrierContext.originalPe
    generatedCarrierContext.originalImports
    generatedCarrierContext.machineImportCallContracts
    {prefix}SourceRegion.original).get (by decide +kernel)

def {prefix}NormalizedBehavior : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior false {prefix}SourceRegion.targets
    {prefix}DecodedBehavior).get (by decide +kernel)

def {prefix}Authority :
    CheckedDecodedLocalRouteTransfer
      (carrierContext := generatedCarrierContext) {route_name}
      {prefix}NormalizedBehavior := {{
  transfer := {_transfer(route, transfer)}
  transferMember := by decide +kernel
  sourceRegion := {prefix}SourceRegion
  sourceTarget := {prefix}SourceTarget
  decodedBehavior := {prefix}DecodedBehavior
  sourceTargetExact := by decide +kernel
  sourceRegionExact := rfl
  sourceRegionStartExact := by decide +kernel
  decodedExact := by decide +kernel
  normalizedExact := by decide +kernel
  sourceLocationId := {transfer.source_location_id}
  sourceLocation := {_location(source.kind, source.register, source.offset)}
  targetLocation := {_location(target.kind, target.register, target.offset)}
  transferKind := {local_kind}
  transferSourceLocation := rfl
  sourceLocationExact := by decide +kernel
  targetLocationExact := by decide +kernel
  outputExpression :=
    locationInputExpression
      {_location(source.kind, source.register, source.offset)}
  outputExpressionExact := by decide +kernel
  valueExact := rfl
}}

#print axioms {prefix}Authority"""
    return prefix, source_text


def _register_call_transfer_authority(
    route,
    route_index: int,
    transfer: RuntimeValueTransfer,
) -> tuple[str, str] | None:
    if (
        transfer.kind
        not in {
            "finite_origin_call_result",
            "direct_call_register_preserve",
        }
        or transfer.authority_status != "checked_dependency"
        or transfer.authority_lean_term is None
    ):
        return None
    target = route.locations[transfer.target_location_id]
    if target.kind != "register" or target.offset != 0:
        raise ValueError(
            "checked register-call transfer has a non-register target"
        )
    prefix = (
        f"generatedRuntimeValueCarryRoute{route_index}"
        f"Transfer{transfer.transfer_id}"
    )
    route_name = f"generatedRuntimeValueCarryRoute{route_index}"
    term = transfer.authority_lean_term.qualified
    if transfer.kind == "direct_call_register_preserve":
        if transfer.source_location_id is None:
            raise ValueError(
                "checked direct-call register transfer has no source"
            )
        source = route.locations[transfer.source_location_id]
        if source != target:
            raise ValueError(
                "checked direct-call register transfer changes location"
            )
        source_text = f"""def {prefix}Authority :
    CheckedDirectCallRegisterRouteTransfer {route_name} {term} := {{
  transfer := {_transfer(route, transfer)}
  transferMember := by decide +kernel
  sourceLocationId := {transfer.source_location_id}
  sourceRegister := .{target.register}
  transferKind := rfl
  transferSourceLocation := rfl
  sourceLocationExact := by decide +kernel
  targetLocationExact := by decide +kernel
  sourceTargetExact := by decide +kernel
  continuationTargetExact := by decide +kernel
  registerRequested := by decide +kernel
}}

#print axioms {prefix}Authority"""
        return prefix, source_text

    if transfer.source_location_id is not None:
        raise ValueError(
            "checked finite-origin call result unexpectedly has a source"
        )
    origin_target_id = route.origin.target_id
    source_text = f"""def {prefix}OriginalTarget : OriginalCodeTarget :=
  (generatedOriginalContext.codeMap.get? {origin_target_id}).get
    (by decide +kernel)

def {prefix}CarrierTarget : CodeTargetPair :=
  (generatedCarrierContext.codeMap.get? {origin_target_id}).get
    (by decide +kernel)

def {prefix}Authority :
    CheckedFiniteOriginCallResultRouteTransfer generatedOriginalContext
      {route_name} {term} := {{
  transfer := {_transfer(route, transfer)}
  transferMember := by decide +kernel
  targetRegister := .{target.register}
  transferKind := rfl
  transferSourceLocation := rfl
  targetLocationExact := by decide +kernel
  sourceTargetExact := by decide +kernel
  continuationTargetExact := by decide +kernel
  targetRegisterExact := by decide +kernel
  originExact := by decide +kernel
  originalPeExact := by decide +kernel
  originalTarget := {prefix}OriginalTarget
  carrierTarget := {prefix}CarrierTarget
  originalTargetExact := by decide +kernel
  carrierTargetExact := by decide +kernel
  targetRvaExact := by decide +kernel
  targetAliasesExact := by decide +kernel
}}

#print axioms {prefix}Authority"""
    return prefix, source_text


def _semantics_source(
    value: RuntimeValueCarryIR,
    graph: OriginalCutpointGraphIR | None,
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    imports = {
        transfer.authority_lean_term.module
        for route in value.routes
        for transfer in route.transfers
        if (
            transfer.kind
            in {
                "finite_origin_call_result",
                "direct_call_register_preserve",
                "call_frame_word_preserve",
            }
            and transfer.authority_status == "checked_dependency"
            and transfer.authority_lean_term is not None
        )
    }
    definitions: list[str] = []
    authorities: list[dict[str, Any]] = []
    value_flow_facts: list[dict[str, Any]] = []
    for route_index, route in enumerate(value.routes):
        for transfer in route.transfers:
            generated = None
            if graph is not None:
                generated = _local_transfer_authority(
                    route, route_index, transfer, graph
                )
            if generated is None:
                generated = _register_call_transfer_authority(
                    route, route_index, transfer
                )
            if generated is None:
                generated = _frame_transfer_authority(
                    route, route_index, transfer
                )
            if generated is None:
                continue
            prefix, source = generated
            definitions.append(source)
            authorities.append({
                "route_index": route_index,
                "transfer_id": transfer.transfer_id,
                "origin": transfer.authority_origin,
                "term": {
                    "module": f"StageA.{SEMANTICS_MODULE}",
                    "namespace": (
                        "StageA.GeneratedRelational.RuntimeValueCarry"
                    ),
                    "symbol": f"{prefix}Authority",
                },
            })
        route_name = f"generatedRuntimeValueCarryRoute{route_index}"
        definitions.append(
            f"""def {route_name}ExecutionInvariant
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract)
    (programBinding : ExactMixedProgramBinding generatedOriginalContext
      ({ORIGINAL_PROGRAM_NAME} environment protocolEnvironment
        externalCallSites))
    (stepClosed : forall before,
      RouteFactsHoldAt generatedOriginalContext {route_name} before ->
        RouteFactsHoldAt generatedOriginalContext {route_name}
          (({ORIGINAL_PROGRAM_NAME} environment protocolEnvironment
            externalCallSites).pe32TransitionSystem.step before).next) :
    CheckedRouteExecutionInvariant generatedOriginalContext
      ({ORIGINAL_PROGRAM_NAME} environment protocolEnvironment
        externalCallSites) {route_name}Authority := {{
  programBinding
  stepClosed
}}

#print axioms {route_name}ExecutionInvariant"""
        )
        origin_checked = f"{route_name}OriginalValueOriginChecked"
        definitions.append(
            f"""theorem {origin_checked} :
    (StageA.Relational.ValueOriginAtom.staticCodeTarget {route.origin.target_id}
      {route.origin.offset}).checked generatedCarrierContext = true := by
  native_decide"""
        )
        facts_by_location: dict[int, list[int]] = {}
        for fact in route.facts:
            facts_by_location.setdefault(fact.location_id, []).append(
                fact.target_id
            )
        for location_id in sorted(facts_by_location):
            target_ids = sorted(facts_by_location[location_id])
            if len(target_ids) != len(set(target_ids)):
                raise ValueError(
                    f"runtime value-carry route {route.stable_id} repeats a "
                    f"target at location {location_id}"
                )
            try:
                location = route.locations[location_id]
            except IndexError as error:
                raise ValueError(
                    f"runtime value-carry route {route.stable_id} references "
                    f"unknown location {location_id}"
                ) from error
            fact_id = len(value_flow_facts)
            fact_name = f"generatedOriginalValueFlowFact{fact_id:04d}"
            fact_id_exact = f"{fact_name}IdExact"
            definitions.append(
                f"""def {fact_name} :
    OriginalFiniteValueFlowFact generatedCarrierContext := {{
  id := {fact_id}
  targetIds := {_nat_list(target_ids)}
  targetIdsNonempty := by decide +kernel
  targetIdsUnique := by decide +kernel
  location := {_control_value_location(
      location.kind, location.register, location.offset
  )}
  locationChecked := by decide +kernel
  finiteAlternativeBudget := 1
  finiteAlternativeBudgetPositive := by decide +kernel
  alternatives := [
    .staticCodeTarget {route.origin.target_id} {route.origin.offset}
  ]
  alternativesNonempty := by decide +kernel
  alternativesUnique := by decide +kernel
  alternativesWithinBudget := by decide +kernel
  alternativesChecked := by
    intro origin member
    simp only [List.mem_singleton] at member
    subst origin
    exact {origin_checked}
}}

theorem {fact_id_exact} : {fact_name}.id = {fact_id} := by
  rfl"""
            )
            value_flow_facts.append(
                {
                    "route_stable_id": route.stable_id,
                    "fact_stable_id": (
                        f"{route.stable_id}:location:{location_id}"
                    ),
                    "location_id": location_id,
                    "target_ids": target_ids,
                    "id": fact_id,
                    "term": {
                        "module": f"StageA.{SEMANTICS_MODULE}",
                        "namespace": (
                            "StageA.GeneratedRelational.RuntimeValueCarry"
                        ),
                        "symbol": fact_name,
                    },
                    "id_exact": {
                        "module": f"StageA.{SEMANTICS_MODULE}",
                        "namespace": (
                            "StageA.GeneratedRelational.RuntimeValueCarry"
                        ),
                        "symbol": fact_id_exact,
                    },
                }
            )
    fact_names = [
        row["term"]["symbol"] for row in value_flow_facts
    ]
    if not fact_names:
        raise ValueError("runtime value-carry produced no original value-flow facts")
    definitions.append(
        f"""def generatedOriginalValueFlowInventory :
    OriginalValueFlowInventory generatedCarrierContext := {{
  facts := [{", ".join(fact_names)}]
  factIdsUnique := by
    simp [{", ".join(fact_names)}]
}}

theorem generatedOriginalValueFlowFactsExact :
    generatedOriginalValueFlowInventory.facts =
      [{", ".join(fact_names)}] := by
  rfl"""
    )
    imported = "\n".join(
        f"import {module}" for module in sorted(imports)
    )
    return f"""import StageA.{BINDING_MODULE}
import StageA.{CONTEXT_MODULE}
import StageA.RelationalRuntimeValueCarrySemantics
import StageA.RelationalOriginalValueFlowExecutionInvariant
{imported}

namespace StageA.GeneratedRelational.RuntimeValueCarry

open StageA.Relational
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.RuntimeValueCarry
open StageA.Relational.RuntimeValueCarrySemantics
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.ValueProvenance

def generatedOriginalContext := {CONTEXT_NAME}
def generatedCarrierContext := {CARRIER_CONTEXT_NAME}

{"\n\n".join(definitions)}

end StageA.GeneratedRelational.RuntimeValueCarry
""", authorities, {
        "inventory": {
            "module": f"StageA.{SEMANTICS_MODULE}",
            "namespace": "StageA.GeneratedRelational.RuntimeValueCarry",
            "symbol": "generatedOriginalValueFlowInventory",
        },
        "facts_exact": {
            "module": f"StageA.{SEMANTICS_MODULE}",
            "namespace": "StageA.GeneratedRelational.RuntimeValueCarry",
            "symbol": "generatedOriginalValueFlowFactsExact",
        },
        "facts": value_flow_facts,
    }


def _kernel_checked(
    source: Path,
    kernel_checks: Mapping[str, Any] | None,
) -> bool:
    if kernel_checks is None:
        return False
    row = kernel_checks.get(f"StageA.{SEMANTICS_MODULE}")
    if not isinstance(row, Mapping):
        return False
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    olean_sha256 = row.get("olean_sha256")
    return (
        row.get("status") == "checked"
        and row.get("source_sha256") == source_sha256
        and isinstance(olean_sha256, str)
        and len(olean_sha256) == 64
        and all(character in "0123456789abcdef" for character in olean_sha256)
    )


def write_runtime_value_carry_lean(
    out: Path,
    value: RuntimeValueCarryIR,
    *,
    kernel_checks: Mapping[str, Any] | None = None,
    graph: OriginalCutpointGraphIR | None = None,
) -> tuple[Path, Path, Path]:
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    structure = stage_a / f"{STRUCTURE_MODULE}.lean"
    binding = stage_a / f"{BINDING_MODULE}.lean"
    semantics = stage_a / f"{SEMANTICS_MODULE}.lean"
    structure.write_text(_structure_source(value, graph), encoding="utf-8")
    binding.write_text(_binding_source(value), encoding="utf-8")
    (
        semantics_source,
        semantic_authorities,
        value_flow_exports,
    ) = _semantics_source(value, graph)
    semantics.write_text(semantics_source, encoding="utf-8")
    semantic_kernel_checked = _kernel_checked(semantics, kernel_checks)
    authorities_by_route = {
        index: [
            authority
            for authority in semantic_authorities
            if authority["route_index"] == index
        ]
        for index in range(len(value.routes))
    }
    route_semantics_complete = {}
    for index, route in enumerate(value.routes):
        expected_semantic_transfers = {
            transfer.transfer_id
            for transfer in route.transfers
            if (
                transfer.kind
                in {
                    "finite_origin_call_result",
                    "direct_call_register_preserve",
                    "decoded_preserve",
                    "decoded_register_to_frame",
                    "call_frame_word_preserve",
                }
                and transfer.authority_status == "checked_dependency"
            )
        }
        generated_semantic_transfers = {
            authority["transfer_id"]
            for authority in authorities_by_route[index]
        }
        route_semantics_complete[index] = (
            route.proof_ready
            and generated_semantic_transfers == expected_semantic_transfers
        )
    for authority in semantic_authorities:
        authority["status"] = (
            "closed"
            if semantic_kernel_checked
            else "kernel_compile_required"
        )
    report = out / "runtime-value-carry-lean.json"
    write_json(
        report,
        {
            "format": "stage-a-runtime-value-carry-lean-v1",
            "modules": [STRUCTURE_MODULE, BINDING_MODULE, SEMANTICS_MODULE],
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
                    "semantic_authority": authorities_by_route[index],
                    "aggregate_invariant_constructor": (
                        "StageA.GeneratedRelational.RuntimeValueCarry."
                        f"generatedRuntimeValueCarryRoute{index}"
                        "ExecutionInvariant"
                    ),
                    "semantic_authority_status": (
                        "closed"
                        if semantic_kernel_checked
                        and route_semantics_complete[index]
                        else (
                            "semantic_dependencies_incomplete"
                            if semantic_kernel_checked
                            else "kernel_compile_required"
                        )
                    ),
                }
                for index, route in enumerate(value.routes)
            ],
            "original_combined_value_flow_declarations": value_flow_exports,
            "proof_authority": False,
            "semantic_authority_complete": (
                value.proof_ready
                and semantic_kernel_checked
                and all(route_semantics_complete.values())
            ),
            "kernel_compile_required": not semantic_kernel_checked,
        },
    )
    write_json(
        out / "kernel-check-requests.json",
        {
            "format": "stage-a-lean-kernel-check-requests-v1",
            "requests": [
                {"term": authority["term"]}
                for authority in semantic_authorities
            ],
        },
    )
    return structure, binding, report


__all__ = [
    "BINDING_MODULE",
    "CARRIER_CONTEXT_NAME",
    "CONTEXT_MODULE",
    "CONTEXT_NAME",
    "ORIGINAL_AUTHORITY_NAME",
    "ORIGINAL_PROGRAM_NAME",
    "SEMANTICS_MODULE",
    "STRUCTURE_MODULE",
    "write_runtime_value_carry_lean",
]
