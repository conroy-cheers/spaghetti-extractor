"""Emit the concrete GNU hello runtime-indirect composition module.

This adapter is intentionally fixture-specific. It binds the generic
runtime-indirect kernel to the exact GNU hello artifacts. The generated Lean
module imports the canonical GNU acceptance requirements and the checked
runtime-value-carry modules directly; it never accepts names of proof terms
from JSON.

Target 292 is closed by binding every route edge to the selected component's
computed execution and deriving its stack range from the finite-origin call's
checked source relation. The plan records the remaining constructor and
dynamic-slot obligations without manufacturing closure from report status or
caller-supplied terms.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ..original_cutpoint_graph_ir import (
    OriginalCutpointGraphIR,
    canonical_original_cutpoint_graph_sha256,
    original_cutpoint_graph_ir_from_json,
)


GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_FORMAT = (
    "stage-a-gnu-hello-runtime-indirect-composition-v1"
)
GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_LEAN_FILENAME = (
    "GeneratedRelationalGNUHelloRuntimeIndirectComposition.lean"
)

STACK_SOURCE_TARGET_ID = 292
CONSTRUCTOR_SOURCE_TARGET_ID = 2595
DYNAMIC_SOURCE_TARGET_ID = 2792
CONSTRUCTOR_INCOMING = (
    (2594, CONSTRUCTOR_SOURCE_TARGET_ID),
    (2596, CONSTRUCTOR_SOURCE_TARGET_ID),
)
DYNAMIC_INCOMING = ((2791, DYNAMIC_SOURCE_TARGET_ID),)

STACK_FRONTIER_ID = "gnu.original.callback-stack-slot"
STACK_SITE_STABLE_ID = "stack-dynamic-ad0bad06992a9b2c16c0"
CONSTRUCTOR_FRONTIER_ID = "stack-dynamic-c50fbcca964899c32624"
DYNAMIC_FRONTIER_ID = "stack-dynamic-11c19b6c127dedbf5fd7"

_CLOSURE_FORMAT = "stage-a-original-stack-dynamic-control-closure-v1"
_RUNTIME_VALUE_CARRY_FORMAT = "stage-a-runtime-value-carry-ir-v1"
_ROOTED_FORMAT = "stage-a-relational-nullable-code-pointer-rooted-scc-v3"
_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)

_CONTEXT_NAME = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
    "generatedOriginalStaticContext"
)
_CARRIER_CONTEXT_NAME = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
    "generatedOriginalCarrierContext"
)
_DECODED_AUTHORITY_NAME = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
    "generatedExactOriginalDecodedAuthority"
)
_STACK_DYNAMIC_MODULE = (
    "StageA.GeneratedRelationalOriginalStackDynamicControlClosure"
)
_RUNTIME_VALUE_CARRY_MODULE = (
    "StageA.GeneratedRelationalRuntimeValueCarryBinding"
)
_RUNTIME_VALUE_CARRY_SEMANTICS_MODULE = (
    "StageA.GeneratedRelationalRuntimeValueCarrySemantics"
)
_GNU_REQUIREMENTS_MODULE = "StageA.GeneratedGnuHelloAcceptanceRequirements"
_GNU_REQUIREMENTS_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloAcceptanceRequirements"
)


class GNUHelloRuntimeIndirectCompositionGenerationError(StageAInputError):
    """GNU hello static evidence cannot safely instantiate the composition."""


@dataclass(frozen=True)
class RuntimeIndirectEvidenceGap:
    frontier_id: str
    source_target_id: int
    extractor_field: str
    checker_type: str
    reason: str


_ROUTE_AUTHORITY_CONSTRUCTORS = {
    ("decoded_preserve", None): "decoded",
    ("decoded_register_to_frame", None): "decoded",
    (
        "direct_call_register_preserve",
        "checked_direct_call_summary",
    ): "directRegister",
    (
        "finite_origin_call_result",
        "checked_finite_origin_call_summary",
    ): "finiteResult",
    (
        "call_frame_word_preserve",
        "checked_direct_call_caller_frame_word_summary",
    ): "directFrame",
    (
        "call_frame_word_preserve",
        "checked_finite_origin_call_caller_frame_word_summary",
    ): "finiteFrame",
}


_UNRESOLVED_OPERATIONAL_FRONTIERS = (
    RuntimeIndirectEvidenceGap(
        frontier_id=CONSTRUCTOR_FRONTIER_ID,
        source_target_id=CONSTRUCTOR_SOURCE_TARGET_ID,
        extractor_field="mixed_component.rooted_scanner_phase_replay",
        checker_type=(
            "CheckedMixedKernelSelectedInvariantClosure "
            "(rooted scanner phase closure)"
        ),
        reason=(
            "the exact scanner decoder, zero/bypass semantics, rooted SCC, and "
            "source-exclusion theorem are checked; the selected mixed component "
            "still needs a phase-preserving replay from selector through "
            "zero/scanner/bridge/gate before the SCC {2595, 2596} is operationally "
            "excluded"
        ),
    ),
    RuntimeIndirectEvidenceGap(
        frontier_id=DYNAMIC_FRONTIER_ID,
        source_target_id=DYNAMIC_SOURCE_TARGET_ID,
        extractor_field="reachable_static_slot.write_preservation",
        checker_type=(
            "OriginalWorldExecutionInvariant "
            "(BSS dtor-head zero and preservation)"
        ),
        reason=(
            "the BSS head at RVA 0x30364 is launch-zero and a generic complete "
            "write-trace theorem now carries that zero to the final state; "
            "the exact artifacts still lack a CompleteWriteFootprintTrace "
            "covering every reachable decoded/external write and checked "
            "separation from runtime-owned ranges"
        ),
    ),
)


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{field} must be an object"
        )
    return value


def _rows(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{field} must be a list"
        )
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{field} must be a non-empty string"
        )
    return value


def _natural(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{field} must be a natural number"
        )
    return value


def _lean_name(value: Any, field: str) -> str:
    name = _string(value, field)
    if _LEAN_NAME.fullmatch(name) is None:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{field} is not a valid Lean name"
        )
    return name


def _load_json(path: Path | str, field: str) -> Mapping[str, Any]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"cannot read {field}: {error}"
        ) from error
    return _mapping(value, field)


def _site(
    closure: Mapping[str, Any],
    *,
    mode: str,
    source_target_id: int,
    stable_id: str,
) -> tuple[int, Mapping[str, Any]]:
    matches: list[tuple[int, Mapping[str, Any]]] = []
    for index, raw in enumerate(_rows(closure.get("sites"), "closure sites")):
        row = _mapping(raw, f"closure site {index}")
        if row.get("closure_mode") == mode:
            matches.append((index, row))
    if len(matches) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"GNU hello requires exactly one {mode} site"
        )
    index, row = matches[0]
    if _natural(row.get("source_target_id"), f"{mode} source target ID") != (
        source_target_id
    ):
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{mode} site is not exact GNU hello target {source_target_id}"
        )
    if _string(row.get("stable_id"), f"{mode} stable ID") != stable_id:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{mode} site has the wrong stable ID"
        )
    return index, row


def _decoded_incoming(
    graph: OriginalCutpointGraphIR,
    target_id: int,
) -> tuple[tuple[int, int], ...]:
    pairs = tuple(sorted(
        (region.target_id, target_id)
        for region in graph.regions
        if target_id in region.successor_target_ids
    ))
    if not pairs:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"target {target_id} has no decoded incoming edges"
        )
    if len(set(pairs)) != len(pairs):
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"target {target_id} has ambiguous decoded incoming edges"
        )
    return pairs


def _same_identity(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    field: str,
) -> None:
    for identity in ("original_pe_sha256", "state_machine_sha256"):
        if left.get(identity) != right.get(identity):
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                f"{field} disagrees on {identity}"
            )


@dataclass(frozen=True)
class GNUHelloRuntimeIndirectCompositionPlan:
    stack_route_index: int
    stack_site_index: int
    constructor_site_index: int
    dynamic_site_index: int
    constructor_rooted_module: str
    constructor_rooted_authority_name: str
    constructor_rooted_execution_authority_name: str
    constructor_rooted_source_excluded_name: str
    constructor_incoming: tuple[tuple[int, int], ...]
    dynamic_incoming: tuple[tuple[int, int], ...]
    stack_transfer_authority_names: tuple[str, ...]
    stack_transfer_authority_constructors: tuple[str, ...]
    stack_target_transfer_index: int
    stack_target_contract_name: str
    evidence_gaps: tuple[RuntimeIndirectEvidenceGap, ...] = (
        _UNRESOLVED_OPERATIONAL_FRONTIERS
    )

    @property
    def stack_route_authority_name(self) -> str:
        return (
            "StageA.GeneratedRelational.RuntimeValueCarry."
            f"generatedRuntimeValueCarryRoute{self.stack_route_index}Authority"
        )

    @property
    def stack_authority_name(self) -> str:
        return (
            "StageA.GeneratedRelational.OriginalStackDynamicControlClosure."
            f"generatedOriginalStackDynamicClosure{self.stack_site_index}"
            "StackAuthority"
        )

    @property
    def constructor_authority_name(self) -> str:
        return (
            "StageA.GeneratedRelational.OriginalStackDynamicControlClosure."
            f"generatedOriginalStackDynamicClosure{self.constructor_site_index}"
            "EmptyIndexedAuthority"
        )

    @property
    def dynamic_site_name(self) -> str:
        return (
            "StageA.GeneratedRelational.OriginalStackDynamicControlClosure."
            f"generatedOriginalStackDynamicClosure{self.dynamic_site_index}"
            "SiteEvidence"
        )

    def validate(self) -> None:
        for field, value in (
            ("stack route index", self.stack_route_index),
            ("stack site index", self.stack_site_index),
            ("constructor site index", self.constructor_site_index),
            ("dynamic site index", self.dynamic_site_index),
        ):
            _natural(value, field)
        _lean_name(self.constructor_rooted_module, "constructor rooted module")
        _lean_name(
            self.constructor_rooted_authority_name,
            "constructor rooted authority",
        )
        _lean_name(
            self.constructor_rooted_execution_authority_name,
            "constructor rooted execution authority",
        )
        _lean_name(
            self.constructor_rooted_source_excluded_name,
            "constructor rooted source exclusion theorem",
        )
        if not self.stack_transfer_authority_names:
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "stack route has no checked transfer authorities"
            )
        for name in self.stack_transfer_authority_names:
            _lean_name(name, "stack transfer authority")
        if len(self.stack_transfer_authority_constructors) != len(
            self.stack_transfer_authority_names
        ):
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "route authority constructors do not cover every transfer"
            )
        if any(
            constructor not in set(_ROUTE_AUTHORITY_CONSTRUCTORS.values())
            for constructor in self.stack_transfer_authority_constructors
        ):
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "route authority constructor is unsupported"
            )
        if not 0 <= self.stack_target_transfer_index < len(
            self.stack_transfer_authority_names
        ):
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "target-292 transfer index is outside the exact route"
            )
        if (
            self.stack_transfer_authority_constructors[
                self.stack_target_transfer_index
            ]
            != "finiteFrame"
        ):
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "target-292 transfer is not a finite-origin caller-frame edge"
            )
        _lean_name(
            self.stack_target_contract_name,
            "target-292 caller-frame contract",
        )
        expected = {
            CONSTRUCTOR_SOURCE_TARGET_ID: self.constructor_incoming,
            DYNAMIC_SOURCE_TARGET_ID: self.dynamic_incoming,
        }
        for target_id, incoming in expected.items():
            if not incoming or tuple(sorted(set(incoming))) != incoming:
                raise GNUHelloRuntimeIndirectCompositionGenerationError(
                    f"target {target_id} incoming inventory is not canonical"
                )
            if any(target != target_id for _source, target in incoming):
                raise GNUHelloRuntimeIndirectCompositionGenerationError(
                    f"target {target_id} incoming inventory crosses cuts"
                )
        if self.constructor_incoming != CONSTRUCTOR_INCOMING:
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "constructor incoming inventory is not exact GNU hello data"
            )
        if self.dynamic_incoming != DYNAMIC_INCOMING:
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "dynamic incoming inventory is not exact GNU hello data"
            )
        if self.evidence_gaps != _UNRESOLVED_OPERATIONAL_FRONTIERS:
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "runtime-indirect evidence gaps are not canonical"
            )
        for gap in self.evidence_gaps:
            if gap.source_target_id not in {
                STACK_SOURCE_TARGET_ID,
                CONSTRUCTOR_SOURCE_TARGET_ID,
                DYNAMIC_SOURCE_TARGET_ID,
            }:
                raise GNUHelloRuntimeIndirectCompositionGenerationError(
                    "runtime-indirect evidence gap names an unknown source"
                )


def plan_gnu_hello_runtime_indirect_composition(
    *,
    cutpoint_graph: Path | str,
    stack_dynamic_closure: Path | str,
    runtime_value_carry: Path | str,
    rooted_unreachability: Path | str,
) -> GNUHelloRuntimeIndirectCompositionPlan:
    graph_payload = _load_json(cutpoint_graph, "cutpoint graph")
    try:
        graph = original_cutpoint_graph_ir_from_json(graph_payload)
    except StageAInputError as error:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"invalid cutpoint graph: {error}"
        ) from error
    closure = _load_json(stack_dynamic_closure, "stack/dynamic closure")
    runtime = _load_json(runtime_value_carry, "runtime value-carry IR")
    rooted = _load_json(rooted_unreachability, "rooted unreachability")
    if closure.get("format") != _CLOSURE_FORMAT:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "stack/dynamic closure has the wrong format"
        )
    if runtime.get("format") != _RUNTIME_VALUE_CARRY_FORMAT:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "runtime value-carry IR has the wrong format"
        )
    if rooted.get("format") != _ROOTED_FORMAT:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "rooted unreachability has the wrong format"
        )

    graph_identity = {
        "original_pe_sha256": graph.original_pe_sha256,
        "state_machine_sha256": graph.state_machine_sha256,
    }
    closure_inputs = _mapping(closure.get("inputs"), "closure inputs")
    runtime_inputs = _mapping(runtime.get("inputs"), "runtime inputs")
    rooted_inputs = _mapping(rooted.get("inputs"), "rooted inputs")
    _same_identity(graph_identity, closure_inputs, "stack/dynamic closure")
    _same_identity(graph_identity, runtime_inputs, "runtime value-carry IR")
    _same_identity(graph_identity, rooted_inputs, "rooted unreachability")
    graph_content = canonical_original_cutpoint_graph_sha256(graph)
    if runtime_inputs.get("cutpoint_graph_content_sha256") != graph_content:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "runtime value-carry IR is not bound to the exact cutpoint graph"
        )
    if rooted_inputs.get("cutpoint_graph_content_sha256") != graph_content:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "rooted unreachability is not bound to the exact cutpoint graph"
        )
    stack_site_index, stack_site = _site(
        closure,
        mode="finite_stack_target",
        source_target_id=STACK_SOURCE_TARGET_ID,
        stable_id=STACK_SITE_STABLE_ID,
    )
    constructor_site_index, _constructor_site = _site(
        closure,
        mode="empty_indexed_source",
        source_target_id=CONSTRUCTOR_SOURCE_TARGET_ID,
        stable_id=CONSTRUCTOR_FRONTIER_ID,
    )
    dynamic_site_index, _dynamic_site = _site(
        closure,
        mode="uninhabited_dynamic_source",
        source_target_id=DYNAMIC_SOURCE_TARGET_ID,
        stable_id=DYNAMIC_FRONTIER_ID,
    )

    allowed = _rows(
        stack_site.get("allowed_target_ids"),
        "stack site target inventory",
    )
    if len(allowed) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello stack site does not have one static callback target"
        )
    routes = _rows(runtime.get("routes"), "runtime value-carry routes")
    route_matches: list[int] = []
    for index, raw in enumerate(routes):
        route = _mapping(raw, f"runtime value-carry route {index}")
        target_fact = _mapping(
            route.get("target_fact"),
            f"runtime value-carry route {index} target fact",
        )
        origin = _mapping(
            route.get("origin"),
            f"runtime value-carry route {index} origin",
        )
        if (
            target_fact.get("target_id") == STACK_SOURCE_TARGET_ID
            and origin.get("target_id") == allowed[0]
        ):
            route_matches.append(index)
            if route.get("stable_id") != STACK_FRONTIER_ID:
                raise GNUHelloRuntimeIndirectCompositionGenerationError(
                    "GNU hello stack route has the wrong stable ID"
                )
    if len(route_matches) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello stack site has no unique runtime value-carry route"
        )
    stack_route_index = route_matches[0]
    stack_route = _mapping(
        routes[stack_route_index],
        f"runtime value-carry route {stack_route_index}",
    )
    route_facts = _rows(
        stack_route.get("facts"),
        f"runtime value-carry route {stack_route_index} facts",
    )
    target_fact = _mapping(
        stack_route.get("target_fact"),
        f"runtime value-carry route {stack_route_index} target fact",
    )
    if target_fact not in route_facts:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello stack route target fact is absent from its exact facts"
        )
    route_transfers = _rows(
        stack_route.get("transfers"),
        f"runtime value-carry route {stack_route_index} transfers",
    )
    if not route_transfers:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello stack route has no semantic transfers"
        )
    graph_edge_pairs = {
        (edge.edge_index, edge.source_target_id, edge.target_target_id)
        for edge in graph.edges
    }
    stack_transfer_authority_names: list[str] = []
    stack_transfer_authority_constructors: list[str] = []
    stack_target_transfer_indices: list[int] = []
    stack_target_contract_names: list[str] = []
    for transfer_index, raw_transfer in enumerate(route_transfers):
        transfer = _mapping(
            raw_transfer,
            f"runtime value-carry route {stack_route_index} "
            f"transfer {transfer_index}",
        )
        edge = (
            _natural(transfer.get("edge_index"), "route transfer edge ID"),
            _natural(
                transfer.get("source_target_id"),
                "route transfer source target ID",
            ),
            _natural(
                transfer.get("target_target_id"),
                "route transfer target target ID",
            ),
        )
        if edge not in graph_edge_pairs:
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "GNU hello route transfer is not an exact cutpoint-graph edge"
            )
        stack_transfer_authority_names.append(
            "StageA.GeneratedRelational.RuntimeValueCarry."
            f"generatedRuntimeValueCarryRoute{stack_route_index}"
            f"Transfer{transfer_index}Authority"
        )
        authority_key = (
            _string(transfer.get("kind"), "route transfer kind"),
            transfer.get("authority_origin"),
        )
        try:
            constructor = _ROUTE_AUTHORITY_CONSTRUCTORS[authority_key]
        except KeyError as error:
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "GNU hello route transfer has no generic semantic authority "
                f"constructor: {authority_key!r}"
            ) from error
        stack_transfer_authority_constructors.append(constructor)
        if edge[1:] == (STACK_SOURCE_TARGET_ID, 293):
            if (
                authority_key
                != (
                    "call_frame_word_preserve",
                    "checked_finite_origin_call_caller_frame_word_summary",
                )
            ):
                raise GNUHelloRuntimeIndirectCompositionGenerationError(
                    "target-292 route edge has the wrong semantic authority"
                )
            stack_target_transfer_indices.append(transfer_index)
            authority_term = _mapping(
                transfer.get("authority_lean_term"),
                "target-292 route authority Lean term",
            )
            namespace = _lean_name(
                authority_term.get("namespace"),
                "target-292 route authority namespace",
            )
            symbol = _lean_name(
                authority_term.get("symbol"),
                "target-292 route authority symbol",
            )
            if (
                symbol
                != "generatedCheckedFiniteOriginCallCallerFrameWordControlContract"
            ):
                raise GNUHelloRuntimeIndirectCompositionGenerationError(
                    "target-292 route authority has the wrong contract symbol"
                )
            stack_target_contract_names.append(f"{namespace}.{symbol}")
    if len(stack_target_transfer_indices) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello route has no unique target-292-to-293 transfer"
        )
    if len(stack_target_contract_names) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello route has no unique target-292 caller-frame contract"
        )

    rooted_entries = _rows(rooted.get("entries"), "rooted entries")
    rooted_matches = [
        _mapping(raw, f"rooted entry {index}")
        for index, raw in enumerate(rooted_entries)
        if (
            isinstance(raw, Mapping)
            and raw.get("source_target_id") == CONSTRUCTOR_SOURCE_TARGET_ID
        )
    ]
    if len(rooted_matches) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello constructor has no unique rooted certificate"
        )
    rooted_entry = rooted_matches[0]
    if rooted_entry.get("stable_id") != CONSTRUCTOR_FRONTIER_ID:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello rooted constructor certificate has the wrong stable ID"
        )
    expected_constructor_authority = (
        "StageA.GeneratedRelational.OriginalStackDynamicControlClosure."
        f"generatedOriginalStackDynamicClosure{constructor_site_index}"
        "EmptyIndexedAuthority"
    )
    if (
        rooted_entry.get("empty_indexed_authority_term")
        != expected_constructor_authority
    ):
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "rooted constructor certificate names the wrong static authority"
        )
    rooted_authority_name = _lean_name(
        rooted_entry.get("authority_term"),
        "rooted constructor authority",
    )
    if not rooted_authority_name.endswith("Authority"):
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "rooted constructor authority does not use the checked companion "
            "naming contract"
        )
    rooted_definition_name = rooted_authority_name.removesuffix("Authority")

    constructor_incoming = _decoded_incoming(
        graph, CONSTRUCTOR_SOURCE_TARGET_ID
    )
    dynamic_incoming = _decoded_incoming(graph, DYNAMIC_SOURCE_TARGET_ID)
    rooted_pairs = {
        (
            _natural(
                _mapping(raw, "rooted incoming edge").get("source_target_id"),
                "rooted incoming source",
            ),
            _natural(
                _mapping(raw, "rooted incoming edge").get("target_target_id"),
                "rooted incoming target",
            ),
        )
        for raw in _rows(rooted_entry.get("incoming_edges"), "rooted incoming")
    }
    if not set(constructor_incoming).issubset(rooted_pairs):
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "rooted constructor certificate omits an exact incoming edge"
        )

    plan = GNUHelloRuntimeIndirectCompositionPlan(
        stack_route_index=stack_route_index,
        stack_site_index=stack_site_index,
        constructor_site_index=constructor_site_index,
        dynamic_site_index=dynamic_site_index,
        constructor_rooted_module=_lean_name(
            rooted_entry.get("module"), "rooted constructor module"
        ),
        constructor_rooted_authority_name=rooted_authority_name,
        constructor_rooted_execution_authority_name=(
            f"{rooted_definition_name}ExecutionAuthority"
        ),
        constructor_rooted_source_excluded_name=(
            f"{rooted_definition_name}SourceExcluded"
        ),
        constructor_incoming=constructor_incoming,
        dynamic_incoming=dynamic_incoming,
        stack_transfer_authority_names=tuple(
            stack_transfer_authority_names
        ),
        stack_transfer_authority_constructors=tuple(
            stack_transfer_authority_constructors
        ),
        stack_target_transfer_index=stack_target_transfer_indices[0],
        stack_target_contract_name=stack_target_contract_names[0],
    )
    plan.validate()
    return plan


def _incoming_guard(
    frontier_id: str,
    source_target_id: int,
    target_target_id: int,
) -> str:
    guard_id = (
        f"{frontier_id}:incoming:{source_target_id}:{target_target_id}"
    )
    return (
        "{ edge := { sourceTargetId := "
        f"{source_target_id}, targetTargetId := {target_target_id} "
        f'}}, guardId := "{guard_id}"'
        " }"
    )


def gnu_hello_runtime_indirect_composition_source(
    plan: GNUHelloRuntimeIndirectCompositionPlan,
) -> str:
    plan.validate()
    constructor_guards = ", ".join(
        _incoming_guard(CONSTRUCTOR_FRONTIER_ID, source, target)
        for source, target in plan.constructor_incoming
    )
    dynamic_guards = ", ".join(
        _incoming_guard(DYNAMIC_FRONTIER_ID, source, target)
        for source, target in plan.dynamic_incoming
    )
    rooted_members = "\n      ".join(
        (
            "generatedConstructorRootedAuthority.certificate.incomingEdges"
            ".contains { sourceTargetId := "
            f"{source}, targetTargetId := {target} "
            "} = true /\\"
        )
        for source, target in plan.constructor_incoming
    ).removesuffix("/\\")
    transfer_aliases = "\n".join(
        f"def generatedStackTransfer{index}Authority := {authority}"
        for index, authority in enumerate(
            plan.stack_transfer_authority_names
        )
    )
    transfer_axioms = "\n".join(
        f"#print axioms generatedStackTransfer{index}Authority"
        for index in range(len(plan.stack_transfer_authority_names))
    )
    selected_authority_exact = "\n\n".join(
        f"""theorem generatedStackTransfer{index}SelectedAuthorityExact :
    generatedStackTransferInventory.authorities[{index}]? =
      some (.{constructor} generatedStackTransfer{index}Authority) := by
  decide +kernel"""
        for index, constructor in enumerate(
            plan.stack_transfer_authority_constructors
        )
    )
    selected_authority_axioms = "\n".join(
        f"#print axioms generatedStackTransfer{index}SelectedAuthorityExact"
        for index in range(len(plan.stack_transfer_authority_names))
    )
    selected_execution_factories = "\n\n".join(
        f"""def generatedStackTransfer{index}SelectedExecution
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{contract : MixedRelationContract}}
    {{reachabilityTargetIds : List Nat}}
    {{base : MixedExecutionInvariant reachabilityTargetIds contract}}
    {{originalBefore : WorldExecution}}
    {{candidateBefore : NativeWorldExecution}}
    (chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore)
    (sourceState targetState : MachineState)
    (sourceAt :
      originalExecutionAtTargetId
        generatedStackTransfer{index}Authority.transfer.sourceTargetId
        originalBefore)
    (targetAt :
      originalExecutionAtTargetId
        generatedStackTransfer{index}Authority.transfer.targetTargetId
        chunk.originalAfter)
    (sourceMachineExact :
      originalExecutionMachine? originalBefore = some sourceState)
    (targetMachineExact :
      originalExecutionMachine? chunk.originalAfter = some targetState)
    (sourceFact :
      CheckedRouteTransferAuthority.SourceFactHolds
        (originalContext := generatedContext)
        (.{constructor} generatedStackTransfer{index}Authority) sourceState)
    (execution :
      CheckedRouteTransferExecution generatedContext generatedCarrierContext
        generatedStackRouteAuthority.route
        (.{constructor} generatedStackTransfer{index}Authority)
        sourceState targetState) :
    CheckedSelectedRouteTransferExecution generatedStackTransferInventory
      originalBefore candidateBefore chunk := {{
  authorityIndex := {index}
  authority := .{constructor} generatedStackTransfer{index}Authority
  authorityExact := generatedStackTransfer{index}SelectedAuthorityExact
  sourceState
  targetState
  sourceAt
  targetAt
  sourceMachineExact
  targetMachineExact
  sourceFact
  execution
}}"""
        for index, constructor in enumerate(
            plan.stack_transfer_authority_constructors
        )
    )
    selected_execution_axioms = "\n".join(
        f"#print axioms generatedStackTransfer{index}SelectedExecution"
        for index in range(len(plan.stack_transfer_authority_names))
    )
    transfer_inventory = ",\n    ".join(
        f".{constructor} generatedStackTransfer{index}Authority"
        for index, constructor in enumerate(
            plan.stack_transfer_authority_constructors
        )
    )
    target_transfer_index = plan.stack_target_transfer_index
    return f"""import StageA.RelationalRuntimeIndirectComposition
import {_RUNTIME_VALUE_CARRY_MODULE}
import {_RUNTIME_VALUE_CARRY_SEMANTICS_MODULE}
import {_STACK_DYNAMIC_MODULE}
import {plan.constructor_rooted_module}
import {_GNU_REQUIREMENTS_MODULE}

namespace StageA.GeneratedRelational.GNUHelloRuntimeIndirectComposition

open StageA.Formal StageA.Relational
open StageA.Relational.GuardedRuntimeCut
open StageA.Relational.InternalDirectCallMixedOriginalIntegration
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.NullableCodePointerDispatch
open StageA.Relational.NullableCodePointerRootedUnreachability
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.RuntimeIndirectComposition
open StageA.Relational.RuntimeValueCarrySemantics
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

namespace Requirements := {_GNU_REQUIREMENTS_NAMESPACE}

def generatedContext : OriginalDecodedStaticContext := {_CONTEXT_NAME}
def generatedCarrierContext : StaticProofContext := {_CARRIER_CONTEXT_NAME}

def generatedStackRouteAuthority := {plan.stack_route_authority_name}
def generatedStackAuthority := {plan.stack_authority_name}
def generatedConstructorAuthority := {plan.constructor_authority_name}
def generatedDynamicSite := {plan.dynamic_site_name}
def generatedConstructorRootedAuthority :=
  {plan.constructor_rooted_authority_name}
def generatedConstructorRootedExecutionAuthority :
    CheckedRootedScannerSccExecution generatedContext
      generatedConstructorAuthority.site :=
  {plan.constructor_rooted_execution_authority_name}

theorem generatedConstructorRootedSourceExcluded
    (reachable : RootedScannerOperationalReachable
      generatedConstructorRootedExecutionAuthority
      generatedConstructorAuthority.site.sourceTargetId) :
    False :=
  {plan.constructor_rooted_source_excluded_name} reachable

{transfer_aliases}

def generatedStackTransferAuthorities :
    List (CheckedRouteTransferAuthority generatedContext
      generatedCarrierContext generatedStackRouteAuthority.route) := [
    {transfer_inventory}
]

theorem generatedStackTransferInventoryChecked :
    checkedRouteTransferInventory generatedStackRouteAuthority.route
      generatedStackTransferAuthorities = true := by
  decide +kernel

def generatedStackTransferInventory :
    CheckedRouteTransferInventory generatedContext generatedCarrierContext
      generatedStackRouteAuthority.route := {{
  authorities := generatedStackTransferAuthorities
  checked := generatedStackTransferInventoryChecked
}}

{selected_authority_exact}

{selected_execution_factories}

def generatedConstructorCut : Certificate := {{
  frontierId := "{CONSTRUCTOR_FRONTIER_ID}"
  sourceTargetId := {CONSTRUCTOR_SOURCE_TARGET_ID}
  incomingGuards := [{constructor_guards}]
}}

theorem generatedConstructorCutChecked :
    generatedConstructorCut.checked generatedContext = true := by
  decide +kernel

def generatedConstructorCutAuthority :
    CheckedCertificate generatedContext := {{
  decodedAuthority := {_DECODED_AUTHORITY_NAME}
  certificate := generatedConstructorCut
  checked := generatedConstructorCutChecked
}}

def generatedDynamicCut : Certificate := {{
  frontierId := "{DYNAMIC_FRONTIER_ID}"
  sourceTargetId := {DYNAMIC_SOURCE_TARGET_ID}
  incomingGuards := [{dynamic_guards}]
}}

theorem generatedDynamicCutChecked :
    generatedDynamicCut.checked generatedContext = true := by
  decide +kernel

def generatedDynamicCutAuthority :
    CheckedCertificate generatedContext := {{
  decodedAuthority := {_DECODED_AUTHORITY_NAME}
  certificate := generatedDynamicCut
  checked := generatedDynamicCutChecked
}}

def generatedFrontierInventory : FrontierInventory := {{
  frontiers := [
    {{ stableId := "{STACK_FRONTIER_ID}", kind := .stackFinite,
      sourceTargetId := {STACK_SOURCE_TARGET_ID} }},
    {{ stableId := "{CONSTRUCTOR_FRONTIER_ID}", kind := .indexedGuarded,
      sourceTargetId := {CONSTRUCTOR_SOURCE_TARGET_ID} }},
    {{ stableId := "{DYNAMIC_FRONTIER_ID}", kind := .dynamicGuarded,
      sourceTargetId := {DYNAMIC_SOURCE_TARGET_ID} }}
  ]
}}

theorem generatedFrontierInventoryChecked :
    generatedFrontierInventory.checked
      generatedStackRouteAuthority.route.stableId
      generatedConstructorCutAuthority.certificate.frontierId
      generatedDynamicCutAuthority.certificate.frontierId
      generatedStackAuthority.static.claim.site.sourceTargetId
      generatedConstructorAuthority.site.sourceTargetId
      generatedDynamicSite.site.sourceTargetId = true := by
  decide +kernel

def StableFrontierIdsExact : Prop :=
    [generatedStackRouteAuthority.route.stableId,
      generatedConstructorCutAuthority.certificate.frontierId,
      generatedDynamicCutAuthority.certificate.frontierId] =
    ["{STACK_FRONTIER_ID}", "{CONSTRUCTOR_FRONTIER_ID}",
      "{DYNAMIC_FRONTIER_ID}"]

theorem generatedStableFrontierIdsExact : StableFrontierIdsExact := by
  decide +kernel

def FrontierSourcesExact : Prop :=
    [generatedStackAuthority.static.claim.site.sourceTargetId,
      generatedConstructorAuthority.site.sourceTargetId,
      generatedDynamicSite.site.sourceTargetId] =
    [{STACK_SOURCE_TARGET_ID}, {CONSTRUCTOR_SOURCE_TARGET_ID},
      {DYNAMIC_SOURCE_TARGET_ID}]

theorem generatedFrontierSourcesExact : FrontierSourcesExact := by
  decide +kernel

theorem generatedRootExclusionChecked :
    rootExclusionChecked generatedStackRouteAuthority
      generatedConstructorCutAuthority generatedDynamicCutAuthority
      Requirements.generatedLaunch.rootTargetId = true := by
  decide +kernel

def ConstructorRootedEvidenceExact : Prop :=
    generatedConstructorRootedAuthority.certificate.sccTargetIds.contains
        {CONSTRUCTOR_SOURCE_TARGET_ID} = true /\\
      {rooted_members}

theorem generatedConstructorRootedEvidenceExact :
    ConstructorRootedEvidenceExact := by
  decide +kernel

noncomputable def generatedStackSeed :
    CheckedStackCarryRouteSeedValue generatedContext
      generatedStackRouteAuthority.graph generatedStackRouteAuthority.route
      generatedStackAuthority generatedStackRouteAuthority.route.targetFact :=
  checkedStackCarryRouteSeedValue_of_relocatedOrigin
    (Route.checked_of_exactChecked generatedContext
      generatedStackRouteAuthority.graph generatedStackRouteAuthority.route
      generatedStackRouteAuthority.checked)
    (by decide +kernel)
    (by decide +kernel)
    (by decide +kernel)
    .esp
    (.add 32)
    (by decide +kernel)
    (by decide +kernel)

def generatedTarget292StackWindow : StackWindowPair := {{
  rangeId := 0
  originalRegister := .esp
  candidateRegister := .esp
  bytesBelow := 0
  bytesAbove := 36
}}

theorem generatedTarget292StackRangeChecked :
    finiteOriginCallerFrameStackRangeChecked
      generatedStackTransfer{target_transfer_index}Authority generatedStackSeed
      generatedTarget292StackWindow 32 = true := by
  decide +kernel

def generatedTarget292CallContract :=
  {plan.stack_target_contract_name}

/-- The checked finite-origin execution retained by the selected mixed
component supplies both the 292-to-293 route transfer and the canonical
[ESP+32, ESP+36) stack-range witness. -/
noncomputable def generatedTarget292StackRangeWitness
    {{originalProgram summaryCandidateProgram : DecodedWorldProgram}}
    (actual : ActualFiniteOriginCallReturnExecution
      generatedTarget292CallContract.entry originalProgram
      summaryCandidateProgram) :
    CheckedFiniteOriginCallerFrameStackRangeWitness
      generatedStackTransfer{target_transfer_index}Authority actual
      generatedStackSeed :=
  checkedFiniteOriginCallerFrameStackRangeWitness_of_checked
    generatedStackTransfer{target_transfer_index}Authority generatedStackSeed
      generatedTarget292StackWindow 32 generatedTarget292StackRangeChecked
      actual

noncomputable def generatedTarget292SelectedExecution
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{contract : MixedRelationContract}}
    {{reachabilityTargetIds : List Nat}}
    {{base : MixedExecutionInvariant reachabilityTargetIds contract}}
    {{originalProgram summaryCandidateProgram : DecodedWorldProgram}}
    (actual : ActualFiniteOriginCallReturnExecution
      generatedTarget292CallContract.entry originalProgram
      summaryCandidateProgram)
    {{originalBefore : WorldExecution}}
    {{candidateBefore : NativeWorldExecution}}
    (chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore)
    (sourceAt :
      originalExecutionAtTargetId
        generatedStackTransfer{target_transfer_index}Authority.transfer.sourceTargetId
        originalBefore)
    (targetAt :
      originalExecutionAtTargetId
        generatedStackTransfer{target_transfer_index}Authority.transfer.targetTargetId
        chunk.originalAfter)
    (sourceMachineExact :
      originalExecutionMachine? originalBefore =
        some actual.sourceOriginal.state)
    (targetMachineExact :
      originalExecutionMachine? chunk.originalAfter =
        some actual.originalExit.state)
    (sourceFact :
      CheckedRouteTransferAuthority.SourceFactHolds
        (originalContext := generatedContext)
        (.finiteFrame
          generatedStackTransfer{target_transfer_index}Authority)
        actual.sourceOriginal.state) :
    CheckedSelectedRouteTransferExecution generatedStackTransferInventory
      originalBefore candidateBefore chunk :=
  CheckedSelectedRouteTransferExecution.ofFiniteFrame
    (inventory := generatedStackTransferInventory)
    {target_transfer_index}
    generatedStackTransfer{target_transfer_index}Authority
    generatedStackTransfer{target_transfer_index}SelectedAuthorityExact
    actual chunk sourceAt targetAt sourceMachineExact targetMachineExact
    sourceFact

/-- This bundle is the complete authority currently derivable from the four
input artifacts. Operational route executions remain attached to the exact
classifier-selected chunks; their authority indices and target-292 stack
window are checked here without accepting endpoints or status fields. -/
structure CheckedArtifactBundle : Prop where
  constructorCutChecked :
    generatedConstructorCut.checked generatedContext = true
  dynamicCutChecked :
    generatedDynamicCut.checked generatedContext = true
  frontierInventoryChecked :
    generatedFrontierInventory.checked
      generatedStackRouteAuthority.route.stableId
      generatedConstructorCutAuthority.certificate.frontierId
      generatedDynamicCutAuthority.certificate.frontierId
      generatedStackAuthority.static.claim.site.sourceTargetId
      generatedConstructorAuthority.site.sourceTargetId
      generatedDynamicSite.site.sourceTargetId = true
  stableFrontierIdsExact : StableFrontierIdsExact
  frontierSourcesExact : FrontierSourcesExact
  rootExclusionChecked :
    rootExclusionChecked generatedStackRouteAuthority
      generatedConstructorCutAuthority generatedDynamicCutAuthority
      Requirements.generatedLaunch.rootTargetId = true
  constructorRootedEvidenceExact : ConstructorRootedEvidenceExact
  constructorRootedSourceExcluded :
    forall reachable : RootedScannerOperationalReachable
      generatedConstructorRootedExecutionAuthority
      generatedConstructorAuthority.site.sourceTargetId,
      False
  target292StackRangeChecked :
    finiteOriginCallerFrameStackRangeChecked
      generatedStackTransfer{target_transfer_index}Authority generatedStackSeed
      generatedTarget292StackWindow 32 = true

def generatedCheckedArtifactBundle : CheckedArtifactBundle := {{
  constructorCutChecked := generatedConstructorCutChecked
  dynamicCutChecked := generatedDynamicCutChecked
  frontierInventoryChecked := generatedFrontierInventoryChecked
  stableFrontierIdsExact := generatedStableFrontierIdsExact
  frontierSourcesExact := generatedFrontierSourcesExact
  rootExclusionChecked := generatedRootExclusionChecked
  constructorRootedEvidenceExact := generatedConstructorRootedEvidenceExact
  constructorRootedSourceExcluded :=
    generatedConstructorRootedSourceExcluded
  target292StackRangeChecked := generatedTarget292StackRangeChecked
}}

#print axioms generatedConstructorCutChecked
#print axioms generatedDynamicCutChecked
#print axioms generatedFrontierInventoryChecked
#print axioms generatedStableFrontierIdsExact
#print axioms generatedRootExclusionChecked
#print axioms generatedConstructorRootedEvidenceExact
#print axioms generatedConstructorRootedSourceExcluded
#print axioms generatedStackSeed
{transfer_axioms}
{selected_authority_axioms}
{selected_execution_axioms}
#print axioms generatedStackTransferInventoryChecked
#print axioms generatedStackTransferInventory
#print axioms generatedTarget292StackRangeChecked
#print axioms generatedTarget292StackRangeWitness
#print axioms generatedTarget292SelectedExecution
#print axioms generatedCheckedArtifactBundle

end StageA.GeneratedRelational.GNUHelloRuntimeIndirectComposition
"""


def write_gnu_hello_runtime_indirect_composition_module(
    output: Path | str,
    plan: GNUHelloRuntimeIndirectCompositionPlan,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        gnu_hello_runtime_indirect_composition_source(plan),
        encoding="utf-8",
    )
    return path


__all__ = [
    "CONSTRUCTOR_FRONTIER_ID",
    "CONSTRUCTOR_INCOMING",
    "CONSTRUCTOR_SOURCE_TARGET_ID",
    "DYNAMIC_FRONTIER_ID",
    "DYNAMIC_INCOMING",
    "DYNAMIC_SOURCE_TARGET_ID",
    "GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_FORMAT",
    "GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_LEAN_FILENAME",
    "GNUHelloRuntimeIndirectCompositionGenerationError",
    "GNUHelloRuntimeIndirectCompositionPlan",
    "RuntimeIndirectEvidenceGap",
    "STACK_FRONTIER_ID",
    "STACK_SITE_STABLE_ID",
    "STACK_SOURCE_TARGET_ID",
    "gnu_hello_runtime_indirect_composition_source",
    "plan_gnu_hello_runtime_indirect_composition",
    "write_gnu_hello_runtime_indirect_composition_module",
]
