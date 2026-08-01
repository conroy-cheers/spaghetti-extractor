"""Emit the concrete GNU hello runtime-indirect composition module.

This adapter is intentionally fixture-specific. It binds the generic
runtime-indirect kernel to the exact GNU hello artifacts. The generated Lean
module imports the canonical GNU acceptance requirements and the checked
runtime-value-carry modules directly; it never accepts names of proof terms
from JSON.

The callback stack source is closed by binding every route edge to the selected
component's computed execution and deriving its stack range from the
finite-origin call's checked source relation. The plan records the remaining
constructor and dynamic-slot obligations without manufacturing closure from
report status or caller-supplied terms.
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

DYNAMIC_HEAD_SLOT_RVA = 0x30364

_STACK_SOURCE_RVA = 0x2033
_STACK_SUCCESSOR_RVA = 0x2040
_CONSTRUCTOR_SOURCE_RVA = 0xA220
_CONSTRUCTOR_INCOMING_SOURCE_RVAS = (0xA20F, 0xA227)
_DYNAMIC_SOURCE_RVA = 0xAB86
_DYNAMIC_INCOMING_SOURCE_RVAS = (0xAB82,)
_DYNAMIC_GUARD_SOURCE_RVA = 0xAB54
_DYNAMIC_GUARD_NONZERO_RVA = 0xAB61

STACK_FRONTIER_ID = "gnu.original.callback-stack-slot"
STACK_SITE_STABLE_ID = "stack-dynamic-8174534cc03bae3851d1"
CONSTRUCTOR_FRONTIER_ID = "stack-dynamic-c50fbcca964899c32624"
DYNAMIC_FRONTIER_ID = "stack-dynamic-ca2114f8215f7e5a27bd"

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


@dataclass(frozen=True)
class RuntimeIndirectCheckedEvidence:
    source_target_id: int
    evidence_kind: str
    lean_terms: tuple[str, ...]


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


def _checked_static_evidence(
    *,
    stack_source_target_id: int,
    constructor_source_target_id: int,
    dynamic_source_target_id: int,
) -> tuple[RuntimeIndirectCheckedEvidence, ...]:
    return (
        RuntimeIndirectCheckedEvidence(
            source_target_id=stack_source_target_id,
            evidence_kind="selected-stack-route-and-frame-window",
            lean_terms=(
                "generatedStackTransferInventory",
                "generatedTarget292StackRangeWitness",
                "generatedTarget292SelectedExecution",
            ),
        ),
        RuntimeIndirectCheckedEvidence(
            source_target_id=constructor_source_target_id,
            evidence_kind="rooted-scanner-scc-execution-exclusion",
            lean_terms=(
                "generatedConstructorRootedExecutionAuthority",
                "generatedConstructorRootedSourceExcluded",
                "generatedConstructorSelectedSourceUninhabited",
                "generatedConstructorSelectedComposition",
            ),
        ),
        RuntimeIndirectCheckedEvidence(
            source_target_id=dynamic_source_target_id,
            evidence_kind="launch-zero-and-decoded-nonzero-guard",
            lean_terms=(
                "generatedDynamicHeadInitialZeroChecked",
                "generatedDynamicGuardEdgeChecked",
                "generatedDynamicSelectedSourceUninhabited",
                "generatedDynamicSelectedComposition",
            ),
        ),
    )


def _remaining_operational_frontiers(
    *,
    constructor_source_target_id: int,
    dynamic_source_target_id: int,
) -> tuple[RuntimeIndirectEvidenceGap, ...]:
    """Return only premises that the imported checked artifacts do not prove."""

    return (
        RuntimeIndirectEvidenceGap(
            frontier_id=CONSTRUCTOR_FRONTIER_ID,
            source_target_id=constructor_source_target_id,
            extractor_field=(
                "mixed_component.rooted_scanner_selected_projection"
            ),
            checker_type="CheckedRootedScannerSelectedSourceProjection",
            reason=(
                "the exact scanner decoder, zero/bypass semantics, rooted SCC, "
                "execution authority, and source-exclusion theorem are checked; "
                "the remaining term must project every classifier-selected "
                "source state into RootedScannerOperationalReachable, including "
                "the selector-to-bypass scanner macro-step"
            ),
        ),
        RuntimeIndirectEvidenceGap(
            frontier_id=DYNAMIC_FRONTIER_ID,
            source_target_id=dynamic_source_target_id,
            extractor_field=(
                "reachable_static_slot.selected_zero_guard_projection"
            ),
            checker_type="CheckedGuardedZeroSelectedSourceProjection",
            reason=(
                "Lean checks the BSS head at RVA 0x30364 is launch-zero and "
                "that the guard site reaches the destructor path only through "
                "its nonzero guard; the remaining term must provide a "
                "CompleteWriteFootprintTrace for each admitted selected source "
                "and prove that reaching the dynamic source entails selection "
                "of that guarded edge"
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
    expected_source_target_id: int,
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
        expected_source_target_id
    ):
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{mode} site does not resolve to its GNU hello RVA"
        )
    if _string(row.get("stable_id"), f"{mode} stable ID") != stable_id:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"{mode} site has the wrong stable ID"
        )
    return index, row


def _target_id_at_rva(
    graph: OriginalCutpointGraphIR,
    rva: int,
    field: str,
) -> int:
    matches = [
        region.target_id
        for region in graph.regions
        if rva == region.rva or rva in region.alias_rvas
    ]
    if len(matches) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"GNU hello {field} RVA 0x{rva:x} does not resolve uniquely"
        )
    return matches[0]


def _decoded_incoming_from_rvas(
    graph: OriginalCutpointGraphIR,
    *,
    target_id: int,
    source_rvas: tuple[int, ...],
    field: str,
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
    expected = tuple(sorted(
        (_target_id_at_rva(graph, rva, f"{field} incoming source"), target_id)
        for rva in source_rvas
    ))
    if pairs != expected:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            f"GNU hello {field} incoming inventory does not match its RVAs"
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
    stack_source_target_id: int
    stack_successor_target_id: int
    constructor_source_target_id: int
    dynamic_source_target_id: int
    dynamic_guard_source_target_id: int
    dynamic_guard_nonzero_target_id: int
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
    checked_evidence: tuple[RuntimeIndirectCheckedEvidence, ...]
    evidence_gaps: tuple[RuntimeIndirectEvidenceGap, ...]

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
            ("stack source target ID", self.stack_source_target_id),
            ("stack successor target ID", self.stack_successor_target_id),
            (
                "constructor source target ID",
                self.constructor_source_target_id,
            ),
            ("dynamic source target ID", self.dynamic_source_target_id),
            (
                "dynamic guard source target ID",
                self.dynamic_guard_source_target_id,
            ),
            (
                "dynamic guard nonzero target ID",
                self.dynamic_guard_nonzero_target_id,
            ),
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
                "stack-source transfer index is outside the exact route"
            )
        if (
            self.stack_transfer_authority_constructors[
                self.stack_target_transfer_index
            ]
            != "finiteFrame"
        ):
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "stack-source transfer is not a finite-origin "
                "caller-frame edge"
            )
        _lean_name(
            self.stack_target_contract_name,
            "stack-source caller-frame contract",
        )
        expected = {
            self.constructor_source_target_id: self.constructor_incoming,
            self.dynamic_source_target_id: self.dynamic_incoming,
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
        expected_evidence = _checked_static_evidence(
            stack_source_target_id=self.stack_source_target_id,
            constructor_source_target_id=self.constructor_source_target_id,
            dynamic_source_target_id=self.dynamic_source_target_id,
        )
        if self.checked_evidence != expected_evidence:
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "runtime-indirect checked evidence is not canonical"
            )
        expected_gaps = _remaining_operational_frontiers(
            constructor_source_target_id=self.constructor_source_target_id,
            dynamic_source_target_id=self.dynamic_source_target_id,
        )
        if self.evidence_gaps != expected_gaps:
            raise GNUHelloRuntimeIndirectCompositionGenerationError(
                "runtime-indirect evidence gaps are not canonical"
            )
        for gap in self.evidence_gaps:
            if gap.source_target_id not in {
                self.stack_source_target_id,
                self.constructor_source_target_id,
                self.dynamic_source_target_id,
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
    stack_source_target_id = _target_id_at_rva(
        graph, _STACK_SOURCE_RVA, "stack source"
    )
    stack_successor_target_id = _target_id_at_rva(
        graph, _STACK_SUCCESSOR_RVA, "stack successor"
    )
    constructor_source_target_id = _target_id_at_rva(
        graph, _CONSTRUCTOR_SOURCE_RVA, "constructor source"
    )
    dynamic_source_target_id = _target_id_at_rva(
        graph, _DYNAMIC_SOURCE_RVA, "dynamic source"
    )
    dynamic_guard_source_target_id = _target_id_at_rva(
        graph, _DYNAMIC_GUARD_SOURCE_RVA, "dynamic guard source"
    )
    dynamic_guard_nonzero_target_id = _target_id_at_rva(
        graph, _DYNAMIC_GUARD_NONZERO_RVA, "dynamic guard nonzero target"
    )
    stack_site_index, stack_site = _site(
        closure,
        mode="finite_stack_target",
        expected_source_target_id=stack_source_target_id,
        stable_id=STACK_SITE_STABLE_ID,
    )
    constructor_site_index, _constructor_site = _site(
        closure,
        mode="empty_indexed_source",
        expected_source_target_id=constructor_source_target_id,
        stable_id=CONSTRUCTOR_FRONTIER_ID,
    )
    dynamic_site_index, _dynamic_site = _site(
        closure,
        mode="uninhabited_dynamic_source",
        expected_source_target_id=dynamic_source_target_id,
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
            target_fact.get("target_id") == stack_source_target_id
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
        if edge[1:] == (
            stack_source_target_id,
            stack_successor_target_id,
        ):
            if (
                authority_key
                != (
                    "call_frame_word_preserve",
                    "checked_finite_origin_call_caller_frame_word_summary",
                )
            ):
                raise GNUHelloRuntimeIndirectCompositionGenerationError(
                    "stack-source route edge has the wrong semantic authority"
                )
            stack_target_transfer_indices.append(transfer_index)
            authority_term = _mapping(
                transfer.get("authority_lean_term"),
                "stack-source route authority Lean term",
            )
            namespace = _lean_name(
                authority_term.get("namespace"),
                "stack-source route authority namespace",
            )
            symbol = _lean_name(
                authority_term.get("symbol"),
                "stack-source route authority symbol",
            )
            if (
                symbol
                != "generatedCheckedFiniteOriginCallCallerFrameWordControlContract"
            ):
                raise GNUHelloRuntimeIndirectCompositionGenerationError(
                    "stack-source route authority has the wrong contract symbol"
                )
            stack_target_contract_names.append(f"{namespace}.{symbol}")
    if len(stack_target_transfer_indices) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello route has no unique stack-source-to-successor transfer"
        )
    if len(stack_target_contract_names) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello route has no unique stack-source caller-frame contract"
        )

    rooted_entries = _rows(rooted.get("entries"), "rooted entries")
    rooted_matches = [
        _mapping(raw, f"rooted entry {index}")
        for index, raw in enumerate(rooted_entries)
        if (
            isinstance(raw, Mapping)
            and raw.get("stable_id") == CONSTRUCTOR_FRONTIER_ID
        )
    ]
    if len(rooted_matches) != 1:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello constructor has no unique rooted certificate"
        )
    rooted_entry = rooted_matches[0]
    if rooted_entry.get("source_target_id") != constructor_source_target_id:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "rooted constructor certificate does not resolve to its "
            "GNU hello RVA"
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

    constructor_incoming = _decoded_incoming_from_rvas(
        graph,
        target_id=constructor_source_target_id,
        source_rvas=_CONSTRUCTOR_INCOMING_SOURCE_RVAS,
        field="constructor",
    )
    dynamic_incoming = _decoded_incoming_from_rvas(
        graph,
        target_id=dynamic_source_target_id,
        source_rvas=_DYNAMIC_INCOMING_SOURCE_RVAS,
        field="dynamic",
    )
    graph_pairs = {
        (edge.source_target_id, edge.target_target_id)
        for edge in graph.edges
    }
    if (
        dynamic_guard_source_target_id,
        dynamic_guard_nonzero_target_id,
    ) not in graph_pairs:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello dynamic guarded predecessor edge is absent"
        )
    if dynamic_guard_nonzero_target_id not in graph.reachable_target_ids:
        raise GNUHelloRuntimeIndirectCompositionGenerationError(
            "GNU hello dynamic guarded predecessor is not reachable"
        )
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
        stack_source_target_id=stack_source_target_id,
        stack_successor_target_id=stack_successor_target_id,
        constructor_source_target_id=constructor_source_target_id,
        dynamic_source_target_id=dynamic_source_target_id,
        dynamic_guard_source_target_id=dynamic_guard_source_target_id,
        dynamic_guard_nonzero_target_id=dynamic_guard_nonzero_target_id,
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
        checked_evidence=_checked_static_evidence(
            stack_source_target_id=stack_source_target_id,
            constructor_source_target_id=constructor_source_target_id,
            dynamic_source_target_id=dynamic_source_target_id,
        ),
        evidence_gaps=_remaining_operational_frontiers(
            constructor_source_target_id=constructor_source_target_id,
            dynamic_source_target_id=dynamic_source_target_id,
        ),
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
open StageA.Relational.ReachableStaticPointerSlot
open StageA.Relational.RuntimeIndirectComposition
open StageA.Relational.RuntimeIndirectEffects
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

/-- The imported rooted scanner authority closes the constructor source once
the selected mixed-component invariant supplies the operational projection.
The projection is the only remaining premise; no endpoint or reachability
status is accepted here. -/
noncomputable def generatedConstructorSelectedSourceUninhabited
    {{originalAuthority : ExactOriginalDecodedAuthority generatedContext}}
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{candidateAuthority : ExactNativeCandidateAuthority candidate}}
    {{contract : MixedRelationContract}}
    {{launch : PE32ConsoleLaunchV2}}
    {{originalRoot :
      DirectExactOriginalDecodedLaunchRoot generatedContext launch}}
    {{reachability : ExactOriginalDecodedReachability generatedContext
      originalAuthority launch originalRoot}}
    {{candidateRootRva : Nat}}
    {{program : CompiledKernelProgram}}
    {{abi : KernelABIRelation}}
    {{dispatches : RelationalWorld -> KernelDispatchRelation}}
    {{invariant : MixedExecutionInvariant reachability.targetIds contract}}
    {{cases : CheckedMixedKernelComponentCases generatedContext
      originalAuthority original candidate candidateAuthority contract launch
      originalRoot reachability candidateRootRva program abi dispatches
      invariant}}
    {{closure : CheckedMixedKernelSelectedInvariantClosure cases}}
    (projection : CheckedRootedScannerSelectedSourceProjection closure
      generatedConstructorRootedExecutionAuthority) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      closure.strengthenedInvariant
      generatedConstructorAuthority.site.sourceTargetId :=
  projection.sourceUninhabited

noncomputable def generatedConstructorSelectedComposition
    {{originalAuthority : ExactOriginalDecodedAuthority generatedContext}}
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{candidateAuthority : ExactNativeCandidateAuthority candidate}}
    {{contract : MixedRelationContract}}
    {{launch : PE32ConsoleLaunchV2}}
    {{originalRoot :
      DirectExactOriginalDecodedLaunchRoot generatedContext launch}}
    {{reachability : ExactOriginalDecodedReachability generatedContext
      originalAuthority launch originalRoot}}
    {{candidateRootRva : Nat}}
    {{program : CompiledKernelProgram}}
    {{abi : KernelABIRelation}}
    {{dispatches : RelationalWorld -> KernelDispatchRelation}}
    {{invariant : MixedExecutionInvariant reachability.targetIds contract}}
    {{cases : CheckedMixedKernelComponentCases generatedContext
      originalAuthority original candidate candidateAuthority contract launch
      originalRoot reachability candidateRootRva program abi dispatches
      invariant}}
    {{closure : CheckedMixedKernelSelectedInvariantClosure cases}}
    (projection : CheckedRootedScannerSelectedSourceProjection closure
      generatedConstructorRootedExecutionAuthority) :
    IndexedTableMixedOriginalComposition generatedConstructorAuthority
      closure.strengthenedInvariant :=
  .unreachable (generatedConstructorSelectedSourceUninhabited projection)

/-- Generic history-sensitive bridge for a zero-initialized word guarding a
later source. Static checking establishes the exact slot and branch shape;
the selected invariant must provide a complete write trace and show that
reaching the later source entails selection of the nonzero edge. -/
structure CheckedGuardedZeroSelectedSourceProjection
    {{originalAuthority : ExactOriginalDecodedAuthority generatedContext}}
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{candidateAuthority : ExactNativeCandidateAuthority candidate}}
    {{contract : MixedRelationContract}}
    {{launch : PE32ConsoleLaunchV2}}
    {{originalRoot :
      DirectExactOriginalDecodedLaunchRoot generatedContext launch}}
    {{reachability : ExactOriginalDecodedReachability generatedContext
      originalAuthority launch originalRoot}}
    {{candidateRootRva : Nat}}
    {{program : CompiledKernelProgram}}
    {{abi : KernelABIRelation}}
    {{dispatches : RelationalWorld -> KernelDispatchRelation}}
    {{invariant : MixedExecutionInvariant reachability.targetIds contract}}
    {{cases : CheckedMixedKernelComponentCases generatedContext
      originalAuthority original candidate candidateAuthority contract launch
      originalRoot reachability candidateRootRva program abi dispatches
      invariant}}
    (closure : CheckedMixedKernelSelectedInvariantClosure cases)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (reachableTargetIds : List Nat)
    (guardedEdge : ReachableStaticPointerSlot.GuardedNonzeroEdge)
    (guardBehavior : NormalizedSymbolicBehavior)
    (sourceTargetId : Nat) : Prop where
  certificateChecked : certificate.checked generatedContext = true
  noTargets : certificate.allowedTargetIds = .exact []
  reachableExact : certificate.reachableTargetIds = .exact reachableTargetIds
  guardNormalized : normalizedRegionBehavior? generatedContext
    guardedEdge.sourceTargetId = some guardBehavior
  guardChecked : guardedEdge.checked generatedContext certificate
    reachableTargetIds = true
  project : forall originalExecution candidateExecution,
    closure.strengthenedInvariant.holds originalExecution candidateExecution ->
      originalExecutionAtTargetId sourceTargetId originalExecution ->
      exists initialMemory guardState,
        LaunchSlotInitialized generatedContext certificate initialMemory /\
          CompleteWriteFootprintTrace generatedContext certificate
            generatedCarrierContext false initialMemory guardState.memory /\
          selectedBranchTarget guardState guardBehavior.outcome =
            some guardedEdge.nonzeroTargetId

theorem CheckedGuardedZeroSelectedSourceProjection.sourceUninhabited
    {{originalAuthority : ExactOriginalDecodedAuthority generatedContext}}
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{candidateAuthority : ExactNativeCandidateAuthority candidate}}
    {{contract : MixedRelationContract}}
    {{launch : PE32ConsoleLaunchV2}}
    {{originalRoot :
      DirectExactOriginalDecodedLaunchRoot generatedContext launch}}
    {{reachability : ExactOriginalDecodedReachability generatedContext
      originalAuthority launch originalRoot}}
    {{candidateRootRva : Nat}}
    {{program : CompiledKernelProgram}}
    {{abi : KernelABIRelation}}
    {{dispatches : RelationalWorld -> KernelDispatchRelation}}
    {{invariant : MixedExecutionInvariant reachability.targetIds contract}}
    {{cases : CheckedMixedKernelComponentCases generatedContext
      originalAuthority original candidate candidateAuthority contract launch
      originalRoot reachability candidateRootRva program abi dispatches
      invariant}}
    {{closure : CheckedMixedKernelSelectedInvariantClosure cases}}
    {{certificate : ReachableStaticPointerSlot.Certificate}}
    {{reachableTargetIds : List Nat}}
    {{guardedEdge : ReachableStaticPointerSlot.GuardedNonzeroEdge}}
    {{guardBehavior : NormalizedSymbolicBehavior}}
    {{sourceTargetId : Nat}}
    (projection : CheckedGuardedZeroSelectedSourceProjection closure
      certificate reachableTargetIds guardedEdge guardBehavior sourceTargetId) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      closure.strengthenedInvariant sourceTargetId := by
  rintro ⟨world, state, reached⟩
  rcases reached with
    ⟨calls, eventIndex, candidateExecution, related⟩ |
    ⟨calls, eventIndex, callbacks, candidateExecution, related⟩
  · rcases projection.project
        (.running sourceTargetId state calls eventIndex world)
        candidateExecution related.2 rfl with
      ⟨initialMemory, guardState, initialized, trace, selected⟩
    have zero := completeWriteFootprintTrace_from_launch_is_zero
      projection.certificateChecked projection.noTargets initialized trace
    exact (guardedEdge.not_selected_when_zero projection.guardChecked
      projection.guardNormalized guardState zero) selected
  · rcases projection.project
        (.callbackRunning sourceTargetId state calls eventIndex world callbacks)
        candidateExecution related.2 rfl with
      ⟨initialMemory, guardState, initialized, trace, selected⟩
    have zero := completeWriteFootprintTrace_from_launch_is_zero
      projection.certificateChecked projection.noTargets initialized trace
    exact (guardedEdge.not_selected_when_zero projection.guardChecked
      projection.guardNormalized guardState zero) selected

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
  sourceTargetId := {plan.constructor_source_target_id}
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
  sourceTargetId := {plan.dynamic_source_target_id}
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

def generatedDynamicHeadRva : Nat := {DYNAMIC_HEAD_SLOT_RVA}

/-- This shape value is not a full writable-slot certificate. It exists only
to make the PE-backed launch-zero and decoded-guard checks independent of the
still-missing complete write trace. -/
def generatedDynamicHeadShape : ReachableStaticPointerSlot.Certificate := {{
  slotRva := generatedDynamicHeadRva
  reachableTargetIds := .exact Requirements.generatedReachability.targetIds
  allowedTargetIds := .unknown
  regions := .unknown
  guardedNonzeroEdges := .unknown
  indirectSlotSites := .unknown
  aliases := .unknown
}}

theorem generatedDynamicHeadInitialZeroChecked :
    initialZeroChecked generatedContext generatedDynamicHeadShape = true := by
  decide +kernel

def generatedDynamicGuardEdge :
    ReachableStaticPointerSlot.GuardedNonzeroEdge := {{
  sourceTargetId := {plan.dynamic_guard_source_target_id}
  nonzeroTargetId := {plan.dynamic_guard_nonzero_target_id}
}}

theorem generatedDynamicGuardEdgeChecked :
    generatedDynamicGuardEdge.checked generatedContext
      generatedDynamicHeadShape Requirements.generatedReachability.targetIds =
        true := by
  decide +kernel

/-- The checked zero-word/guard projection rules out the dynamic source and
constructs the standard composition. A complete certificate and selected
history projection remain explicit inputs. -/
noncomputable def generatedDynamicSelectedSourceUninhabited
    {{originalAuthority : ExactOriginalDecodedAuthority generatedContext}}
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{candidateAuthority : ExactNativeCandidateAuthority candidate}}
    {{contract : MixedRelationContract}}
    {{launch : PE32ConsoleLaunchV2}}
    {{originalRoot :
      DirectExactOriginalDecodedLaunchRoot generatedContext launch}}
    {{reachability : ExactOriginalDecodedReachability generatedContext
      originalAuthority launch originalRoot}}
    {{candidateRootRva : Nat}}
    {{program : CompiledKernelProgram}}
    {{abi : KernelABIRelation}}
    {{dispatches : RelationalWorld -> KernelDispatchRelation}}
    {{invariant : MixedExecutionInvariant reachability.targetIds contract}}
    {{cases : CheckedMixedKernelComponentCases generatedContext
      originalAuthority original candidate candidateAuthority contract launch
      originalRoot reachability candidateRootRva program abi dispatches
      invariant}}
    {{closure : CheckedMixedKernelSelectedInvariantClosure cases}}
    {{certificate : ReachableStaticPointerSlot.Certificate}}
    {{reachableTargetIds : List Nat}}
    {{guardBehavior : NormalizedSymbolicBehavior}}
    (slotExact : certificate.slotRva = generatedDynamicHeadRva)
    (projection : CheckedGuardedZeroSelectedSourceProjection closure
      certificate reachableTargetIds generatedDynamicGuardEdge guardBehavior
      generatedDynamicSite.site.sourceTargetId) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      closure.strengthenedInvariant generatedDynamicSite.site.sourceTargetId := by
  have _slotExact := slotExact
  exact projection.sourceUninhabited

noncomputable def generatedDynamicSelectedComposition
    {{originalAuthority : ExactOriginalDecodedAuthority generatedContext}}
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{candidateAuthority : ExactNativeCandidateAuthority candidate}}
    {{contract : MixedRelationContract}}
    {{launch : PE32ConsoleLaunchV2}}
    {{originalRoot :
      DirectExactOriginalDecodedLaunchRoot generatedContext launch}}
    {{reachability : ExactOriginalDecodedReachability generatedContext
      originalAuthority launch originalRoot}}
    {{candidateRootRva : Nat}}
    {{program : CompiledKernelProgram}}
    {{abi : KernelABIRelation}}
    {{dispatches : RelationalWorld -> KernelDispatchRelation}}
    {{invariant : MixedExecutionInvariant reachability.targetIds contract}}
    {{cases : CheckedMixedKernelComponentCases generatedContext
      originalAuthority original candidate candidateAuthority contract launch
      originalRoot reachability candidateRootRva program abi dispatches
      invariant}}
    {{closure : CheckedMixedKernelSelectedInvariantClosure cases}}
    {{certificate : ReachableStaticPointerSlot.Certificate}}
    {{reachableTargetIds : List Nat}}
    {{guardBehavior : NormalizedSymbolicBehavior}}
    (slotExact : certificate.slotRva = generatedDynamicHeadRva)
    (projection : CheckedGuardedZeroSelectedSourceProjection closure
      certificate reachableTargetIds generatedDynamicGuardEdge guardBehavior
      generatedDynamicSite.site.sourceTargetId) :
    DynamicSourceMixedOriginalComposition generatedDynamicSite
      closure.strengthenedInvariant where
  complete := {{
    sourceUninhabited :=
      generatedDynamicSelectedSourceUninhabited slotExact projection
  }}

def generatedFrontierInventory : FrontierInventory := {{
  frontiers := [
    {{ stableId := "{STACK_FRONTIER_ID}", kind := .stackFinite,
      sourceTargetId := {plan.stack_source_target_id} }},
    {{ stableId := "{CONSTRUCTOR_FRONTIER_ID}", kind := .indexedGuarded,
      sourceTargetId := {plan.constructor_source_target_id} }},
    {{ stableId := "{DYNAMIC_FRONTIER_ID}", kind := .dynamicGuarded,
      sourceTargetId := {plan.dynamic_source_target_id} }}
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
    [{plan.stack_source_target_id}, {plan.constructor_source_target_id},
      {plan.dynamic_source_target_id}]

theorem generatedFrontierSourcesExact : FrontierSourcesExact := by
  decide +kernel

theorem generatedRootExclusionChecked :
    rootExclusionChecked generatedStackRouteAuthority
      generatedConstructorCutAuthority generatedDynamicCutAuthority
      Requirements.generatedLaunch.rootTargetId = true := by
  decide +kernel

def ConstructorRootedEvidenceExact : Prop :=
    generatedConstructorRootedAuthority.certificate.sccTargetIds.contains
        {plan.constructor_source_target_id} = true /\\
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
component supplies both the stack-source route transfer and the canonical
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
classifier-selected chunks; their authority indices and stack-source
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
  dynamicHeadInitialZeroChecked :
    initialZeroChecked generatedContext generatedDynamicHeadShape = true
  dynamicGuardEdgeChecked :
    generatedDynamicGuardEdge.checked generatedContext
      generatedDynamicHeadShape Requirements.generatedReachability.targetIds =
        true
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
  dynamicHeadInitialZeroChecked := generatedDynamicHeadInitialZeroChecked
  dynamicGuardEdgeChecked := generatedDynamicGuardEdgeChecked
  target292StackRangeChecked := generatedTarget292StackRangeChecked
}}

#print axioms generatedConstructorCutChecked
#print axioms generatedDynamicCutChecked
#print axioms generatedFrontierInventoryChecked
#print axioms generatedStableFrontierIdsExact
#print axioms generatedRootExclusionChecked
#print axioms generatedConstructorRootedEvidenceExact
#print axioms generatedConstructorRootedSourceExcluded
#print axioms generatedConstructorSelectedSourceUninhabited
#print axioms generatedConstructorSelectedComposition
#print axioms CheckedGuardedZeroSelectedSourceProjection.sourceUninhabited
#print axioms generatedDynamicHeadInitialZeroChecked
#print axioms generatedDynamicGuardEdgeChecked
#print axioms generatedDynamicSelectedSourceUninhabited
#print axioms generatedDynamicSelectedComposition
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
    "DYNAMIC_FRONTIER_ID",
    "DYNAMIC_HEAD_SLOT_RVA",
    "GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_FORMAT",
    "GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_LEAN_FILENAME",
    "GNUHelloRuntimeIndirectCompositionGenerationError",
    "GNUHelloRuntimeIndirectCompositionPlan",
    "RuntimeIndirectCheckedEvidence",
    "RuntimeIndirectEvidenceGap",
    "STACK_FRONTIER_ID",
    "STACK_SITE_STABLE_ID",
    "gnu_hello_runtime_indirect_composition_source",
    "plan_gnu_hello_runtime_indirect_composition",
    "write_gnu_hello_runtime_indirect_composition_module",
]
