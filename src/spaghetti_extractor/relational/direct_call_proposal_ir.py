"""Hash-bound mixed-original input for direct-call proposal rounds.

The full mixed-original planner is intentionally more expressive than the
direct-call proposal phase needs.  Reconstructing that plan in every proposal
round repeats PE decoding, register dataflow, and rooted-closure work that was
already performed by an upstream phase.  This module projects the stable
facts needed by later rounds into a strict, deterministic artifact.

The artifact is proposal input only.  It neither authorizes an indirect edge
nor replaces the generated Lean checks over exact PE bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import StageAInputError
from ..util import sha256_file
from .original_cutpoint_graph_ir import (
    OriginalCutpointGraphIR,
    original_cutpoint_graph_ir_from_json,
    original_cutpoint_graph_ir_from_plan,
    validate_original_cutpoint_graph_semantic_bindings,
)
from .stack_dynamic_control_ir import (
    StackDynamicControlInput,
    StackDynamicControlRegion,
    StackDynamicControlSite,
    stack_dynamic_control_input_from_plan,
)


DIRECT_CALL_PROPOSAL_IR_FORMAT = "stage-a-direct-call-proposal-ir-v2"
DIRECT_CALL_PROPOSAL_IR_INPUTS = (
    "base_plan",
    "load_image_contract",
    "machine_import_report",
    "original_pe",
    "reference_contract",
    "state_machine",
    "writable_slot_authority_report",
)

_INPUT_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_U32_LIMIT = 1 << 32
_IA32_REGISTERS = frozenset(
    ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
)


class DirectCallProposalIRError(StageAInputError):
    """The cached direct-call proposal input is malformed or stale."""


@dataclass(frozen=True)
class DirectCallSummaryRequest:
    """One internal call and the machine values required across it.

    Caller-frame offsets are measured from ESP immediately before the call.
    The summary planner accounts for the architectural return-address push
    when it constructs the callee-entry certificate.
    """

    callsite_rva: int
    registers: tuple[str, ...]
    caller_rva: int | None = None
    caller_frame_word_offsets: tuple[int, ...] = ()

    def checked(self) -> "DirectCallSummaryRequest":
        _u32(self.callsite_rva, "request.callsite_rva")
        if self.caller_rva is not None:
            _u32(self.caller_rva, "request.caller_rva")
        if not self.registers and not self.caller_frame_word_offsets:
            raise DirectCallProposalIRError(
                "request must name at least one register or caller-frame word"
            )
        if len(set(self.registers)) != len(self.registers):
            raise DirectCallProposalIRError(
                "request.registers contains duplicates"
            )
        for register in self.registers:
            if register not in _IA32_REGISTERS:
                raise DirectCallProposalIRError(
                    f"request register {register!r} is not a supported "
                    "IA-32 register"
                )
        if (
            len(set(self.caller_frame_word_offsets))
            != len(self.caller_frame_word_offsets)
        ):
            raise DirectCallProposalIRError(
                "request.caller_frame_word_offsets contains duplicates"
            )
        for index, offset in enumerate(self.caller_frame_word_offsets):
            _u32(
                offset,
                f"request.caller_frame_word_offsets[{index}]",
            )
            if offset > 65528:
                raise DirectCallProposalIRError(
                    "request caller-frame word must remain within the "
                    "checked callee-frame offset bound after the call push"
                )
        return self


def _u32(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < _U32_LIMIT
    ):
        raise DirectCallProposalIRError(
            f"{field} must be an unsigned PE32 word"
        )
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DirectCallProposalIRError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DirectCallProposalIRError(f"{field} must be an object")
    return value


def _rows(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise DirectCallProposalIRError(f"{field} must be a list")
    return value


def _canonical_plan_sha256(plan: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            plan.to_json(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, order=True)
class DirectCallProposalRegion:
    target_id: int
    rva: int
    alias_rvas: tuple[int, ...] = ()


@dataclass(frozen=True, order=True)
class DirectCallProposalSite:
    callsite_rva: int
    source_rva: int
    source_target_id: int
    continuation_rva: int
    continuation_target_id: int
    edge_index: int


@dataclass(frozen=True, order=True)
class DirectCallProposalEdge:
    edge_index: int
    source_target_id: int
    target_target_id: int


@dataclass(frozen=True)
class DirectCallProposalIR:
    input_sha256s: Mapping[str, str]
    authority_base_plan_sha256: str
    consumed_plan_sha256: str
    original_cutpoint_graph: OriginalCutpointGraphIR
    regions: tuple[DirectCallProposalRegion, ...]
    direct_call_sites: tuple[DirectCallProposalSite, ...]
    call_return_edges: tuple[DirectCallProposalEdge, ...]
    prebound_finite_origin_call_instruction_rvas: tuple[int, ...]
    stack_dynamic_control: StackDynamicControlInput

    @property
    def target_rvas(self) -> dict[int, int]:
        return {region.target_id: region.rva for region in self.regions}

    @property
    def target_ids_by_rva(self) -> dict[int, int]:
        return {
            rva: region.target_id
            for region in self.regions
            for rva in (region.rva, *region.alias_rvas)
        }

    @property
    def direct_call_sites_by_rva(self) -> dict[int, DirectCallProposalSite]:
        return {site.callsite_rva: site for site in self.direct_call_sites}

    def call_return_edge_index(
        self, source_target_id: int, target_target_id: int
    ) -> int:
        matches = [
            edge.edge_index
            for edge in self.call_return_edges
            if edge.source_target_id == source_target_id
            and edge.target_target_id == target_target_id
        ]
        if len(matches) != 1:
            raise DirectCallProposalIRError(
                "direct-call proposal IR has no unique call-return edge for "
                f"{source_target_id}->{target_target_id}"
            )
        return matches[0]

    def to_json(self) -> dict[str, Any]:
        return {
            "format": DIRECT_CALL_PROPOSAL_IR_FORMAT,
            "inputs": dict(sorted(self.input_sha256s.items())),
            "plans": {
                "authority_base_plan_sha256": (
                    self.authority_base_plan_sha256
                ),
                "consumed_plan_sha256": self.consumed_plan_sha256,
            },
            "original_cutpoint_graph": self.original_cutpoint_graph.to_json(),
            "regions": [
                {
                    "alias_rvas": list(region.alias_rvas),
                    "rva": region.rva,
                    "target_id": region.target_id,
                }
                for region in self.regions
            ],
            "direct_call_sites": [
                {
                    "callsite_rva": site.callsite_rva,
                    "continuation_rva": site.continuation_rva,
                    "continuation_target_id": site.continuation_target_id,
                    "edge_index": site.edge_index,
                    "source_rva": site.source_rva,
                    "source_target_id": site.source_target_id,
                }
                for site in self.direct_call_sites
            ],
            "call_return_edges": [
                {
                    "edge_index": edge.edge_index,
                    "source_target_id": edge.source_target_id,
                    "target_target_id": edge.target_target_id,
                }
                for edge in self.call_return_edges
            ],
            "prebound_finite_origin_call_instruction_rvas": list(
                self.prebound_finite_origin_call_instruction_rvas
            ),
            "stack_dynamic_control": self.stack_dynamic_control.to_json(),
        }


def _validate_ir(value: DirectCallProposalIR) -> DirectCallProposalIR:
    expected_inputs = set(DIRECT_CALL_PROPOSAL_IR_INPUTS)
    if set(value.input_sha256s) != expected_inputs:
        raise DirectCallProposalIRError(
            "direct-call proposal IR input inventory is incomplete"
        )
    for name, digest in value.input_sha256s.items():
        if _INPUT_NAME.fullmatch(name) is None:
            raise DirectCallProposalIRError(
                f"direct-call proposal IR input name {name!r} is invalid"
            )
        _sha256(digest, f"input {name}")
    _sha256(
        value.authority_base_plan_sha256,
        "authority base plan SHA-256",
    )
    _sha256(value.consumed_plan_sha256, "consumed plan SHA-256")
    graph = value.original_cutpoint_graph
    if graph.original_pe_sha256 != value.input_sha256s["original_pe"]:
        raise DirectCallProposalIRError(
            "original cutpoint graph has the wrong original PE identity"
        )
    if graph.state_machine_sha256 != value.input_sha256s["state_machine"]:
        raise DirectCallProposalIRError(
            "original cutpoint graph has the wrong state-machine identity"
        )

    if tuple(sorted(value.regions)) != value.regions:
        raise DirectCallProposalIRError(
            "direct-call proposal regions are not canonically ordered"
        )
    if tuple(region.target_id for region in value.regions) != tuple(
        range(len(value.regions))
    ):
        raise DirectCallProposalIRError(
            "direct-call proposal target IDs are not a dense canonical index"
        )
    all_region_rvas = [
        rva
        for region in value.regions
        for rva in (region.rva, *region.alias_rvas)
    ]
    if len(set(all_region_rvas)) != len(all_region_rvas):
        raise DirectCallProposalIRError(
            "direct-call proposal region and alias RVAs are not unique"
        )
    for index, region in enumerate(value.regions):
        _u32(region.target_id, f"region {index} target ID")
        _u32(region.rva, f"region {index} RVA")
        if tuple(sorted(set(region.alias_rvas))) != region.alias_rvas:
            raise DirectCallProposalIRError(
                f"region {index} alias RVAs are not unique and ordered"
            )
        for alias_index, alias_rva in enumerate(region.alias_rvas):
            _u32(alias_rva, f"region {index} alias RVA {alias_index}")

    if tuple(sorted(value.direct_call_sites)) != value.direct_call_sites:
        raise DirectCallProposalIRError(
            "direct-call proposal sites are not canonically ordered"
        )
    if len({site.callsite_rva for site in value.direct_call_sites}) != len(
        value.direct_call_sites
    ):
        raise DirectCallProposalIRError(
            "direct-call proposal callsite RVAs are not unique"
        )
    target_rvas = value.target_rvas
    target_ids_by_rva = value.target_ids_by_rva
    for index, site in enumerate(value.direct_call_sites):
        for field, number in (
            ("callsite RVA", site.callsite_rva),
            ("source RVA", site.source_rva),
            ("source target ID", site.source_target_id),
            ("continuation RVA", site.continuation_rva),
            ("continuation target ID", site.continuation_target_id),
            ("edge index", site.edge_index),
        ):
            _u32(number, f"direct-call site {index} {field}")
        if target_rvas.get(site.source_target_id) != site.source_rva:
            raise DirectCallProposalIRError(
                f"direct-call site {index} source is outside the canonical map"
            )
        if target_ids_by_rva.get(site.continuation_rva) != (
            site.continuation_target_id
        ):
            raise DirectCallProposalIRError(
                f"direct-call site {index} continuation is outside the "
                "canonical map"
            )

    if tuple(sorted(value.call_return_edges)) != value.call_return_edges:
        raise DirectCallProposalIRError(
            "call-return edges are not canonically ordered"
        )
    if len({edge.edge_index for edge in value.call_return_edges}) != len(
        value.call_return_edges
    ):
        raise DirectCallProposalIRError("call-return edge indexes are not unique")
    edge_pairs: set[tuple[int, int]] = set()
    for index, edge in enumerate(value.call_return_edges):
        for field, number in (
            ("edge index", edge.edge_index),
            ("source target ID", edge.source_target_id),
            ("target target ID", edge.target_target_id),
        ):
            _u32(number, f"call-return edge {index} {field}")
        if (
            edge.source_target_id not in target_rvas
            or edge.target_target_id not in target_rvas
        ):
            raise DirectCallProposalIRError(
                f"call-return edge {index} is outside the canonical map"
            )
        pair = (edge.source_target_id, edge.target_target_id)
        if pair in edge_pairs:
            raise DirectCallProposalIRError(
                "call-return source/target pairs are not unique"
            )
        edge_pairs.add(pair)
    edges_by_index = {
        edge.edge_index: edge for edge in value.call_return_edges
    }
    for index, site in enumerate(value.direct_call_sites):
        edge = edges_by_index.get(site.edge_index)
        if (
            edge is None
            or edge.source_target_id != site.source_target_id
            or edge.target_target_id != site.continuation_target_id
        ):
            raise DirectCallProposalIRError(
                f"direct-call site {index} disagrees with its exact graph edge"
            )

    prebound = value.prebound_finite_origin_call_instruction_rvas
    if tuple(sorted(set(prebound))) != prebound:
        raise DirectCallProposalIRError(
            "prebound finite-origin call RVAs are not unique and ordered"
        )
    for index, instruction_rva in enumerate(prebound):
        _u32(instruction_rva, f"prebound call instruction RVA {index}")

    stack = value.stack_dynamic_control
    stack_regions = tuple(
        DirectCallProposalRegion(region.target_id, region.rva)
        for region in stack.regions
    )
    primary_regions = tuple(
        DirectCallProposalRegion(region.target_id, region.rva)
        for region in value.regions
    )
    graph_regions = tuple(
        DirectCallProposalRegion(
            region.target_id,
            region.rva,
            region.alias_rvas,
        )
        for region in graph.regions
    )
    if graph_regions != value.regions:
        raise DirectCallProposalIRError(
            "direct-call and original cutpoint region maps differ"
        )
    graph_call_return_edges = tuple(
        DirectCallProposalEdge(
            edge.edge_index,
            edge.source_target_id,
            edge.target_target_id,
        )
        for edge in graph.edges
        if edge.kind == "call_return"
    )
    if graph_call_return_edges != value.call_return_edges:
        raise DirectCallProposalIRError(
            "direct-call and original cutpoint call-return edges differ"
        )
    if stack_regions != primary_regions:
        raise DirectCallProposalIRError(
            "stack/dynamic and direct-call canonical region maps differ"
        )
    if stack.state_machine_sha256 != value.input_sha256s["state_machine"]:
        raise DirectCallProposalIRError(
            "stack/dynamic input has the wrong state-machine identity"
        )
    if stack.original_pe_sha256 != value.input_sha256s["original_pe"]:
        raise DirectCallProposalIRError(
            "stack/dynamic input has the wrong original PE identity"
        )
    return value


def direct_call_proposal_ir_from_plans(
    *,
    authority_base_plan: Any,
    consumed_plan: Any,
    input_paths: Mapping[str, Path | str],
) -> DirectCallProposalIR:
    """Project stable direct-call facts where both full plans already exist."""

    if set(input_paths) != set(DIRECT_CALL_PROPOSAL_IR_INPUTS):
        raise DirectCallProposalIRError(
            "direct-call proposal IR producer input inventory is incomplete"
        )
    input_sha256s = {
        name: sha256_file(Path(path))
        for name, path in sorted(input_paths.items())
    }
    cutpoint_graph = original_cutpoint_graph_ir_from_plan(
        consumed_plan,
        original_pe=input_paths["original_pe"],
        state_machine=input_paths["state_machine"],
    )
    regions = tuple(
        DirectCallProposalRegion(
            target_id=_u32(region.target_id, "region target ID"),
            rva=_u32(region.rva, "region RVA"),
            alias_rvas=tuple(sorted(
                _u32(alias_rva, "region alias RVA")
                for alias_rva in getattr(region, "alias_rvas", ())
            )),
        )
        for region in consumed_plan.regions
    )
    register_control = consumed_plan.register_control_provenance
    if not isinstance(register_control, Mapping):
        raise DirectCallProposalIRError(
            "consumed plan has no register-control proposal"
        )
    raw_sites = _rows(
        register_control.get("internal_direct_call_sites"),
        "internal direct-call sites",
    )
    sites = tuple(sorted(
        (
            DirectCallProposalSite(
                callsite_rva=_u32(
                    _mapping(row, f"direct-call site {index}").get(
                        "callsite_rva"
                    ),
                    f"direct-call site {index} callsite RVA",
                ),
                source_rva=_u32(
                    row.get("source_rva"),
                    f"direct-call site {index} source RVA",
                ),
                source_target_id=_u32(
                    row.get("source_target_id"),
                    f"direct-call site {index} source target ID",
                ),
                continuation_rva=_u32(
                    row.get("continuation_rva"),
                    f"direct-call site {index} continuation RVA",
                ),
                continuation_target_id=_u32(
                    row.get("continuation_target_id"),
                    f"direct-call site {index} continuation target ID",
                ),
                edge_index=_u32(
                    row.get("edge_index"),
                    f"direct-call site {index} edge index",
                ),
            )
            for index, row in enumerate(raw_sites)
        ),
        key=lambda site: site.callsite_rva,
    ))
    exact_graph = _mapping(
        register_control.get("exact_graph"), "register-control exact graph"
    )
    raw_edges = _rows(exact_graph.get("edges"), "exact graph edges")
    edges = tuple(sorted(
        (
            DirectCallProposalEdge(
                edge_index=_u32(
                    row.get("edge_index"), f"edge {index} edge index"
                ),
                source_target_id=_u32(
                    row.get("source_target_id"),
                    f"edge {index} source target ID",
                ),
                target_target_id=_u32(
                    row.get("target_target_id"),
                    f"edge {index} target target ID",
                ),
            )
            for index, raw in enumerate(raw_edges)
            if (
                (row := _mapping(raw, f"edge {index}")).get("kind")
                == "call_return"
            )
        ),
        key=lambda edge: (
            edge.edge_index,
            edge.source_target_id,
            edge.target_target_id,
        ),
    ))

    from .lean.interpreter_mixed_original import (
        OriginalRegisterCodePointerBinding,
    )

    prebound = tuple(sorted({
        site.instruction_rva
        for region in consumed_plan.regions
        for site in region.indirect_sites
        if site.is_call
        and isinstance(
            site.static_binding, OriginalRegisterCodePointerBinding
        )
    }))
    result = DirectCallProposalIR(
        input_sha256s=input_sha256s,
        authority_base_plan_sha256=_canonical_plan_sha256(
            authority_base_plan
        ),
        consumed_plan_sha256=_canonical_plan_sha256(consumed_plan),
        original_cutpoint_graph=cutpoint_graph,
        regions=regions,
        direct_call_sites=sites,
        call_return_edges=edges,
        prebound_finite_origin_call_instruction_rvas=prebound,
        stack_dynamic_control=stack_dynamic_control_input_from_plan(
            consumed_plan,
            original_pe_sha256=input_sha256s["original_pe"],
        ),
    )
    return _validate_ir(result)


def _parse_stack_dynamic_control(
    payload: Any,
) -> StackDynamicControlInput:
    root = _mapping(payload, "stack/dynamic control input")
    if root.get("format") != "stage-a-stack-dynamic-control-ir-v1":
        raise DirectCallProposalIRError(
            "stack/dynamic control input has the wrong format"
        )
    inputs = _mapping(root.get("inputs"), "stack/dynamic input identities")
    regions = tuple(
        StackDynamicControlRegion(
            target_id=_u32(
                _mapping(row, f"stack region {index}").get("target_id"),
                f"stack region {index} target ID",
            ),
            rva=_u32(row.get("rva"), f"stack region {index} RVA"),
        )
        for index, row in enumerate(
            _rows(root.get("regions"), "stack/dynamic regions")
        )
    )
    sites: list[StackDynamicControlSite] = []
    for index, raw in enumerate(
        _rows(root.get("indirect_sites"), "stack/dynamic sites")
    ):
        row = _mapping(raw, f"stack/dynamic site {index}")
        expression = _mapping(
            row.get("target_expression"),
            f"stack/dynamic site {index} target expression",
        )
        category = row.get("category")
        is_call = row.get("is_call")
        continuation = row.get("continuation_rva")
        if category != "stack_or_dynamic_pointer" or not isinstance(
            is_call, bool
        ):
            raise DirectCallProposalIRError(
                f"stack/dynamic site {index} has an invalid transfer"
            )
        sites.append(StackDynamicControlSite(
            source_rva=_u32(
                row.get("source_rva"),
                f"stack/dynamic site {index} source RVA",
            ),
            instruction_rva=_u32(
                row.get("instruction_rva"),
                f"stack/dynamic site {index} instruction RVA",
            ),
            category=category,
            is_call=is_call,
            continuation_rva=(
                None
                if continuation is None
                else _u32(
                    continuation,
                    f"stack/dynamic site {index} continuation RVA",
                )
            ),
            target_expression=dict(expression),
        ))
    remaining = tuple(
        _u32(value, f"remaining stack/dynamic source RVA {index}")
        for index, value in enumerate(
            _rows(
                root.get("remaining_source_rvas"),
                "remaining stack/dynamic source RVAs",
            )
        )
    )
    if tuple(sorted(sites, key=lambda site: (
        site.source_rva, site.instruction_rva
    ))) != tuple(sites):
        raise DirectCallProposalIRError(
            "stack/dynamic sites are not canonically ordered"
        )
    if tuple(sorted(set(remaining))) != remaining:
        raise DirectCallProposalIRError(
            "remaining stack/dynamic source RVAs are not unique and ordered"
        )
    if remaining != tuple(sorted({site.source_rva for site in sites})):
        raise DirectCallProposalIRError(
            "stack/dynamic source and site inventories differ"
        )
    return StackDynamicControlInput(
        original_pe_sha256=_sha256(
            inputs.get("original_pe_sha256"), "stack original PE SHA-256"
        ),
        state_machine_sha256=_sha256(
            inputs.get("state_machine_sha256"),
            "stack state-machine SHA-256",
        ),
        regions=regions,
        indirect_sites=tuple(sites),
        remaining_source_rvas=remaining,
    )


def _parse_original_cutpoint_graph(
    payload: Any,
) -> OriginalCutpointGraphIR:
    return original_cutpoint_graph_ir_from_json(
        _mapping(payload, "original cutpoint graph")
    )


def load_direct_call_proposal_ir(
    path: Path | str,
    *,
    expected_input_paths: Mapping[str, Path | str],
) -> DirectCallProposalIR:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DirectCallProposalIRError(
            f"cannot read direct-call proposal IR: {error}"
        ) from error
    root = _mapping(payload, "direct-call proposal IR")
    if root.get("format") != DIRECT_CALL_PROPOSAL_IR_FORMAT:
        raise DirectCallProposalIRError(
            "direct-call proposal IR has the wrong format"
        )
    if set(expected_input_paths) != set(DIRECT_CALL_PROPOSAL_IR_INPUTS):
        raise DirectCallProposalIRError(
            "direct-call proposal IR expected input inventory is incomplete"
        )
    inputs = _mapping(root.get("inputs"), "direct-call proposal IR inputs")
    expected_hashes = {
        name: sha256_file(Path(input_path))
        for name, input_path in sorted(expected_input_paths.items())
    }
    if dict(inputs) != expected_hashes:
        mismatches = [
            name
            for name in DIRECT_CALL_PROPOSAL_IR_INPUTS
            if inputs.get(name) != expected_hashes[name]
        ]
        raise DirectCallProposalIRError(
            "direct-call proposal IR input hashes do not match: "
            + ", ".join(mismatches)
        )
    plans = _mapping(root.get("plans"), "direct-call proposal plan identities")
    base_plan_path = Path(expected_input_paths["base_plan"])
    try:
        base_plan_payload = json.loads(
            base_plan_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise DirectCallProposalIRError(
            f"cannot read direct-call base plan: {error}"
        ) from error
    consumed_plan_sha256 = hashlib.sha256(
        json.dumps(
            base_plan_payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if plans.get("consumed_plan_sha256") != consumed_plan_sha256:
        raise DirectCallProposalIRError(
            "direct-call proposal IR does not match the canonical base plan"
        )
    regions = tuple(
        DirectCallProposalRegion(
            target_id=_u32(
                _mapping(row, f"region {index}").get("target_id"),
                f"region {index} target ID",
            ),
            rva=_u32(row.get("rva"), f"region {index} RVA"),
            alias_rvas=tuple(
                _u32(
                    alias_rva,
                    f"region {index} alias RVA {alias_index}",
                )
                for alias_index, alias_rva in enumerate(
                    _rows(
                        row.get("alias_rvas"),
                        f"region {index} alias RVAs",
                    )
                )
            ),
        )
        for index, row in enumerate(_rows(root.get("regions"), "regions"))
    )
    sites = tuple(
        DirectCallProposalSite(
            callsite_rva=_u32(
                _mapping(row, f"direct-call site {index}").get(
                    "callsite_rva"
                ),
                f"direct-call site {index} callsite RVA",
            ),
            source_rva=_u32(
                row.get("source_rva"),
                f"direct-call site {index} source RVA",
            ),
            source_target_id=_u32(
                row.get("source_target_id"),
                f"direct-call site {index} source target ID",
            ),
            continuation_rva=_u32(
                row.get("continuation_rva"),
                f"direct-call site {index} continuation RVA",
            ),
            continuation_target_id=_u32(
                row.get("continuation_target_id"),
                f"direct-call site {index} continuation target ID",
            ),
            edge_index=_u32(
                row.get("edge_index"),
                f"direct-call site {index} edge index",
            ),
        )
        for index, row in enumerate(
            _rows(root.get("direct_call_sites"), "direct-call sites")
        )
    )
    edges = tuple(
        DirectCallProposalEdge(
            edge_index=_u32(
                _mapping(row, f"call-return edge {index}").get(
                    "edge_index"
                ),
                f"call-return edge {index} edge index",
            ),
            source_target_id=_u32(
                row.get("source_target_id"),
                f"call-return edge {index} source target ID",
            ),
            target_target_id=_u32(
                row.get("target_target_id"),
                f"call-return edge {index} target target ID",
            ),
        )
        for index, row in enumerate(
            _rows(root.get("call_return_edges"), "call-return edges")
        )
    )
    prebound = tuple(
        _u32(value, f"prebound call instruction RVA {index}")
        for index, value in enumerate(_rows(
            root.get("prebound_finite_origin_call_instruction_rvas"),
            "prebound finite-origin call instruction RVAs",
        ))
    )
    cutpoint_graph = _parse_original_cutpoint_graph(
        root.get("original_cutpoint_graph")
    )
    validate_original_cutpoint_graph_semantic_bindings(
        cutpoint_graph,
        Path(expected_input_paths["state_machine"]),
    )
    return _validate_ir(DirectCallProposalIR(
        input_sha256s=expected_hashes,
        authority_base_plan_sha256=_sha256(
            plans.get("authority_base_plan_sha256"),
            "authority base plan SHA-256",
        ),
        consumed_plan_sha256=_sha256(
            consumed_plan_sha256,
            "consumed plan SHA-256",
        ),
        original_cutpoint_graph=cutpoint_graph,
        regions=regions,
        direct_call_sites=sites,
        call_return_edges=edges,
        prebound_finite_origin_call_instruction_rvas=prebound,
        stack_dynamic_control=_parse_stack_dynamic_control(
            root.get("stack_dynamic_control")
        ),
    ))


__all__ = [
    "DirectCallSummaryRequest",
    "DIRECT_CALL_PROPOSAL_IR_FORMAT",
    "DIRECT_CALL_PROPOSAL_IR_INPUTS",
    "DirectCallProposalEdge",
    "DirectCallProposalIR",
    "DirectCallProposalIRError",
    "DirectCallProposalRegion",
    "DirectCallProposalSite",
    "direct_call_proposal_ir_from_plans",
    "load_direct_call_proposal_ir",
]
