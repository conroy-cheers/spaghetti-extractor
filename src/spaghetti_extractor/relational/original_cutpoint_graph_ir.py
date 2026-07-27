"""Strict original-side cutpoint graph shared by proof proposal phases.

The mixed-original planner performs expensive PE recovery, decoding, control
discovery, and rooted-closure analysis.  Later proof phases need the resulting
cutpoint identities and graph, but must not rerun that analysis or trust a
mutable planner object.  This module projects the result into a deterministic,
hash-bound artifact.

The artifact is not proof authority.  In particular, a semantic-transfer hash
only binds a cutpoint to the corresponding exact state-machine row.  Lean must
still check the PE bytes, decoded semantics, edge guards, and any invariant
certificate that uses the graph.
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


ORIGINAL_CUTPOINT_GRAPH_IR_FORMAT = "stage-a-original-cutpoint-graph-ir-v2"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_U32_LIMIT = 1 << 32
_EDGE_KINDS = frozenset((
    "direct",
    "call_entry",
    "call_return",
    "indirect_target",
))
_TRANSITION_ROLES = frozenset(("immediate", "continuation", "dataflow"))


class OriginalCutpointGraphIRError(StageAInputError):
    """The cached original cutpoint graph is malformed or stale."""


def _u32(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < _U32_LIMIT
    ):
        raise OriginalCutpointGraphIRError(
            f"{field} must be an unsigned PE32 word"
        )
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise OriginalCutpointGraphIRError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OriginalCutpointGraphIRError(f"{field} must be an object")
    return value


def _rows(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise OriginalCutpointGraphIRError(f"{field} must be a list")
    return value


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise OriginalCutpointGraphIRError(f"{field} must be a Boolean")
    return value


@dataclass(frozen=True, order=True)
class OriginalCutpointRegion:
    target_id: int
    rva: int
    size: int
    alias_rvas: tuple[int, ...]
    successor_target_ids: tuple[int, ...]
    root: bool
    synthetic_terminal_padding: bool
    semantic_contract_sha256: str | None
    instruction_bytes_sha256: str | None


@dataclass(frozen=True, order=True)
class OriginalCutpointEdge:
    edge_index: int
    source_target_id: int
    target_target_id: int
    kind: str
    machine_contract_id: int | None
    transition_role: str
    execution_successor: bool


@dataclass(frozen=True)
class OriginalCutpointGraphIR:
    original_pe_sha256: str
    state_machine_sha256: str
    regions: tuple[OriginalCutpointRegion, ...]
    edges: tuple[OriginalCutpointEdge, ...]
    root_target_ids: tuple[int, ...]
    reachable_target_ids: tuple[int, ...]

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

    def edge_index(
        self,
        source_target_id: int,
        target_target_id: int,
        *,
        kind: str | None = None,
    ) -> int:
        matches = [
            edge.edge_index
            for edge in self.edges
            if edge.source_target_id == source_target_id
            and edge.target_target_id == target_target_id
            and (kind is None or edge.kind == kind)
        ]
        if len(matches) != 1:
            suffix = "" if kind is None else f" of kind {kind}"
            raise OriginalCutpointGraphIRError(
                "original cutpoint graph has no unique edge for "
                f"{source_target_id}->{target_target_id}{suffix}"
            )
        return matches[0]

    def to_json(self) -> dict[str, Any]:
        return {
            "format": ORIGINAL_CUTPOINT_GRAPH_IR_FORMAT,
            "inputs": {
                "original_pe_sha256": self.original_pe_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "regions": [
                {
                    "alias_rvas": list(region.alias_rvas),
                    "instruction_bytes_sha256": (
                        region.instruction_bytes_sha256
                    ),
                    "root": region.root,
                    "rva": region.rva,
                    "semantic_contract_sha256": (
                        region.semantic_contract_sha256
                    ),
                    "size": region.size,
                    "successor_target_ids": list(
                        region.successor_target_ids
                    ),
                    "synthetic_terminal_padding": (
                        region.synthetic_terminal_padding
                    ),
                    "target_id": region.target_id,
                }
                for region in self.regions
            ],
            "edges": [
                {
                    "edge_index": edge.edge_index,
                    "execution_successor": edge.execution_successor,
                    "kind": edge.kind,
                    "machine_contract_id": edge.machine_contract_id,
                    "source_target_id": edge.source_target_id,
                    "target_target_id": edge.target_target_id,
                    "transition_role": edge.transition_role,
                }
                for edge in self.edges
            ],
            "root_target_ids": list(self.root_target_ids),
            "reachable_target_ids": list(self.reachable_target_ids),
        }


def canonical_original_cutpoint_graph_sha256(
    graph: OriginalCutpointGraphIR,
) -> str:
    return hashlib.sha256(
        json.dumps(
            graph.to_json(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _synthetic_transition_edge_index(
    state_machine_sha256: str,
    kind: str,
    source_target_id: int,
    target_target_id: int,
) -> int:
    """Return a stable ID for an execution edge absent from analysis data."""

    digest = hashlib.sha256(
        (
            "stage-a-original-cutpoint-transition-v1\0"
            f"{state_machine_sha256}\0{kind}\0"
            f"{source_target_id}\0{target_target_id}"
        ).encode("ascii")
    ).digest()
    return int.from_bytes(digest[:4], "big")


def _execution_edge_classification(
    row: Mapping[str, Any],
    target_rvas: set[int],
) -> tuple[str, str]:
    """Classify one canonical successor from exact state-machine evidence."""

    continuation_rvas: set[int] = set()
    call_entry_rvas: set[int] = set()
    for index, item in enumerate(
        _rows(row.get("external_events"), "state-machine external events")
    ):
        event = _mapping(item, f"state-machine external event {index}")
        return_rva = event.get("return_rva")
        if return_rva is not None:
            continuation_rvas.add(
                _u32(return_rva, f"state-machine external event {index} return RVA")
            )
        if event.get("kind") == "internal_call":
            target_rva = event.get("target_rva")
            if target_rva is None:
                raise OriginalCutpointGraphIRError(
                    f"state-machine internal call {index} has no target RVA"
                )
            call_entry_rvas.add(
                _u32(target_rva, f"state-machine internal call {index} target RVA")
            )

    direct_rvas: set[int] = set()
    for index, item in enumerate(
        _rows(row.get("edge_conditions"), "state-machine edge conditions")
    ):
        edge = _mapping(item, f"state-machine edge condition {index}")
        direct_rvas.add(
            _u32(
                edge.get("target_rva"),
                f"state-machine edge condition {index} target RVA",
            )
        )
    outcome = _mapping(row.get("outcome"), "state-machine outcome")
    for field in ("target_rva", "true_target_rva", "false_target_rva"):
        value = outcome.get(field)
        if value is not None:
            direct_rvas.add(_u32(value, f"state-machine outcome {field}"))

    if target_rvas & continuation_rvas:
        return "call_return", "continuation"
    if target_rvas & call_entry_rvas:
        return "call_entry", "immediate"
    if target_rvas & direct_rvas:
        return "direct", "immediate"
    # A canonical successor absent from the static branch/call inventory is a
    # finite target recovered for an indirect exit. The successor map is bound
    # to the exact decoded authority; later Lean certificates still prove the
    # runtime target expression belongs to this set.
    return "indirect_target", "immediate"


def _validate_graph(
    graph: OriginalCutpointGraphIR,
) -> OriginalCutpointGraphIR:
    _sha256(graph.original_pe_sha256, "original PE SHA-256")
    _sha256(graph.state_machine_sha256, "state-machine SHA-256")
    if not graph.regions:
        raise OriginalCutpointGraphIRError(
            "original cutpoint graph has no regions"
        )
    if tuple(region.target_id for region in graph.regions) != tuple(
        range(len(graph.regions))
    ):
        raise OriginalCutpointGraphIRError(
            "original cutpoint target IDs are not a dense canonical index"
        )
    all_rvas: list[int] = []
    successor_pairs: set[tuple[int, int]] = set()
    for index, region in enumerate(graph.regions):
        _u32(region.target_id, f"region {index} target ID")
        _u32(region.rva, f"region {index} RVA")
        _u32(region.size, f"region {index} size")
        if region.size == 0 or region.rva + region.size > _U32_LIMIT:
            raise OriginalCutpointGraphIRError(
                f"region {index} has an empty or overflowing span"
            )
        if tuple(sorted(set(region.alias_rvas))) != region.alias_rvas:
            raise OriginalCutpointGraphIRError(
                f"region {index} alias RVAs are not unique and ordered"
            )
        if tuple(sorted(set(region.successor_target_ids))) != (
            region.successor_target_ids
        ):
            raise OriginalCutpointGraphIRError(
                f"region {index} successors are not unique and ordered"
            )
        all_rvas.append(region.rva)
        for alias_index, alias_rva in enumerate(region.alias_rvas):
            _u32(alias_rva, f"region {index} alias RVA {alias_index}")
            all_rvas.append(alias_rva)
        for successor_index, successor in enumerate(
            region.successor_target_ids
        ):
            _u32(
                successor,
                f"region {index} successor target ID {successor_index}",
            )
            if successor >= len(graph.regions):
                raise OriginalCutpointGraphIRError(
                    f"region {index} successor is outside the canonical map"
                )
            successor_pairs.add((region.target_id, successor))
        if region.synthetic_terminal_padding:
            if (
                region.semantic_contract_sha256 is not None
                or region.instruction_bytes_sha256 is not None
            ):
                raise OriginalCutpointGraphIRError(
                    f"synthetic region {index} unexpectedly has semantic hashes"
                )
        else:
            _sha256(
                region.semantic_contract_sha256,
                f"region {index} semantic contract SHA-256",
            )
            _sha256(
                region.instruction_bytes_sha256,
                f"region {index} instruction-bytes SHA-256",
            )
    if len(all_rvas) != len(set(all_rvas)):
        raise OriginalCutpointGraphIRError(
            "original cutpoint primary and alias RVAs are not unique"
        )

    if tuple(sorted(graph.edges)) != graph.edges:
        raise OriginalCutpointGraphIRError(
            "original cutpoint edges are not canonically ordered"
        )
    if len({edge.edge_index for edge in graph.edges}) != len(graph.edges):
        raise OriginalCutpointGraphIRError(
            "original cutpoint edge indexes are not unique"
        )
    edge_pairs: set[tuple[int, int]] = set()
    covered_successors: set[tuple[int, int]] = set()
    for index, edge in enumerate(graph.edges):
        _u32(edge.edge_index, f"edge {index} index")
        _u32(edge.source_target_id, f"edge {index} source target ID")
        _u32(edge.target_target_id, f"edge {index} target target ID")
        if edge.kind not in _EDGE_KINDS:
            raise OriginalCutpointGraphIRError(
                f"edge {index} has unsupported kind {edge.kind!r}"
            )
        if edge.transition_role not in _TRANSITION_ROLES:
            raise OriginalCutpointGraphIRError(
                f"edge {index} has unsupported transition role "
                f"{edge.transition_role!r}"
            )
        if edge.machine_contract_id is not None:
            _u32(
                edge.machine_contract_id,
                f"edge {index} machine contract ID",
            )
        pair = (edge.source_target_id, edge.target_target_id)
        if edge.execution_successor != (
            edge.transition_role == "immediate"
        ):
            raise OriginalCutpointGraphIRError(
                f"edge {index} execution-successor classification is wrong"
            )
        if edge.transition_role == "dataflow":
            if pair in successor_pairs:
                raise OriginalCutpointGraphIRError(
                    f"edge {index} classifies a decoded successor as dataflow"
                )
        else:
            if pair not in successor_pairs:
                raise OriginalCutpointGraphIRError(
                    f"edge {index} transition {pair[0]}->{pair[1]} is not a "
                    "decoded successor"
                )
            covered_successors.add(pair)
        if edge.kind == "call_entry" and edge.transition_role != "immediate":
            raise OriginalCutpointGraphIRError(
                f"edge {index} call entry is not immediate"
            )
        if (
            edge.kind == "call_return"
            and edge.transition_role not in {"continuation", "dataflow"}
        ):
            raise OriginalCutpointGraphIRError(
                f"edge {index} call return has an invalid transition role"
            )
        if pair in edge_pairs:
            raise OriginalCutpointGraphIRError(
                "original cutpoint source/target edge pairs are not unique"
            )
        edge_pairs.add(pair)
    if covered_successors != successor_pairs:
        missing = sorted(successor_pairs - covered_successors)
        extra = sorted(covered_successors - successor_pairs)
        detail = []
        if missing:
            detail.append(
                "missing " + ", ".join(f"{source}->{target}" for source, target in missing)
            )
        if extra:
            detail.append(
                "extra " + ", ".join(f"{source}->{target}" for source, target in extra)
            )
        raise OriginalCutpointGraphIRError(
            "original cutpoint transition inventory is incomplete: "
            + "; ".join(detail)
        )
    roots = tuple(sorted(set(graph.root_target_ids)))
    reachable = tuple(sorted(set(graph.reachable_target_ids)))
    if roots != graph.root_target_ids or not roots:
        raise OriginalCutpointGraphIRError(
            "original cutpoint roots are empty, duplicated, or unordered"
        )
    if reachable != graph.reachable_target_ids:
        raise OriginalCutpointGraphIRError(
            "original reachable target IDs are duplicated or unordered"
        )
    for context, target_ids in (
        ("root", roots),
        ("reachable", reachable),
    ):
        for index, target_id in enumerate(target_ids):
            _u32(target_id, f"{context} target ID {index}")
            if target_id >= len(graph.regions):
                raise OriginalCutpointGraphIRError(
                    f"{context} target ID {target_id} is outside the map"
                )
    declared_roots = tuple(
        region.target_id for region in graph.regions if region.root
    )
    if roots != declared_roots:
        raise OriginalCutpointGraphIRError(
            "root inventory disagrees with region root flags"
        )
    if not set(roots).issubset(reachable):
        raise OriginalCutpointGraphIRError(
            "original roots are absent from the reachable inventory"
        )
    return graph


def _load_state_machine_rows(
    path: Path,
) -> dict[int, Mapping[str, Any]]:
    rows: dict[int, Mapping[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise OriginalCutpointGraphIRError(
            f"cannot read original state machine: {error}"
        ) from error
    for index, line in enumerate(lines):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise OriginalCutpointGraphIRError(
                f"state-machine row {index} is invalid JSON: {error}"
            ) from error
        item = _mapping(row, f"state-machine row {index}")
        original = _mapping(
            item.get("original"),
            f"state-machine row {index} original span",
        )
        start = _u32(
            original.get("rva_start"),
            f"state-machine row {index} start RVA",
        )
        if start in rows:
            raise OriginalCutpointGraphIRError(
                f"state-machine start RVA 0x{start:x} is duplicated"
            )
        rows[start] = item
    return rows


def original_cutpoint_graph_ir_from_plan(
    plan: Any,
    *,
    original_pe: Path | str,
    state_machine: Path | str,
) -> OriginalCutpointGraphIR:
    """Project one checked planner result into the stable graph artifact."""

    original_path = Path(original_pe)
    state_machine_path = Path(state_machine)
    state_machine_sha256 = sha256_file(state_machine_path)
    if getattr(plan, "state_machine_sha256", None) != state_machine_sha256:
        raise OriginalCutpointGraphIRError(
            "planner and state-machine identities differ"
        )
    rows_by_rva = _load_state_machine_rows(state_machine_path)
    regions: list[OriginalCutpointRegion] = []
    for index, region in enumerate(getattr(plan, "regions", ())):
        target_id = _u32(
            getattr(region, "target_id", None),
            f"region {index} target ID",
        )
        rva = _u32(getattr(region, "rva", None), f"region {index} RVA")
        size = _u32(getattr(region, "size", None), f"region {index} size")
        synthetic = bool(
            getattr(region, "synthetic_terminal_padding", False)
        )
        row = rows_by_rva.get(rva)
        if synthetic:
            if row is not None:
                raise OriginalCutpointGraphIRError(
                    f"synthetic region {index} has a state-machine row"
                )
            contract_sha256 = None
            instruction_sha256 = None
        else:
            if row is None:
                raise OriginalCutpointGraphIRError(
                    f"region {index} has no state-machine row at 0x{rva:x}"
                )
            original = _mapping(
                row.get("original"),
                f"state-machine row for region {index}",
            )
            end = _u32(
                original.get("rva_end"),
                f"state-machine row for region {index} end RVA",
            )
            if end - rva != size:
                raise OriginalCutpointGraphIRError(
                    f"region {index} span disagrees with the state machine"
                )
            contract_sha256 = _sha256(
                row.get("contract_sha256"),
                f"region {index} semantic contract SHA-256",
            )
            instruction_sha256 = _sha256(
                row.get("instruction_bytes_sha256"),
                f"region {index} instruction-bytes SHA-256",
            )
        regions.append(OriginalCutpointRegion(
            target_id=target_id,
            rva=rva,
            size=size,
            alias_rvas=tuple(sorted(
                _u32(alias, f"region {index} alias RVA")
                for alias in getattr(region, "alias_rvas", ())
            )),
            successor_target_ids=tuple(sorted(
                _u32(successor, f"region {index} successor target ID")
                for successor in getattr(region, "successor_ids", ())
            )),
            root=bool(getattr(region, "root", False)),
            synthetic_terminal_padding=synthetic,
            semantic_contract_sha256=contract_sha256,
            instruction_bytes_sha256=instruction_sha256,
        ))

    register_control = _mapping(
        getattr(plan, "register_control_provenance", None),
        "register-control provenance",
    )
    exact_graph = _mapping(
        register_control.get("exact_graph"),
        "register-control exact graph",
    )
    successor_pairs = {
        (region.target_id, successor)
        for region in regions
        for successor in region.successor_target_ids
    }
    projected_edges = [
        OriginalCutpointEdge(
                edge_index=_u32(
                    _mapping(raw, f"edge {index}").get("edge_index"),
                    f"edge {index} index",
                ),
                source_target_id=_u32(
                    raw.get("source_target_id"),
                    f"edge {index} source target ID",
                ),
                target_target_id=_u32(
                    raw.get("target_target_id"),
                    f"edge {index} target target ID",
                ),
                kind=str(raw.get("kind")),
                machine_contract_id=(
                    None
                    if raw.get("machine_contract_id") is None
                    else _u32(
                        raw.get("machine_contract_id"),
                        f"edge {index} machine contract ID",
                    )
                ),
                transition_role="dataflow",
                execution_successor=False,
            )
            for index, item in enumerate(
                _rows(exact_graph.get("edges"), "exact graph edges")
            )
            for raw in (_mapping(item, f"edge {index}"),)
    ]
    existing_by_pair = {
        (edge.source_target_id, edge.target_target_id): index
        for index, edge in enumerate(projected_edges)
    }
    if len(existing_by_pair) != len(projected_edges):
        raise OriginalCutpointGraphIRError(
            "register-control graph contains duplicate source/target pairs"
        )
    for region in regions:
        row = rows_by_rva.get(region.rva)
        if row is None:
            if region.successor_target_ids:
                raise OriginalCutpointGraphIRError(
                    f"synthetic region {region.target_id} has successors"
                )
            continue
        for target_target_id in region.successor_target_ids:
            target_region = regions[target_target_id]
            kind, role = _execution_edge_classification(
                row,
                {target_region.rva, *target_region.alias_rvas},
            )
            pair = (region.target_id, target_target_id)
            existing_index = existing_by_pair.get(pair)
            if existing_index is None:
                edge = OriginalCutpointEdge(
                    edge_index=_synthetic_transition_edge_index(
                        state_machine_sha256,
                        kind,
                        region.target_id,
                        target_target_id,
                    ),
                    source_target_id=region.target_id,
                    target_target_id=target_target_id,
                    kind=kind,
                    machine_contract_id=None,
                    transition_role=role,
                    execution_successor=role == "immediate",
                )
                existing_by_pair[pair] = len(projected_edges)
                projected_edges.append(edge)
            else:
                existing = projected_edges[existing_index]
                projected_edges[existing_index] = OriginalCutpointEdge(
                    edge_index=existing.edge_index,
                    source_target_id=existing.source_target_id,
                    target_target_id=existing.target_target_id,
                    kind=kind,
                    machine_contract_id=existing.machine_contract_id,
                    transition_role=role,
                    execution_successor=role == "immediate",
                )
    edges = tuple(sorted(
        projected_edges,
        key=lambda edge: (
            edge.edge_index,
            edge.source_target_id,
            edge.target_target_id,
        ),
    ))
    graph = OriginalCutpointGraphIR(
        original_pe_sha256=sha256_file(original_path),
        state_machine_sha256=state_machine_sha256,
        regions=tuple(regions),
        edges=edges,
        root_target_ids=tuple(
            region.target_id for region in regions if region.root
        ),
        reachable_target_ids=tuple(sorted(
            _u32(target_id, "reachable target ID")
            for target_id in getattr(plan, "reachable_target_ids", ())
        )),
    )
    return _validate_graph(graph)


def validate_original_cutpoint_graph_semantic_bindings(
    graph: OriginalCutpointGraphIR,
    state_machine: Path,
) -> None:
    rows_by_rva = _load_state_machine_rows(state_machine)
    for index, region in enumerate(graph.regions):
        row = rows_by_rva.get(region.rva)
        if region.synthetic_terminal_padding:
            if row is not None:
                raise OriginalCutpointGraphIRError(
                    f"synthetic region {index} has a state-machine row"
                )
            continue
        if row is None:
            raise OriginalCutpointGraphIRError(
                f"region {index} has no authoritative state-machine row"
            )
        original = _mapping(
            row.get("original"),
            f"state-machine row for region {index}",
        )
        if (
            original.get("rva_start") != region.rva
            or original.get("rva_end") != region.rva + region.size
            or row.get("contract_sha256")
                != region.semantic_contract_sha256
            or row.get("instruction_bytes_sha256")
                != region.instruction_bytes_sha256
        ):
            raise OriginalCutpointGraphIRError(
                f"region {index} semantic binding does not match the "
                "authoritative state-machine row"
            )


def original_cutpoint_graph_ir_from_json(
    payload: Mapping[str, Any],
) -> OriginalCutpointGraphIR:
    if payload.get("format") != ORIGINAL_CUTPOINT_GRAPH_IR_FORMAT:
        raise OriginalCutpointGraphIRError(
            "original cutpoint graph has the wrong format"
        )
    inputs = _mapping(payload.get("inputs"), "cutpoint graph inputs")
    regions: list[OriginalCutpointRegion] = []
    for index, item in enumerate(_rows(payload.get("regions"), "regions")):
        row = _mapping(item, f"region {index}")
        contract_hash = row.get("semantic_contract_sha256")
        instruction_hash = row.get("instruction_bytes_sha256")
        regions.append(OriginalCutpointRegion(
            target_id=_u32(row.get("target_id"), f"region {index} target ID"),
            rva=_u32(row.get("rva"), f"region {index} RVA"),
            size=_u32(row.get("size"), f"region {index} size"),
            alias_rvas=tuple(
                _u32(alias, f"region {index} alias RVA {alias_index}")
                for alias_index, alias in enumerate(
                    _rows(row.get("alias_rvas"), f"region {index} aliases")
                )
            ),
            successor_target_ids=tuple(
                _u32(
                    successor,
                    f"region {index} successor target ID {successor_index}",
                )
                for successor_index, successor in enumerate(
                    _rows(
                        row.get("successor_target_ids"),
                        f"region {index} successors",
                    )
                )
            ),
            root=_bool(row.get("root"), f"region {index} root"),
            synthetic_terminal_padding=_bool(
                row.get("synthetic_terminal_padding"),
                f"region {index} synthetic-terminal-padding flag",
            ),
            semantic_contract_sha256=(
                None
                if contract_hash is None
                else _sha256(
                    contract_hash,
                    f"region {index} semantic contract SHA-256",
                )
            ),
            instruction_bytes_sha256=(
                None
                if instruction_hash is None
                else _sha256(
                    instruction_hash,
                    f"region {index} instruction-bytes SHA-256",
                )
            ),
        ))
    edges: list[OriginalCutpointEdge] = []
    for index, item in enumerate(_rows(payload.get("edges"), "edges")):
        row = _mapping(item, f"edge {index}")
        contract_id = row.get("machine_contract_id")
        edges.append(OriginalCutpointEdge(
            edge_index=_u32(row.get("edge_index"), f"edge {index} index"),
            source_target_id=_u32(
                row.get("source_target_id"),
                f"edge {index} source target ID",
            ),
            target_target_id=_u32(
                row.get("target_target_id"),
                f"edge {index} target target ID",
            ),
            kind=str(row.get("kind")),
            machine_contract_id=(
                None
                if contract_id is None
                else _u32(
                    contract_id,
                    f"edge {index} machine contract ID",
                )
            ),
            transition_role=str(row.get("transition_role")),
            execution_successor=_bool(
                row.get("execution_successor"),
                f"edge {index} execution-successor flag",
            ),
        ))
    return _validate_graph(OriginalCutpointGraphIR(
        original_pe_sha256=_sha256(
            inputs.get("original_pe_sha256"),
            "original PE SHA-256",
        ),
        state_machine_sha256=_sha256(
            inputs.get("state_machine_sha256"),
            "state-machine SHA-256",
        ),
        regions=tuple(regions),
        edges=tuple(edges),
        root_target_ids=tuple(
            _u32(value, f"root target ID {index}")
            for index, value in enumerate(
                _rows(payload.get("root_target_ids"), "root target IDs")
            )
        ),
        reachable_target_ids=tuple(
            _u32(value, f"reachable target ID {index}")
            for index, value in enumerate(
                _rows(
                    payload.get("reachable_target_ids"),
                    "reachable target IDs",
                )
            )
        ),
    ))


def load_original_cutpoint_graph_ir(
    path: Path | str,
    *,
    original_pe: Path | str,
    state_machine: Path | str,
) -> OriginalCutpointGraphIR:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise OriginalCutpointGraphIRError(
            f"cannot read original cutpoint graph: {error}"
        ) from error
    graph = original_cutpoint_graph_ir_from_json(
        _mapping(payload, "original cutpoint graph")
    )
    if graph.original_pe_sha256 != sha256_file(Path(original_pe)):
        raise OriginalCutpointGraphIRError(
            "original cutpoint graph does not match the original PE"
        )
    if graph.state_machine_sha256 != sha256_file(Path(state_machine)):
        raise OriginalCutpointGraphIRError(
            "original cutpoint graph does not match the state machine"
        )
    validate_original_cutpoint_graph_semantic_bindings(
        graph, Path(state_machine)
    )
    return graph


__all__ = [
    "ORIGINAL_CUTPOINT_GRAPH_IR_FORMAT",
    "OriginalCutpointEdge",
    "OriginalCutpointGraphIR",
    "OriginalCutpointGraphIRError",
    "OriginalCutpointRegion",
    "canonical_original_cutpoint_graph_sha256",
    "load_original_cutpoint_graph_ir",
    "original_cutpoint_graph_ir_from_plan",
    "original_cutpoint_graph_ir_from_json",
    "validate_original_cutpoint_graph_semantic_bindings",
]
