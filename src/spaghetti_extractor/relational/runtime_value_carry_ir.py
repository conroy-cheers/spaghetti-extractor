"""Strict route IR for values carried across original cutpoints.

The mixed-original planner and direct-call analysis are expensive.  A later
proof phase only needs a small predecessor-closed graph, the value location at
each tracked cutpoint, and exact references to the semantic authorities used
by each transfer.  This module serializes that projection without granting it
proof authority.

An ``authority_status`` of ``required`` is intentionally representable.  It
keeps a missing call-frame theorem at its exact graph edge, but Lean acceptance
must reject the route until every transfer has ``checked_dependency`` status
and consumes the named checked authority.
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
    canonical_original_cutpoint_graph_sha256,
)


RUNTIME_VALUE_CARRY_IR_FORMAT = "stage-a-runtime-value-carry-ir-v1"
DIRECT_CALL_AUTHORITY_FORMAT = (
    "stage-a-mixed-original-direct-call-authority-bindings-v2"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_STABLE_ID = re.compile(r"[a-z0-9][a-z0-9_.:-]*\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*"
    r"(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_NAMESPACE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_U32_LIMIT = 1 << 32
_REGISTERS = frozenset(
    ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
)
_LOCATION_KINDS = frozenset(("register", "frame_word"))
_TRANSFER_KINDS = frozenset(
    (
        "finite_origin_call_result",
        "direct_call_register_preserve",
        "decoded_preserve",
        "decoded_register_to_frame",
        "call_frame_word_preserve",
    )
)
_AUTHORITY_STATUSES = frozenset(("checked_dependency", "required"))


class RuntimeValueCarryIRError(StageAInputError):
    """A cached runtime value-carry route is malformed or stale."""


def _u32(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < _U32_LIMIT
    ):
        raise RuntimeValueCarryIRError(
            f"{field} must be an unsigned PE32 word"
        )
    return value


def _natural(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeValueCarryIRError(f"{field} must be a natural number")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RuntimeValueCarryIRError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeValueCarryIRError(f"{field} must be an object")
    return value


def _rows(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise RuntimeValueCarryIRError(f"{field} must be a list")
    return value


def _stable_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _STABLE_ID.fullmatch(value) is None:
        raise RuntimeValueCarryIRError(
            f"{field} must be a stable lowercase identifier"
        )
    return value


@dataclass(frozen=True, order=True)
class RuntimeValueOrigin:
    kind: str
    target_id: int
    offset: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "offset": self.offset,
            "target_id": self.target_id,
        }


@dataclass(frozen=True, order=True)
class RuntimeValueLocation:
    location_id: int
    kind: str
    register: str
    offset: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "location_id": self.location_id,
            "offset": self.offset,
            "register": self.register,
        }


@dataclass(frozen=True, order=True)
class RuntimeValueFact:
    target_id: int
    location_id: int

    def to_json(self) -> dict[str, Any]:
        return {
            "location_id": self.location_id,
            "target_id": self.target_id,
        }


@dataclass(frozen=True, order=True)
class RuntimeValueLeanTerm:
    module: str
    namespace: str
    symbol: str

    @property
    def qualified(self) -> str:
        return f"{self.namespace}.{self.symbol}"

    def to_json(self) -> dict[str, str]:
        return {
            "module": self.module,
            "namespace": self.namespace,
            "symbol": self.symbol,
        }


@dataclass(frozen=True, order=True)
class RuntimeValueTransfer:
    transfer_id: int
    edge_index: int
    source_target_id: int
    target_target_id: int
    kind: str
    source_location_id: int | None
    target_location_id: int
    authority_status: str
    authority_contract_id: int | None
    source_semantic_contract_sha256: str
    source_instruction_bytes_sha256: str
    authority_origin: str | None = None
    authority_callee_target_id: int | None = None
    authority_lean_term: RuntimeValueLeanTerm | None = None
    authority_kernel_source_sha256: str | None = None
    authority_kernel_olean_sha256: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "authority_callee_target_id": self.authority_callee_target_id,
            "authority_contract_id": self.authority_contract_id,
            "authority_kernel_olean_sha256": (
                self.authority_kernel_olean_sha256
            ),
            "authority_kernel_source_sha256": (
                self.authority_kernel_source_sha256
            ),
            "authority_lean_term": (
                None
                if self.authority_lean_term is None
                else self.authority_lean_term.to_json()
            ),
            "authority_origin": self.authority_origin,
            "authority_status": self.authority_status,
            "edge_index": self.edge_index,
            "kind": self.kind,
            "source_instruction_bytes_sha256": (
                self.source_instruction_bytes_sha256
            ),
            "source_location_id": self.source_location_id,
            "source_semantic_contract_sha256": (
                self.source_semantic_contract_sha256
            ),
            "source_target_id": self.source_target_id,
            "target_location_id": self.target_location_id,
            "target_target_id": self.target_target_id,
            "transfer_id": self.transfer_id,
        }


@dataclass(frozen=True)
class RuntimeValueCarryRoute:
    stable_id: str
    origin: RuntimeValueOrigin
    locations: tuple[RuntimeValueLocation, ...]
    facts: tuple[RuntimeValueFact, ...]
    transfers: tuple[RuntimeValueTransfer, ...]
    target_fact: RuntimeValueFact

    @property
    def proof_ready(self) -> bool:
        return all(
            transfer.authority_status == "checked_dependency"
            for transfer in self.transfers
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "facts": [fact.to_json() for fact in self.facts],
            "locations": [
                location.to_json() for location in self.locations
            ],
            "origin": self.origin.to_json(),
            "proof_ready": self.proof_ready,
            "stable_id": self.stable_id,
            "target_fact": self.target_fact.to_json(),
            "transfers": [
                transfer.to_json() for transfer in self.transfers
            ],
        }


@dataclass(frozen=True)
class RuntimeValueCarryIR:
    original_pe_sha256: str
    state_machine_sha256: str
    cutpoint_graph_content_sha256: str
    cutpoint_graph_artifact_sha256: str
    direct_call_authority_sha256: str
    stack_dynamic_authority_sha256: str
    routes: tuple[RuntimeValueCarryRoute, ...]

    @property
    def proof_ready(self) -> bool:
        return all(route.proof_ready for route in self.routes)

    def to_json(self) -> dict[str, Any]:
        return {
            "format": RUNTIME_VALUE_CARRY_IR_FORMAT,
            "inputs": {
                "cutpoint_graph_artifact_sha256": (
                    self.cutpoint_graph_artifact_sha256
                ),
                "cutpoint_graph_content_sha256": (
                    self.cutpoint_graph_content_sha256
                ),
                "direct_call_authority_sha256": (
                    self.direct_call_authority_sha256
                ),
                "original_pe_sha256": self.original_pe_sha256,
                "stack_dynamic_authority_sha256": (
                    self.stack_dynamic_authority_sha256
                ),
                "state_machine_sha256": self.state_machine_sha256,
            },
            "proof_ready": self.proof_ready,
            "routes": [route.to_json() for route in self.routes],
        }


def canonical_runtime_value_carry_ir_sha256(
    value: RuntimeValueCarryIR,
) -> str:
    return hashlib.sha256(
        json.dumps(
            value.to_json(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _direct_call_contracts(
    report: Mapping[str, Any],
) -> dict[tuple[int, int], Mapping[str, Any]]:
    if report.get("format") != DIRECT_CALL_AUTHORITY_FORMAT:
        raise RuntimeValueCarryIRError(
            "direct-call authority has the wrong format"
        )
    if (
        report.get("report_authority") is not False
        or report.get("authority_source") != "named Lean terms only"
    ):
        raise RuntimeValueCarryIRError(
            "direct-call authority does not use named Lean terms only"
        )
    rows = _rows(report.get("contracts"), "direct-call authority contracts")
    result: dict[tuple[int, int], Mapping[str, Any]] = {}
    contract_ids: set[int] = set()
    for index, item in enumerate(rows):
        row = _mapping(item, f"direct-call authority contract {index}")
        contract_id = _u32(
            row.get("contract_id"),
            f"direct-call authority contract {index} contract ID",
        )
        if contract_id in contract_ids:
            raise RuntimeValueCarryIRError(
                f"direct-call authority duplicates contract ID {contract_id}"
            )
        contract_ids.add(contract_id)
        source = _u32(
            row.get("source_target_id"),
            f"direct-call authority contract {index} source target ID",
        )
        target = _u32(
            row.get("continuation_target_id"),
            f"direct-call authority contract {index} continuation target ID",
        )
        key = (source, target)
        if key in result:
            raise RuntimeValueCarryIRError(
                "direct-call authority contains duplicate source/continuation "
                f"pair {source}->{target}"
            )
        result[key] = row
    return result


def _lean_term(value: Any, field: str) -> RuntimeValueLeanTerm:
    row = _mapping(value, field)
    module = row.get("module")
    namespace = row.get("namespace")
    symbol = row.get("symbol")
    if not isinstance(module, str) or _LEAN_MODULE.fullmatch(module) is None:
        raise RuntimeValueCarryIRError(f"{field} has an invalid Lean module")
    if (
        not isinstance(namespace, str)
        or _LEAN_NAMESPACE.fullmatch(namespace) is None
    ):
        raise RuntimeValueCarryIRError(
            f"{field} has an invalid Lean namespace"
        )
    if not isinstance(symbol, str) or _LEAN_SYMBOL.fullmatch(symbol) is None:
        raise RuntimeValueCarryIRError(f"{field} has an invalid Lean symbol")
    return RuntimeValueLeanTerm(module, namespace, symbol)


def _checked_call_kernel_authority(
    call: Mapping[str, Any],
    *,
    field: str,
) -> tuple[RuntimeValueLeanTerm, str, str]:
    term = _lean_term(call.get("authorizing_lean_term"), f"{field} term")
    kernel = _mapping(call.get("kernel_check"), f"{field} kernel check")
    if (
        kernel.get("status") != "checked"
        or kernel.get("term") != term.to_json()
        or kernel.get("module") != term.module
    ):
        raise RuntimeValueCarryIRError(
            f"{field} was not kernel-compiled for its exact named Lean term"
        )
    source_sha256 = _sha256(
        kernel.get("source_sha256"), f"{field} kernel source SHA-256"
    )
    olean_sha256 = _sha256(
        kernel.get("olean_sha256"), f"{field} kernel olean SHA-256"
    )
    return term, source_sha256, olean_sha256


def _validate_exact_call_metadata(
    transfer: RuntimeValueTransfer,
    call: Mapping[str, Any],
    *,
    route: RuntimeValueCarryRoute,
    graph: OriginalCutpointGraphIR,
) -> None:
    field = (
        f"route {route.stable_id} transfer {transfer.transfer_id} "
        "direct-call authority"
    )
    source = graph.regions[transfer.source_target_id]
    continuation = graph.regions[transfer.target_target_id]
    callee_target_id = _natural(
        call.get("callee_target_id"), f"{field} callee target ID"
    )
    if callee_target_id >= len(graph.regions):
        raise RuntimeValueCarryIRError(f"{field} callee is outside the graph")
    callee = graph.regions[callee_target_id]
    callsite_rva = _u32(call.get("callsite_rva"), f"{field} callsite RVA")
    if (
        call.get("edge_index") != transfer.edge_index
        or call.get("source_rva") != source.rva
        or call.get("continuation_rva") != continuation.rva
        or call.get("callee_rva") != callee.rva
        or not source.rva <= callsite_rva < source.rva + source.size
    ):
        raise RuntimeValueCarryIRError(
            f"{field} does not match its exact edge/source/continuation/callee"
        )
    term, source_sha256, olean_sha256 = _checked_call_kernel_authority(
        call, field=field
    )
    if (
        transfer.authority_contract_id != call.get("contract_id")
        or transfer.authority_origin != call.get("origin")
        or transfer.authority_callee_target_id != callee_target_id
        or transfer.authority_lean_term != term
        or transfer.authority_kernel_source_sha256 != source_sha256
        or transfer.authority_kernel_olean_sha256 != olean_sha256
    ):
        raise RuntimeValueCarryIRError(
            f"{field} does not match the transfer's exact authority reference"
        )


def _validate_transfer_authority(
    transfer: RuntimeValueTransfer,
    *,
    route: RuntimeValueCarryRoute,
    locations: Mapping[int, RuntimeValueLocation],
    direct_calls: Mapping[tuple[int, int], Mapping[str, Any]],
    graph: OriginalCutpointGraphIR,
) -> None:
    source_location = (
        None
        if transfer.source_location_id is None
        else locations[transfer.source_location_id]
    )
    target_location = locations[transfer.target_location_id]
    call = direct_calls.get(
        (transfer.source_target_id, transfer.target_target_id)
    )

    if transfer.authority_status == "required":
        if (
            transfer.authority_contract_id is not None
            or transfer.authority_origin is not None
            or transfer.authority_callee_target_id is not None
            or transfer.authority_lean_term is not None
            or transfer.authority_kernel_source_sha256 is not None
            or transfer.authority_kernel_olean_sha256 is not None
        ):
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} transfer {transfer.transfer_id} "
                "cannot name a contract while its authority is required"
            )
        if transfer.kind != "call_frame_word_preserve":
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} transfer {transfer.transfer_id} "
                "uses required status for a non-call-frame transfer"
            )
        return

    if transfer.authority_contract_id is not None:
        if call is None:
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} transfer {transfer.transfer_id} "
                "names a direct-call contract outside an exact call edge"
            )
        _validate_exact_call_metadata(
            transfer,
            call,
            route=route,
            graph=graph,
        )

    if transfer.kind == "finite_origin_call_result":
        if source_location is not None or target_location.kind != "register":
            raise RuntimeValueCarryIRError(
                "finite-origin call result must seed one register location"
            )
        if call is None or call.get("origin") != (
            "checked_finite_origin_call_summary"
        ):
            raise RuntimeValueCarryIRError(
                "finite-origin call result has no checked direct-call authority"
            )
        finite_targets = _rows(
            call.get("finite_target_ids"),
            "finite-origin direct-call targets",
        )
        carried = _rows(
            call.get("target_carried_registers"),
            "finite-origin target-carried registers",
        )
        if (
            finite_targets != [route.origin.target_id]
            or target_location.register not in carried
        ):
            raise RuntimeValueCarryIRError(
                "finite-origin call result does not carry the requested origin"
            )
    elif transfer.kind == "direct_call_register_preserve":
        if (
            source_location is None
            or source_location.kind != "register"
            or target_location.kind != "register"
            or source_location.register != target_location.register
        ):
            raise RuntimeValueCarryIRError(
                "direct-call register preservation requires one matching "
                "register location"
            )
        if call is None or target_location.register not in _rows(
            call.get("preserved_registers"),
            "direct-call preserved registers",
        ):
            raise RuntimeValueCarryIRError(
                "direct-call register preservation has no checked authority"
            )
        if (
            call.get("origin") != "checked_direct_call_summary"
            or _rows(
                call.get("finite_target_ids"),
                "direct-call finite target IDs",
            )
        ):
            raise RuntimeValueCarryIRError(
                "direct-call register preservation has the wrong exact origin"
            )
    elif transfer.kind == "call_frame_word_preserve":
        if (
            source_location is None
            or source_location.kind != "frame_word"
            or target_location.kind != "frame_word"
            or source_location != target_location
        ):
            raise RuntimeValueCarryIRError(
                "call-frame preservation requires one unchanged frame word"
            )
        if call is None:
            raise RuntimeValueCarryIRError(
                "checked call-frame preservation has no direct-call authority"
            )
        preserved_offsets = _rows(
            call.get("preserved_caller_frame_word_offsets"),
            "direct-call preserved caller-frame word offsets",
        )
        if target_location.offset not in preserved_offsets:
            raise RuntimeValueCarryIRError(
                "direct-call authority does not preserve the caller-frame word"
            )
        dedicated_term = call.get(
            "caller_frame_word_authorizing_lean_term"
        )
        origin = call.get("origin")
        if (
            origin
            not in {
                "checked_direct_call_caller_frame_word_summary",
                "checked_finite_origin_call_caller_frame_word_summary",
            }
            or not isinstance(dedicated_term, Mapping)
            or dedicated_term != call.get("authorizing_lean_term")
        ):
            raise RuntimeValueCarryIRError(
                "direct-call frame preservation has no exact named "
                "caller-frame authority"
            )
        finite_targets = _rows(
            call.get("finite_target_ids"),
            "direct-call finite target IDs",
        )
        if origin == "checked_finite_origin_call_caller_frame_word_summary":
            if finite_targets != [route.origin.target_id]:
                raise RuntimeValueCarryIRError(
                    "finite-origin frame preservation does not name the "
                    "route's exact callee origin"
                )
        elif finite_targets:
            raise RuntimeValueCarryIRError(
                "exact direct-call frame preservation unexpectedly has "
                "finite-origin targets"
            )
    else:
        if (
            transfer.authority_contract_id is not None
            or transfer.authority_origin is not None
            or transfer.authority_callee_target_id is not None
            or transfer.authority_lean_term is not None
            or transfer.authority_kernel_source_sha256 is not None
            or transfer.authority_kernel_olean_sha256 is not None
        ):
            raise RuntimeValueCarryIRError(
                "decoded transfer unexpectedly names a call contract"
            )
        if transfer.kind == "decoded_preserve":
            if source_location is None or source_location != target_location:
                raise RuntimeValueCarryIRError(
                    "decoded preservation requires one unchanged location"
                )
        elif transfer.kind == "decoded_register_to_frame":
            if (
                source_location is None
                or source_location.kind != "register"
                or target_location.kind != "frame_word"
            ):
                raise RuntimeValueCarryIRError(
                    "decoded register-to-frame transfer has invalid locations"
                )

    if call is not None:
        if (
            call.get("remaining_semantic_premises") != []
            or not isinstance(call.get("authorizing_lean_term"), Mapping)
        ):
            raise RuntimeValueCarryIRError(
                "direct-call transfer has no closed named Lean authority"
            )
        observed_contract = _u32(
            call.get("contract_id"), "direct-call contract ID"
        )
        if transfer.authority_contract_id != observed_contract:
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} transfer {transfer.transfer_id} "
                "names the wrong direct-call contract"
            )


def validate_runtime_value_carry_ir(
    value: RuntimeValueCarryIR,
    *,
    graph: OriginalCutpointGraphIR,
    direct_call_authority: Mapping[str, Any],
) -> RuntimeValueCarryIR:
    """Validate graph closure and every available semantic dependency."""

    _sha256(value.original_pe_sha256, "original PE SHA-256")
    _sha256(value.state_machine_sha256, "state-machine SHA-256")
    _sha256(
        value.cutpoint_graph_content_sha256,
        "cutpoint graph content SHA-256",
    )
    _sha256(
        value.cutpoint_graph_artifact_sha256,
        "cutpoint graph artifact SHA-256",
    )
    _sha256(
        value.direct_call_authority_sha256,
        "direct-call authority SHA-256",
    )
    _sha256(
        value.stack_dynamic_authority_sha256,
        "stack/dynamic authority SHA-256",
    )
    if value.original_pe_sha256 != graph.original_pe_sha256:
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR has the wrong original PE identity"
        )
    if value.state_machine_sha256 != graph.state_machine_sha256:
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR has the wrong state-machine identity"
        )
    if value.cutpoint_graph_content_sha256 != (
        canonical_original_cutpoint_graph_sha256(graph)
    ):
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR has the wrong cutpoint graph identity"
        )
    if not value.routes:
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR has no routes"
        )
    if tuple(sorted(value.routes, key=lambda route: route.stable_id)) != (
        value.routes
    ):
        raise RuntimeValueCarryIRError(
            "runtime value-carry routes are not canonically ordered"
        )
    if len({route.stable_id for route in value.routes}) != len(value.routes):
        raise RuntimeValueCarryIRError(
            "runtime value-carry route IDs are not unique"
        )

    graph_edges = {edge.edge_index: edge for edge in graph.edges}
    direct_calls = _direct_call_contracts(direct_call_authority)
    for route in value.routes:
        _stable_id(route.stable_id, "runtime value-carry route ID")
        if route.origin.kind != "static_code_target":
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} has an unsupported value origin"
            )
        _natural(route.origin.target_id, "origin target ID")
        _natural(route.origin.offset, "origin offset")
        if route.origin.offset != 0:
            raise RuntimeValueCarryIRError(
                "runtime value-carry currently requires an entry code address"
            )
        if route.origin.target_id >= len(graph.regions):
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} origin target is outside the graph"
            )
        if tuple(location.location_id for location in route.locations) != tuple(
            range(len(route.locations))
        ):
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} location IDs are not a dense index"
            )
        locations = {
            location.location_id: location
            for location in route.locations
        }
        for location in route.locations:
            if (
                location.kind not in _LOCATION_KINDS
                or location.register not in _REGISTERS
            ):
                raise RuntimeValueCarryIRError(
                    f"route {route.stable_id} has an invalid location"
                )
            _natural(location.offset, "location offset")
            if location.kind == "register" and location.offset != 0:
                raise RuntimeValueCarryIRError(
                    "register locations cannot have an offset"
                )
            if location.kind == "frame_word" and (
                location.offset + 4 > _U32_LIMIT
            ):
                raise RuntimeValueCarryIRError(
                    "frame-word location overflows PE32 address arithmetic"
                )

        if tuple(sorted(set(route.facts))) != route.facts:
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} facts are duplicated or unordered"
            )
        facts = {(fact.target_id, fact.location_id) for fact in route.facts}
        for fact in route.facts:
            if (
                fact.target_id >= len(graph.regions)
                or fact.location_id not in locations
            ):
                raise RuntimeValueCarryIRError(
                    f"route {route.stable_id} fact is outside its inventories"
                )
        if (
            route.target_fact.target_id,
            route.target_fact.location_id,
        ) not in facts:
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} target fact is not tracked"
            )

        if tuple(
            transfer.transfer_id for transfer in route.transfers
        ) != tuple(range(len(route.transfers))):
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} transfer IDs are not a dense index"
            )
        represented_incoming: set[int] = set()
        for transfer in route.transfers:
            if (
                transfer.kind not in _TRANSFER_KINDS
                or transfer.authority_status not in _AUTHORITY_STATUSES
            ):
                raise RuntimeValueCarryIRError(
                    f"route {route.stable_id} transfer has an invalid kind "
                    "or authority status"
                )
            _sha256(
                transfer.source_semantic_contract_sha256,
                "source semantic contract SHA-256",
            )
            _sha256(
                transfer.source_instruction_bytes_sha256,
                "source instruction-bytes SHA-256",
            )
            edge = graph_edges.get(transfer.edge_index)
            if (
                edge is None
                or edge.source_target_id != transfer.source_target_id
                or edge.target_target_id != transfer.target_target_id
            ):
                raise RuntimeValueCarryIRError(
                    f"route {route.stable_id} transfer "
                    f"{transfer.transfer_id} has no exact graph edge"
                )
            source_region = graph.regions[transfer.source_target_id]
            if (
                source_region.semantic_contract_sha256
                    != transfer.source_semantic_contract_sha256
                or source_region.instruction_bytes_sha256
                    != transfer.source_instruction_bytes_sha256
            ):
                raise RuntimeValueCarryIRError(
                    f"route {route.stable_id} transfer "
                    f"{transfer.transfer_id} has stale source semantics"
                )
            if (
                transfer.target_target_id,
                transfer.target_location_id,
            ) not in facts:
                raise RuntimeValueCarryIRError(
                    f"route {route.stable_id} transfer "
                    f"{transfer.transfer_id} does not establish a tracked fact"
                )
            if transfer.source_location_id is not None and (
                transfer.source_target_id,
                transfer.source_location_id,
            ) not in facts:
                raise RuntimeValueCarryIRError(
                    f"route {route.stable_id} transfer "
                    f"{transfer.transfer_id} consumes an untracked fact"
                )
            _validate_transfer_authority(
                transfer,
                route=route,
                locations=locations,
                direct_calls=direct_calls,
                graph=graph,
            )
            if transfer.edge_index in represented_incoming:
                raise RuntimeValueCarryIRError(
                    f"route {route.stable_id} duplicates graph edge "
                    f"{transfer.edge_index}"
                )
            represented_incoming.add(transfer.edge_index)

        tracked_targets = {fact.target_id for fact in route.facts}
        expected_incoming = {
            edge.edge_index
            for edge in graph.edges
            if edge.target_target_id in tracked_targets
        }
        if represented_incoming != expected_incoming:
            missing = sorted(expected_incoming - represented_incoming)
            extra = sorted(represented_incoming - expected_incoming)
            detail: list[str] = []
            if missing:
                detail.append("missing " + ", ".join(map(str, missing)))
            if extra:
                detail.append("extra " + ", ".join(map(str, extra)))
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} does not exactly cover incoming "
                "graph edges: " + "; ".join(detail)
            )
    return value


def _parse_origin(value: Any, field: str) -> RuntimeValueOrigin:
    row = _mapping(value, field)
    return RuntimeValueOrigin(
        kind=str(row.get("kind")),
        target_id=_natural(row.get("target_id"), f"{field} target ID"),
        offset=_natural(row.get("offset"), f"{field} offset"),
    )


def _parse_location(value: Any, field: str) -> RuntimeValueLocation:
    row = _mapping(value, field)
    return RuntimeValueLocation(
        location_id=_natural(
            row.get("location_id"), f"{field} location ID"
        ),
        kind=str(row.get("kind")),
        register=str(row.get("register")),
        offset=_natural(row.get("offset"), f"{field} offset"),
    )


def _parse_fact(value: Any, field: str) -> RuntimeValueFact:
    row = _mapping(value, field)
    return RuntimeValueFact(
        target_id=_natural(row.get("target_id"), f"{field} target ID"),
        location_id=_natural(
            row.get("location_id"), f"{field} location ID"
        ),
    )


def _parse_transfer(value: Any, field: str) -> RuntimeValueTransfer:
    row = _mapping(value, field)
    source_location = row.get("source_location_id")
    authority_contract = row.get("authority_contract_id")
    authority_callee = row.get("authority_callee_target_id")
    authority_term = row.get("authority_lean_term")
    authority_kernel_source = row.get("authority_kernel_source_sha256")
    authority_kernel_olean = row.get("authority_kernel_olean_sha256")
    return RuntimeValueTransfer(
        transfer_id=_natural(
            row.get("transfer_id"), f"{field} transfer ID"
        ),
        edge_index=_u32(row.get("edge_index"), f"{field} edge index"),
        source_target_id=_natural(
            row.get("source_target_id"), f"{field} source target ID"
        ),
        target_target_id=_natural(
            row.get("target_target_id"), f"{field} target target ID"
        ),
        kind=str(row.get("kind")),
        source_location_id=(
            None
            if source_location is None
            else _natural(source_location, f"{field} source location ID")
        ),
        target_location_id=_natural(
            row.get("target_location_id"),
            f"{field} target location ID",
        ),
        authority_status=str(row.get("authority_status")),
        authority_contract_id=(
            None
            if authority_contract is None
            else _u32(authority_contract, f"{field} authority contract ID")
        ),
        source_semantic_contract_sha256=_sha256(
            row.get("source_semantic_contract_sha256"),
            f"{field} source semantic contract SHA-256",
        ),
        source_instruction_bytes_sha256=_sha256(
            row.get("source_instruction_bytes_sha256"),
            f"{field} source instruction-bytes SHA-256",
        ),
        authority_origin=(
            None
            if row.get("authority_origin") is None
            else str(row.get("authority_origin"))
        ),
        authority_callee_target_id=(
            None
            if authority_callee is None
            else _natural(
                authority_callee, f"{field} authority callee target ID"
            )
        ),
        authority_lean_term=(
            None
            if authority_term is None
            else _lean_term(authority_term, f"{field} authority Lean term")
        ),
        authority_kernel_source_sha256=(
            None
            if authority_kernel_source is None
            else _sha256(
                authority_kernel_source,
                f"{field} authority kernel source SHA-256",
            )
        ),
        authority_kernel_olean_sha256=(
            None
            if authority_kernel_olean is None
            else _sha256(
                authority_kernel_olean,
                f"{field} authority kernel olean SHA-256",
            )
        ),
    )


def runtime_value_carry_ir_from_json(
    payload: Mapping[str, Any],
    *,
    graph: OriginalCutpointGraphIR,
    direct_call_authority: Mapping[str, Any],
) -> RuntimeValueCarryIR:
    if payload.get("format") != RUNTIME_VALUE_CARRY_IR_FORMAT:
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR has the wrong format"
        )
    inputs = _mapping(payload.get("inputs"), "runtime value-carry inputs")
    routes: list[RuntimeValueCarryRoute] = []
    for route_index, item in enumerate(
        _rows(payload.get("routes"), "runtime value-carry routes")
    ):
        row = _mapping(item, f"route {route_index}")
        routes.append(RuntimeValueCarryRoute(
            stable_id=_stable_id(
                row.get("stable_id"), f"route {route_index} stable ID"
            ),
            origin=_parse_origin(
                row.get("origin"), f"route {route_index} origin"
            ),
            locations=tuple(
                _parse_location(
                    location,
                    f"route {route_index} location {location_index}",
                )
                for location_index, location in enumerate(
                    _rows(
                        row.get("locations"),
                        f"route {route_index} locations",
                    )
                )
            ),
            facts=tuple(
                _parse_fact(
                    fact, f"route {route_index} fact {fact_index}"
                )
                for fact_index, fact in enumerate(
                    _rows(row.get("facts"), f"route {route_index} facts")
                )
            ),
            transfers=tuple(
                _parse_transfer(
                    transfer,
                    f"route {route_index} transfer {transfer_index}",
                )
                for transfer_index, transfer in enumerate(
                    _rows(
                        row.get("transfers"),
                        f"route {route_index} transfers",
                    )
                )
            ),
            target_fact=_parse_fact(
                row.get("target_fact"),
                f"route {route_index} target fact",
            ),
        ))
    value = RuntimeValueCarryIR(
        original_pe_sha256=_sha256(
            inputs.get("original_pe_sha256"), "original PE SHA-256"
        ),
        state_machine_sha256=_sha256(
            inputs.get("state_machine_sha256"),
            "state-machine SHA-256",
        ),
        cutpoint_graph_content_sha256=_sha256(
            inputs.get("cutpoint_graph_content_sha256"),
            "cutpoint graph content SHA-256",
        ),
        cutpoint_graph_artifact_sha256=_sha256(
            inputs.get("cutpoint_graph_artifact_sha256"),
            "cutpoint graph artifact SHA-256",
        ),
        direct_call_authority_sha256=_sha256(
            inputs.get("direct_call_authority_sha256"),
            "direct-call authority SHA-256",
        ),
        stack_dynamic_authority_sha256=_sha256(
            inputs.get("stack_dynamic_authority_sha256"),
            "stack/dynamic authority SHA-256",
        ),
        routes=tuple(routes),
    )
    if payload.get("proof_ready") is not value.proof_ready:
        raise RuntimeValueCarryIRError(
            "runtime value-carry proof-ready summary is stale"
        )
    for index, route in enumerate(value.routes):
        raw_route = _mapping(
            _rows(payload.get("routes"), "runtime value-carry routes")[index],
            f"route {index}",
        )
        if raw_route.get("proof_ready") is not route.proof_ready:
            raise RuntimeValueCarryIRError(
                f"route {route.stable_id} proof-ready summary is stale"
            )
    return validate_runtime_value_carry_ir(
        value,
        graph=graph,
        direct_call_authority=direct_call_authority,
    )


def load_runtime_value_carry_ir(
    path: Path | str,
    *,
    graph: OriginalCutpointGraphIR,
    graph_path: Path | str,
    direct_call_authority: Mapping[str, Any],
    direct_call_authority_path: Path | str,
    stack_dynamic_authority_path: Path | str,
) -> RuntimeValueCarryIR:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeValueCarryIRError(
            f"cannot read runtime value-carry IR: {error}"
        ) from error
    if not isinstance(payload, Mapping):
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR must be an object"
        )
    value = runtime_value_carry_ir_from_json(
        payload,
        graph=graph,
        direct_call_authority=direct_call_authority,
    )
    if value.cutpoint_graph_artifact_sha256 != sha256_file(Path(graph_path)):
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR does not match its graph file"
        )
    if value.direct_call_authority_sha256 != sha256_file(
        Path(direct_call_authority_path)
    ):
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR does not match its direct-call authority"
        )
    if value.stack_dynamic_authority_sha256 != sha256_file(
        Path(stack_dynamic_authority_path)
    ):
        raise RuntimeValueCarryIRError(
            "runtime value-carry IR does not match its stack/dynamic authority"
        )
    return value


__all__ = [
    "DIRECT_CALL_AUTHORITY_FORMAT",
    "RUNTIME_VALUE_CARRY_IR_FORMAT",
    "RuntimeValueCarryIR",
    "RuntimeValueCarryIRError",
    "RuntimeValueCarryRoute",
    "RuntimeValueFact",
    "RuntimeValueLocation",
    "RuntimeValueLeanTerm",
    "RuntimeValueOrigin",
    "RuntimeValueTransfer",
    "canonical_runtime_value_carry_ir_sha256",
    "load_runtime_value_carry_ir",
    "runtime_value_carry_ir_from_json",
    "validate_runtime_value_carry_ir",
]
