"""Non-authorizing hypotheses for cyclic mutable-slot proofs.

Some indirect targets and call summaries form one SCC with the mutable image
slots that contain those targets.  This module may propose either the exact
loader value of a slot or a bounded value set at one exact read event.  The
proposals are not authority: the joint fixed-point driver must discard them
after the first round unless point-sensitive global-slot replay derives the
successor checked ``GlobalSlotInvariant`` inventory without proposal seeds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Mapping, Sequence

from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import AuthorityDataError, BinaryBinding, EventBinding
from .authority_record_core_v2 import FiniteAlternatives
from .global_slot_contract_v2 import GlobalSlotInvariant
from .global_slot_image_v2 import (
    GlobalSlotImageV2Error,
    build_image_span_binding_v2,
    loader_initial_bytes_v2,
)
from .mutable_slot_candidates_v2 import writable_image_span
from .machine_ir_authority_v2 import (
    MachineIRAuthorityV2Error,
    recompute_event_binding,
    recompute_unit_binding,
)
from .provenance_domain import PERSISTENT_ORIGIN_KINDS
from .stage_binary import StageABinary


GLOBAL_SLOT_INDUCTION_HYPOTHESIS_V2_FORMAT = (
    "spaghetti-extractor-global-slot-induction-hypothesis-v2"
)


class GlobalSlotHypothesisV2Error(ValueError):
    """A proposal cannot be represented as a bounded exact launch hypothesis."""


@dataclass(frozen=True)
class GlobalSlotInductionHypothesisV2:
    """One immutable proposal wrapper around a checked-record-shaped invariant."""

    invariant: GlobalSlotInvariant
    exit_ids: tuple[str, ...]
    dependency_sha256: str

    FORMAT: ClassVar[str] = GLOBAL_SLOT_INDUCTION_HYPOTHESIS_V2_FORMAT

    def __post_init__(self) -> None:
        if self.invariant.status.value != "complete":
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis must contain a complete typed invariant"
            )
        if (
            not isinstance(self.exit_ids, tuple)
            or not self.exit_ids
            or any(not isinstance(value, str) or not value for value in self.exit_ids)
            or self.exit_ids != tuple(sorted(set(self.exit_ids)))
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis exit inventory is not canonical"
            )
        if (
            not isinstance(self.dependency_sha256, str)
            or len(self.dependency_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.dependency_sha256)
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis dependency hash is invalid"
            )

    @property
    def id(self) -> str:
        return "global-slot-induction-hypothesis-v2:" + canonical_sha256(
            self._identity_payload()
        )

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "invariant_content_id": self.invariant.content_id,
            "slot_rva": self.invariant.slot_rva,
            "exit_ids": list(self.exit_ids),
            "dependency_sha256": self.dependency_sha256,
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.FORMAT,
            "id": self.id,
            "status": "prepared",
            "proof_authority": False,
            **self._identity_payload(),
            "invariant": self.invariant.to_payload(),
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "GlobalSlotInductionHypothesisV2":
        expected = {
            "format",
            "id",
            "status",
            "proof_authority",
            "invariant_content_id",
            "slot_rva",
            "exit_ids",
            "dependency_sha256",
            "invariant",
        }
        if set(value) != expected:
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis has an unexpected schema"
            )
        if (
            value.get("format") != cls.FORMAT
            or value.get("status") != "prepared"
            or value.get("proof_authority") is not False
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis is not explicitly non-authorizing"
            )
        raw_exits = value.get("exit_ids")
        raw_invariant = value.get("invariant")
        if (
            not isinstance(raw_exits, list)
            or not isinstance(raw_invariant, Mapping)
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis payload is malformed"
            )
        try:
            invariant = GlobalSlotInvariant.parse(raw_invariant)
        except (AuthorityDataError, TypeError, ValueError) as exc:
            raise GlobalSlotHypothesisV2Error(
                f"slot induction invariant does not parse: {exc}"
            ) from exc
        result = cls(
            invariant=invariant,
            exit_ids=tuple(raw_exits),
            dependency_sha256=str(value.get("dependency_sha256")),
        )
        if (
            value.get("id") != result.id
            or value.get("invariant_content_id") != invariant.content_id
            or value.get("slot_rva") != invariant.slot_rva
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis identity does not match its invariant"
            )
        return result


def derive_global_slot_induction_hypotheses_v2(
    binary: StageABinary,
    *,
    machine_ir_sha256: str,
    proposal_slot_dependencies: Sequence[Mapping[str, Any]],
    finite_value_budget: int = 32,
) -> tuple[GlobalSlotInductionHypothesisV2, ...]:
    """Derive exact launch-value hypotheses for proposal-dependent slots.

    Every dependency is checked structurally and against writable image memory.
    Unsupported loader spans fail closed rather than producing a weaker value.
    """

    if (
        not isinstance(finite_value_budget, int)
        or isinstance(finite_value_budget, bool)
        or finite_value_budget <= 0
    ):
        raise GlobalSlotHypothesisV2Error(
            "slot induction finite-value budget must be positive"
        )
    grouped: dict[int, list[dict[str, Any]]] = {}
    for index, raw in enumerate(proposal_slot_dependencies):
        row = _normalize_dependency(raw, index=index)
        slot_rva = int(row["slot_rva"])
        address = binary.image_base + slot_rva
        if not writable_image_span(binary, address, 4):
            raise GlobalSlotHypothesisV2Error(
                f"proposal slot dependency {slot_rva:#x} is not writable image data"
            )
        grouped.setdefault(slot_rva, []).append(row)

    result: list[GlobalSlotInductionHypothesisV2] = []
    for slot_rva, rows in sorted(grouped.items()):
        canonical_rows = sorted(
            {canonical_sha256(row): row for row in rows}.values(),
            key=canonical_sha256,
        )
        try:
            data, _initialization_kind = loader_initial_bytes_v2(
                binary,
                rva_start=slot_rva,
                width_bytes=4,
            )
            binding = build_image_span_binding_v2(
                binary,
                machine_ir_sha256=machine_ir_sha256,
                rva_start=slot_rva,
                width_bytes=4,
            )
        except GlobalSlotImageV2Error as exc:
            raise GlobalSlotHypothesisV2Error(
                f"proposal slot {slot_rva:#x} has no exact loader value: {exc}"
            ) from exc
        invariant = GlobalSlotInvariant(
            binding=binding,
            slot_rva=slot_rva,
            width_bytes=4,
            invariant_kind="finite_set",
            alternatives=FiniteAlternatives.of(
                [{
                    "kind": "exact_bits",
                    "value": int.from_bytes(data, "little"),
                    "width_bits": 32,
                }],
                maximum=finite_value_budget,
            ),
        )
        result.append(GlobalSlotInductionHypothesisV2(
            invariant=invariant,
            exit_ids=tuple(sorted({str(row["exit_id"]) for row in canonical_rows})),
            dependency_sha256=canonical_sha256(canonical_rows),
        ))
    return tuple(result)


def derive_event_bound_global_slot_induction_hypotheses_v2(
    binary: StageABinary,
    *,
    units: Sequence[Mapping[str, Any]],
    machine_ir_sha256: str,
    proposal_slot_dependencies: Sequence[Mapping[str, Any]],
    proposal_global_slot_analysis: Mapping[str, Any],
    finite_value_budget: int = 32,
) -> tuple[GlobalSlotInductionHypothesisV2, ...]:
    """Propose bounded values at exact reads from bootstrap slot replay.

    Bootstrap replay may know the finite values reaching a read while still
    marking that read tainted because unresolved calls prevent complete write
    coverage. For an indexed read, evidence for slot S means only that the
    loaded value is bounded when the exact read expression evaluates to S; it
    does not claim that the expression necessarily selects S. Those values are
    useful as an induction hypothesis for the
    mutually recursive call graph, but never as authority.  This function
    therefore binds each proposal to the exact machine-IR read event.  The
    joint fixed point uses it once and requires later unseeded replay to derive
    the actual checked invariant inventory.

    Missing, unreachable, tainted, or over-budget read evidence simply emits
    no hypothesis.  Contradictory exact identities fail closed.
    """

    if (
        not isinstance(finite_value_budget, int)
        or isinstance(finite_value_budget, bool)
        or finite_value_budget <= 0
    ):
        raise GlobalSlotHypothesisV2Error(
            "slot induction finite-value budget must be positive"
        )
    if not isinstance(proposal_global_slot_analysis, Mapping):
        raise GlobalSlotHypothesisV2Error(
            "proposal global-slot analysis is not an object"
        )

    binary_binding = BinaryBinding(binary.sha256, machine_ir_sha256)
    units_by_id: dict[str, Mapping[str, Any]] = {}
    unit_bindings = {}
    for index, raw_unit in enumerate(units):
        if not isinstance(raw_unit, Mapping):
            raise GlobalSlotHypothesisV2Error(
                f"machine-IR unit {index} is not an object"
            )
        unit_id = raw_unit.get("id")
        if not isinstance(unit_id, str) or not unit_id or unit_id in units_by_id:
            raise GlobalSlotHypothesisV2Error(
                "machine-IR unit inventory has a missing or duplicate ID"
            )
        try:
            binding = recompute_unit_binding(raw_unit, binary=binary_binding)
        except (MachineIRAuthorityV2Error, TypeError, ValueError) as exc:
            raise GlobalSlotHypothesisV2Error(
                f"machine-IR unit {unit_id!r} has no exact binding: {exc}"
            ) from exc
        units_by_id[unit_id] = raw_unit
        unit_bindings[unit_id] = binding

    evidence_by_address = _global_slot_evidence_by_address(
        proposal_global_slot_analysis
    )
    grouped: dict[tuple[int, str, int], list[dict[str, Any]]] = {}
    for index, raw in enumerate(proposal_slot_dependencies):
        row = _normalize_dependency(raw, index=index)
        if row.get("witness_only") is True:
            continue
        slot_rva = int(row["slot_rva"])
        address = binary.image_base + slot_rva
        if not writable_image_span(binary, address, 4):
            raise GlobalSlotHypothesisV2Error(
                f"proposal slot dependency {slot_rva:#x} is not writable image data"
            )
        unit_id = str(row["unit_id"])
        event_index = int(row["event_index"])
        unit = units_by_id.get(unit_id)
        if unit is None:
            raise GlobalSlotHypothesisV2Error(
                f"proposal slot dependency references unknown unit {unit_id!r}"
            )
        event = _memory_event_at(unit, event_index=event_index)
        if (
            event is None
            or event.get("kind") not in {"read", "read_write"}
            or event.get("width") != 4
        ):
            raise GlobalSlotHypothesisV2Error(
                "proposal slot dependency does not bind its exact 32-bit read"
            )
        event_address = _constant_u32(event.get("address"))
        if event_address is not None and event_address != address:
            raise GlobalSlotHypothesisV2Error(
                "proposal slot dependency contradicts its exact read address"
            )
        grouped.setdefault((slot_rva, unit_id, event_index), []).append(row)

    result: list[GlobalSlotInductionHypothesisV2] = []
    analysis_sha256 = canonical_sha256(proposal_global_slot_analysis)
    for (slot_rva, unit_id, event_index), rows in sorted(grouped.items()):
        address = binary.image_base + slot_rva
        evidence = evidence_by_address.get(address)
        if evidence is None:
            continue
        read = _exact_read_evidence(
            evidence,
            unit_id=unit_id,
            event_index=event_index,
        )
        if read is None:
            continue
        alternatives = _proposal_read_alternatives(
            read,
            finite_value_budget=finite_value_budget,
        )
        if alternatives is None:
            continue
        event = _exact_32bit_read_event(
            units_by_id[unit_id],
            event_index=event_index,
        )
        assert event is not None
        try:
            event_binding = recompute_event_binding(
                unit_bindings[unit_id],
                event,
                event_index=event_index,
            )
        except (MachineIRAuthorityV2Error, TypeError, ValueError) as exc:
            raise GlobalSlotHypothesisV2Error(
                f"proposal read {unit_id}:{event_index} has no exact binding: {exc}"
            ) from exc
        _check_read_site_binding(read, expected=event_binding)
        canonical_rows = sorted(
            {canonical_sha256(row): row for row in rows}.values(),
            key=canonical_sha256,
        )
        invariant = GlobalSlotInvariant(
            binding=event_binding,
            slot_rva=slot_rva,
            width_bytes=4,
            invariant_kind="finite_set_at_read",
            alternatives=FiniteAlternatives.of(
                alternatives,
                maximum=finite_value_budget,
            ),
        )
        result.append(GlobalSlotInductionHypothesisV2(
            invariant=invariant,
            exit_ids=tuple(sorted({str(row["exit_id"]) for row in canonical_rows})),
            dependency_sha256=canonical_sha256({
                "proposal_global_slot_analysis_sha256": analysis_sha256,
                "dependencies": canonical_rows,
                "read_site": {
                    "slot_rva": slot_rva,
                    "unit_id": unit_id,
                    "event_index": event_index,
                    "address_expression_sha256": canonical_sha256(
                        event.get("address")
                    ),
                },
                "alternatives": alternatives,
            }),
        ))
    return tuple(sorted(result, key=lambda item: item.id))


def _global_slot_evidence_by_address(
    analysis: Mapping[str, Any],
) -> dict[int, Mapping[str, Any]]:
    raw = analysis.get("global_slot_evidence")
    if not isinstance(raw, list):
        raise GlobalSlotHypothesisV2Error(
            "proposal global-slot evidence inventory is malformed"
        )
    result: dict[int, Mapping[str, Any]] = {}
    for index, evidence in enumerate(raw):
        address = evidence.get("address") if isinstance(evidence, Mapping) else None
        if (
            not isinstance(evidence, Mapping)
            or not isinstance(address, int)
            or isinstance(address, bool)
            or not 0 <= address <= 0xFFFF_FFFF
            or evidence.get("width", 4) != 4
        ):
            raise GlobalSlotHypothesisV2Error(
                f"proposal global-slot evidence {index} is malformed"
            )
        if address in result:
            raise GlobalSlotHypothesisV2Error(
                f"proposal global-slot evidence duplicates address {address:#x}"
            )
        result[address] = evidence
    return result


def _exact_32bit_read_event(
    unit: Mapping[str, Any],
    *,
    event_index: int,
) -> Mapping[str, Any] | None:
    event = _memory_event_at(unit, event_index=event_index)
    if (
        event is None
        or event.get("kind") not in {"read", "read_write"}
        or event.get("width") != 4
        or not isinstance(event.get("address"), Mapping)
    ):
        return None
    return event


def _memory_event_at(
    unit: Mapping[str, Any],
    *,
    event_index: int,
) -> Mapping[str, Any] | None:
    semantics = unit.get("semantics")
    events = semantics.get("memory_events") if isinstance(semantics, Mapping) else None
    if not isinstance(events, list) or event_index >= len(events):
        return None
    event = events[event_index]
    return event if isinstance(event, Mapping) else None


def _constant_u32(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    if str(value.get("op", "")).lower() not in {"const", "constant"}:
        return None
    concrete = value.get("value")
    if not isinstance(concrete, int) or isinstance(concrete, bool):
        return None
    return concrete & 0xFFFF_FFFF


def _exact_read_evidence(
    evidence: Mapping[str, Any],
    *,
    unit_id: str,
    event_index: int,
) -> Mapping[str, Any] | None:
    reads = evidence.get("read_inventory")
    if not isinstance(reads, list):
        raise GlobalSlotHypothesisV2Error(
            "proposal global-slot read inventory is malformed"
        )
    matches = [
        row
        for row in reads
        if isinstance(row, Mapping)
        and isinstance(row.get("site"), Mapping)
        and row["site"].get("unit_id") == unit_id
        and row["site"].get("event_index") == event_index
    ]
    if len(matches) > 1:
        raise GlobalSlotHypothesisV2Error(
            f"proposal global-slot read duplicates {unit_id}:{event_index}"
        )
    return None if not matches else matches[0]


def _proposal_read_alternatives(
    read: Mapping[str, Any],
    *,
    finite_value_budget: int,
) -> list[dict[str, Any]] | None:
    if read.get("status") == "violated":
        raise GlobalSlotHypothesisV2Error(
            "proposal global-slot read is contradictory"
        )
    state = read.get("state")
    if not isinstance(state, Mapping):
        raise GlobalSlotHypothesisV2Error(
            "proposal global-slot read state is malformed"
        )
    if (
        state.get("reachable") is not True
        or state.get("initialized") is not True
        or state.get("overflow") is not False
    ):
        return None
    raw = state.get("alternatives")
    if not isinstance(raw, list) or not raw or len(raw) > finite_value_budget:
        return None
    alternatives: list[dict[str, Any]] = []
    for index, alternative in enumerate(raw):
        if not isinstance(alternative, Mapping):
            raise GlobalSlotHypothesisV2Error(
                f"proposal read alternative {index} is malformed"
            )
        row = dict(alternative)
        if row.get("kind") == "exact_bits":
            value = row.get("value")
            if (
                set(row) != {"kind", "value", "width_bits"}
                or not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 0xFFFF_FFFF
                or row.get("width_bits") != 32
            ):
                raise GlobalSlotHypothesisV2Error(
                    f"proposal exact-bits alternative {index} is malformed"
                )
        elif (
            set(row) != {"kind", "key"}
            or row.get("kind") not in PERSISTENT_ORIGIN_KINDS
            or not isinstance(row.get("key"), list)
        ):
            raise GlobalSlotHypothesisV2Error(
                f"proposal read alternative {index} is not persistent"
            )
        alternatives.append(row)
    normalized = FiniteAlternatives.of(
        alternatives,
        maximum=finite_value_budget,
    )
    return [value.to_value() for value in normalized.values]


def _check_read_site_binding(
    read: Mapping[str, Any],
    *,
    expected: EventBinding,
) -> None:
    site = read.get("site")
    instruction_rva = site.get("instruction_rva") if isinstance(site, Mapping) else None
    if (
        not isinstance(site, Mapping)
        or set(site) != {"unit_id", "event_index", "instruction_rva"}
        or site.get("unit_id") != expected.unit.unit_id
        or site.get("event_index") != expected.event_index
        or instruction_rva != expected.instruction_rva
    ):
        raise GlobalSlotHypothesisV2Error(
            "proposal global-slot read site contradicts its exact event binding"
        )


def _normalize_dependency(raw: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise GlobalSlotHypothesisV2Error(
            f"proposal slot dependency {index} is not an object"
        )
    witness_only = raw.get("witness_only") is True
    expected = (
        {"slot_rva", "exit_id", "witness_only", "proof_authority"}
        if witness_only
        else {
            "slot_rva",
            "exit_id",
            "unit_id",
            "event_index",
            "proof_authority",
        }
    )
    slot_rva = raw.get("slot_rva")
    exit_id = raw.get("exit_id")
    if (
        set(raw) != expected
        or not isinstance(slot_rva, int)
        or isinstance(slot_rva, bool)
        or not 0 <= slot_rva <= 0xFFFF_FFFB
        or not isinstance(exit_id, str)
        or not exit_id
        or raw.get("proof_authority") is not False
    ):
        raise GlobalSlotHypothesisV2Error(
            f"proposal slot dependency {index} is malformed"
        )
    if not witness_only and (
        not isinstance(raw.get("unit_id"), str)
        or not raw.get("unit_id")
        or not isinstance(raw.get("event_index"), int)
        or isinstance(raw.get("event_index"), bool)
        or raw["event_index"] < 0
    ):
        raise GlobalSlotHypothesisV2Error(
            f"proposal slot dependency {index} has no exact read site"
        )
    return dict(raw)


__all__ = [
    "GLOBAL_SLOT_INDUCTION_HYPOTHESIS_V2_FORMAT",
    "GlobalSlotHypothesisV2Error",
    "GlobalSlotInductionHypothesisV2",
    "derive_event_bound_global_slot_induction_hypotheses_v2",
    "derive_global_slot_induction_hypotheses_v2",
]
