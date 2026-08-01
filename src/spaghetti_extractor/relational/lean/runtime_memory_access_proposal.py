"""Build non-authorizing runtime memory-partition checker inputs.

The exact target-effect declarations identify the checked normalized target
whose state-machine row is being inspected.  This module classifies address
expressions, but it never promotes that classification to proof authority.
Every emitted footprint must be rechecked against the exact declarations and
runtime state by Lean.  Unsupported or ambiguous expressions remain present
as explicit blockers.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import StageAInputError
from .gnu_hello_source_transition_index import (
    GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT,
)


RUNTIME_MEMORY_ACCESS_PROPOSAL_FORMAT = (
    "stage-a-runtime-memory-access-proposal-v1"
)
RUNTIME_MEMORY_PARTITION_CHECK_INPUTS_FORMAT = (
    "stage-a-runtime-memory-partition-check-inputs-v1"
)

_MIXED_ORIGINAL_FORMAT = "stage-a-interpreter-mixed-original-v1"
_STATE_MACHINE_FORMAT = "stage-b-state-machine-transfer-v1"
_U32_LIMIT = 1 << 32
_U32_MAX = _U32_LIMIT - 1
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_AFFINE_ADD = frozenset({"add", "add32"})
_AFFINE_SUB = frozenset({"sub", "sub32", "subtract"})
_DYNAMIC_BASE_OPS = frozenset(
    {
        "call_memory_load",
        "call_response",
        "env_response",
        "input_reg",
        "load",
        "read32",
        "reg",
    }
)


class RuntimeMemoryAccessProposalError(StageAInputError):
    """An exact input binding is malformed or internally inconsistent."""


@dataclass(frozen=True)
class GeneratedRuntimeMemoryAccessProposal:
    proposal: Path
    check_inputs: Path
    target_count: int
    write_count: int
    blocked_write_count: int
    ready_target_count: int


@dataclass(frozen=True)
class _StaticBinding:
    index: int
    rva: int
    va: int
    size: int

    @property
    def stop(self) -> int:
        return self.va + self.size

    def to_json(self) -> dict[str, int]:
        return {
            "binding_index": self.index,
            "rva": self.rva,
            "size": self.size,
            "va": self.va,
        }


@dataclass(frozen=True)
class _AffineAddress:
    base: Mapping[str, Any] | None
    constant_u32: int

    @property
    def signed_offset(self) -> int:
        if self.constant_u32 >= 1 << 31:
            return self.constant_u32 - _U32_LIMIT
        return self.constant_u32


def generate_runtime_memory_access_proposal(
    out: Path | str,
    *,
    state_machine: Path | str,
    mixed_original_plan: Path | str,
    source_target_effect_declarations: Path | str,
) -> GeneratedRuntimeMemoryAccessProposal:
    """Emit deterministic proposal data and hash-bound Lean checker inputs."""

    paths = {
        "mixed_original_plan": Path(mixed_original_plan),
        "source_target_effect_declarations": Path(
            source_target_effect_declarations
        ),
        "state_machine": Path(state_machine),
    }
    hashes = {name: _sha256(path, name) for name, path in paths.items()}
    artifact_binding_sha256 = _value_sha256(dict(sorted(hashes.items())))
    mixed = _load_object(paths["mixed_original_plan"], "mixed-original plan")
    declarations = _load_object(
        paths["source_target_effect_declarations"],
        "source target-effect declarations",
    )
    rows = _state_machine_rows(paths["state_machine"])

    _require_format(mixed, _MIXED_ORIGINAL_FORMAT, "mixed-original plan")
    _require_format(
        declarations,
        GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT,
        "source target-effect declarations",
    )
    state_hash = _digest(
        mixed.get("state_machine_sha256"),
        "mixed-original plan state_machine_sha256",
    )
    if state_hash != hashes["state_machine"]:
        raise RuntimeMemoryAccessProposalError(
            "mixed-original plan is not bound to the exact state machine"
        )

    targets = _declaration_targets(declarations)
    reachable = _natural_list(
        mixed.get("reachable_target_ids"),
        "mixed-original plan reachable_target_ids",
    )
    if reachable != sorted(set(reachable)):
        raise RuntimeMemoryAccessProposalError(
            "mixed-original reachable target identifiers must be sorted and unique"
        )
    target_ids = [target["target_id"] for target in targets]
    if target_ids != reachable:
        raise RuntimeMemoryAccessProposalError(
            "target-effect declarations differ from mixed-plan reachability"
        )
    counts = mixed.get("counts")
    if isinstance(counts, Mapping) and "reachable_targets" in counts:
        if _natural(
            counts["reachable_targets"],
            "mixed-original plan counts.reachable_targets",
        ) != len(targets):
            raise RuntimeMemoryAccessProposalError(
                "mixed-original reachable target count is inconsistent"
            )

    rows_by_rva: dict[int, tuple[int, dict[str, Any]]] = {}
    for line_number, row in rows:
        original = _object(
            row.get("original"), f"state-machine line {line_number}.original"
        )
        rva = _word(
            original.get("rva_start"),
            f"state-machine line {line_number}.original.rva_start",
        )
        if rva in rows_by_rva:
            raise RuntimeMemoryAccessProposalError(
                f"state machine contains duplicate source RVA 0x{rva:x}"
            )
        rows_by_rva[rva] = (line_number, row)

    static_bindings = _static_bindings(mixed)
    proposal_targets: list[dict[str, Any]] = []
    all_blockers: list[dict[str, Any]] = []
    class_counts: Counter[str] = Counter()
    write_count = 0
    blocked_write_ids: set[str] = set()

    for target in targets:
        target_id = target["target_id"]
        source_rva = target["source_rva"]
        located = rows_by_rva.get(source_rva)
        if located is None:
            raise RuntimeMemoryAccessProposalError(
                f"target {target_id} source RVA 0x{source_rva:x} is absent "
                "from the exact state machine"
            )
        line_number, row = located
        row_is_x87 = (
            row.get("fpu_state") is not None
            or row.get("instruction_effect_schedule") is not None
        )
        if row_is_x87 != (target["kind"] == "x87"):
            raise RuntimeMemoryAccessProposalError(
                f"target {target_id} semantic kind differs from its exact "
                "state-machine row"
            )

        raw_writes, extraction_blockers = _target_writes(
            row,
            target_kind=target["kind"],
            target_id=target_id,
            source_rva=source_rva,
            line_number=line_number,
        )
        writes: list[dict[str, Any]] = []
        target_blockers = list(extraction_blockers)
        for index, raw_write in enumerate(raw_writes):
            write_id = f"target-{target_id}-write-{index:04d}"
            width = _positive(
                raw_write.get("width"), f"{write_id}.width"
            )
            address = raw_write.get("address")
            provenance, classification_blockers = _classify_address(
                address,
                width,
                static_bindings,
            )
            class_counts[provenance["class"]] += 1
            write_blockers = [
                _blocker(
                    reason_code,
                    target_id=target_id,
                    source_rva=source_rva,
                    write_id=write_id,
                    detail=detail,
                )
                for reason_code, detail in classification_blockers
            ]
            if write_blockers:
                blocked_write_ids.add(write_id)
            target_blockers.extend(write_blockers)
            write = {
                "address_expression": address,
                "address_expression_sha256": _value_sha256(address),
                "checker_obligations": _checker_obligations(
                    provenance, width
                ),
                "event_sha256": raw_write["event_sha256"],
                "instruction_rva": raw_write.get("instruction_rva"),
                "provenance": provenance,
                "source": raw_write["source"],
                "source_index": raw_write["source_index"],
                "width": width,
                "write_id": write_id,
            }
            writes.append(write)
            write_count += 1

        aliasing = _aliasing_obligations(writes)
        target_blockers = sorted(
            target_blockers,
            key=lambda item: (
                item["reason_code"],
                item.get("write_id") or "",
                item["detail"],
            ),
        )
        all_blockers.extend(target_blockers)
        target_payload = {
            "aliasing_obligations": aliasing,
            "artifact_binding_sha256": artifact_binding_sha256,
            "blockers": target_blockers,
            "declaration_binding_sha256": _value_sha256(target["raw"]),
            "ready_for_lean_check": not target_blockers,
            "semantic_kind": target["kind"],
            "source_rva": source_rva,
            "state_machine_row_sha256": _value_sha256(row),
            "target_id": target_id,
            "writes": writes,
        }
        target_payload["requirement_sha256"] = _value_sha256(target_payload)
        proposal_targets.append(target_payload)

    all_blockers.sort(
        key=lambda item: (
            item["target_id"],
            item.get("write_id") or "",
            item["reason_code"],
            item["detail"],
        )
    )
    input_bindings = {
        name: {"path": path.name, "sha256": hashes[name]}
        for name, path in sorted(paths.items())
    }
    ready_targets = sum(
        bool(target["ready_for_lean_check"]) for target in proposal_targets
    )
    proposal_value = {
        "artifact_role": {
            "acceptance_authority": False,
            "classification_is_provisional": True,
            "lean_checker_must_recheck": True,
            "proof_authority": False,
            "proposal_only": True,
        },
        "blockers": all_blockers,
        "counts": {
            "blocked_writes": len(blocked_write_ids),
            "footprints_by_class": dict(sorted(class_counts.items())),
            "ready_targets": ready_targets,
            "targets": len(proposal_targets),
            "writes": write_count,
        },
        "format": RUNTIME_MEMORY_ACCESS_PROPOSAL_FORMAT,
        "artifact_binding_sha256": artifact_binding_sha256,
        "inputs": input_bindings,
        "protected_static_word_policy": {
            "accepted_resolutions": [
                "checked_byte_range_disjointness",
                "explicit_related_update",
            ],
            "disjointness_assumed_from_provenance": False,
            "inventory": "exact_original_static_word_inventory",
            "protected_word_width": 4,
            "requirement": "one resolution for every footprint and protected word",
        },
        "ready_for_lean_check": not all_blockers,
        "state_machine_sha256": hashes["state_machine"],
        "targets": proposal_targets,
    }

    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    proposal_path = root / "runtime-memory-access-proposal.json"
    _write_json(proposal_path, proposal_value)
    check_value = {
        "artifact_role": {
            "acceptance_authority": False,
            "checker_input_only": True,
            "proof_authority": False,
        },
        "blockers": all_blockers,
        "checker_contract": {
            "address_space_bits": 32,
            "no_unknown_footprints": True,
            "protected_word_predicate": "ByteWritesAvoidWord",
            "runtime_bounds_must_imply_no_wrap": True,
            "write_order_preserved_when_ranges_alias": True,
        },
        "format": RUNTIME_MEMORY_PARTITION_CHECK_INPUTS_FORMAT,
        "artifact_binding_sha256": artifact_binding_sha256,
        "inputs": input_bindings,
        "proposal": {
            "path": proposal_path.name,
            "sha256": _sha256(proposal_path, "runtime memory-access proposal"),
        },
        "ready_for_lean_check": not all_blockers,
        "targets": [
            {
                "ready_for_lean_check": target["ready_for_lean_check"],
                "artifact_binding_sha256": target[
                    "artifact_binding_sha256"
                ],
                "requirement_sha256": target["requirement_sha256"],
                "source_rva": target["source_rva"],
                "target_id": target["target_id"],
                "write_ids": [write["write_id"] for write in target["writes"]],
            }
            for target in proposal_targets
        ],
    }
    check_path = root / "runtime-memory-partition-check-inputs.json"
    _write_json(check_path, check_value)
    return GeneratedRuntimeMemoryAccessProposal(
        proposal=proposal_path,
        check_inputs=check_path,
        target_count=len(proposal_targets),
        write_count=write_count,
        blocked_write_count=len(blocked_write_ids),
        ready_target_count=ready_targets,
    )


def _declaration_targets(
    declarations: Mapping[str, Any],
) -> list[dict[str, Any]]:
    _string(declarations.get("namespace"), "declarations.namespace")
    _string(declarations.get("module_prefix"), "declarations.module_prefix")
    _positive(declarations.get("shard_span"), "declarations.shard_span")
    for index, module in enumerate(
        _list(declarations.get("imports"), "declarations.imports")
    ):
        name = _string(module, f"declarations.imports[{index}]")
        if _STAGE_A_MODULE.fullmatch(name) is None:
            raise RuntimeMemoryAccessProposalError(
                f"declarations.imports[{index}] must be a canonical StageA module"
            )
    for name in (
        "original_pe",
        "original_pe_exact",
        "original_side",
        "source_program_constructor",
        "world_program",
    ):
        _lean_ref(declarations.get(name), f"declarations.{name}")
    result: list[dict[str, Any]] = []
    for index, value in enumerate(
        _list(declarations.get("targets"), "declarations.targets")
    ):
        row = _object(value, f"declarations.targets[{index}]")
        target_id = _natural(
            row.get("target_id"), f"declarations.targets[{index}].target_id"
        )
        source_rva = _word(
            row.get("source_rva"), f"declarations.targets[{index}].source_rva"
        )
        kind = _string(row.get("kind"), f"declarations.targets[{index}].kind")
        evidence = _object(
            row.get("evidence"), f"declarations.targets[{index}].evidence"
        )
        if kind == "ordinary":
            required = {"checked_effect"}
        elif kind == "x87":
            required = {"facts", "successful_components"}
        else:
            raise RuntimeMemoryAccessProposalError(
                f"target {target_id} has unsupported semantic kind {kind!r}"
            )
        missing = sorted(required - set(evidence))
        if missing:
            raise RuntimeMemoryAccessProposalError(
                f"target {target_id} evidence is missing {', '.join(missing)}"
            )
        for name in sorted(required):
            _lean_ref(evidence[name], f"target {target_id} evidence.{name}")
        result.append(
            {
                "kind": kind,
                "raw": dict(row),
                "source_rva": source_rva,
                "target_id": target_id,
            }
        )
    ids = [target["target_id"] for target in result]
    rvas = [target["source_rva"] for target in result]
    if ids != sorted(set(ids)):
        raise RuntimeMemoryAccessProposalError(
            "target-effect identifiers must be sorted and unique"
        )
    if len(rvas) != len(set(rvas)):
        raise RuntimeMemoryAccessProposalError(
            "target-effect source RVAs must be unique"
        )
    return result


def _target_writes(
    row: Mapping[str, Any],
    *,
    target_kind: str,
    target_id: int,
    source_rva: int,
    line_number: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    top_writes = _memory_writes(
        row,
        source="normalized_memory_events",
        context=f"state-machine line {line_number}",
    )
    if target_kind == "ordinary":
        blockers = []
        if _has_conflicting_write_inventories(top_writes):
            blockers.append(
                _blocker(
                    "ambiguous_normalized_write_inventory",
                    target_id=target_id,
                    source_rva=source_rva,
                    detail=(
                        "normalized memory_events and ordered_events contain "
                        "different write footprints; both inventories are retained"
                    ),
                )
            )
        return top_writes, blockers

    schedule = row.get("instruction_effect_schedule")
    blockers: list[dict[str, Any]] = []
    if not isinstance(schedule, Mapping):
        blockers.append(
            _blocker(
                "x87_effect_schedule_missing",
                target_id=target_id,
                source_rva=source_rva,
                detail=(
                    "x87 target has no exact instruction effect schedule; a "
                    "physical store footprint cannot be inferred"
                ),
            )
        )
        return top_writes, blockers

    records = _list(schedule.get("records"), "x87 schedule.records")
    scheduled: list[dict[str, Any]] = []
    for record_index, value in enumerate(records):
        record = _object(value, f"x87 schedule.records[{record_index}]")
        effects = _object(
            record.get("effects"),
            f"x87 schedule.records[{record_index}].effects",
        )
        instruction_class = _string(
            record.get("instruction_class"),
            f"x87 schedule.records[{record_index}].instruction_class",
        )
        record_writes = _memory_writes(
            effects,
            source=(
                "x87_instruction_schedule"
                if instruction_class == "x87_singleton_checked_replay"
                else "scheduled_ordinary_instruction"
            ),
            context=f"x87 schedule.records[{record_index}].effects",
            instruction_rva=_word(
                record.get("rva_start"),
                f"x87 schedule.records[{record_index}].rva_start",
            ),
        )
        for write in record_writes:
            write["source_index"] = [record_index, write["source_index"]]
        scheduled.extend(record_writes)

    if _has_conflicting_write_inventories(scheduled):
        blockers.append(
            _blocker(
                "ambiguous_scheduled_write_inventory",
                target_id=target_id,
                source_rva=source_rva,
                detail=(
                    "an instruction schedule record has different memory_events "
                    "and ordered_events write footprints; both are retained"
                ),
            )
        )

    if top_writes and _write_projection(top_writes) != _write_projection(scheduled):
        blockers.append(
            _blocker(
                "ambiguous_x87_write_inventory",
                target_id=target_id,
                source_rva=source_rva,
                detail=(
                    "top-level and instruction-scheduled x87 write inventories "
                    "differ; both inventories are retained"
                ),
            )
        )
        scheduled.extend(top_writes)
    return scheduled, blockers


def _memory_writes(
    owner: Mapping[str, Any],
    *,
    source: str,
    context: str,
    instruction_rva: int | None = None,
) -> list[dict[str, Any]]:
    memory_events = owner.get("memory_events", [])
    ordered_events = owner.get("ordered_events", [])
    events = _list(memory_events, f"{context}.memory_events")
    ordered = _list(ordered_events, f"{context}.ordered_events")
    primary = _write_rows(
        events,
        source=source,
        context=f"{context}.memory_events",
        default_instruction_rva=instruction_rva,
    )
    ordered_writes = _write_rows(
        [
            event
            for event in ordered
            if isinstance(event, Mapping)
            and event.get("kind") == "write"
            and event.get("family", "memory") == "memory"
        ],
        source=f"{source}_ordered",
        context=f"{context}.ordered_events",
        default_instruction_rva=instruction_rva,
    )
    if not primary:
        return ordered_writes
    if not ordered_writes:
        return primary
    if _write_projection(primary) == _write_projection(ordered_writes):
        for primary_write, ordered_write in zip(primary, ordered_writes):
            if primary_write["instruction_rva"] is None:
                primary_write["instruction_rva"] = ordered_write[
                    "instruction_rva"
                ]
        return primary
    return primary + ordered_writes


def _write_rows(
    events: Sequence[object],
    *,
    source: str,
    context: str,
    default_instruction_rva: int | None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, value in enumerate(events):
        event = _object(value, f"{context}[{index}]")
        if event.get("kind") != "write":
            continue
        event_rva = event.get("instruction_rva", default_instruction_rva)
        if event_rva is not None:
            event_rva = _word(event_rva, f"{context}[{index}].instruction_rva")
        result.append(
            {
                "address": event.get("address"),
                "event_sha256": _value_sha256(event),
                "instruction_rva": event_rva,
                "source": source,
                "source_index": index,
                "value": event.get("value"),
                "width": event.get("width"),
            }
        )
    return result


def _write_projection(writes: Sequence[Mapping[str, Any]]) -> list[object]:
    return [
        {
            "address": write.get("address"),
            "value": write.get("value"),
            "width": write.get("width"),
        }
        for write in writes
    ]


def _has_conflicting_write_inventories(
    writes: Sequence[Mapping[str, Any]],
) -> bool:
    sources = {write.get("source") for write in writes}
    return any(
        isinstance(source, str)
        and source.endswith("_ordered")
        and source[: -len("_ordered")] in sources
        for source in sources
    )


def _classify_address(
    address: object,
    width: int,
    static_bindings: Sequence[_StaticBinding],
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    affine = _affine_address(address)
    if affine is None:
        return (
            {
                "class": "unknown",
                "reason": "address expression is not one unambiguous affine base plus offset",
            },
            [
                (
                    "unknown_write_address_provenance",
                    "write address is not a supported unambiguous affine expression",
                )
            ],
        )

    if affine.base is None:
        address_u32 = affine.constant_u32
        matching = [
            binding
            for binding in static_bindings
            if binding.va <= address_u32 < binding.stop
        ]
        blockers: list[tuple[str, str]] = []
        if len(matching) != 1:
            reason = (
                "concrete_write_matches_multiple_static_bindings"
                if len(matching) > 1
                else "concrete_write_not_in_declared_static_binding"
            )
            detail = (
                f"concrete write address 0x{address_u32:08x} does not select "
                "exactly one mixed-plan static binding"
            )
            blockers.append((reason, detail))
            if address_u32 + width > _U32_LIMIT:
                blockers.append(
                    (
                        "concrete_write_footprint_wraparound",
                        "concrete write footprint wraps the IA-32 address space",
                    )
                )
            return (
                {
                    "absolute_address": address_u32,
                    "class": "unknown",
                    "reason": "concrete address has no unique declared image/static slot",
                },
                blockers,
            )

        binding = matching[0]
        wraps = address_u32 + width > _U32_LIMIT
        within_binding = address_u32 + width <= binding.stop
        if wraps:
            blockers.append(
                (
                    "concrete_write_footprint_wraparound",
                    "concrete write footprint wraps the IA-32 address space",
                )
            )
        if not within_binding:
            blockers.append(
                (
                    "static_binding_headroom_insufficient",
                    "write footprint extends beyond its declared static binding",
                )
            )
        return (
            {
                "absolute_address": address_u32,
                "binding": binding.to_json(),
                "binding_offset": address_u32 - binding.va,
                "class": "image_static_slot",
                "footprint_end_exclusive": (
                    None if wraps else address_u32 + width
                ),
                "headroom": {
                    "bytes_after_footprint": max(
                        0, binding.stop - min(binding.stop, address_u32 + width)
                    ),
                    "bytes_before_footprint": address_u32 - binding.va,
                    "footprint_within_binding": within_binding,
                },
                "wraparound": {
                    "address_space_bits": 32,
                    "footprint_wraps": wraps,
                    "lean_check_required": True,
                },
            },
            blockers,
        )

    base = dict(affine.base)
    offset = affine.signed_offset
    base_register = _register_name(base)
    if base_register in {"esp", "ebp"}:
        provenance_class = "stack_range"
        partition = "runtime_stack"
    else:
        provenance_class = "dynamic_range"
        partition = "runtime_dynamic_range"
    base_min = max(0, -offset)
    base_max = min(_U32_MAX, _U32_LIMIT - width - offset)
    blockers = []
    if base_max < base_min:
        blockers.append(
            (
                "symbolic_write_has_no_nonwrapping_base",
                "no IA-32 base value can satisfy this offset and write width",
            )
        )
    provenance = {
        "base_expression": base,
        "base_expression_sha256": _value_sha256(base),
        "class": provenance_class,
        "headroom": {
            "bytes_before_base": max(0, -offset),
            "bytes_from_base": max(0, offset + width),
            "footprint_offset_end_exclusive": offset + width,
            "footprint_offset_start": offset,
        },
        "partition": partition,
        "signed_offset": offset,
        "wraparound": {
            "address_space_bits": 32,
            "base_max_inclusive": base_max,
            "base_min_inclusive": base_min,
            "condition": "base_min_inclusive <= base <= base_max_inclusive",
            "lean_check_required": True,
        },
    }
    if base_register in {"esp", "ebp"}:
        provenance["base_register"] = base_register
    return provenance, blockers


def _affine_address(value: object) -> _AffineAddress | None:
    if not isinstance(value, Mapping):
        return None
    op = value.get("op")
    if op == "const":
        constant = value.get("value")
        if (
            not isinstance(constant, int)
            or isinstance(constant, bool)
            or not 0 <= constant < _U32_LIMIT
        ):
            return None
        return _AffineAddress(None, constant)
    if op in _DYNAMIC_BASE_OPS:
        if op in {"reg", "input_reg"} and _register_name(value) is None:
            return None
        return _AffineAddress(dict(value), 0)
    if op not in _AFFINE_ADD | _AFFINE_SUB:
        return None
    args = value.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    left = _affine_address(args[0])
    right = _affine_address(args[1])
    if left is None or right is None:
        return None
    if op in _AFFINE_ADD:
        if left.base is not None and right.base is not None:
            return None
        return _AffineAddress(
            left.base if left.base is not None else right.base,
            (left.constant_u32 + right.constant_u32) & _U32_MAX,
        )
    if right.base is not None:
        return None
    return _AffineAddress(
        left.base,
        (left.constant_u32 - right.constant_u32) & _U32_MAX,
    )


def _checker_obligations(
    provenance: Mapping[str, Any], width: int
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "preserve_write_order_if_aliasing": True,
        "protected_static_words": {
            "accepted_resolutions": [
                "checked_byte_range_disjointness",
                "explicit_related_update",
            ],
            "footprint_width": width,
            "lean_predicate": "ByteWritesAvoidWord",
            "required_for_each_exact_protected_word": True,
        },
    }
    if provenance["class"] == "image_static_slot":
        result["static_binding"] = {
            "exact_binding_recheck_required": True,
            "headroom_recheck_required": True,
            "wraparound_recheck_required": True,
        }
    elif provenance["class"] in {"stack_range", "dynamic_range"}:
        result["runtime_partition"] = {
            "base_range_binding_required": True,
            "headroom_recheck_required": True,
            "partition": provenance["partition"],
            "wraparound_recheck_required": True,
        }
    else:
        result["classification"] = {
            "blocker_must_be_resolved_before_check": True
        }
    return result


def _aliasing_obligations(
    writes: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    symbolic = [
        write
        for write in writes
        if _object(write.get("provenance"), "write provenance").get("class")
        in {"stack_range", "dynamic_range"}
    ]
    result: list[dict[str, Any]] = []
    for left_index, left in enumerate(symbolic):
        left_provenance = _object(left["provenance"], "left provenance")
        for right in symbolic[left_index + 1 :]:
            right_provenance = _object(right["provenance"], "right provenance")
            same_base = (
                left_provenance["base_expression_sha256"]
                == right_provenance["base_expression_sha256"]
            )
            if same_base:
                left_start = left_provenance["signed_offset"]
                left_stop = left_start + _positive(left["width"], "left width")
                right_start = right_provenance["signed_offset"]
                right_stop = right_start + _positive(
                    right["width"], "right width"
                )
                if max(left_start, right_start) < min(left_stop, right_stop):
                    relation = "exact_overlap"
                elif left_stop == right_start or right_stop == left_start:
                    relation = "exact_adjacent"
                else:
                    relation = "exact_disjoint"
            else:
                relation = "runtime_base_relation_required"
            result.append(
                {
                    "disjointness_assumed": False,
                    "left_write_id": left["write_id"],
                    "relation": relation,
                    "right_write_id": right["write_id"],
                    "write_order_must_be_preserved_if_aliasing": True,
                }
            )
    return result


def _static_bindings(mixed: Mapping[str, Any]) -> list[_StaticBinding]:
    values = mixed.get("static_data_bindings", [])
    result: list[_StaticBinding] = []
    image_base: int | None = None
    for index, value in enumerate(
        _list(values, "mixed-original plan static_data_bindings")
    ):
        row = _object(value, f"static_data_bindings[{index}]")
        rva = _word(row.get("rva"), f"static_data_bindings[{index}].rva")
        va = _word(row.get("va"), f"static_data_bindings[{index}].va")
        size = _positive(
            row.get("size"), f"static_data_bindings[{index}].size"
        )
        if rva + size > _U32_LIMIT or va + size > _U32_LIMIT:
            raise RuntimeMemoryAccessProposalError(
                f"static_data_bindings[{index}] exceeds the IA-32 address space"
            )
        candidate_base = va - rva
        if candidate_base < 0:
            raise RuntimeMemoryAccessProposalError(
                f"static_data_bindings[{index}] VA precedes its RVA"
            )
        if image_base is None:
            image_base = candidate_base
        elif image_base != candidate_base:
            raise RuntimeMemoryAccessProposalError(
                "mixed-original static bindings imply different image bases"
            )
        result.append(_StaticBinding(index=index, rva=rva, va=va, size=size))
    return result


def _register_name(value: Mapping[str, Any]) -> str | None:
    name = value.get("name", value.get("register"))
    if not isinstance(name, str) or not name:
        return None
    return name.lower()


def _blocker(
    reason_code: str,
    *,
    target_id: int,
    source_rva: int,
    detail: str,
    write_id: str | None = None,
) -> dict[str, Any]:
    return {
        "detail": detail,
        "next_action": (
            "provide an exact runtime range/alias fact or an explicit related "
            "protected-word update and discharge it in the Lean checker"
        ),
        "reason_code": reason_code,
        "source_rva": source_rva,
        "target_id": target_id,
        "write_id": write_id,
    }


def _lean_ref(value: object, label: str) -> None:
    row = _object(value, label)
    if set(row) != {"module", "declaration"}:
        raise RuntimeMemoryAccessProposalError(
            f"{label} must contain exactly module and declaration"
        )
    module = _string(row["module"], f"{label}.module")
    declaration = _string(row["declaration"], f"{label}.declaration")
    if _STAGE_A_MODULE.fullmatch(module) is None:
        raise RuntimeMemoryAccessProposalError(
            f"{label}.module must be a canonical StageA module"
        )
    if _LEAN_NAME.fullmatch(declaration) is None:
        raise RuntimeMemoryAccessProposalError(
            f"{label}.declaration must be a qualified Lean name"
        )


def _state_machine_rows(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise RuntimeMemoryAccessProposalError(
            f"cannot read state machine: {error}"
        ) from error
    result: list[tuple[int, dict[str, Any]]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise RuntimeMemoryAccessProposalError(
                f"state-machine line {line_number} is invalid JSON: {error}"
            ) from error
        row = _object(value, f"state-machine line {line_number}")
        if row.get("stage_b_format") != _STATE_MACHINE_FORMAT:
            raise RuntimeMemoryAccessProposalError(
                f"state-machine line {line_number} has unsupported format"
            )
        result.append((line_number, dict(row)))
    if not result:
        raise RuntimeMemoryAccessProposalError("state machine must not be empty")
    return result


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeMemoryAccessProposalError(
            f"cannot read {label}: {error}"
        ) from error
    return dict(_object(value, label))


def _require_format(
    value: Mapping[str, Any], expected: str, label: str
) -> None:
    if value.get("format") != expected:
        raise RuntimeMemoryAccessProposalError(
            f"{label} has unsupported format {value.get('format')!r}"
        )


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeMemoryAccessProposalError(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise RuntimeMemoryAccessProposalError(
            f"{label} field names must be strings"
        )
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RuntimeMemoryAccessProposalError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeMemoryAccessProposalError(
            f"{label} must be a non-empty string"
        )
    return value


def _natural(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeMemoryAccessProposalError(
            f"{label} must be a non-negative integer"
        )
    return value


def _positive(value: object, label: str) -> int:
    result = _natural(value, label)
    if result == 0:
        raise RuntimeMemoryAccessProposalError(f"{label} must be positive")
    if result > _U32_LIMIT:
        raise RuntimeMemoryAccessProposalError(
            f"{label} exceeds the IA-32 address space"
        )
    return result


def _word(value: object, label: str) -> int:
    result = _natural(value, label)
    if result >= _U32_LIMIT:
        raise RuntimeMemoryAccessProposalError(f"{label} must fit in 32 bits")
    return result


def _natural_list(value: object, label: str) -> list[int]:
    return [_natural(item, f"{label}[]") for item in _list(value, label)]


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RuntimeMemoryAccessProposalError(
            f"{label} must be a canonical SHA-256 digest"
        )
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise RuntimeMemoryAccessProposalError(
            f"value is not canonical JSON: {error}"
        ) from error


def _value_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256(path: Path, label: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise RuntimeMemoryAccessProposalError(
            f"cannot read {label}: {error}"
        ) from error


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )


__all__ = [
    "GeneratedRuntimeMemoryAccessProposal",
    "RUNTIME_MEMORY_ACCESS_PROPOSAL_FORMAT",
    "RUNTIME_MEMORY_PARTITION_CHECK_INPUTS_FORMAT",
    "RuntimeMemoryAccessProposalError",
    "generate_runtime_memory_access_proposal",
]
