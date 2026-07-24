"""Discover exact framed external-tail/static-slot authority requests.

The scanner is proposal-only.  It recognizes a deliberately narrow PE32
shape, binds every field to the exact mixed-original inventory, and emits Lean
sources whose static authority is checked against the original PE context.
Runtime frame, environment, event, and candidate premises remain part of the
composition theorem and cannot be manufactured by this module.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import pefile

from ...errors import StageAInputError
from .external_tail_static_pointer_slot_composition import (
    ExternalImportIdentity,
    ExternalTailStaticPointerSlotStaticAuthorityBinding,
    external_tail_static_pointer_slot_static_authority_source,
)
from .interpreter_mixed_original import InterpreterMixedOriginalPlan


EXTERNAL_TAIL_STATIC_POINTER_SLOT_AUTHORITY_FORMAT = (
    "stage-a-external-tail-static-pointer-slot-authorities-v1"
)

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_PRESERVED = ("ebp", "ebx", "edi", "esi")
_CLOBBERED = ("eax", "ecx", "edx")


class ExternalTailStaticPointerSlotProposalError(StageAInputError):
    """The authority proposal inputs are malformed or inconsistent."""


@dataclass(frozen=True)
class ExternalTailStaticPointerSlotProposalBlocker:
    category: str
    location_rva: int | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "detail": self.detail,
            "location_rva": self.location_rva,
        }


@dataclass(frozen=True)
class ExternalTailStaticPointerSlotAuthorityPlan:
    original_sha256: str
    state_machine_sha256: str
    machine_import_report_sha256: str
    mixed_original_blocker_count: int
    bindings: tuple[
        ExternalTailStaticPointerSlotStaticAuthorityBinding, ...
    ]
    blockers: tuple[ExternalTailStaticPointerSlotProposalBlocker, ...]
    remaining_site_classes: tuple[tuple[str, int], ...]

    @property
    def matching_mixed_original_frontiers(self) -> int:
        covered = {
            binding.source_rva for binding in self.bindings
        } | {
            binding.wrapper_rva for binding in self.bindings
        }
        return sum(
            1 for blocker in self.blockers
            if blocker.category == "mixed_original_frontier"
            and blocker.location_rva in covered
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "format": EXTERNAL_TAIL_STATIC_POINTER_SLOT_AUTHORITY_FORMAT,
            "inputs": {
                "machine_import_report_sha256": (
                    self.machine_import_report_sha256
                ),
                "original_sha256": self.original_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "authority": {
                "acceptance_authority": False,
                "source": "named Lean terms only",
            },
            "sites": [
                {
                    "authorizing_lean_term": {
                        "module": (
                            "StageA."
                            f"GeneratedRelationalExternalTailStaticPointerSlotAuthority"
                            f"{binding.site_id:04d}"
                        ),
                        "namespace": binding.namespace,
                        "symbol": "generatedStaticAuthority",
                    },
                    "call_instruction_size": binding.call_instruction_size,
                    "callsite_rva": binding.callsite_rva,
                    "continuation_rva": binding.continuation_rva,
                    "continuation_target_id": (
                        binding.continuation_target_id
                    ),
                    "import": {
                        "dll": binding.imported.dll,
                        "ordinal": binding.imported.ordinal,
                        "symbol": binding.imported.symbol,
                    },
                    "iat_rva": binding.iat_rva,
                    "machine_contract_id": binding.machine_contract_id,
                    "profile": "framed_external_tail_static_pointer_slot_v1",
                    "route_kind": binding.route_kind,
                    "site_id": binding.site_id,
                    "slot_rva": binding.slot_rva,
                    "slot_target_id": binding.slot_target_id,
                    "slot_value": binding.slot_value,
                    "source_rva": binding.source_rva,
                    "source_target_id": binding.source_target_id,
                    "wrapper_rva": binding.wrapper_rva,
                    "wrapper_target_id": binding.wrapper_target_id,
                }
                for binding in self.bindings
            ],
            "blockers": [blocker.to_json() for blocker in self.blockers],
            "counts": {
                "authority_terms": len(self.bindings),
                "consumed_authority_terms": 0,
                "matching_mixed_original_frontiers": (
                    self.matching_mixed_original_frontiers
                ),
                "mixed_original_blockers_after": self.mixed_original_blocker_count,
                "mixed_original_blockers_before": (
                    self.mixed_original_blocker_count
                ),
            },
            "remaining_site_classes": {
                name: count for name, count in self.remaining_site_classes
            },
        }


def construct_external_tail_static_pointer_slot_authorities(
    *,
    original_pe: Path | str,
    state_machine: Path | str,
    machine_import_report: Path | str,
    mixed_original_plan: InterpreterMixedOriginalPlan,
    context_term: str,
    original_context_term: str,
    original_decoded_authority_term: str,
    original_module: str,
) -> ExternalTailStaticPointerSlotAuthorityPlan:
    """Find every exact site supported by the framed-tail profile."""

    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    report_path = Path(machine_import_report)
    original_sha256 = _sha256(pe_path)
    state_sha256 = _sha256(state_path)
    report_sha256 = _sha256(report_path)
    if mixed_original_plan.state_machine_sha256 != state_sha256:
        raise ExternalTailStaticPointerSlotProposalError(
            "mixed-original plan is not bound to the exact state machine"
        )

    report = _object(report_path)
    inputs = _mapping(report.get("inputs"), "machine import report inputs")
    if (
        inputs.get("original_sha256") != original_sha256
        or inputs.get("state_machine_sha256") != state_sha256
    ):
        raise ExternalTailStaticPointerSlotProposalError(
            "machine import report hashes do not match the exact inputs"
        )
    rows = _jsonl_by_rva(state_path)
    signatures = {
        _natural(row.get("id"), "signature id"): row
        for row in _object_list(report.get("signatures"), "signatures")
    }
    regions = {region.rva: region for region in mixed_original_plan.regions}
    blockers: list[ExternalTailStaticPointerSlotProposalBlocker] = []
    bindings: list[ExternalTailStaticPointerSlotStaticAuthorityBinding] = []

    pe = pefile.PE(str(pe_path), fast_load=False)
    try:
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        for boundary in _object_list(report.get("boundaries"), "boundaries"):
            if boundary.get("route") != "framed_thunk_tail":
                continue
            try:
                binding = _binding_for_boundary(
                    pe=pe,
                    image_base=image_base,
                    rows=rows,
                    regions=regions,
                    signatures=signatures,
                    boundary=boundary,
                    context_term=context_term,
                    original_context_term=original_context_term,
                    original_decoded_authority_term=(
                        original_decoded_authority_term
                    ),
                    original_module=original_module,
                )
            except ExternalTailStaticPointerSlotProposalError as error:
                location = boundary.get("source_rva")
                blockers.append(
                    ExternalTailStaticPointerSlotProposalBlocker(
                        "unsupported_framed_external_tail",
                        location if isinstance(location, int) else None,
                        str(error),
                    )
                )
                continue
            bindings.append(binding)
    finally:
        pe.close()

    frontier_classes = Counter(
        blocker.detail.split(" at ", 1)[0]
        for blocker in mixed_original_plan.blockers
    )
    blockers.extend(
        ExternalTailStaticPointerSlotProposalBlocker(
            "mixed_original_frontier", blocker.rva, blocker.detail
        )
        for blocker in mixed_original_plan.blockers
    )
    return ExternalTailStaticPointerSlotAuthorityPlan(
        original_sha256=original_sha256,
        state_machine_sha256=state_sha256,
        machine_import_report_sha256=report_sha256,
        mixed_original_blocker_count=len(mixed_original_plan.blockers),
        bindings=tuple(sorted(bindings, key=lambda item: item.site_id)),
        blockers=tuple(blockers),
        remaining_site_classes=tuple(sorted(frontier_classes.items())),
    )


def write_external_tail_static_pointer_slot_authorities(
    out: Path | str,
    plan: ExternalTailStaticPointerSlotAuthorityPlan,
) -> tuple[Path, tuple[Path, ...]]:
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    sources: list[Path] = []
    for binding in plan.bindings:
        path = (
            stage_a
            / (
                "GeneratedRelationalExternalTailStaticPointerSlotAuthority"
                f"{binding.site_id:04d}.lean"
            )
        )
        path.write_text(
            external_tail_static_pointer_slot_static_authority_source(binding),
            encoding="utf-8",
        )
        sources.append(path)
    report = root / "external-tail-static-pointer-slot-authorities.json"
    report.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report, tuple(sources)


def _binding_for_boundary(
    *,
    pe: pefile.PE,
    image_base: int,
    rows: Mapping[int, Mapping[str, Any]],
    regions: Mapping[int, Any],
    signatures: Mapping[int, Mapping[str, Any]],
    boundary: Mapping[str, Any],
    context_term: str,
    original_context_term: str,
    original_decoded_authority_term: str,
    original_module: str,
) -> ExternalTailStaticPointerSlotStaticAuthorityBinding:
    site_id = _natural(boundary.get("id"), "boundary id")
    source_rva = _natural(boundary.get("source_rva"), "source_rva")
    wrapper_rva = _natural(boundary.get("frame_entry_rva"), "frame_entry_rva")
    callsite_rva = _natural(
        boundary.get("instruction_rva"), "instruction_rva"
    )
    continuation_rva = _natural(
        boundary.get("continuation_rva"), "continuation_rva"
    )
    source = _region(regions, source_rva, "source")
    wrapper = _region(regions, wrapper_rva, "wrapper")
    continuation = _region(regions, continuation_rva, "continuation")
    if (
        boundary.get("source_size") != source.size
        or boundary.get("frame_entry_size") != wrapper.size
        or boundary.get("tail_rva") != wrapper_rva
        or boundary.get("tail_size") != wrapper.size
    ):
        raise ExternalTailStaticPointerSlotProposalError(
            "boundary spans differ from the exact mixed-original regions"
        )
    for label, region in (
        ("source", source),
        ("wrapper", wrapper),
        ("continuation", continuation),
    ):
        if region.alias_rvas:
            raise ExternalTailStaticPointerSlotProposalError(
                f"{label} code target has aliases"
            )

    source_row = _row(rows, source_rva, "source")
    wrapper_row = _row(rows, wrapper_rva, "wrapper")
    instruction = next(
        (
            item
            for item in _object_list(
                source_row.get("instructions"), "source instructions"
            )
            if item.get("rva") == callsite_rva
        ),
        None,
    )
    if instruction is None or instruction.get("mnemonic") != "call":
        raise ExternalTailStaticPointerSlotProposalError(
            "source boundary lacks the exact direct call instruction"
        )
    call_size = _natural(instruction.get("size"), "call instruction size")
    if callsite_rva + call_size != continuation_rva:
        raise ExternalTailStaticPointerSlotProposalError(
            "direct call does not end at the declared continuation"
        )
    call_event = next(
        (
            item
            for item in _object_list(
                source_row.get("ordered_events"), "source ordered events"
            )
            if item.get("kind") == "internal_call"
            and item.get("instruction_rva") == callsite_rva
        ),
        None,
    )
    if (
        call_event is None
        or call_event.get("target_rva") != wrapper_rva
        or call_event.get("return_rva") != continuation_rva
    ):
        raise ExternalTailStaticPointerSlotProposalError(
            "source call event does not bind the wrapper and continuation"
        )
    stack_inputs = _object_list(call_event.get("stack_inputs"), "stack inputs")
    if len(stack_inputs) != 1 or stack_inputs[0].get("offset") != 0:
        raise ExternalTailStaticPointerSlotProposalError(
            "framed tail requires one exact caller stack argument"
        )
    slot_value = _constant(stack_inputs[0].get("value"))
    if slot_value is None:
        raise ExternalTailStaticPointerSlotProposalError(
            "caller frame argument is not one exact code pointer"
        )
    target_rva = slot_value - image_base
    target = _region(regions, target_rva, "slot code target")
    if target.alias_rvas:
        raise ExternalTailStaticPointerSlotProposalError(
            "slot code target has aliases"
        )

    imported = _import_identity(boundary.get("import"))
    outcome = _mapping(wrapper_row.get("outcome"), "wrapper outcome")
    if (
        outcome.get("kind") != "external_jump"
        or _import_identity(outcome) != imported
    ):
        raise ExternalTailStaticPointerSlotProposalError(
            "wrapper is not an exact direct imported tail"
        )
    writes = [
        item
        for item in _object_list(
            wrapper_row.get("memory_events"), "wrapper memory events"
        )
        if item.get("kind") == "write"
        and _constant(item.get("address")) is not None
    ]
    slot_writes = [
        item for item in writes
        if item.get("width") == 4
        and _expression_stack_word(item.get("value"), 4)
    ]
    if len(slot_writes) != 1:
        raise ExternalTailStaticPointerSlotProposalError(
            "wrapper does not copy frame argument +4 to one static word"
        )
    slot_va = _constant(slot_writes[0].get("address"))
    assert slot_va is not None
    slot_rva = slot_va - image_base
    _check_initial_writable_zero_slot(pe, slot_rva)

    signature_id = _natural(boundary.get("signature_id"), "signature id")
    signature = signatures.get(signature_id)
    if signature is None:
        raise ExternalTailStaticPointerSlotProposalError(
            "boundary references an absent machine-call signature"
        )
    if _import_identity(signature.get("import")) != imported:
        raise ExternalTailStaticPointerSlotProposalError(
            "boundary and signature import identities differ"
        )
    arity = _mapping(signature.get("arity"), "signature arity")
    if arity.get("kind") != "fixed":
        raise ExternalTailStaticPointerSlotProposalError(
            "framed external tail requires a fixed machine arity"
        )
    words = _natural(arity.get("words"), "signature arity words")
    if words != boundary.get("argument_words"):
        raise ExternalTailStaticPointerSlotProposalError(
            "boundary argument count differs from its signature"
        )
    if signature.get("callback_mode") == "nestedFrames":
        raise ExternalTailStaticPointerSlotProposalError(
            "nested callback behavior is outside this macro profile"
        )
    footprints = _object_list(
        signature.get("memory_footprints"), "memory footprints"
    )
    if any(item.get("access") == "write" for item in footprints):
        raise ExternalTailStaticPointerSlotProposalError(
            "external write footprint requires a separate slot-disjointness proof"
        )
    abi = signature.get("abi")
    if abi not in {"cdecl", "stdcall"}:
        raise ExternalTailStaticPointerSlotProposalError(
            "unsupported machine-call ABI"
        )
    stack_delta = words * 4 if abi == "stdcall" else 0
    namespace = (
        "StageA.Generated.ExternalTailStaticPointerSlotAuthority"
        f"{site_id:04d}"
    )
    return ExternalTailStaticPointerSlotStaticAuthorityBinding(
        context_term=context_term,
        original_context_term=original_context_term,
        original_decoded_authority_term=original_decoded_authority_term,
        source_target_id=source.target_id,
        wrapper_target_id=wrapper.target_id,
        continuation_target_id=continuation.target_id,
        source_rva=source_rva,
        callsite_rva=callsite_rva,
        call_instruction_size=call_size,
        wrapper_rva=wrapper_rva,
        continuation_rva=continuation_rva,
        route_kind="direct_import",
        iat_rva=None,
        slot_rva=slot_rva,
        slot_target_id=target.target_id,
        slot_value=slot_value,
        site_id=site_id,
        machine_contract_id=signature_id,
        imported=imported,
        original_frame_argument_offset=4,
        candidate_frame_argument_offset=4,
        stack_argument_offsets=tuple(index * 4 for index in range(words)),
        stack_result_delta=stack_delta,
        preserved_registers=_PRESERVED,
        clobbered_registers=_CLOBBERED,
        source_region_index=source.target_id,
        wrapper_region_index=wrapper.target_id,
        continuation_region_index=continuation.target_id,
        imports=(original_module,),
        namespace=namespace,
    ).checked()


def _check_initial_writable_zero_slot(pe: pefile.PE, slot_rva: int) -> None:
    if slot_rva < 0 or slot_rva % 4:
        raise ExternalTailStaticPointerSlotProposalError(
            "static slot is not an aligned PE32 RVA"
        )
    section = next(
        (
            section
            for section in pe.sections
            if int(section.VirtualAddress) <= slot_rva
            and slot_rva + 4
            <= int(section.VirtualAddress)
            + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        ),
        None,
    )
    if section is None:
        raise ExternalTailStaticPointerSlotProposalError(
            "static slot is outside mapped PE sections"
        )
    characteristics = int(section.Characteristics)
    if (
        not characteristics & _IMAGE_SCN_MEM_WRITE
        or characteristics & _IMAGE_SCN_MEM_EXECUTE
    ):
        raise ExternalTailStaticPointerSlotProposalError(
            "static slot is not writable non-executable data"
        )
    if int.from_bytes(bytes(pe.get_data(slot_rva, 4)), "little") != 0:
        raise ExternalTailStaticPointerSlotProposalError(
            "static slot is not initially zero"
        )
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ()):
        if any(
            int(entry.rva) < slot_rva + 4
            and slot_rva < int(entry.rva) + 4
            for entry in block.entries
            if int(entry.type) != 0
        ):
            raise ExternalTailStaticPointerSlotProposalError(
                "static slot overlaps a loader relocation"
            )


def _expression_stack_word(value: Any, offset: int) -> bool:
    if not isinstance(value, Mapping) or value.get("op") != "load":
        return False
    address = value.get("address")
    if not isinstance(address, Mapping) or address.get("op") != "add32":
        return False
    args = address.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return False
    return (
        _constant(args[0]) == offset
        and isinstance(args[1], Mapping)
        and args[1].get("op") == "reg"
        and args[1].get("name") == "esp"
    )


def _region(regions: Mapping[int, Any], rva: int, label: str):
    result = regions.get(rva)
    if result is None:
        raise ExternalTailStaticPointerSlotProposalError(
            f"{label} RVA 0x{rva:x} is not an exact code target"
        )
    return result


def _row(
    rows: Mapping[int, Mapping[str, Any]], rva: int, label: str
) -> Mapping[str, Any]:
    result = rows.get(rva)
    if result is None:
        raise ExternalTailStaticPointerSlotProposalError(
            f"{label} RVA 0x{rva:x} has no exact state-machine row"
        )
    return result


def _import_identity(value: Any) -> ExternalImportIdentity:
    row = _mapping(value, "import identity")
    dll = row.get("dll")
    symbol = row.get("symbol")
    ordinal = row.get("ordinal")
    if not isinstance(dll, str):
        raise ExternalTailStaticPointerSlotProposalError(
            "import identity has no DLL"
        )
    if symbol is not None and not isinstance(symbol, str):
        raise ExternalTailStaticPointerSlotProposalError(
            "import symbol is malformed"
        )
    if ordinal is not None and not isinstance(ordinal, int):
        raise ExternalTailStaticPointerSlotProposalError(
            "import ordinal is malformed"
        )
    return ExternalImportIdentity(
        dll=dll.lower(), symbol=symbol, ordinal=ordinal
    ).checked()


def _jsonl_by_rva(path: Path) -> dict[int, Mapping[str, Any]]:
    result: dict[int, Mapping[str, Any]] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        row = _mapping(json.loads(line), f"state-machine line {line_number}")
        original = _mapping(row.get("original"), "original span")
        rva = _natural(original.get("rva_start"), "original RVA")
        if rva in result:
            raise ExternalTailStaticPointerSlotProposalError(
                f"duplicate state-machine RVA 0x{rva:x}"
            )
        result[rva] = row
    return result


def _object(path: Path) -> Mapping[str, Any]:
    try:
        return _mapping(
            json.loads(path.read_text(encoding="utf-8")), str(path)
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ExternalTailStaticPointerSlotProposalError(
            f"cannot read {path}: {error}"
        ) from error


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExternalTailStaticPointerSlotProposalError(
            f"{label} must be an object"
        )
    return value


def _object_list(value: Any, label: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, Mapping) for item in value
    ):
        raise ExternalTailStaticPointerSlotProposalError(
            f"{label} must be a list of objects"
        )
    return tuple(value)


def _natural(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExternalTailStaticPointerSlotProposalError(
            f"{label} must be a natural number"
        )
    return value


def _constant(value: Any) -> int | None:
    if (
        isinstance(value, Mapping)
        and value.get("op") == "const"
        and isinstance(value.get("value"), int)
    ):
        return int(value["value"])
    return None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "EXTERNAL_TAIL_STATIC_POINTER_SLOT_AUTHORITY_FORMAT",
    "ExternalTailStaticPointerSlotAuthorityPlan",
    "ExternalTailStaticPointerSlotProposalBlocker",
    "ExternalTailStaticPointerSlotProposalError",
    "construct_external_tail_static_pointer_slot_authorities",
    "write_external_tail_static_pointer_slot_authorities",
]
