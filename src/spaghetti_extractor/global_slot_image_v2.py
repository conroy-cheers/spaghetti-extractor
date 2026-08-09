"""Exact PE launch-image evidence for writable global-slot invariants."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence

import pefile

from .authority_bindings_v2 import (
    BinaryBinding,
    EventBinding,
    ImageSpanBinding,
    UnitBinding,
)
from .global_slot_contract_v2 import GlobalSlotInvariant
from .machine_ir_authority_v2 import (
    recompute_event_binding,
    recompute_unit_binding,
)
from .mutable_slot_candidates_v2 import writable_image_span
from .stage_binary import StageABinary


class GlobalSlotImageV2Error(ValueError):
    """The requested span has no single supported loader initialization."""


def build_image_span_binding_v2(
    binary: StageABinary,
    *,
    machine_ir_sha256: str,
    rva_start: int,
    width_bytes: int,
) -> ImageSpanBinding:
    data, initialization_kind = loader_initial_bytes_v2(
        binary, rva_start=rva_start, width_bytes=width_bytes
    )
    relocation_kind = image_span_relocation_kind_v2(
        binary, rva_start=rva_start, width_bytes=width_bytes
    )
    return ImageSpanBinding(
        binary=BinaryBinding(binary.sha256, machine_ir_sha256),
        rva_start=rva_start,
        rva_end=rva_start + width_bytes,
        initial_bytes_sha256=sha256(data).hexdigest(),
        initialization_kind=initialization_kind,
        relocation_kind=relocation_kind,
    )


def validate_image_span_binding_v2(
    binding: ImageSpanBinding,
    *,
    binary: StageABinary,
    machine_ir_sha256: str,
) -> bytes:
    expected = build_image_span_binding_v2(
        binary,
        machine_ir_sha256=machine_ir_sha256,
        rva_start=binding.rva_start,
        width_bytes=binding.rva_end - binding.rva_start,
    )
    if binding != expected:
        raise GlobalSlotImageV2Error(
            "image-span binding differs from the exact PE launch image"
        )
    data, _kind = loader_initial_bytes_v2(
        binary,
        rva_start=binding.rva_start,
        width_bytes=binding.rva_end - binding.rva_start,
    )
    return data


def validate_global_slot_invariant_binding_v2(
    invariant: GlobalSlotInvariant,
    *,
    binary: StageABinary,
    machine_ir_sha256: str,
    units: Sequence[Mapping[str, Any]],
) -> None:
    """Replay one slot binding against the exact PE and machine-IR inventory."""

    expected_binary = BinaryBinding(binary.sha256, machine_ir_sha256)
    binding = invariant.binding
    if isinstance(binding, ImageSpanBinding):
        if binding.binary != expected_binary:
            raise GlobalSlotImageV2Error(
                "global-slot image span binds different binary artifacts"
            )
        validate_image_span_binding_v2(
            binding,
            binary=binary,
            machine_ir_sha256=machine_ir_sha256,
        )
    else:
        unit_binding = binding.unit if isinstance(binding, EventBinding) else binding
        if not isinstance(unit_binding, UnitBinding):
            raise GlobalSlotImageV2Error(
                "global-slot invariant has no supported exact binding"
            )
        if unit_binding.binary != expected_binary:
            raise GlobalSlotImageV2Error(
                "global-slot unit binds different binary artifacts"
            )
        units_by_id = {str(unit.get("id")): unit for unit in units}
        unit = units_by_id.get(unit_binding.unit_id)
        if unit is None:
            raise GlobalSlotImageV2Error(
                "global-slot unit binding is absent from exact machine IR"
            )
        try:
            expected_unit = recompute_unit_binding(unit, binary=expected_binary)
        except ValueError as exc:
            raise GlobalSlotImageV2Error(
                "global-slot unit binding cannot be replayed"
            ) from exc
        if unit_binding != expected_unit:
            raise GlobalSlotImageV2Error(
                "global-slot unit binding differs from exact machine IR"
            )
        if isinstance(binding, EventBinding):
            semantics = unit.get("semantics")
            events = (
                semantics.get("memory_events")
                if isinstance(semantics, Mapping)
                else None
            )
            if (
                not isinstance(events, list)
                or binding.event_index >= len(events)
                or not isinstance(events[binding.event_index], Mapping)
            ):
                raise GlobalSlotImageV2Error(
                    "global-slot event binding is absent from exact machine IR"
                )
            try:
                expected_event = recompute_event_binding(
                    expected_unit,
                    events[binding.event_index],
                    event_index=binding.event_index,
                )
            except ValueError as exc:
                raise GlobalSlotImageV2Error(
                    "global-slot event binding cannot be replayed"
                ) from exc
            if binding != expected_event:
                raise GlobalSlotImageV2Error(
                    "global-slot event binding differs from exact machine IR"
                )

    address = binary.image_base + invariant.slot_rva
    if not writable_image_span(binary, address, invariant.width_bytes):
        raise GlobalSlotImageV2Error(
            "global-slot invariant span is outside writable image memory"
        )


def loader_initial_bytes_v2(
    binary: StageABinary,
    *,
    rva_start: int,
    width_bytes: int,
) -> tuple[bytes, str]:
    if width_bytes <= 0 or rva_start < 0:
        raise GlobalSlotImageV2Error("image span is empty or negative")
    rva_end = rva_start + width_bytes
    if rva_end > binary.size_of_image:
        raise GlobalSlotImageV2Error("image span exceeds SizeOfImage")
    for section in binary.sections:
        if not (
            section.writable
            and section.rva_start <= rva_start
            and rva_end <= section.rva_end
        ):
            continue
        raw_end = section.rva_start + section.raw_size
        if rva_end <= raw_end:
            data = bytes(binary.pe.get_data(rva_start, width_bytes))
            if len(data) != width_bytes:
                raise GlobalSlotImageV2Error(
                    "PE parser did not return the exact initialized bytes"
                )
            return data, "file_bytes"
        if rva_start >= raw_end:
            return bytes(width_bytes), "zero_fill"
        raise GlobalSlotImageV2Error(
            "image span crosses file-backed and zero-fill initialization"
        )
    raise GlobalSlotImageV2Error(
        "image span is outside initialized writable PE memory"
    )


def image_span_relocation_kind_v2(
    binary: StageABinary,
    *,
    rva_start: int,
    width_bytes: int,
) -> str:
    overlapping = [
        (rva, relocation_type)
        for rva, relocation_type in _base_relocations(binary)
        if _overlaps(rva, _relocation_width(relocation_type), rva_start, width_bytes)
    ]
    if not overlapping:
        return "none"
    if overlapping == [(rva_start, 3)] and width_bytes == 4:
        return "pe32_highlow"
    raise GlobalSlotImageV2Error(
        "image span overlaps an unsupported or partial base relocation"
    )


def _base_relocations(binary: StageABinary) -> Iterable[tuple[int, int]]:
    try:
        binary.pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
            ]
        )
    except pefile.PEFormatError as exc:
        raise GlobalSlotImageV2Error(
            "PE base-relocation directory is malformed"
        ) from exc
    for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", ()):
        for entry in getattr(block, "entries", ()):
            relocation_type = getattr(entry, "type", None)
            rva = getattr(entry, "rva", None)
            if (
                isinstance(relocation_type, int)
                and relocation_type != 0
                and isinstance(rva, int)
            ):
                yield rva, relocation_type


def _relocation_width(relocation_type: int) -> int:
    return {1: 2, 2: 2, 3: 4, 4: 4}.get(relocation_type, 1)


def _overlaps(
    left_start: int, left_width: int, right_start: int, right_width: int
) -> bool:
    return left_start < right_start + right_width and right_start < left_start + left_width


__all__ = [
    "GlobalSlotImageV2Error",
    "build_image_span_binding_v2",
    "image_span_relocation_kind_v2",
    "loader_initial_bytes_v2",
    "validate_global_slot_invariant_binding_v2",
    "validate_image_span_binding_v2",
]
