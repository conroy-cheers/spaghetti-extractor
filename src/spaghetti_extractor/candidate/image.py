"""Derive candidate-generation inputs from an exact static analysis load-image contract."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..external.machine_import_profiles import load_machine_import_profile_set
from ..roundtrip_fuzz.image_io import (
    load_spx_load_image_contract,
)
from ..errors import ToolkitInputError
from .imports import NativeImportSlot, NativeImportSlotIndex


_DYNAMIC_BASE = 0x0040


@dataclass(frozen=True)
class NativeImageInputs:
    entry_rva: int
    image_base: int
    fixed_image_base: int | None
    import_slots: tuple[NativeImportSlot, ...]
    tls_callback_targets: tuple[Mapping[str, Any], ...]
    base_relocation_evidence: Mapping[str, Any] | None
    initial_zero_ranges: tuple[tuple[int, int], ...]


def derive_native_image_inputs(
    *,
    load_image_contract: Path | str,
    static_program_contract_sha256: str | None = None,
) -> NativeImageInputs:
    contract = load_spx_load_image_contract(Path(load_image_contract))
    headers = contract.runtime_headers.data
    if len(headers) < 0x40:
        raise ToolkitInputError("load-image runtime headers are truncated")
    pe_offset = struct.unpack_from("<I", headers, 0x3C)[0]
    optional_offset = pe_offset + 24
    if optional_offset + 72 > len(headers):
        raise ToolkitInputError("load-image optional header is truncated")
    if struct.unpack_from("<H", headers, optional_offset)[0] != 0x10B:
        raise ToolkitInputError("native candidate requires a PE32 optional header")
    dll_characteristics = struct.unpack_from("<H", headers, optional_offset + 70)[0]
    dynamic_base = bool(dll_characteristics & _DYNAMIC_BASE)

    imports: list[NativeImportSlot] = []
    for descriptor in contract.imports:
        for cell in descriptor.cells:
            identity: str | int | None = (
                cell.symbol if cell.symbol is not None else cell.ordinal
            )
            if identity is None:
                raise ToolkitInputError("load-image import cell has no identity")
            imports.append(NativeImportSlot(
                image_id=contract.identity.pe_sha256,
                descriptor_index=descriptor.index,
                cell_index=cell.index,
                dll=descriptor.dll.lower(),
                symbol=cell.symbol,
                ordinal=cell.ordinal,
                iat_rva=cell.iat_rva,
                iat_va=contract.identity.preferred_base + cell.iat_rva,
            ))
    import_index = NativeImportSlotIndex.create(imports)

    relocation_rows = [
        {
            "source_rva": relocation.target_rva,
            "type": relocation.type,
            "kind": relocation.kind,
            "width": relocation.width,
            "preferred_value": relocation.preferred_value,
        }
        for block in contract.relocations
        for relocation in block.relocations
        if relocation.target_rva is not None
        and relocation.preferred_value is not None
        and relocation.width > 0
    ]
    if relocation_rows:
        if static_program_contract_sha256 is None:
            raise ToolkitInputError(
                "relocatable native image inputs require a static-program SHA-256"
            )
        fixed_image_base = None
        relocation_evidence: Mapping[str, Any] | None = {
            "format": "spaghetti-extractor-pe32-base-relocation-evidence-v1",
            "complete": True,
            "pe_sha256": contract.identity.pe_sha256,
            "static_program_contract_sha256": static_program_contract_sha256,
            "image_base": contract.identity.preferred_base,
            "relocations": sorted(relocation_rows, key=lambda row: row["source_rva"]),
        }
    else:
        if dynamic_base:
            raise ToolkitInputError(
                "PE requests dynamic-base loading but has no usable base relocations"
            )
        fixed_image_base = contract.identity.preferred_base
        relocation_evidence = None

    callbacks: list[Mapping[str, Any]] = []
    if contract.tls is not None:
        callbacks.extend(
            {
                "rva": callback.rva,
                "kind": "tls_callback",
                "stack_cleanup_bytes": 12,
            }
            for callback in contract.tls.callbacks
        )
    initial_zero_ranges = tuple(
        (
            contract.identity.preferred_base + zero.rva,
            contract.identity.preferred_base + zero.rva + zero.size,
        )
        for section in contract.sections
        for zero in section.zero_fill
    )
    return NativeImageInputs(
        entry_rva=contract.identity.entry_rva,
        image_base=contract.identity.preferred_base,
        fixed_image_base=fixed_image_base,
        import_slots=import_index.slots,
        tls_callback_targets=tuple(callbacks),
        base_relocation_evidence=relocation_evidence,
        initial_zero_ranges=initial_zero_ranges,
    )


def select_native_termination_import(
    *,
    profile_paths: Sequence[Path | str],
    import_slots: Sequence[NativeImportSlot],
    preferred_identity: Mapping[str, Any] | None = None,
) -> Mapping[str, Any] | None:
    profile_set = load_machine_import_profile_set(profile_paths)
    import_index = NativeImportSlotIndex.create(import_slots)
    requested_profile_paths = {Path(path).resolve() for path in profile_paths}
    declared_identities: list[tuple[str, str | int]] = []
    if preferred_identity is not None:
        declared_identities.append(
            _native_termination_identity(
                preferred_identity, context="native process termination intent"
            )
        )
    for profile in profile_set.profiles:
        if profile.path not in requested_profile_paths:
            continue
        declared = profile.payload.get("native_process_termination")
        if declared is None:
            continue
        declared_identities.append(
            _native_termination_identity(
                declared, context=f"{profile.path} native_process_termination"
            )
        )
    if len(set(declared_identities)) > 1:
        raise ToolkitInputError(
            "requested machine-import profiles declare conflicting native process "
            "termination imports"
        )
    declared_identity = (
        declared_identities[0] if declared_identities else None
    )
    candidates: list[Mapping[str, Any]] = []
    for selected in profile_set.contracts:
        contract = selected.contract
        identity = selected.identity.value
        key = (selected.identity.dll, identity)
        if (
            contract.get("disposition") == "terminates"
            and selected.arity_kind == "fixed"
            and selected.argument_words == 1
            and key in import_index.by_identity
            and (declared_identity is None or key == declared_identity)
        ):
            slots = import_index.by_identity[key]
            if len(slots) != 1:
                raise ToolkitInputError(
                    "native process termination import has multiple physical IAT "
                    "cells; select an exact termination slot in target intent"
                )
            selected_slot = slots[0]
            candidates.append({
                "dll": selected.identity.dll,
                "symbol": identity if isinstance(identity, str) else None,
                "ordinal": identity if isinstance(identity, int) else None,
                "disposition": "terminates",
                "slot_id": selected_slot.slot_id,
            })
    if declared_identity is not None and not candidates:
        raise ToolkitInputError(
            "declared native process termination import is not an imported, "
            "one-word terminates contract"
        )
    if len(candidates) > 1:
        rendered = ", ".join(
            f"{item['dll']}!{item['symbol'] or ('#' + str(item['ordinal']))}"
            for item in candidates
        )
        raise ToolkitInputError(
            "multiple imported one-word termination contracts are available: " + rendered
        )
    return candidates[0] if candidates else None


def _native_termination_identity(
    value: Mapping[str, Any], *, context: str
) -> tuple[str, str | int]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an import identity")
    dll = value.get("dll")
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    allowed = {"dll", "symbol"} if symbol is not None else {"dll", "ordinal"}
    has_symbol = isinstance(symbol, str) and bool(symbol)
    has_ordinal = (
        isinstance(ordinal, int)
        and not isinstance(ordinal, bool)
        and ordinal >= 0
    )
    if (
        set(value) != allowed
        or not isinstance(dll, str)
        or not dll
        or has_symbol == has_ordinal
    ):
        raise ToolkitInputError(f"{context} is malformed")
    return dll.lower(), symbol if has_symbol else int(ordinal)


__all__ = [
    "NativeImageInputs",
    "derive_native_image_inputs",
    "select_native_termination_import",
]
