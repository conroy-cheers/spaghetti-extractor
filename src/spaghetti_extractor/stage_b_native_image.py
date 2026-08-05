"""Derive candidate-generation inputs from an exact Stage A load-image contract."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .machine_import_profiles import load_machine_import_profile_set
from .roundtrip_fuzz.image_contract import load_stage_a_load_image_contract
from .stage_binary import StageAInputError


_DYNAMIC_BASE = 0x0040


@dataclass(frozen=True)
class NativeImageInputs:
    entry_rva: int
    image_base: int
    fixed_image_base: int | None
    import_iat_vas: Mapping[tuple[str, str | int], int]
    callback_targets: tuple[Mapping[str, Any], ...]
    base_relocation_evidence: Mapping[str, Any] | None
    initial_zero_ranges: tuple[tuple[int, int], ...]


def derive_native_image_inputs(
    *,
    load_image_contract: Path | str,
    reference_contract_sha256: str | None = None,
) -> NativeImageInputs:
    contract = load_stage_a_load_image_contract(Path(load_image_contract))
    headers = contract.runtime_headers.data
    if len(headers) < 0x40:
        raise StageAInputError("load-image runtime headers are truncated")
    pe_offset = struct.unpack_from("<I", headers, 0x3C)[0]
    optional_offset = pe_offset + 24
    if optional_offset + 72 > len(headers):
        raise StageAInputError("load-image optional header is truncated")
    if struct.unpack_from("<H", headers, optional_offset)[0] != 0x10B:
        raise StageAInputError("native candidate requires a PE32 optional header")
    dll_characteristics = struct.unpack_from("<H", headers, optional_offset + 70)[0]
    dynamic_base = bool(dll_characteristics & _DYNAMIC_BASE)

    imports: dict[tuple[str, str | int], int] = {}
    for descriptor in contract.imports:
        for cell in descriptor.cells:
            identity: str | int | None = (
                cell.symbol if cell.symbol is not None else cell.ordinal
            )
            if identity is None:
                raise StageAInputError("load-image import cell has no identity")
            key = (descriptor.dll.lower(), identity)
            value = contract.identity.preferred_base + cell.iat_rva
            prior = imports.get(key)
            if prior is not None and prior != value:
                raise StageAInputError(
                    f"load-image import identity {key!r} has multiple IAT cells"
                )
            imports[key] = value

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
        if reference_contract_sha256 is None:
            raise StageAInputError(
                "relocatable native image inputs require a reference-contract SHA-256"
            )
        fixed_image_base = None
        relocation_evidence: Mapping[str, Any] | None = {
            "format": "stage-b-pe32-base-relocation-evidence-v1",
            "complete": True,
            "pe_sha256": contract.identity.pe_sha256,
            "reference_contract_sha256": reference_contract_sha256,
            "image_base": contract.identity.preferred_base,
            "relocations": sorted(relocation_rows, key=lambda row: row["source_rva"]),
        }
    else:
        if dynamic_base:
            raise StageAInputError(
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
        import_iat_vas=imports,
        callback_targets=tuple(callbacks),
        base_relocation_evidence=relocation_evidence,
        initial_zero_ranges=initial_zero_ranges,
    )


def select_native_termination_import(
    *,
    profile_paths: Sequence[Path | str],
    import_iat_vas: Mapping[tuple[str, str | int], int],
) -> Mapping[str, Any] | None:
    profile_set = load_machine_import_profile_set(profile_paths)
    candidates: list[Mapping[str, Any]] = []
    for selected in profile_set.contracts:
        contract = selected.contract
        identity = selected.identity.value
        key = (selected.identity.dll, identity)
        if (
            contract.get("disposition") == "terminates"
            and selected.arity_kind == "fixed"
            and selected.argument_words == 1
            and key in import_iat_vas
        ):
            candidates.append({
                "dll": selected.identity.dll,
                "symbol": identity if isinstance(identity, str) else None,
                "ordinal": identity if isinstance(identity, int) else None,
                "disposition": "terminates",
            })
    if len(candidates) > 1:
        rendered = ", ".join(
            f"{item['dll']}!{item['symbol'] or ('#' + str(item['ordinal']))}"
            for item in candidates
        )
        raise StageAInputError(
            "multiple imported one-word termination contracts are available: " + rendered
        )
    return candidates[0] if candidates else None


__all__ = [
    "NativeImageInputs",
    "derive_native_image_inputs",
    "select_native_termination_import",
]
