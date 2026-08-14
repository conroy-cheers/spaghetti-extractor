"""Round-trip image validation."""


from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..errors import StageAInputError
from ..util import sha256_bytes, sha256_file, write_json


from .image_model import (
    STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT,
    StageALoadImageContract,
    _DIRECTORY_BASE_RELOCATION,
    _DIRECTORY_DELAY_IMPORT,
    _DIRECTORY_IMPORT,
    _DIRECTORY_TLS,
)
from .image_parsing import (
    _PEHeaders,
    _make_completeness,
    _make_hashes,
    _parse_pe_headers,
    _section_for_span,
)

def _validate_contract(contract: StageALoadImageContract) -> None:
    if contract.format != STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT:
        raise StageAInputError("unsupported Stage A load-image contract format")
    identity = contract.identity
    if identity.machine not in {"i386", "x86_64"}:
        raise StageAInputError("load-image identity has an unsupported machine")
    expected_shape = {
        "i386": (32, 4),
        "x86_64": (64, 8),
    }[identity.machine]
    if (identity.bitness, identity.pointer_width) != expected_shape:
        raise StageAInputError("load-image identity bitness is inconsistent")
    if contract.runtime_headers.rva != 0:
        raise StageAInputError("runtime PE headers must be mapped at RVA zero")
    if len(contract.runtime_headers.data) != identity.size_of_headers:
        raise StageAInputError("runtime PE headers do not cover SizeOfHeaders")
    if contract.runtime_headers.data_sha256 != sha256_bytes(
        contract.runtime_headers.data
    ):
        raise StageAInputError("runtime PE header byte hash changed")
    parsed_headers = _parse_pe_headers(
        contract.runtime_headers.data, exact_file_size=identity.file_size
    )
    header_identity = (
        parsed_headers.machine,
        parsed_headers.bitness,
        parsed_headers.pointer_width,
        parsed_headers.preferred_base,
        parsed_headers.image_size,
        parsed_headers.entry_rva,
        parsed_headers.size_of_headers,
    )
    artifact_identity = (
        identity.machine,
        identity.bitness,
        identity.pointer_width,
        identity.preferred_base,
        identity.image_size,
        identity.entry_rva,
        identity.size_of_headers,
    )
    if header_identity != artifact_identity:
        raise StageAInputError("load-image identity disagrees with its runtime PE headers")
    if len(contract.sections) != len(parsed_headers.sections):
        raise StageAInputError("load-image section inventory is incomplete")
    for expected_index, (section, header) in enumerate(
        zip(contract.sections, parsed_headers.sections)
    ):
        if section.index != expected_index:
            raise StageAInputError("load-image sections are not in exact table order")
        metadata = (
            section.index,
            section.name,
            section.rva,
            section.virtual_size,
            section.mapped_size,
            section.raw_size,
            section.characteristics,
            section.executable,
        )
        header_metadata = (
            header.index,
            header.name,
            header.rva,
            header.virtual_size,
            header.mapped_size,
            header.raw_size,
            header.characteristics,
            header.executable,
        )
        if metadata != header_metadata:
            raise StageAInputError(
                f"load-image section {section.index} disagrees with the PE header"
            )
        if section.executable:
            if section.initialized or section.zero_fill:
                raise StageAInputError("executable section bodies must remain opaque")
        else:
            expected_initialized = (
                (section.rva, section.raw_size) if section.raw_size else None
            )
            actual_initialized = (
                (section.initialized[0].rva, len(section.initialized[0].data))
                if len(section.initialized) == 1
                else None
            )
            if actual_initialized != expected_initialized:
                raise StageAInputError(
                    f"non-executable section {section.index} initialized coverage is incomplete"
                )
            expected_zero = (
                (section.rva + section.raw_size, section.mapped_size - section.raw_size)
                if section.mapped_size > section.raw_size
                else None
            )
            actual_zero = (
                (section.zero_fill[0].rva, section.zero_fill[0].size)
                if len(section.zero_fill) == 1
                else None
            )
            if actual_zero != expected_zero:
                raise StageAInputError(
                    f"non-executable section {section.index} zero-fill coverage is incomplete"
                )
        for item in section.initialized:
            if item.data_sha256 != sha256_bytes(item.data):
                raise StageAInputError(
                    f"non-executable section {section.index} byte hash changed"
                )
    _validate_import_records(contract, parsed_headers)
    _validate_relocation_records(contract, parsed_headers)
    _validate_tls_record(contract, parsed_headers)
    expected_completeness = _make_completeness(
        contract.runtime_headers,
        contract.sections,
        contract.imports,
        contract.relocations,
        contract.tls,
    )
    if contract.completeness != expected_completeness:
        raise StageAInputError("load-image completeness inventory does not close")
    expected_hashes = _make_hashes(
        core_payload=contract._core_payload(),
        runtime_headers=contract.runtime_headers,
        sections=contract.sections,
        imports=contract.imports,
        relocations=contract.relocations,
        tls=contract.tls,
        completeness=contract.completeness,
    )
    if contract.hashes != expected_hashes:
        raise StageAInputError("load-image deterministic hashes do not close")


def _nonexec_contract_read(
    contract: StageALoadImageContract, rva: int, size: int, *, context: str
) -> bytes:
    if size == 0:
        return b""
    if rva < len(contract.runtime_headers.data) and rva + size <= len(
        contract.runtime_headers.data
    ):
        return contract.runtime_headers.data[rva : rva + size]
    for section in contract.sections:
        if section.executable or not (
            section.rva <= rva and rva + size <= section.rva + section.mapped_size
        ):
            continue
        offset = rva - section.rva
        initialized_size = section.raw_size
        result = bytearray()
        raw_count = max(0, min(size, initialized_size - offset))
        if raw_count:
            if len(section.initialized) != 1:
                raise StageAInputError(f"{context} lacks initialized section bytes")
            result.extend(section.initialized[0].data[offset : offset + raw_count])
        result.extend(bytes(size - raw_count))
        return bytes(result)
    raise StageAInputError(f"{context} is not covered by opaque-safe image bytes")


def _validate_import_records(
    contract: StageALoadImageContract, headers: _PEHeaders
) -> None:
    import_present = headers.directories[_DIRECTORY_IMPORT] != (0, 0)
    if bool(contract.imports) != import_present:
        raise StageAInputError("typed import inventory disagrees with the PE directory")
    if headers.directories[_DIRECTORY_DELAY_IMPORT] != (0, 0):
        raise StageAInputError("load-image contract cannot admit delay imports")
    seen_iat: set[int] = set()
    for descriptor_index, descriptor in enumerate(contract.imports):
        if descriptor.index != descriptor_index or not descriptor.cells:
            raise StageAInputError("typed import descriptors are incomplete or unordered")
        for cell_index, cell in enumerate(descriptor.cells):
            if cell.index != cell_index:
                raise StageAInputError("typed IAT cells are not in lookup order")
            if (cell.symbol is None) == (cell.ordinal is None):
                raise StageAInputError("typed import must select exactly one identity")
            if (cell.symbol is None) != (cell.hint is None):
                raise StageAInputError("typed import hint is inconsistent with its symbol")
            if cell.pointer_width != contract.identity.pointer_width:
                raise StageAInputError("typed IAT cell width is inconsistent")
            if cell.lookup_rva != descriptor.lookup_table_rva + cell_index * cell.pointer_width:
                raise StageAInputError("typed import lookup RVA is not contiguous")
            if cell.iat_rva != descriptor.iat_rva + cell_index * cell.pointer_width:
                raise StageAInputError("typed IAT RVA is not contiguous")
            if cell.iat_rva in seen_iat:
                raise StageAInputError("typed IAT cell is duplicated")
            seen_iat.add(cell.iat_rva)
            observed = int.from_bytes(
                _nonexec_contract_read(
                    contract,
                    cell.iat_rva,
                    cell.pointer_width,
                    context="typed IAT cell",
                ),
                "little",
            )
            if observed != cell.initial_value:
                raise StageAInputError("typed IAT initial value disagrees with section bytes")
def _validate_relocation_records(
    contract: StageALoadImageContract, headers: _PEHeaders
) -> None:
    relocation_present = headers.directories[_DIRECTORY_BASE_RELOCATION] != (0, 0)
    if bool(contract.relocations) != relocation_present:
        raise StageAInputError("typed relocation inventory disagrees with the PE directory")
    seen_targets: set[tuple[int, int]] = set()
    for block_index, block in enumerate(contract.relocations):
        if block.index != block_index or block.page_rva % 0x1000:
            raise StageAInputError("typed relocation blocks are malformed or unordered")
        if block.size != 8 + 2 * block.slot_count:
            raise StageAInputError("typed relocation block size does not match its slots")
        slot_cursor = 0
        for relocation in block.relocations:
            if relocation.slot_index != slot_cursor:
                raise StageAInputError("typed relocations do not cover every block slot")
            slot_cursor += relocation.consumed_slots
            if relocation.type == 0:
                if (
                    relocation.kind != "absolute_padding"
                    or relocation.consumed_slots != 1
                    or relocation.target_rva is not None
                    or relocation.width != 0
                    or relocation.preferred_value is not None
                    or relocation.adjustment is not None
                ):
                    raise StageAInputError("typed ABSOLUTE relocation padding is malformed")
                continue
            allowed = (
                {1: ("high", 2, 1), 2: ("low", 2, 1), 3: ("highlow", 4, 1), 4: ("highadj", 2, 2)}
                if contract.identity.bitness == 32
                else {10: ("dir64", 8, 1)}
            )
            expected = allowed.get(relocation.type)
            if expected is None or (
                relocation.kind, relocation.width, relocation.consumed_slots
            ) != expected:
                raise StageAInputError("typed base-relocation kind is unsupported")
            if relocation.target_rva is None or relocation.preferred_value is None:
                raise StageAInputError("typed base relocation omits its target value")
            if (relocation.adjustment is None) != (relocation.type != 4):
                raise StageAInputError("typed HIGHADJ adjustment is inconsistent")
            if not block.page_rva <= relocation.target_rva < block.page_rva + 0x1000:
                raise StageAInputError("typed base-relocation target is outside its page")
            if relocation.target_rva + relocation.width > headers.image_size:
                raise StageAInputError("typed base-relocation target exceeds SizeOfImage")
            key = (relocation.target_rva, relocation.width)
            if key in seen_targets:
                raise StageAInputError("typed base-relocation target is duplicated")
            seen_targets.add(key)
        if slot_cursor != block.slot_count:
            raise StageAInputError("typed relocations do not close the block slot count")


def _validate_tls_record(
    contract: StageALoadImageContract, headers: _PEHeaders
) -> None:
    tls_rva, tls_size = headers.directories[_DIRECTORY_TLS]
    if (contract.tls is not None) != (tls_rva != 0):
        raise StageAInputError("typed TLS inventory disagrees with the PE directory")
    if contract.tls is None:
        return
    tls = contract.tls
    if (tls.directory_rva, tls.directory_size) != (tls_rva, tls_size):
        raise StageAInputError("typed TLS directory span changed")
    if tls.template_sha256 != sha256_bytes(tls.template_data):
        raise StageAInputError("typed TLS template hash changed")
    if tls.template_rva is None and tls.template_data:
        raise StageAInputError("typed TLS template bytes omit their RVA")
    if tls.template_rva is not None:
        observed = _nonexec_contract_read(
            contract,
            tls.template_rva,
            len(tls.template_data),
            context="typed TLS template",
        )
        if observed != tls.template_data:
            raise StageAInputError("typed TLS template disagrees with section bytes")
    if bool(tls.callbacks) != (tls.callback_array_rva is not None):
        # A present but empty callback array is represented by its RVA.
        if tls.callback_array_rva is None or tls.callbacks:
            raise StageAInputError("typed TLS callback-array presence is incoherent")
    for order, callback in enumerate(tls.callbacks):
        if callback.order != order:
            raise StageAInputError("typed TLS callbacks are not in loader order")
        section = _section_for_span(headers, callback.rva, 1)
        if section is None or not section.executable:
            raise StageAInputError("typed TLS callback target is not executable")
