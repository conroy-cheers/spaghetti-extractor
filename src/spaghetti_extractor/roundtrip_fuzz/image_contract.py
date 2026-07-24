"""Typed Stage A load-image contract for an opaque Stage B runtime.

The original PE is read only while this artifact is built.  The artifact keeps
the bytes and metadata required to reproduce static loader initialization while
deliberately omitting executable section bodies.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..errors import StageAInputError
from ..util import sha256_bytes, sha256_file, write_json


STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT = "stage-a-load-image-contract-v1"
_HASH_ALGORITHM = "sha256"
_COVERAGE_KINDS = (
    "runtime_pe_headers",
    "non_executable_initialized_bytes",
    "non_executable_zero_fill",
    "imports_and_iat_cells",
    "base_relocations",
    "tls_callback_order",
)

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_DIRECTORY_IMPORT = 1
_DIRECTORY_BASE_RELOCATION = 5
_DIRECTORY_TLS = 9
_DIRECTORY_IAT = 12
_DIRECTORY_DELAY_IMPORT = 13
_DIRECTORY_NAMES = (
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "base_relocation",
    "debug",
    "architecture",
    "global_pointer",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr_runtime",
    "reserved",
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _payload_sha256(value: Any) -> str:
    return sha256_bytes(_canonical_bytes(value))


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing fields: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected fields: {', '.join(unexpected)}")
        raise StageAInputError(f"{context} has {'; '.join(details)}")


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    return value


def _integer(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StageAInputError(
            f"{context} must be an integer greater than or equal to {minimum}"
        )
    return value


def _optional_integer(value: Any, context: str) -> int | None:
    if value is None:
        return None
    return _integer(value, context)


def _string(value: Any, context: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        suffix = " a nonempty string" if nonempty else " a string"
        raise StageAInputError(f"{context} must be{suffix}")
    return value


def _sha256(value: Any, context: str) -> str:
    text = _string(value, context)
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise StageAInputError(f"{context} must be a lowercase SHA-256 digest")
    return text


def _hex_bytes(value: Any, context: str) -> bytes:
    encoded = _string(value, context, nonempty=False)
    try:
        decoded = bytes.fromhex(encoded)
    except ValueError as exc:
        raise StageAInputError(f"{context} must be canonical hexadecimal") from exc
    if decoded.hex() != encoded:
        raise StageAInputError(f"{context} must be lowercase canonical hexadecimal")
    return decoded


@dataclass(frozen=True)
class PEImageIdentity:
    pe_sha256: str
    file_size: int
    machine: str
    bitness: int
    pointer_width: int
    preferred_base: int
    image_size: int
    entry_rva: int
    size_of_headers: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "pe_sha256": self.pe_sha256,
            "file_size": self.file_size,
            "machine": self.machine,
            "bitness": self.bitness,
            "pointer_width": self.pointer_width,
            "preferred_base": self.preferred_base,
            "image_size": self.image_size,
            "entry_rva": self.entry_rva,
            "size_of_headers": self.size_of_headers,
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "PEImageIdentity":
        context = "load-image identity"
        _exact_fields(payload, {
            "pe_sha256", "file_size", "machine", "bitness", "pointer_width",
            "preferred_base", "image_size", "entry_rva", "size_of_headers",
        }, context)
        return cls(
            pe_sha256=_sha256(payload["pe_sha256"], f"{context}.pe_sha256"),
            file_size=_integer(payload["file_size"], f"{context}.file_size", minimum=1),
            machine=_string(payload["machine"], f"{context}.machine"),
            bitness=_integer(payload["bitness"], f"{context}.bitness", minimum=1),
            pointer_width=_integer(
                payload["pointer_width"], f"{context}.pointer_width", minimum=1
            ),
            preferred_base=_integer(
                payload["preferred_base"], f"{context}.preferred_base"
            ),
            image_size=_integer(
                payload["image_size"], f"{context}.image_size", minimum=1
            ),
            entry_rva=_integer(payload["entry_rva"], f"{context}.entry_rva"),
            size_of_headers=_integer(
                payload["size_of_headers"],
                f"{context}.size_of_headers",
                minimum=1,
            ),
        )


@dataclass(frozen=True)
class RuntimePEHeaders:
    rva: int
    data: bytes
    data_sha256: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "size": len(self.data),
            "data_hex": self.data.hex(),
            "data_sha256": self.data_sha256,
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "RuntimePEHeaders":
        context = "runtime PE headers"
        _exact_fields(payload, {"rva", "size", "data_hex", "data_sha256"}, context)
        data = _hex_bytes(payload["data_hex"], f"{context}.data_hex")
        size = _integer(payload["size"], f"{context}.size", minimum=1)
        if size != len(data):
            raise StageAInputError(f"{context}.size does not match data_hex")
        return cls(
            rva=_integer(payload["rva"], f"{context}.rva"),
            data=data,
            data_sha256=_sha256(
                payload["data_sha256"], f"{context}.data_sha256"
            ),
        )


@dataclass(frozen=True)
class InitializedRange:
    rva: int
    data: bytes
    data_sha256: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "size": len(self.data),
            "data_hex": self.data.hex(),
            "data_sha256": self.data_sha256,
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "InitializedRange":
        _exact_fields(payload, {"rva", "size", "data_hex", "data_sha256"}, context)
        data = _hex_bytes(payload["data_hex"], f"{context}.data_hex")
        if _integer(payload["size"], f"{context}.size") != len(data):
            raise StageAInputError(f"{context}.size does not match data_hex")
        return cls(
            rva=_integer(payload["rva"], f"{context}.rva"),
            data=data,
            data_sha256=_sha256(payload["data_sha256"], f"{context}.data_sha256"),
        )


@dataclass(frozen=True)
class ZeroFillRange:
    rva: int
    size: int

    def to_payload(self) -> dict[str, Any]:
        return {"rva": self.rva, "size": self.size}

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ZeroFillRange":
        _exact_fields(payload, {"rva", "size"}, context)
        return cls(
            rva=_integer(payload["rva"], f"{context}.rva"),
            size=_integer(payload["size"], f"{context}.size", minimum=1),
        )


@dataclass(frozen=True)
class SectionInitialization:
    index: int
    name: str
    rva: int
    virtual_size: int
    mapped_size: int
    raw_size: int
    characteristics: int
    executable: bool
    initialized: tuple[InitializedRange, ...]
    zero_fill: tuple[ZeroFillRange, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "rva": self.rva,
            "virtual_size": self.virtual_size,
            "mapped_size": self.mapped_size,
            "raw_size": self.raw_size,
            "characteristics": self.characteristics,
            "executable": self.executable,
            "initialized": [item.to_payload() for item in self.initialized],
            "zero_fill": [item.to_payload() for item in self.zero_fill],
        }

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str
    ) -> "SectionInitialization":
        _exact_fields(payload, {
            "index", "name", "rva", "virtual_size", "mapped_size", "raw_size",
            "characteristics", "executable", "initialized", "zero_fill",
        }, context)
        executable = payload["executable"]
        if not isinstance(executable, bool):
            raise StageAInputError(f"{context}.executable must be a boolean")
        initialized = tuple(
            InitializedRange.parse(
                _mapping(item, f"{context}.initialized[{index}]"),
                context=f"{context}.initialized[{index}]",
            )
            for index, item in enumerate(
                _list(payload["initialized"], f"{context}.initialized")
            )
        )
        zero_fill = tuple(
            ZeroFillRange.parse(
                _mapping(item, f"{context}.zero_fill[{index}]"),
                context=f"{context}.zero_fill[{index}]",
            )
            for index, item in enumerate(
                _list(payload["zero_fill"], f"{context}.zero_fill")
            )
        )
        return cls(
            index=_integer(payload["index"], f"{context}.index"),
            name=_string(payload["name"], f"{context}.name", nonempty=False),
            rva=_integer(payload["rva"], f"{context}.rva"),
            virtual_size=_integer(payload["virtual_size"], f"{context}.virtual_size"),
            mapped_size=_integer(
                payload["mapped_size"], f"{context}.mapped_size", minimum=1
            ),
            raw_size=_integer(payload["raw_size"], f"{context}.raw_size"),
            characteristics=_integer(
                payload["characteristics"], f"{context}.characteristics"
            ),
            executable=executable,
            initialized=initialized,
            zero_fill=zero_fill,
        )


@dataclass(frozen=True)
class ImportIATCell:
    index: int
    lookup_rva: int
    iat_rva: int
    symbol: str | None
    ordinal: int | None
    hint: int | None
    pointer_width: int
    initial_value: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "lookup_rva": self.lookup_rva,
            "iat_rva": self.iat_rva,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
            "hint": self.hint,
            "pointer_width": self.pointer_width,
            "initial_value": self.initial_value,
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ImportIATCell":
        _exact_fields(payload, {
            "index", "lookup_rva", "iat_rva", "symbol", "ordinal", "hint",
            "pointer_width", "initial_value",
        }, context)
        symbol = payload["symbol"]
        if symbol is not None:
            symbol = _string(symbol, f"{context}.symbol")
        return cls(
            index=_integer(payload["index"], f"{context}.index"),
            lookup_rva=_integer(payload["lookup_rva"], f"{context}.lookup_rva"),
            iat_rva=_integer(payload["iat_rva"], f"{context}.iat_rva"),
            symbol=symbol,
            ordinal=_optional_integer(payload["ordinal"], f"{context}.ordinal"),
            hint=_optional_integer(payload["hint"], f"{context}.hint"),
            pointer_width=_integer(
                payload["pointer_width"], f"{context}.pointer_width", minimum=1
            ),
            initial_value=_integer(
                payload["initial_value"], f"{context}.initial_value"
            ),
        )


@dataclass(frozen=True)
class ImportDescriptor:
    index: int
    dll: str
    lookup_table_rva: int
    iat_rva: int
    cells: tuple[ImportIATCell, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "dll": self.dll,
            "lookup_table_rva": self.lookup_table_rva,
            "iat_rva": self.iat_rva,
            "cells": [cell.to_payload() for cell in self.cells],
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ImportDescriptor":
        _exact_fields(
            payload, {"index", "dll", "lookup_table_rva", "iat_rva", "cells"}, context
        )
        return cls(
            index=_integer(payload["index"], f"{context}.index"),
            dll=_string(payload["dll"], f"{context}.dll"),
            lookup_table_rva=_integer(
                payload["lookup_table_rva"], f"{context}.lookup_table_rva"
            ),
            iat_rva=_integer(payload["iat_rva"], f"{context}.iat_rva"),
            cells=tuple(
                ImportIATCell.parse(
                    _mapping(cell, f"{context}.cells[{index}]"),
                    context=f"{context}.cells[{index}]",
                )
                for index, cell in enumerate(
                    _list(payload["cells"], f"{context}.cells")
                )
            ),
        )


@dataclass(frozen=True)
class BaseRelocation:
    slot_index: int
    consumed_slots: int
    type: int
    kind: str
    target_rva: int | None
    width: int
    preferred_value: int | None
    adjustment: int | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "slot_index": self.slot_index,
            "consumed_slots": self.consumed_slots,
            "type": self.type,
            "kind": self.kind,
            "target_rva": self.target_rva,
            "width": self.width,
            "preferred_value": self.preferred_value,
            "adjustment": self.adjustment,
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "BaseRelocation":
        _exact_fields(payload, {
            "slot_index", "consumed_slots", "type", "kind", "target_rva",
            "width", "preferred_value", "adjustment",
        }, context)
        adjustment = payload["adjustment"]
        if adjustment is not None and (
            isinstance(adjustment, bool)
            or not isinstance(adjustment, int)
            or not -0x8000 <= adjustment <= 0x7FFF
        ):
            raise StageAInputError(f"{context}.adjustment must fit signed 16 bits")
        return cls(
            slot_index=_integer(payload["slot_index"], f"{context}.slot_index"),
            consumed_slots=_integer(
                payload["consumed_slots"], f"{context}.consumed_slots", minimum=1
            ),
            type=_integer(payload["type"], f"{context}.type"),
            kind=_string(payload["kind"], f"{context}.kind"),
            target_rva=_optional_integer(payload["target_rva"], f"{context}.target_rva"),
            width=_integer(payload["width"], f"{context}.width"),
            preferred_value=_optional_integer(
                payload["preferred_value"], f"{context}.preferred_value"
            ),
            adjustment=adjustment,
        )


@dataclass(frozen=True)
class RelocationBlock:
    index: int
    page_rva: int
    size: int
    slot_count: int
    relocations: tuple[BaseRelocation, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "page_rva": self.page_rva,
            "size": self.size,
            "slot_count": self.slot_count,
            "relocations": [item.to_payload() for item in self.relocations],
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "RelocationBlock":
        _exact_fields(
            payload, {"index", "page_rva", "size", "slot_count", "relocations"}, context
        )
        return cls(
            index=_integer(payload["index"], f"{context}.index"),
            page_rva=_integer(payload["page_rva"], f"{context}.page_rva"),
            size=_integer(payload["size"], f"{context}.size", minimum=8),
            slot_count=_integer(payload["slot_count"], f"{context}.slot_count"),
            relocations=tuple(
                BaseRelocation.parse(
                    _mapping(item, f"{context}.relocations[{index}]"),
                    context=f"{context}.relocations[{index}]",
                )
                for index, item in enumerate(
                    _list(payload["relocations"], f"{context}.relocations")
                )
            ),
        )


@dataclass(frozen=True)
class TLSCallback:
    order: int
    rva: int

    def to_payload(self) -> dict[str, Any]:
        return {"order": self.order, "rva": self.rva}

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "TLSCallback":
        _exact_fields(payload, {"order", "rva"}, context)
        return cls(
            order=_integer(payload["order"], f"{context}.order"),
            rva=_integer(payload["rva"], f"{context}.rva"),
        )


@dataclass(frozen=True)
class TLSInitialization:
    directory_rva: int
    directory_size: int
    template_rva: int | None
    template_data: bytes
    template_sha256: str
    zero_fill_size: int
    index_rva: int | None
    callback_array_rva: int | None
    callbacks: tuple[TLSCallback, ...]
    characteristics: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "directory_rva": self.directory_rva,
            "directory_size": self.directory_size,
            "template_rva": self.template_rva,
            "template_size": len(self.template_data),
            "template_data_hex": self.template_data.hex(),
            "template_sha256": self.template_sha256,
            "zero_fill_size": self.zero_fill_size,
            "index_rva": self.index_rva,
            "callback_array_rva": self.callback_array_rva,
            "callbacks": [callback.to_payload() for callback in self.callbacks],
            "characteristics": self.characteristics,
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "TLSInitialization":
        context = "TLS initialization"
        _exact_fields(payload, {
            "directory_rva", "directory_size", "template_rva", "template_size",
            "template_data_hex", "template_sha256", "zero_fill_size", "index_rva",
            "callback_array_rva", "callbacks", "characteristics",
        }, context)
        data = _hex_bytes(payload["template_data_hex"], f"{context}.template_data_hex")
        if _integer(payload["template_size"], f"{context}.template_size") != len(data):
            raise StageAInputError(f"{context}.template_size does not match its bytes")
        return cls(
            directory_rva=_integer(payload["directory_rva"], f"{context}.directory_rva"),
            directory_size=_integer(
                payload["directory_size"], f"{context}.directory_size", minimum=1
            ),
            template_rva=_optional_integer(payload["template_rva"], f"{context}.template_rva"),
            template_data=data,
            template_sha256=_sha256(
                payload["template_sha256"], f"{context}.template_sha256"
            ),
            zero_fill_size=_integer(
                payload["zero_fill_size"], f"{context}.zero_fill_size"
            ),
            index_rva=_optional_integer(payload["index_rva"], f"{context}.index_rva"),
            callback_array_rva=_optional_integer(
                payload["callback_array_rva"], f"{context}.callback_array_rva"
            ),
            callbacks=tuple(
                TLSCallback.parse(
                    _mapping(item, f"{context}.callbacks[{index}]"),
                    context=f"{context}.callbacks[{index}]",
                )
                for index, item in enumerate(
                    _list(payload["callbacks"], f"{context}.callbacks")
                )
            ),
            characteristics=_integer(
                payload["characteristics"], f"{context}.characteristics"
            ),
        )


@dataclass(frozen=True)
class CompletenessInventory:
    complete: bool
    coverage: tuple[str, ...]
    section_count: int
    non_executable_section_indices: tuple[int, ...]
    excluded_executable_section_indices: tuple[int, ...]
    runtime_header_bytes: int
    initialized_range_count: int
    initialized_byte_count: int
    zero_fill_range_count: int
    zero_fill_byte_count: int
    import_descriptor_count: int
    import_iat_cell_count: int
    relocation_block_count: int
    relocation_slot_count: int
    base_relocation_count: int
    tls_present: bool
    tls_callback_count: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "coverage": list(self.coverage),
            "section_count": self.section_count,
            "non_executable_section_indices": list(self.non_executable_section_indices),
            "excluded_executable_section_indices": list(self.excluded_executable_section_indices),
            "runtime_header_bytes": self.runtime_header_bytes,
            "initialized_range_count": self.initialized_range_count,
            "initialized_byte_count": self.initialized_byte_count,
            "zero_fill_range_count": self.zero_fill_range_count,
            "zero_fill_byte_count": self.zero_fill_byte_count,
            "import_descriptor_count": self.import_descriptor_count,
            "import_iat_cell_count": self.import_iat_cell_count,
            "relocation_block_count": self.relocation_block_count,
            "relocation_slot_count": self.relocation_slot_count,
            "base_relocation_count": self.base_relocation_count,
            "tls_present": self.tls_present,
            "tls_callback_count": self.tls_callback_count,
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "CompletenessInventory":
        context = "load-image completeness inventory"
        _exact_fields(payload, {
            "complete", "coverage", "section_count", "non_executable_section_indices",
            "excluded_executable_section_indices", "runtime_header_bytes",
            "initialized_range_count", "initialized_byte_count", "zero_fill_range_count",
            "zero_fill_byte_count", "import_descriptor_count", "import_iat_cell_count",
            "relocation_block_count", "relocation_slot_count", "base_relocation_count",
            "tls_present", "tls_callback_count",
        }, context)
        complete = payload["complete"]
        tls_present = payload["tls_present"]
        if not isinstance(complete, bool) or not isinstance(tls_present, bool):
            raise StageAInputError(f"{context} boolean fields must be booleans")

        def integers(field: str) -> tuple[int, ...]:
            return tuple(
                _integer(item, f"{context}.{field}[{index}]")
                for index, item in enumerate(_list(payload[field], f"{context}.{field}"))
            )

        return cls(
            complete=complete,
            coverage=tuple(
                _string(item, f"{context}.coverage[{index}]")
                for index, item in enumerate(
                    _list(payload["coverage"], f"{context}.coverage")
                )
            ),
            section_count=_integer(payload["section_count"], f"{context}.section_count"),
            non_executable_section_indices=integers("non_executable_section_indices"),
            excluded_executable_section_indices=integers("excluded_executable_section_indices"),
            runtime_header_bytes=_integer(
                payload["runtime_header_bytes"], f"{context}.runtime_header_bytes"
            ),
            initialized_range_count=_integer(
                payload["initialized_range_count"], f"{context}.initialized_range_count"
            ),
            initialized_byte_count=_integer(
                payload["initialized_byte_count"], f"{context}.initialized_byte_count"
            ),
            zero_fill_range_count=_integer(
                payload["zero_fill_range_count"], f"{context}.zero_fill_range_count"
            ),
            zero_fill_byte_count=_integer(
                payload["zero_fill_byte_count"], f"{context}.zero_fill_byte_count"
            ),
            import_descriptor_count=_integer(
                payload["import_descriptor_count"], f"{context}.import_descriptor_count"
            ),
            import_iat_cell_count=_integer(
                payload["import_iat_cell_count"], f"{context}.import_iat_cell_count"
            ),
            relocation_block_count=_integer(
                payload["relocation_block_count"], f"{context}.relocation_block_count"
            ),
            relocation_slot_count=_integer(
                payload["relocation_slot_count"], f"{context}.relocation_slot_count"
            ),
            base_relocation_count=_integer(
                payload["base_relocation_count"], f"{context}.base_relocation_count"
            ),
            tls_present=tls_present,
            tls_callback_count=_integer(
                payload["tls_callback_count"], f"{context}.tls_callback_count"
            ),
        )


@dataclass(frozen=True)
class ContractHashes:
    algorithm: str
    runtime_headers_sha256: str
    sections_sha256: str
    imports_sha256: str
    relocations_sha256: str
    tls_sha256: str
    completeness_sha256: str
    contract_sha256: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "runtime_headers_sha256": self.runtime_headers_sha256,
            "sections_sha256": self.sections_sha256,
            "imports_sha256": self.imports_sha256,
            "relocations_sha256": self.relocations_sha256,
            "tls_sha256": self.tls_sha256,
            "completeness_sha256": self.completeness_sha256,
            "contract_sha256": self.contract_sha256,
        }

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ContractHashes":
        context = "load-image hashes"
        fields = {
            "algorithm", "runtime_headers_sha256", "sections_sha256",
            "imports_sha256", "relocations_sha256", "tls_sha256",
            "completeness_sha256", "contract_sha256",
        }
        _exact_fields(payload, fields, context)
        return cls(
            algorithm=_string(payload["algorithm"], f"{context}.algorithm"),
            **{
                field: _sha256(payload[field], f"{context}.{field}")
                for field in fields
                if field != "algorithm"
            },
        )


@dataclass(frozen=True)
class StageALoadImageContract:
    identity: PEImageIdentity
    runtime_headers: RuntimePEHeaders
    sections: tuple[SectionInitialization, ...]
    imports: tuple[ImportDescriptor, ...]
    relocations: tuple[RelocationBlock, ...]
    tls: TLSInitialization | None
    completeness: CompletenessInventory
    hashes: ContractHashes
    format: str = STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT

    def _core_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "identity": self.identity.to_payload(),
            "runtime_headers": self.runtime_headers.to_payload(),
            "sections": [section.to_payload() for section in self.sections],
            "imports": [item.to_payload() for item in self.imports],
            "relocations": [item.to_payload() for item in self.relocations],
            "tls": None if self.tls is None else self.tls.to_payload(),
            "completeness": self.completeness.to_payload(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {**self._core_payload(), "hashes": self.hashes.to_payload()}

    def validate(self, *, original_pe: Path | None = None) -> None:
        _validate_contract(self)
        if original_pe is not None:
            original_pe = Path(original_pe)
            try:
                observed_size = original_pe.stat().st_size
                observed_sha256 = sha256_file(original_pe)
            except OSError as exc:
                raise StageAInputError(
                    f"cannot verify original PE {original_pe}: {exc}"
                ) from exc
            if (
                observed_size != self.identity.file_size
                or observed_sha256 != self.identity.pe_sha256
            ):
                raise StageAInputError(
                    "load-image contract does not bind the supplied original PE"
                )
            if build_stage_a_load_image_contract(original_pe) != self:
                raise StageAInputError(
                    "load-image contract contents do not match the supplied original PE"
                )

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "StageALoadImageContract":
        context = "Stage A load-image contract"
        _exact_fields(payload, {
            "format", "identity", "runtime_headers", "sections", "imports",
            "relocations", "tls", "completeness", "hashes",
        }, context)
        if payload["format"] != STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT:
            raise StageAInputError("unsupported Stage A load-image contract format")
        raw_tls = payload["tls"]
        contract = cls(
            identity=PEImageIdentity.parse(
                _mapping(payload["identity"], f"{context}.identity")
            ),
            runtime_headers=RuntimePEHeaders.parse(
                _mapping(payload["runtime_headers"], f"{context}.runtime_headers")
            ),
            sections=tuple(
                SectionInitialization.parse(
                    _mapping(item, f"{context}.sections[{index}]"),
                    context=f"{context}.sections[{index}]",
                )
                for index, item in enumerate(
                    _list(payload["sections"], f"{context}.sections")
                )
            ),
            imports=tuple(
                ImportDescriptor.parse(
                    _mapping(item, f"{context}.imports[{index}]"),
                    context=f"{context}.imports[{index}]",
                )
                for index, item in enumerate(
                    _list(payload["imports"], f"{context}.imports")
                )
            ),
            relocations=tuple(
                RelocationBlock.parse(
                    _mapping(item, f"{context}.relocations[{index}]"),
                    context=f"{context}.relocations[{index}]",
                )
                for index, item in enumerate(
                    _list(payload["relocations"], f"{context}.relocations")
                )
            ),
            tls=(
                None
                if raw_tls is None
                else TLSInitialization.parse(
                    _mapping(raw_tls, f"{context}.tls")
                )
            ),
            completeness=CompletenessInventory.parse(
                _mapping(payload["completeness"], f"{context}.completeness")
            ),
            hashes=ContractHashes.parse(
                _mapping(payload["hashes"], f"{context}.hashes")
            ),
        )
        contract.validate()
        return contract


@dataclass(frozen=True)
class _SectionHeader:
    index: int
    name: str
    rva: int
    virtual_size: int
    mapped_size: int
    raw_pointer: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_EXECUTE)


@dataclass(frozen=True)
class _PEHeaders:
    machine: str
    bitness: int
    pointer_width: int
    preferred_base: int
    image_size: int
    entry_rva: int
    size_of_headers: int
    section_alignment: int
    file_alignment: int
    directories: tuple[tuple[int, int], ...]
    sections: tuple[_SectionHeader, ...]


class _ImageReader:
    def __init__(self, data: bytes, headers: _PEHeaders):
        self.data = data
        self.headers = headers

    def read(self, rva: int, size: int, *, context: str) -> bytes:
        if size < 0 or rva < 0 or rva + size > self.headers.image_size:
            raise StageAInputError(f"{context} is outside SizeOfImage")
        if size == 0:
            return b""
        if rva < self.headers.size_of_headers and rva + size <= self.headers.size_of_headers:
            if rva + size > len(self.data):
                raise StageAInputError(f"{context} is not backed by exact header bytes")
            return self.data[rva : rva + size]
        matches = [
            section
            for section in self.headers.sections
            if section.rva <= rva and rva + size <= section.rva + section.mapped_size
        ]
        if len(matches) != 1:
            raise StageAInputError(f"{context} is not in exactly one mapped section")
        section = matches[0]
        offset = rva - section.rva
        raw_count = max(0, min(size, section.raw_size - offset))
        result = bytearray()
        if raw_count:
            file_offset = section.raw_pointer + offset
            if file_offset + raw_count > len(self.data):
                raise StageAInputError(f"{context} is not backed by exact file bytes")
            result.extend(self.data[file_offset : file_offset + raw_count])
        result.extend(bytes(size - raw_count))
        return bytes(result)

    def c_string(self, rva: int, *, context: str) -> str:
        encoded = bytearray()
        for offset in range(4096):
            byte = self.read(rva + offset, 1, context=context)[0]
            if byte == 0:
                if not encoded:
                    raise StageAInputError(f"{context} is empty")
                try:
                    return encoded.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise StageAInputError(f"{context} is not ASCII") from exc
            encoded.append(byte)
        raise StageAInputError(f"{context} is not NUL terminated within 4096 bytes")


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _parse_pe_headers(data: bytes, *, exact_file_size: int) -> _PEHeaders:
    if exact_file_size < len(data) or len(data) < 0x40 or data[:2] != b"MZ":
        raise StageAInputError("original is not a bounded MZ image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise StageAInputError("PE signature or COFF header is outside the header bytes")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise StageAInputError("original does not contain a PE signature")
    coff_offset = pe_offset + 4
    machine_value, section_count = struct.unpack_from("<HH", data, coff_offset)
    optional_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if section_count == 0 or section_count > 96:
        raise StageAInputError("PE section count is outside the supported bound")
    if optional_end > len(data) or optional_size < 2:
        raise StageAInputError("PE optional header is truncated")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if machine_value == 0x014C and magic == 0x10B:
        machine, bitness, pointer_width = "i386", 32, 4
        required_optional_size = 96
        directory_count_offset = 92
        directory_offset = 96
        preferred_base = struct.unpack_from("<I", data, optional_offset + 28)[0]
    elif machine_value == 0x8664 and magic == 0x20B:
        machine, bitness, pointer_width = "x86_64", 64, 8
        required_optional_size = 112
        directory_count_offset = 108
        directory_offset = 112
        preferred_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
    else:
        raise StageAInputError(
            "load-image contracts support only x86 PE32 and x86_64 PE32+"
        )
    if optional_size < required_optional_size:
        raise StageAInputError("PE optional header is too small for its declared bitness")
    entry_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
    section_alignment = struct.unpack_from("<I", data, optional_offset + 32)[0]
    file_alignment = struct.unpack_from("<I", data, optional_offset + 36)[0]
    image_size = struct.unpack_from("<I", data, optional_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    if not _is_power_of_two(section_alignment) or not _is_power_of_two(file_alignment):
        raise StageAInputError("PE section and file alignments must be powers of two")
    if section_alignment < file_alignment:
        raise StageAInputError("PE SectionAlignment is smaller than FileAlignment")
    if size_of_headers == 0 or size_of_headers > exact_file_size:
        raise StageAInputError("PE SizeOfHeaders is outside the exact file")
    if size_of_headers > len(data):
        raise StageAInputError("required runtime PE header bytes are unavailable")
    if image_size == 0 or image_size % section_alignment:
        raise StageAInputError("PE SizeOfImage is zero or misaligned")
    address_limit = 1 << bitness
    if preferred_base + image_size > address_limit:
        raise StageAInputError("preferred PE image exceeds its address space")

    directory_count = struct.unpack_from(
        "<I", data, optional_offset + directory_count_offset
    )[0]
    directory_capacity = (optional_size - directory_offset) // 8
    if directory_count > min(directory_capacity, 16):
        raise StageAInputError("PE data-directory count is outside the supported bound")
    directories: list[tuple[int, int]] = []
    for index in range(16):
        if index < directory_count:
            rva, size = struct.unpack_from(
                "<II", data, optional_offset + directory_offset + index * 8
            )
            if (rva == 0) != (size == 0):
                raise StageAInputError(
                    f"PE {_DIRECTORY_NAMES[index]} directory has incoherent presence"
                )
            directories.append((rva, size))
        else:
            if index < directory_capacity:
                undeclared_rva, undeclared_size = struct.unpack_from(
                    "<II", data, optional_offset + directory_offset + index * 8
                )
                if undeclared_rva != 0 or undeclared_size != 0:
                    raise StageAInputError(
                        f"PE {_DIRECTORY_NAMES[index]} directory is present but undeclared"
                    )
            directories.append((0, 0))

    section_table_offset = optional_end
    section_table_end = section_table_offset + section_count * 40
    if section_table_end > size_of_headers or section_table_end > len(data):
        raise StageAInputError("PE section table is outside SizeOfHeaders")
    minimum_headers = _align_up(section_table_end, file_alignment)
    if size_of_headers < minimum_headers or size_of_headers % file_alignment:
        raise StageAInputError("PE SizeOfHeaders does not cover its aligned section table")

    sections: list[_SectionHeader] = []
    for index in range(section_count):
        offset = section_table_offset + index * 40
        (
            encoded_name,
            virtual_size,
            rva,
            raw_size,
            raw_pointer,
            _relocation_pointer,
            _line_pointer,
            _relocation_count,
            _line_count,
            characteristics,
        ) = struct.unpack_from("<8sIIIIIIHHI", data, offset)
        mapped_size = max(virtual_size, raw_size)
        if mapped_size == 0:
            raise StageAInputError(f"PE section {index} has no mapped extent")
        if rva % section_alignment or rva < size_of_headers:
            raise StageAInputError(f"PE section {index} has an invalid RVA")
        if rva + mapped_size > image_size:
            raise StageAInputError(f"PE section {index} exceeds SizeOfImage")
        if raw_size:
            if raw_pointer < size_of_headers or raw_pointer % file_alignment:
                raise StageAInputError(f"PE section {index} has an invalid raw pointer")
            if raw_size % file_alignment or raw_pointer + raw_size > exact_file_size:
                raise StageAInputError(f"PE section {index} raw bytes exceed the file")
        elif raw_pointer != 0:
            raise StageAInputError(f"PE section {index} has a pointer without raw bytes")
        sections.append(_SectionHeader(
            index=index,
            name=encoded_name.rstrip(b"\0").decode("latin-1"),
            rva=rva,
            virtual_size=virtual_size,
            mapped_size=mapped_size,
            raw_pointer=raw_pointer,
            raw_size=raw_size,
            characteristics=characteristics,
        ))
    _require_disjoint(
        [(item.rva, item.rva + item.mapped_size, item.index) for item in sections],
        "mapped section",
    )
    _require_disjoint(
        [
            (item.raw_pointer, item.raw_pointer + item.raw_size, item.index)
            for item in sections
            if item.raw_size
        ],
        "raw section",
    )
    highest = max(size_of_headers, *(item.rva + item.mapped_size for item in sections))
    if image_size != _align_up(highest, section_alignment):
        raise StageAInputError("PE SizeOfImage does not exactly cover its sections")
    if entry_rva:
        matches = [
            item
            for item in sections
            if item.executable and item.rva <= entry_rva < item.rva + item.mapped_size
        ]
        if len(matches) != 1:
            raise StageAInputError("PE entry RVA is not in exactly one executable section")
    return _PEHeaders(
        machine=machine,
        bitness=bitness,
        pointer_width=pointer_width,
        preferred_base=preferred_base,
        image_size=image_size,
        entry_rva=entry_rva,
        size_of_headers=size_of_headers,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        directories=tuple(directories),
        sections=tuple(sections),
    )


def _require_disjoint(ranges: Sequence[tuple[int, int, int]], label: str) -> None:
    ordered = sorted(ranges)
    for (_, previous_end, previous_index), (start, _end, index) in zip(
        ordered, ordered[1:]
    ):
        if start < previous_end:
            raise StageAInputError(
                f"PE {label}s {previous_index} and {index} overlap"
            )


def _directory_bytes(
    reader: _ImageReader, index: int, *, required_minimum: int = 1
) -> tuple[int, bytes]:
    rva, size = reader.headers.directories[index]
    if rva == 0:
        return 0, b""
    if size < required_minimum:
        raise StageAInputError(
            f"PE {_DIRECTORY_NAMES[index]} directory is smaller than its header"
        )
    return rva, reader.read(
        rva, size, context=f"PE {_DIRECTORY_NAMES[index]} directory"
    )


def _extract_sections(data: bytes, headers: _PEHeaders) -> tuple[SectionInitialization, ...]:
    result: list[SectionInitialization] = []
    for section in headers.sections:
        initialized: tuple[InitializedRange, ...] = ()
        zero_fill: tuple[ZeroFillRange, ...] = ()
        if not section.executable:
            if section.raw_size:
                raw = data[
                    section.raw_pointer : section.raw_pointer + section.raw_size
                ]
                if len(raw) != section.raw_size:
                    raise StageAInputError(
                        f"PE section {section.index} initialized bytes are truncated"
                    )
                initialized = (
                    InitializedRange(
                        rva=section.rva,
                        data=raw,
                        data_sha256=sha256_bytes(raw),
                    ),
                )
            if section.mapped_size > section.raw_size:
                zero_fill = (
                    ZeroFillRange(
                        rva=section.rva + section.raw_size,
                        size=section.mapped_size - section.raw_size,
                    ),
                )
        result.append(SectionInitialization(
            index=section.index,
            name=section.name,
            rva=section.rva,
            virtual_size=section.virtual_size,
            mapped_size=section.mapped_size,
            raw_size=section.raw_size,
            characteristics=section.characteristics,
            executable=section.executable,
            initialized=initialized,
            zero_fill=zero_fill,
        ))
    return tuple(result)


def _extract_imports(reader: _ImageReader) -> tuple[ImportDescriptor, ...]:
    if reader.headers.directories[_DIRECTORY_DELAY_IMPORT] != (0, 0):
        raise StageAInputError(
            "delay-import IAT cells are unsupported by this load-image contract"
        )
    directory_rva, directory = _directory_bytes(
        reader, _DIRECTORY_IMPORT, required_minimum=20
    )
    if not directory:
        if reader.headers.directories[_DIRECTORY_IAT] != (0, 0):
            raise StageAInputError("PE declares an IAT without a typed import directory")
        return ()
    descriptors: list[ImportDescriptor] = []
    terminated_at: int | None = None
    seen_iat_rvas: set[int] = set()
    pointer_width = reader.headers.pointer_width
    pointer_format = "<I" if pointer_width == 4 else "<Q"
    ordinal_mask = 1 << (reader.headers.bitness - 1)
    for descriptor_offset in range(0, len(directory) - 19, 20):
        row = struct.unpack_from("<IIIII", directory, descriptor_offset)
        if row == (0, 0, 0, 0, 0):
            terminated_at = descriptor_offset + 20
            break
        lookup_rva, _timestamp, _forwarder_chain, name_rva, iat_rva = row
        if name_rva == 0 or iat_rva == 0:
            raise StageAInputError("PE import descriptor omits its DLL name or IAT")
        if lookup_rva == 0:
            lookup_rva = iat_rva
        dll = reader.c_string(name_rva, context="PE import DLL name").lower()
        cells: list[ImportIATCell] = []
        maximum_cells = reader.headers.image_size // pointer_width
        for index in range(maximum_cells):
            lookup_cell_rva = lookup_rva + index * pointer_width
            iat_cell_rva = iat_rva + index * pointer_width
            lookup_value = struct.unpack(
                pointer_format,
                reader.read(
                    lookup_cell_rva,
                    pointer_width,
                    context="PE import lookup cell",
                ),
            )[0]
            initial_value = struct.unpack(
                pointer_format,
                reader.read(
                    iat_cell_rva, pointer_width, context="PE IAT cell"
                ),
            )[0]
            if lookup_value == 0:
                if initial_value != 0:
                    raise StageAInputError("PE IAT is not terminated with its lookup table")
                break
            if iat_cell_rva in seen_iat_rvas:
                raise StageAInputError("PE import descriptors contain duplicate IAT cells")
            seen_iat_rvas.add(iat_cell_rva)
            if lookup_value & ordinal_mask:
                ordinal = lookup_value & 0xFFFF
                if lookup_value & ~(ordinal_mask | 0xFFFF):
                    raise StageAInputError("PE ordinal import contains reserved bits")
                symbol = None
                hint = None
            else:
                if lookup_value > 0xFFFFFFFF:
                    raise StageAInputError("PE import-by-name RVA exceeds 32 bits")
                hint_name_rva = int(lookup_value)
                hint = struct.unpack(
                    "<H",
                    reader.read(
                        hint_name_rva, 2, context="PE import-by-name hint"
                    ),
                )[0]
                symbol = reader.c_string(
                    hint_name_rva + 2, context="PE import symbol"
                )
                ordinal = None
            cells.append(ImportIATCell(
                index=index,
                lookup_rva=lookup_cell_rva,
                iat_rva=iat_cell_rva,
                symbol=symbol,
                ordinal=ordinal,
                hint=hint,
                pointer_width=pointer_width,
                initial_value=initial_value,
            ))
        else:
            raise StageAInputError("PE import table is not null terminated")
        if not cells:
            raise StageAInputError("PE import descriptor has no IAT cells")
        descriptors.append(ImportDescriptor(
            index=len(descriptors),
            dll=dll,
            lookup_table_rva=lookup_rva,
            iat_rva=iat_rva,
            cells=tuple(cells),
        ))
    if terminated_at is None:
        raise StageAInputError("PE import descriptor table is not null terminated")
    # The import data-directory range is not restricted to IMAGE_IMPORT_DESCRIPTOR
    # rows.  GNU linkers commonly include the lookup tables and import names in
    # the same range, after the null descriptor.  The descriptor terminator is
    # therefore the end of the descriptor inventory, not an assertion that the
    # remainder of the declared directory is zero-filled.
    iat_directory_rva, iat_directory_size = reader.headers.directories[_DIRECTORY_IAT]
    if iat_directory_rva:
        iat_end = iat_directory_rva + iat_directory_size
        if any(
            not iat_directory_rva <= cell.iat_rva
            or cell.iat_rva + pointer_width > iat_end
            for descriptor in descriptors
            for cell in descriptor.cells
        ):
            raise StageAInputError("typed IAT cell is outside the declared IAT directory")
    return tuple(descriptors)


def _extract_relocations(reader: _ImageReader) -> tuple[RelocationBlock, ...]:
    _directory_rva, directory = _directory_bytes(
        reader, _DIRECTORY_BASE_RELOCATION, required_minimum=8
    )
    if not directory:
        return ()
    blocks: list[RelocationBlock] = []
    cursor = 0
    seen_targets: set[tuple[int, int]] = set()
    while cursor < len(directory):
        if len(directory) - cursor < 8:
            raise StageAInputError("PE base-relocation directory has a partial block")
        page_rva, block_size = struct.unpack_from("<II", directory, cursor)
        if page_rva % 0x1000:
            raise StageAInputError("PE base-relocation block page is not 4 KiB aligned")
        if block_size < 8 or block_size % 2 or cursor + block_size > len(directory):
            raise StageAInputError("PE base-relocation block has an invalid size")
        slot_count = (block_size - 8) // 2
        raw_slots = struct.unpack_from(
            "<" + "H" * slot_count, directory, cursor + 8
        )
        relocations: list[BaseRelocation] = []
        slot_index = 0
        while slot_index < slot_count:
            raw = raw_slots[slot_index]
            type_value = raw >> 12
            offset = raw & 0xFFF
            if type_value == 0:
                relocations.append(BaseRelocation(
                    slot_index=slot_index,
                    consumed_slots=1,
                    type=0,
                    kind="absolute_padding",
                    target_rva=None,
                    width=0,
                    preferred_value=None,
                    adjustment=None,
                ))
                slot_index += 1
                continue
            if reader.headers.bitness == 32:
                kinds = {
                    1: ("high", 2),
                    2: ("low", 2),
                    3: ("highlow", 4),
                    4: ("highadj", 2),
                }
            else:
                kinds = {10: ("dir64", 8)}
            if type_value not in kinds:
                raise StageAInputError(
                    f"unsupported PE base-relocation type {type_value} for "
                    f"{reader.headers.bitness}-bit image"
                )
            kind, width = kinds[type_value]
            adjustment: int | None = None
            consumed_slots = 1
            if type_value == 4:
                if slot_index + 1 >= slot_count:
                    raise StageAInputError("PE HIGHADJ relocation omits its adjustment")
                adjustment = struct.unpack("<h", struct.pack("<H", raw_slots[slot_index + 1]))[0]
                consumed_slots = 2
            target_rva = page_rva + offset
            preferred = int.from_bytes(
                reader.read(
                    target_rva, width, context="PE base-relocation target"
                ),
                "little",
            )
            target_key = (target_rva, width)
            if target_key in seen_targets:
                raise StageAInputError("PE base-relocation target is duplicated")
            seen_targets.add(target_key)
            relocations.append(BaseRelocation(
                slot_index=slot_index,
                consumed_slots=consumed_slots,
                type=type_value,
                kind=kind,
                target_rva=target_rva,
                width=width,
                preferred_value=preferred,
                adjustment=adjustment,
            ))
            slot_index += consumed_slots
        blocks.append(RelocationBlock(
            index=len(blocks),
            page_rva=page_rva,
            size=block_size,
            slot_count=slot_count,
            relocations=tuple(relocations),
        ))
        cursor += block_size
    return tuple(blocks)


def _va_to_rva(
    value: int, headers: _PEHeaders, *, context: str, allow_end: bool = False
) -> int:
    maximum = headers.preferred_base + headers.image_size
    if value < headers.preferred_base or value > maximum or (
        value == maximum and not allow_end
    ):
        raise StageAInputError(f"{context} VA is outside the preferred image")
    return value - headers.preferred_base


def _section_for_span(
    headers: _PEHeaders, rva: int, size: int
) -> _SectionHeader | None:
    matches = [
        section
        for section in headers.sections
        if section.rva <= rva and rva + size <= section.rva + section.mapped_size
    ]
    return matches[0] if len(matches) == 1 else None


def _extract_tls(reader: _ImageReader) -> TLSInitialization | None:
    directory_rva, directory = _directory_bytes(
        reader,
        _DIRECTORY_TLS,
        required_minimum=24 if reader.headers.bitness == 32 else 40,
    )
    if not directory:
        return None
    if reader.headers.bitness == 32:
        fields = struct.unpack_from("<IIIIII", directory)
    else:
        fields = struct.unpack_from("<QQQQII", directory)
    start_va, end_va, index_va, callbacks_va, zero_fill_size, characteristics = fields
    if (start_va == 0) != (end_va == 0):
        raise StageAInputError("PE TLS template has incoherent start/end VAs")
    template_rva: int | None = None
    template_data = b""
    if start_va:
        template_rva = _va_to_rva(
            start_va, reader.headers, context="PE TLS template start"
        )
        template_end_rva = _va_to_rva(
            end_va, reader.headers, context="PE TLS template end", allow_end=True
        )
        if template_end_rva < template_rva:
            raise StageAInputError("PE TLS template end precedes its start")
        template_data = reader.read(
            template_rva,
            template_end_rva - template_rva,
            context="PE TLS template",
        )
        template_section = _section_for_span(
            reader.headers, template_rva, len(template_data)
        )
        if template_data and (template_section is None or template_section.executable):
            raise StageAInputError("PE TLS template is not in a non-executable section")
    index_rva = (
        None
        if index_va == 0
        else _va_to_rva(index_va, reader.headers, context="PE TLS index")
    )
    if index_rva is not None:
        reader.read(
            index_rva, reader.headers.pointer_width, context="PE TLS index cell"
        )
    callback_array_rva = (
        None
        if callbacks_va == 0
        else _va_to_rva(
            callbacks_va, reader.headers, context="PE TLS callback array"
        )
    )
    callbacks: list[TLSCallback] = []
    if callback_array_rva is not None:
        width = reader.headers.pointer_width
        maximum = (reader.headers.image_size - callback_array_rva) // width
        for order in range(maximum):
            callback_va = int.from_bytes(
                reader.read(
                    callback_array_rva + order * width,
                    width,
                    context="PE TLS callback array",
                ),
                "little",
            )
            if callback_va == 0:
                break
            callback_rva = _va_to_rva(
                callback_va, reader.headers, context="PE TLS callback"
            )
            section = _section_for_span(reader.headers, callback_rva, 1)
            if section is None or not section.executable:
                raise StageAInputError("PE TLS callback is not executable")
            callbacks.append(TLSCallback(order=order, rva=callback_rva))
        else:
            raise StageAInputError("PE TLS callback array is not null terminated")
    return TLSInitialization(
        directory_rva=directory_rva,
        directory_size=len(directory),
        template_rva=template_rva,
        template_data=template_data,
        template_sha256=sha256_bytes(template_data),
        zero_fill_size=zero_fill_size,
        index_rva=index_rva,
        callback_array_rva=callback_array_rva,
        callbacks=tuple(callbacks),
        characteristics=characteristics,
    )


def _make_completeness(
    runtime_headers: RuntimePEHeaders,
    sections: tuple[SectionInitialization, ...],
    imports: tuple[ImportDescriptor, ...],
    relocations: tuple[RelocationBlock, ...],
    tls: TLSInitialization | None,
) -> CompletenessInventory:
    initialized = [item for section in sections for item in section.initialized]
    zero_fill = [item for section in sections for item in section.zero_fill]
    cells = [cell for descriptor in imports for cell in descriptor.cells]
    relocation_records = [
        item for block in relocations for item in block.relocations if item.type != 0
    ]
    return CompletenessInventory(
        complete=True,
        coverage=_COVERAGE_KINDS,
        section_count=len(sections),
        non_executable_section_indices=tuple(
            section.index for section in sections if not section.executable
        ),
        excluded_executable_section_indices=tuple(
            section.index for section in sections if section.executable
        ),
        runtime_header_bytes=len(runtime_headers.data),
        initialized_range_count=len(initialized),
        initialized_byte_count=sum(len(item.data) for item in initialized),
        zero_fill_range_count=len(zero_fill),
        zero_fill_byte_count=sum(item.size for item in zero_fill),
        import_descriptor_count=len(imports),
        import_iat_cell_count=len(cells),
        relocation_block_count=len(relocations),
        relocation_slot_count=sum(block.slot_count for block in relocations),
        base_relocation_count=len(relocation_records),
        tls_present=tls is not None,
        tls_callback_count=0 if tls is None else len(tls.callbacks),
    )


def _make_hashes(
    *,
    core_payload: Mapping[str, Any],
    runtime_headers: RuntimePEHeaders,
    sections: tuple[SectionInitialization, ...],
    imports: tuple[ImportDescriptor, ...],
    relocations: tuple[RelocationBlock, ...],
    tls: TLSInitialization | None,
    completeness: CompletenessInventory,
) -> ContractHashes:
    return ContractHashes(
        algorithm=_HASH_ALGORITHM,
        runtime_headers_sha256=sha256_bytes(runtime_headers.data),
        sections_sha256=_payload_sha256(
            [section.to_payload() for section in sections]
        ),
        imports_sha256=_payload_sha256([item.to_payload() for item in imports]),
        relocations_sha256=_payload_sha256(
            [item.to_payload() for item in relocations]
        ),
        tls_sha256=_payload_sha256(None if tls is None else tls.to_payload()),
        completeness_sha256=_payload_sha256(completeness.to_payload()),
        contract_sha256=_payload_sha256(core_payload),
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


def build_stage_a_load_image_contract(original_pe: Path) -> StageALoadImageContract:
    """Read an original PE statically and produce its opaque-safe image contract."""

    original_pe = Path(original_pe)
    try:
        data = original_pe.read_bytes()
    except OSError as exc:
        raise StageAInputError(f"cannot read original PE {original_pe}: {exc}") from exc
    headers = _parse_pe_headers(data, exact_file_size=len(data))
    reader = _ImageReader(data, headers)
    sections = _extract_sections(data, headers)
    imports = _extract_imports(reader)
    relocations = _extract_relocations(reader)
    tls = _extract_tls(reader)
    identity = PEImageIdentity(
        pe_sha256=sha256_bytes(data),
        file_size=len(data),
        machine=headers.machine,
        bitness=headers.bitness,
        pointer_width=headers.pointer_width,
        preferred_base=headers.preferred_base,
        image_size=headers.image_size,
        entry_rva=headers.entry_rva,
        size_of_headers=headers.size_of_headers,
    )
    header_data = data[: headers.size_of_headers]
    runtime_headers = RuntimePEHeaders(
        rva=0,
        data=header_data,
        data_sha256=sha256_bytes(header_data),
    )
    completeness = _make_completeness(
        runtime_headers, sections, imports, relocations, tls
    )
    placeholder_hashes = ContractHashes(
        algorithm=_HASH_ALGORITHM,
        runtime_headers_sha256="0" * 64,
        sections_sha256="0" * 64,
        imports_sha256="0" * 64,
        relocations_sha256="0" * 64,
        tls_sha256="0" * 64,
        completeness_sha256="0" * 64,
        contract_sha256="0" * 64,
    )
    provisional = StageALoadImageContract(
        identity=identity,
        runtime_headers=runtime_headers,
        sections=sections,
        imports=imports,
        relocations=relocations,
        tls=tls,
        completeness=completeness,
        hashes=placeholder_hashes,
    )
    hashes = _make_hashes(
        core_payload=provisional._core_payload(),
        runtime_headers=runtime_headers,
        sections=sections,
        imports=imports,
        relocations=relocations,
        tls=tls,
        completeness=completeness,
    )
    contract = StageALoadImageContract(
        identity=identity,
        runtime_headers=runtime_headers,
        sections=sections,
        imports=imports,
        relocations=relocations,
        tls=tls,
        completeness=completeness,
        hashes=hashes,
    )
    contract.validate()
    return contract


def write_stage_a_load_image_contract(
    *, original_pe: Path, out: Path
) -> StageALoadImageContract:
    contract = build_stage_a_load_image_contract(original_pe)
    write_json(Path(out), contract.to_payload())
    return contract


def load_stage_a_load_image_contract(
    path: Path, *, original_pe: Path | None = None
) -> StageALoadImageContract:
    path = Path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read Stage A load-image contract {path}: {exc}") from exc
    contract = StageALoadImageContract.parse(
        _mapping(payload, "Stage A load-image contract")
    )
    if original_pe is not None:
        contract.validate(original_pe=original_pe)
    return contract


__all__ = [
    "STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT",
    "BaseRelocation",
    "CompletenessInventory",
    "ContractHashes",
    "ImportDescriptor",
    "ImportIATCell",
    "InitializedRange",
    "PEImageIdentity",
    "RelocationBlock",
    "RuntimePEHeaders",
    "SectionInitialization",
    "StageALoadImageContract",
    "TLSCallback",
    "TLSInitialization",
    "ZeroFillRange",
    "build_stage_a_load_image_contract",
    "load_stage_a_load_image_contract",
    "write_stage_a_load_image_contract",
]
