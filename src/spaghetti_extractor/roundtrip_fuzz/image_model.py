"""Round-trip image model."""


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
        from .image_validation import _validate_contract

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
            from .image_io import build_stage_a_load_image_contract

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
