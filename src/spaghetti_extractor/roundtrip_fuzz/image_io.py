"""Round-trip image io."""


from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..errors import ToolkitInputError
from ..util import sha256_bytes, sha256_file, write_json


from .image_model import (
    ContractHashes,
    PEImageIdentity,
    RuntimePEHeaders,
    LoadImageContract,
    _HASH_ALGORITHM,
    _mapping,
)
from .image_parsing import (
    _ImageReader,
    _extract_imports,
    _extract_relocations,
    _extract_sections,
    _extract_tls,
    _make_completeness,
    _make_hashes,
    _parse_pe_headers,
)

def build_spx_load_image_contract(original_pe: Path) -> LoadImageContract:
    """Read an original PE statically and produce its opaque-safe image contract."""

    original_pe = Path(original_pe)
    try:
        data = original_pe.read_bytes()
    except OSError as exc:
        raise ToolkitInputError(f"cannot read original PE {original_pe}: {exc}") from exc
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
    provisional = LoadImageContract(
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
    contract = LoadImageContract(
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


def write_spx_load_image_contract(
    *, original_pe: Path, out: Path
) -> LoadImageContract:
    contract = build_spx_load_image_contract(original_pe)
    write_json(Path(out), contract.to_payload())
    return contract


def load_spx_load_image_contract(
    path: Path, *, original_pe: Path | None = None
) -> LoadImageContract:
    path = Path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read static analysis load-image contract {path}: {exc}") from exc
    contract = LoadImageContract.parse(
        _mapping(payload, "static analysis load-image contract")
    )
    if original_pe is not None:
        contract.validate(original_pe=original_pe)
    return contract


__all__ = [
    "SPX_LOAD_IMAGE_CONTRACT_FORMAT",
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
    "LoadImageContract",
    "TLSCallback",
    "TLSInitialization",
    "ZeroFillRange",
    "build_spx_load_image_contract",
    "load_spx_load_image_contract",
    "write_spx_load_image_contract",
]
