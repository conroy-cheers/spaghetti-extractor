from __future__ import annotations

import json
import struct
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.artifacts.formats import (
    COMPONENT_QUALIFICATION_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
    LIBRARY_MATCH_EVIDENCE_FORMAT,
    LIBRARY_INTERFACE_CATALOG_FORMAT,
    LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
    LINKED_ISLAND_REVIEW_FORMAT,
)
from spaghetti_extractor.libraries.catalog import (
    bind_library_artifact_inputs,
    index_library_artifacts,
    lock_library_catalog,
)
from spaghetti_extractor.libraries.interfaces import (
    bind_interface_contract_catalog,
    bind_linked_interface_assignments,
    qualify_linked_interfaces,
)
from spaghetti_extractor.libraries.matching import (
    bind_linked_island_review,
    infer_library_hypotheses,
    match_linked_islands,
    propose_library_match_evidence,
)
from spaghetti_extractor.libraries.matching_support import (
    validate_linked_island_manifest,
)
from spaghetti_extractor.libraries.model import (
    LinkedLibraryError,
)
from spaghetti_extractor.libraries.refinement import (
    derive_dynamic_library_requirements,
    refine_linked_islands,
)
from spaghetti_extractor.libraries.replacements import (
    plan_library_replacements,
)
from spaghetti_extractor.util import sha256_file, write_json
from tests.pe_fixtures import pe32_import_image


_FUNCTION = bytes.fromhex("5589e5b801000000c3")
_APPLICATION = b"\xc3"
_THUNK = bytes.fromhex("ff2540204000")


class LinkedLibraryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.original = self.root / "fixture.exe"
        self.original.write_bytes(
            pe32_import_image(
                _FUNCTION + _APPLICATION + _THUNK,
                symbol="WriteFile",
            )
        )
        self.machine = self.root / "machine-ir"
        self.machine.mkdir()
        self._write_machine_package()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_machine_package(self) -> None:
        start = 0x1000
        units = [
            _unit(start, start + len(_FUNCTION)),
            _unit(start + len(_FUNCTION), start + len(_FUNCTION) + 1),
            _unit(
                start + len(_FUNCTION) + 1,
                start + len(_FUNCTION) + 1 + len(_THUNK),
                control={"kind": "external_jump"},
                events=[
                    {
                        "kind": "external_call",
                        "dll": "KERNEL32.dll",
                        "symbol": "WriteFile",
                        "ordinal": None,
                    }
                ],
            ),
        ]
        ir = self.machine / "machine-ir.jsonl"
        ir.write_text(
            "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in units),
            encoding="utf-8",
        )
        write_json(
            self.machine / "machine-ir-manifest.json",
            {
                "format": "stage-a-machine-ir-v2",
                "binary": {"sha256": sha256_file(self.original)},
                "artifacts": {
                    "machine_ir": {
                        "path": "machine-ir.jsonl",
                        "sha256": sha256_file(ir),
                    }
                },
            },
        )

    @staticmethod
    def _complement_policy(
        *, kind: str = "compiler_linker_support"
    ) -> dict[str, object]:
        return {
            "authority": "operator_reviewed_exact_complement",
            "id": "compiler-linker-support:reviewed-complement",
            "kind": kind,
            "operator_reviewed": True,
            "replacement_authorized": False,
            "review_rationale": (
                "The remaining exact fixture units were reviewed as linked runtime "
                "ownership only."
            ),
            "scope": "otherwise_unclaimed_exact_machine_units",
        }

    def _review_with_complement(
        self, *, kind: str = "compiler_linker_support"
    ) -> dict[str, object]:
        return bind_linked_island_review(
            {
                "format": LINKED_ISLAND_REVIEW_FORMAT,
                "original_binary_sha256": sha256_file(self.original),
                "islands": [
                    {
                        "id": "application:entry",
                        "kind": "application",
                        "authority": "operator_reviewed_exact_range",
                        "ranges": [
                            {
                                "rva_start": 0x1000 + len(_FUNCTION),
                                "rva_end": 0x1000 + len(_FUNCTION) + 1,
                            }
                        ],
                    }
                ],
                "unclaimed_exact_units": self._complement_policy(kind=kind),
            }
        )

    def _write_runtime_catalog(self) -> Path:
        (self.artifacts / "runtime.a").write_bytes(
            _archive("runtime.obj", _coff_object(_FUNCTION, symbol="_runtime"))
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "runtime",
                "artifacts": [{"id": "runtime", "path": "runtime.a"}],
            }
        )
        index = self.root / "runtime-index.json"
        index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=index,
        )
        lock_library_catalog(indexes=[index], out=self.root / "lock.json")
        return self.root / "lock.json"

    def _write_single_reviewed_island(
        self, *, kind: str = "application"
    ) -> dict[str, object]:
        review = bind_linked_island_review(
            {
                "format": LINKED_ISLAND_REVIEW_FORMAT,
                "original_binary_sha256": sha256_file(self.original),
                "islands": [
                    {
                        "id": "application:all",
                        "kind": kind,
                        "authority": "operator_reviewed_exact_range",
                        "ranges": [
                            {
                                "rva_start": 0x1000,
                                "rva_end": 0x1000
                                + len(_FUNCTION)
                                + len(_APPLICATION)
                                + len(_THUNK),
                            }
                        ],
                    }
                ],
            }
        )
        return match_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=None,
            review=review,
            out=self.root / "all-island.json",
        )

    @staticmethod
    def _interface_catalog() -> dict[str, object]:
        return bind_interface_contract_catalog(
            {
                "format": LIBRARY_INTERFACE_CATALOG_FORMAT,
                "catalog_id": "portable-interfaces",
                "contracts": [
                    {
                        "id": "byte-transform-v1",
                        "component_contract": {
                            "format": "fixture-component-contract-v1",
                            "contract_sha256": "a" * 64,
                        },
                        "domain": {"kind": "total"},
                    }
                ],
                "replacements": [
                    {
                        "id": "portable-byte-transform",
                        "contract_id": "byte-transform-v1",
                        "kind": "replace_by_canonical_interface",
                        "portable": True,
                        "implementation": {
                            "portable_source_sha256": "b" * 64,
                            "portable_symbol": "portable_byte_transform",
                        },
                        "qualification": {"status": "qualified"},
                    }
                ],
            }
        )


def _canonical_sha256(payload: object) -> str:
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _candidate(
    *, artifact: str, member: str, release: str, symbol: str
) -> dict[str, object]:
    return {
        "catalog_id": "fixture-catalog",
        "artifact_id": "fixture-runtime",
        "artifact_sha256": artifact,
        "island_kind": "linked_dependency",
        "snapshot": {
            "id": f"snapshot-{release}",
            "target": {
                "architecture": "i686",
                "object_format": "coff",
                "abi": "mingw32",
            },
        },
        "library_identity": {
            "family_id": "fixture-runtime",
            "component_id": "runtime",
            "release_id": release,
            "abi_id": "mingw32",
        },
        "retention_model": "archive_member",
        "member_path": [f"runtime-{release}.obj"],
        "member_id": member,
        "symbols": [symbol],
        "candidate_ids": [f"fixture:{release}:{symbol}"],
        "normalized_sha256": "a" * 64,
        "fixed_bytes": 16,
    }


def _observation(
    identity: str, start: int, candidates: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "id": f"target:{identity}",
        "target": {
            "rva_start": start,
            "rva_end": start + 16,
            "unit_ids": [f"unit:{start:x}"],
            "reachable": True,
        },
        "candidates": candidates,
        "candidate_count": len(candidates),
    }


def _unit(
    start: int,
    end: int,
    *,
    control: dict[str, object] | None = None,
    events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": f"unit:{start:x}",
        "reachable": True,
        "source": {
            "original": {"rva_start": start, "rva_end": end},
            "contract_sha256": sha256(f"contract:{start:x}".encode()).hexdigest(),
            "instruction_bytes_sha256": sha256(f"bytes:{start:x}".encode()).hexdigest(),
        },
        "control": control or {"kind": "return"},
        "semantics": {"external_events": events or []},
    }


def _coff_object(code: bytes, *, symbol: str) -> bytes:
    raw_pointer = 20 + 40
    symbol_pointer = raw_pointer + len(code)
    header = struct.pack("<HHIIIHH", 0x014C, 1, 0, symbol_pointer, 2, 0, 0)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0,
        0,
        len(code),
        raw_pointer,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    encoded_name = symbol.encode("ascii")
    if len(encoded_name) > 8:
        raise ValueError("fixture symbol must fit in the COFF short-name field")
    symbol_row = struct.pack(
        "<8sIhHBB",
        encoded_name.ljust(8, b"\0"),
        0,
        1,
        0x20,
        2,
        1,
    )
    aux = bytearray(18)
    struct.pack_into("<I", aux, 4, len(code))
    return header + section + code + symbol_row + bytes(aux) + struct.pack("<I", 4)


def _archive(name: str, body: bytes) -> bytes:
    encoded_name = (name + "/").encode("ascii")
    header = (
        encoded_name.ljust(16, b" ")
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + b"100644".ljust(8, b" ")
        + str(len(body)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    return b"!<arch>\n" + header + body + (b"\n" if len(body) & 1 else b"")


def _omf_record(record_type: int, payload: bytes) -> bytes:
    length = len(payload) + 1
    prefix = bytes([record_type]) + struct.pack("<H", length) + payload
    checksum = (-sum(prefix)) & 0xFF
    return prefix + bytes([checksum])


__all__ = [name for name in globals() if not name.startswith("__")]
