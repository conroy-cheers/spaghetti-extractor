"""Deterministic original-only static-program contract generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import STATIC_PROGRAM_CONTRACT_FORMAT
from ..extraction.binary_inventory import parse_binary_cutpoint_inventory
from ..pe32.stage_binary import BlockSide, StageAInputError, _parse_stage_a_pe
from ..reference_contract.reference_semantics import _semantic_transfer_contracts
from ..roundtrip_fuzz.image_io import write_stage_a_load_image_contract
from ..util import sha256_bytes, sha256_file, write_json
from .model import StaticProgramContract, StaticUnitContext


STATIC_PROGRAM_EXPORT_FORMAT = "spaghetti-extractor-static-program-export-v1"
_NO_LINKER_MAP_SHA256 = sha256_bytes(b"")


def _span(row: Mapping[str, Any]) -> tuple[int, int]:
    value = row.get("span")
    if not isinstance(value, Mapping):
        raise StageAInputError("static-program unit span is malformed")
    start = int(value["rva_start"])
    return start, start + int(value["size"])


def _relocations(binary: Any) -> dict[str, Any]:
    directory = binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    blocks = [
        {
            "rva": int(raw.struct.VirtualAddress),
            "size": int(raw.struct.SizeOfBlock),
            "entries": [
                {"rva": int(entry.rva), "type": int(entry.type)}
                for entry in raw.entries
            ],
        }
        for raw in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", []) or []
    ]
    return {
        "directory": {
            "rva": int(directory.VirtualAddress),
            "size": int(directory.Size),
        },
        "blocks": blocks,
    }


def _binary_payload(binary: Any) -> dict[str, Any]:
    return {
        "path": binary.path.name,
        "sha256": binary.sha256,
        "size": binary.size,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "size_of_image": binary.size_of_image,
        "size_of_headers": binary.size_of_headers,
        "subsystem": binary.subsystem,
        "is_dll": binary.is_dll,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "raw_pointer": section.raw_pointer,
                "raw_size": section.raw_size,
                "characteristics": section.characteristics,
                "permissions": {
                    "execute": section.executable,
                    "read": section.readable,
                    "write": section.writable,
                    "code": section.contains_code,
                },
            }
            for section in binary.sections
        ],
        "imports": [
            {
                "dll": imported.dll,
                "symbol": imported.symbol,
                "ordinal": imported.ordinal,
                "thunk_rva": imported.thunk_rva,
            }
            for imported in binary.imports
        ],
        "exports": [
            {
                "ordinal": exported.ordinal,
                "name": exported.name,
                "rva": exported.rva,
                "kind": exported.kind,
                "forwarder": exported.forwarder,
            }
            for exported in binary.exports or ()
        ],
        "tls": {
            "directory_rva": binary.tls_directory_rva,
            "directory_size": binary.tls_directory_size,
            "callback_rvas": list(binary.tls_callback_rvas or ()),
            "callback_array_rva": binary.tls_callback_array_rva,
            "callback_array_size": binary.tls_callback_array_size,
            "callback_array_immutable": binary.tls_callback_array_immutable,
        },
        "relocations": _relocations(binary),
    }


def _roots(binary: Any) -> list[dict[str, Any]]:
    rows: dict[tuple[str, int], dict[str, Any]] = {
        ("pe_entrypoint", binary.entrypoint_rva): {
            "kind": "pe_entrypoint",
            "rva": binary.entrypoint_rva,
        }
    }
    for exported in binary.exports or ():
        if exported.kind == "code":
            rows[("pe_export", exported.rva)] = {
                "kind": "pe_export",
                "rva": exported.rva,
                "name": exported.name,
                "ordinal": exported.ordinal,
            }
    for rva in binary.tls_callback_rvas or ():
        rows[("pe_tls_callback", rva)] = {
            "kind": "pe_tls_callback",
            "rva": rva,
        }
    return sorted(rows.values(), key=lambda row: (int(row["rva"]), str(row["kind"])))


def _target_rvas(value: Any) -> set[int]:
    result: set[int] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in {"target_rva", "return_rva", "fallthrough_rva"} and isinstance(
                item, int
            ):
                result.add(item)
            else:
                result.update(_target_rvas(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_target_rvas(item))
    return result


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def stage_a_export_static_program(
    *, original: Path, inventory: Path, out: Path
) -> dict[str, Any]:
    original = Path(original).resolve()
    inventory = Path(inventory).resolve()
    out = Path(out).resolve()
    if (
        not original.is_file()
        or original.is_symlink()
        or not inventory.is_file()
        or inventory.is_symlink()
    ):
        raise StageAInputError("static-program inputs must be regular files")
    try:
        parsed_inventory = parse_binary_cutpoint_inventory(
            json.loads(inventory.read_text(encoding="utf-8"))
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"could not read binary inventory: {exc}") from exc
    if parsed_inventory["status"] != "pass" or parsed_inventory["side"] != "original":
        raise StageAInputError(
            "static-program export requires a passing original inventory"
        )
    if parsed_inventory["linker_map_sha256"] != _NO_LINKER_MAP_SHA256:
        raise StageAInputError(
            "static-program authority cannot contain linker-map provenance"
        )
    if sha256_file(original) != parsed_inventory["binary_sha256"]:
        raise StageAInputError("static-program binary hash differs from its inventory")

    binary = _parse_stage_a_pe(original)
    try:
        units: list[dict[str, Any]] = []
        contexts: list[StaticUnitContext] = []
        for index, region in enumerate(parsed_inventory["regions"]):
            start, end = _span(region)
            data = bytes(binary.pe.get_data(start, end - start))
            if len(data) != end - start:
                raise StageAInputError(
                    f"static-program unit {index} bytes are unreadable"
                )
            source = dict(region["source"])
            units.append(
                {
                    "index": index,
                    "id": str(region["id"]),
                    "kind": "code",
                    "span": {
                        "rva_start": start,
                        "rva_end": end,
                        "size": end - start,
                    },
                    "bytes_sha256": sha256_bytes(data),
                    "source": source,
                }
            )
            contexts.append(
                StaticUnitContext(
                    id=str(region["id"]),
                    original=BlockSide(start, end),
                    kind="code",
                    source={"source": source},
                )
            )

        roots = _roots(binary)
        uncovered_roots = [
            root
            for root in roots
            if not any(
                unit["span"]["rva_start"]
                <= root["rva"]
                < unit["span"]["rva_end"]
                for unit in units
            )
        ]
        issues = [
            {
                "id": f"static-root-{int(root['rva']):08x}",
                "status": "incomplete",
                "category": "root_outside_structural_universe",
                "location": {"rva": root["rva"]},
                "message": "declared PE root is outside every structural unit",
                "next_action": "extend exact structural discovery to cover the root",
            }
            for root in uncovered_roots
        ]
        placeholder = {
            "format": STATIC_PROGRAM_CONTRACT_FORMAT,
            "path": "static-program-contract.json",
            "sha256": "0" * 64,
        }
        semantic_rows = _semantic_transfer_contracts(binary, contexts, placeholder)
        for row in semantic_rows:
            row.pop("reference_contract", None)
            # Semantic extraction enumerates structural transfers. Rooted closure
            # is the only phase permitted to establish behavioral reachability.
            row["reachable"] = False
        out.mkdir(parents=True, exist_ok=True)
        semantic_path = out / "semantic-transfer-contracts.jsonl"
        _write_jsonl(semantic_path, semantic_rows)
        semantic_sha256 = sha256_file(semantic_path)
        cfg_edges = [
            {
                "source_unit_id": row["block_id"],
                "target_rvas": sorted(
                    _target_rvas(row.get("outcome"))
                    | _target_rvas(row.get("external_events"))
                ),
                "indirect": row.get("outcome", {}).get("kind") == "indirect",
            }
            for row in semantic_rows
        ]
        padding = [
            {
                "id": str(row["id"]),
                "span": {
                    "rva_start": int(row["rva"]),
                    "rva_end": int(row["rva"]) + int(row["size"]),
                    "size": int(row["size"]),
                },
                "classification": "verified_padding",
                "reason": str(row["reason"]),
            }
            for row in parsed_inventory["padding_waivers"]
        ]
        status = "complete" if not issues else "incomplete"
        contract = StaticProgramContract(
            binary=_binary_payload(binary),
            structural_universe={
                "units": units,
                "padding": padding,
                "roots": roots,
                "cfg_edges": cfg_edges,
            },
            families={
                "pe_layout": {"status": "complete"},
                "executable_coverage": {
                    "status": "complete",
                    "executable_sections": list(
                        parsed_inventory["executable_sections"]
                    ),
                    "code_spans": [unit["span"] for unit in units],
                    "padding_spans": [row["span"] for row in padding],
                    "unknown_spans": [],
                },
                "structural_units": {"status": "complete", "count": len(units)},
                "roots": {
                    "status": "complete" if not uncovered_roots else "incomplete"
                },
                "cfg": {"status": "complete", "edge_sources": len(cfg_edges)},
                "imports": {"status": "complete", "count": len(binary.imports)},
            },
            sidecars={
                "semantic_transfers": {
                    "path": semantic_path.name,
                    "sha256": semantic_sha256,
                }
            },
            issues=tuple(issues),
            counts={
                "units": len(units),
                "padding": len(padding),
                "roots": len(roots),
                "imports": len(binary.imports),
                "semantic_transfers": len(semantic_rows),
                "issues": len(issues),
            },
            status=status,
        )
        contract_path = out / "static-program-contract.json"
        write_json(contract_path, contract.payload())
        load_image_path = out / "load-image-contract.json"
        load_image = write_stage_a_load_image_contract(
            original_pe=original, out=load_image_path
        )
    finally:
        binary.pe.close()

    manifest = {
        "format": STATIC_PROGRAM_EXPORT_FORMAT,
        "status": "ready" if contract.status == "complete" else "incomplete",
        "original": {
            "path": str(original),
            "sha256": parsed_inventory["binary_sha256"],
        },
        "outputs": {
            "static_program_contract": {
                "path": contract_path.name,
                "sha256": sha256_file(contract_path),
            },
            "semantic_transfers": {
                "path": semantic_path.name,
                "sha256": sha256_file(semantic_path),
            },
            "load_image_contract": {
                "path": load_image_path.name,
                "sha256": sha256_file(load_image_path),
                "contract_sha256": load_image.hashes.contract_sha256,
            },
        },
        "counts": dict(contract.counts),
        "trust": contract.payload()["trust"],
    }
    write_json(out / "static-program-export.json", manifest)
    return manifest


__all__ = ["STATIC_PROGRAM_EXPORT_FORMAT", "stage_a_export_static_program"]
