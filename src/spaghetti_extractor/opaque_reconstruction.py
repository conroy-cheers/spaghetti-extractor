"""Map-blind static export for high-assurance reconstruction.

The export deliberately uses the binary cutpoint inventory as its only code
discovery authority.  Symbols and linker maps may be attached later as labels,
but they are rejected from this provenance chain.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .analysis.binary_inventory import parse_binary_cutpoint_inventory
from .contract_tools import stage_a_export_reference_contract
from .roundtrip_fuzz.image_contract import write_stage_a_load_image_contract
from .stage_b_state_machine import write_stage_b_state_machine_from_stage_a_export
from .stage_binary import StageAInputError, _parse_stage_a_pe
from .util import sha256_bytes, sha256_file, write_json


OPAQUE_SELF_MAP_FORMAT = "stage-a-opaque-self-map-v1"
OPAQUE_STATIC_EXPORT_FORMAT = "stage-a-opaque-static-export-v1"
_NO_LINKER_MAP_SHA256 = sha256_bytes(b"")


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def opaque_self_map_from_inventory(
    inventory: Mapping[str, Any], *, binary_path: str, entry_rva: int
) -> dict[str, Any]:
    """Convert a strict binary-only inventory into an identity block map."""

    parsed = parse_binary_cutpoint_inventory(inventory)
    if parsed["status"] != "pass" or parsed["side"] != "original":
        raise StageAInputError(
            "opaque reconstruction requires a passing original-side inventory"
        )
    if parsed["linker_map_sha256"] != _NO_LINKER_MAP_SHA256:
        raise StageAInputError(
            "opaque reconstruction inventory must not contain linker-map provenance"
        )
    if isinstance(entry_rva, bool) or not isinstance(entry_rva, int) or entry_rva < 0:
        raise StageAInputError("opaque reconstruction entry RVA is invalid")

    blocks: list[dict[str, Any]] = []
    entry_bound = False
    for region in parsed["regions"]:
        row = _mapping(region, "binary inventory region")
        span = _mapping(row["span"], "binary inventory region span")
        start = int(span["rva_start"])
        size = int(span["size"])
        is_entry = start <= entry_rva < start + size
        entry_bound = entry_bound or is_entry
        source = _mapping(row["source"], "binary inventory region source")
        block: dict[str, Any] = {
            "id": str(row["id"]),
            "kind": "code",
            "original": {"rva": start, "size": size},
            "candidate": {"rva": start, "size": size},
            # The baseline contains all recovered code, including code whose
            # behavioral reachability has not yet been reduced.
            "reachable": True,
            "invariant": {"checked": True, "kind": "exact_identity_range"},
            "source": {
                "kind": "binary_only_static_cutpoint",
                "inventory_region_id": str(row["id"]),
                "inventory_source": dict(source),
            },
        }
        if is_entry:
            block["root"] = {
                "checked": True,
                "kind": "pe_entrypoint",
                "rva": entry_rva,
            }
        blocks.append(block)
    if not entry_bound:
        raise StageAInputError(
            "binary inventory does not bind the PE entrypoint to a code region"
        )

    waivers = [
        {
            "id": str(row["id"]),
            "binary": "original",
            "rva": int(row["rva"]),
            "size": int(row["size"]),
            "reason": str(row["reason"]),
        }
        for row in parsed["padding_waivers"]
    ]
    return {
        "format": "stage-a-block-map-v1",
        "profile": OPAQUE_SELF_MAP_FORMAT,
        "status": "pass",
        "generator": "stage-a-export-opaque-reconstruction",
        "original": {
            "path": binary_path,
            "sha256": parsed["binary_sha256"],
        },
        "candidate": {
            "path": binary_path,
            "sha256": parsed["binary_sha256"],
        },
        "linker_maps": {"original": None, "candidate": None},
        "inventory": {
            "format": parsed["format"],
            "binary_sha256": parsed["binary_sha256"],
            "linker_map_sha256": parsed["linker_map_sha256"],
        },
        "blocks": blocks,
        "waivers": waivers,
        "issues": [],
        "counts": {
            "blocks": len(blocks),
            "waivers": len(waivers),
            "issues": 0,
            "roots": 1,
        },
    }


def stage_a_export_opaque_reconstruction(
    *, original: Path, inventory: Path, out: Path
) -> dict[str, Any]:
    """Emit a complete static reconstruction input without symbols or tracing."""

    original = Path(original).resolve()
    inventory = Path(inventory).resolve()
    out = Path(out).resolve()
    if not original.is_file() or not inventory.is_file():
        raise StageAInputError("opaque reconstruction inputs must be regular files")
    try:
        inventory_payload = json.loads(inventory.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"could not read binary inventory: {exc}") from exc
    parsed_inventory = parse_binary_cutpoint_inventory(inventory_payload)
    if sha256_file(original) != parsed_inventory["binary_sha256"]:
        raise StageAInputError(
            "opaque reconstruction binary hash differs from its inventory"
        )

    binary = _parse_stage_a_pe(original)
    try:
        entry_rva = binary.entrypoint_rva
    finally:
        binary.pe.close()

    out.mkdir(parents=True, exist_ok=True)
    self_map_path = out / "opaque-self-map.json"
    self_map = opaque_self_map_from_inventory(
        parsed_inventory,
        binary_path=str(original),
        entry_rva=entry_rva,
    )
    write_json(self_map_path, self_map)

    reference_path = out / "reference-contract.json"
    stage_a_export_reference_contract(
        original=original,
        mapping=self_map_path,
        out=reference_path,
        sidecar_dir=out,
        unit_contract_dir=out,
    )
    semantic_path = out / "semantic-transfer-contracts.jsonl"
    state_machine_path = out / "state-machine.jsonl"
    write_stage_b_state_machine_from_stage_a_export(
        reference_contract=reference_path,
        semantic_transfer_contracts=semantic_path,
        original_pe=original,
        out=state_machine_path,
    )
    load_image_path = out / "load-image-contract.json"
    load_image = write_stage_a_load_image_contract(
        original_pe=original,
        out=load_image_path,
    )

    transfer_count = sum(
        1 for line in state_machine_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    manifest = {
        "format": OPAQUE_STATIC_EXPORT_FORMAT,
        "status": "ready",
        "authority": "static-binary-only-reconstruction-input",
        "original": {
            "path": str(original),
            "sha256": parsed_inventory["binary_sha256"],
            "entry_rva": entry_rva,
        },
        "inventory": {
            "path": inventory.name,
            "sha256": sha256_file(inventory),
            "regions": parsed_inventory["counts"]["regions"],
            "padding_waivers": parsed_inventory["counts"]["padding_waivers"],
            "linker_map_sha256": parsed_inventory["linker_map_sha256"],
        },
        "outputs": {
            "self_map": {"path": self_map_path.name, "sha256": sha256_file(self_map_path)},
            "reference_contract": {
                "path": reference_path.name,
                "sha256": sha256_file(reference_path),
            },
            "semantic_transfers": {
                "path": semantic_path.name,
                "sha256": sha256_file(semantic_path),
            },
            "state_machine": {
                "path": state_machine_path.name,
                "sha256": sha256_file(state_machine_path),
            },
            "load_image_contract": {
                "path": load_image_path.name,
                "sha256": sha256_file(load_image_path),
                "contract_sha256": load_image.hashes.contract_sha256,
            },
        },
        "counts": {
            "regions": parsed_inventory["counts"]["regions"],
            "transfers": transfer_count,
            "padding_waivers": parsed_inventory["counts"]["padding_waivers"],
            "imports": sum(len(item.cells) for item in load_image.imports),
            "tls_callbacks": (
                0 if load_image.tls is None else len(load_image.tls.callbacks)
            ),
        },
        "trust": {
            "executes_original_binary": False,
            "uses_linker_map": False,
            "uses_symbols_for_authority": False,
            "includes_all_recovered_code": True,
            "reference_contract_is_formal_acceptance": False,
        },
    }
    write_json(out / "opaque-static-export.json", manifest)
    return manifest


__all__ = [
    "OPAQUE_SELF_MAP_FORMAT",
    "OPAQUE_STATIC_EXPORT_FORMAT",
    "opaque_self_map_from_inventory",
    "stage_a_export_opaque_reconstruction",
]
