from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.artifacts.formats import NATIVE_INGRESS_PLAN_FORMAT
from spaghetti_extractor.candidate.module_composer import compose_pe32_native_module
from spaghetti_extractor.candidate.native_ingress import (
    write_native_ingress_link_receipt,
)
from spaghetti_extractor.util import sha256_file, write_json


def main() -> None:
    original = Path(sys.argv[1])
    interface_path = Path(sys.argv[2])
    output = Path(sys.argv[3])
    output.mkdir(parents=True, exist_ok=True)
    interface = json.loads(interface_path.read_text(encoding="utf-8"))

    by_rva: dict[int, list[dict[str, object]]] = defaultdict(list)
    entry_rva = int(interface["loader"]["entry_rva"])
    by_rva[entry_rva].append({
        "role": str(interface["loader"]["entry_kind"]),
        "target_rva": entry_rva,
    })
    for callback in (interface.get("tls") or {}).get("callbacks", []):
        rva = int(callback["rva"])
        by_rva[rva].append({
            "role": "tls_callback",
            "target_rva": rva,
            "tls_order": int(callback["order"]),
        })
    for slot in interface["export_directory"]["slots"]:
        if slot["kind"] != "code":
            continue
        rva = int(slot["rva"])
        aliases = [
            {"name": name, "ordinal": int(slot["ordinal"])}
            for name in slot["names"]
        ] or [{"name": None, "ordinal": int(slot["ordinal"])}]
        by_rva[rva].append({
            "role": "export",
            "target_rva": rva,
            "exports": aliases,
        })

    ingresses: list[dict[str, object]] = []
    bridges: list[dict[str, object]] = []
    map_lines: list[str] = []
    image_base = int(interface["loader"]["preferred_base"])
    for index, (rva, rows) in enumerate(sorted(by_rva.items())):
        symbol = f"spx_ingress_{index:04d}"
        bridges.append({"symbol": symbol})
        map_lines.append(f"0x{image_base + rva:08x} _{symbol}")
        for row in rows:
            ingresses.append({
                **row,
                "bridge_symbol": symbol,
                "physical_frame_id": f"fixture-frame-{rva:08x}",
            })

    anchor_slots: dict[int, list[dict[str, object]]] = defaultdict(list)
    for slot in interface["export_directory"]["slots"]:
        if slot["kind"] != "data":
            continue
        aliases = [
            {"name": name, "ordinal": int(slot["ordinal"])}
            for name in slot["names"]
        ] or [{"name": None, "ordinal": int(slot["ordinal"])}]
        anchor_slots[int(slot["rva"])].extend(aliases)
    anchors = [
        {
            "id": f"fixture-data-anchor-{rva:08x}",
            "rule_id": f"fixture-image-object-{rva:08x}",
            "locator": {"kind": "image_rva", "rva": rva},
            "byte_offset": 0,
            "access": "read_write",
            "aliases": sorted(
                aliases,
                key=lambda row: (int(row["ordinal"]), str(row["name"])),
            ),
        }
        for rva, aliases in sorted(anchor_slots.items())
    ]
    tls = interface.get("tls")
    template_size = 0 if tls is None else int(tls["template_size"])
    zero_fill = 0 if tls is None else int(tls["zero_fill_size"])
    core = {
        "format": NATIVE_INGRESS_PLAN_FORMAT,
        "status": "complete",
        "module": {
            "image_id": interface["image_id"],
            "module_interface_sha256": sha256_file(interface_path),
        },
        "ingresses": ingresses,
        "bridges": bridges,
        "data_export_anchors": anchors,
        "tls_layout": {
            "runtime_offset": template_size + zero_fill,
            "runtime_bytes": 0,
        },
        "required_support_imports": [],
        "support_symbols": [],
        "seh_protocols": [],
    }
    plan = {**core, "plan_sha256": canonical_sha256_v3(core)}
    plan_path = output / "native-ingress-plan.json"
    write_json(plan_path, plan)
    map_path = output / "linked.map"
    map_path.write_text("\n".join(map_lines) + "\n", encoding="ascii")
    link_root = output / "link"
    write_native_ingress_link_receipt(
        native_ingress_plan=plan_path,
        linked_module=original,
        linker_map=map_path,
        out=link_root,
    )
    base_manifest = output / "base-composition.json"
    write_json(base_manifest, {
        "format": "spaghetti-extractor-fixture-linked-module-v1",
        "status": "composed",
        "candidate": {"sha256": sha256_file(original)},
    })
    compose_pe32_native_module(
        base_candidate=original,
        base_composition_manifest=base_manifest,
        original_module_interface=interface_path,
        native_ingress_plan=plan_path,
        native_ingress_link_receipt=(
            link_root / "native-ingress-link-receipt.json"
        ),
        out=output / "composed",
        candidate_filename="private.dll",
    )


if __name__ == "__main__":
    main()
