from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_image
from spaghetti_extractor.analysis.binary_inventory import stage_a_inventory_binary
from spaghetti_extractor.analysis.cutpoints import semantic_cutpoint_spans_for_side
from spaghetti_extractor.opaque_reconstruction import (
    opaque_self_map_from_inventory,
    stage_a_export_opaque_reconstruction,
)
from spaghetti_extractor.stage_binary import StageAInputError, _parse_stage_a_pe
from spaghetti_extractor.util import sha256_bytes


def _inventory() -> dict[str, object]:
    region = {
        "index": 0,
        "id": "original-cutpoint-00001000-00001008",
        "numeric_id": 0,
        "span": {"rva_start": 0x1000, "size": 8},
        "source": {"kind": "static_executable_section_block"},
    }
    return {
        "format": "stage-a-binary-cutpoint-inventory-v1",
        "profile": "x86-pe32-static-reconstruction-v1",
        "model": "x86-pe32-machine-ir-v1",
        "status": "pass",
        "side": "original",
        "binary_sha256": "1" * 64,
        "linker_map_sha256": sha256_bytes(b""),
        "executable_sections": [
            {"name": ".text", "rva_start": 0x1000, "rva_end": 0x1010}
        ],
        "regions": [region],
        "extraction_regions": [copy.deepcopy(region)],
        "padding_waivers": [
            {
                "binary": "original",
                "id": "original-padding-1008-1010",
                "reason": "verified zero fill",
                "rva": 0x1008,
                "size": 8,
            }
        ],
        "issues": [],
        "counts": {
            "regions": 1,
            "extraction_regions": 1,
            "padding_waivers": 1,
            "issues": 0,
        },
    }


class OpaqueReconstructionTests(unittest.TestCase):
    def test_binary_only_inventory_becomes_conservative_identity_map(self) -> None:
        payload = opaque_self_map_from_inventory(
            _inventory(), binary_path="/nix/store/example/hello.exe", entry_rva=0x1000
        )
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["counts"], {
            "blocks": 1,
            "waivers": 1,
            "issues": 0,
            "roots": 1,
        })
        self.assertTrue(payload["blocks"][0]["reachable"])
        self.assertEqual(payload["blocks"][0]["root"]["kind"], "pe_entrypoint")
        self.assertEqual(payload["waivers"][0]["binary"], "original")
        self.assertIsNone(payload["linker_maps"]["original"])

    def test_linker_map_provenance_is_rejected(self) -> None:
        inventory = _inventory()
        inventory["linker_map_sha256"] = "2" * 64
        with self.assertRaisesRegex(StageAInputError, "must not contain linker-map"):
            opaque_self_map_from_inventory(
                inventory, binary_path="hello.exe", entry_rva=0x1000
            )

    def test_entrypoint_must_be_covered(self) -> None:
        with self.assertRaisesRegex(StageAInputError, "does not bind the PE entrypoint"):
            opaque_self_map_from_inventory(
                _inventory(), binary_path="hello.exe", entry_rva=0x2000
            )

    def test_public_inventory_round_trips_through_opaque_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            inventory = root / "inventory.json"
            output = root / "opaque"
            original.write_bytes(pe32_image(b"\x31\xc0\xc3", virtual_size=16))
            stage_a_inventory_binary(
                binary=original,
                linker_map=None,
                side="original",
                out=inventory,
            )

            result = stage_a_export_opaque_reconstruction(
                original=original,
                inventory=inventory,
                out=output,
            )

            self.assertEqual(result["status"], "ready")
            self.assertTrue((output / "reference-contract.json").is_file())
            self.assertTrue((output / "state-machine.jsonl").is_file())

    def test_opaque_inventory_splits_nop_padding_before_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            inventory = root / "inventory.json"
            original.write_bytes(
                pe32_image(b"\x90\x90\x90\x56\xc3", virtual_size=5)
            )

            payload = stage_a_inventory_binary(
                binary=original,
                linker_map=None,
                side="original",
                out=inventory,
            )

            spans = [row["span"] for row in payload["regions"]]
            self.assertIn({"rva_start": 0x1003, "size": 2}, spans)
            self.assertTrue(any(
                waiver["rva"] == 0x1000 and waiver["size"] == 3
                for waiver in payload["padding_waivers"]
            ))

    def test_nop_split_does_not_treat_table_like_bytes_as_a_prologue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            original.write_bytes(
                pe32_image(b"\x90\x83\x39\x41\xc3", virtual_size=5)
            )
            binary = _parse_stage_a_pe(original)
            try:
                spans = semantic_cutpoint_spans_for_side(
                    binary,
                    {"rva_start": 0x1000, "rva_end": 0x1005, "size": 5},
                    "table-like",
                    periodic=False,
                    split_nop_padding=True,
                )
            finally:
                binary.pe.close()

            self.assertEqual(
                spans,
                [{"rva_start": 0x1000, "rva_end": 0x1005, "size": 5}],
            )


if __name__ == "__main__":
    unittest.main()
