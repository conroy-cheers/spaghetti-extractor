from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.opaque_reconstruction import (
    opaque_self_map_from_inventory,
)
from spaghetti_extractor.stage_binary import StageAInputError
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


if __name__ == "__main__":
    unittest.main()
