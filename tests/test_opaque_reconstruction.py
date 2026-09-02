from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_image
from spaghetti_extractor.extraction.binary_inventory import spx_inventory_binary
from spaghetti_extractor.extraction.cutpoints import semantic_cutpoint_spans_for_side
from spaghetti_extractor.reconstruction.static_export import (
    export_static_reconstruction,
)
from spaghetti_extractor.reconstruction.ir_evidence import _static_program_inventory
from spaghetti_extractor.static_program.codec import (
    load_static_program_contract_binding,
    parse_static_program_contract,
)
from spaghetti_extractor.static_program.model import StaticProgramContractError
from spaghetti_extractor.pe32.image import parse_pe_image
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
        "format": "spaghetti-extractor-binary-cutpoint-inventory-v1",
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
                "classification": "verified_padding",
                "id": "original-padding-1008-1010",
                "reason": "verified zero fill",
                "rva": 0x1008,
                "size": 8,
                "source": {"kind": "test_fixture"},
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
    def test_static_program_contract_rejects_pair_and_reachability_fields(self) -> None:
        base = {
            "format": "spaghetti-extractor-static-program-contract-v2",
            "generator": "spaghetti-extractor-static-program",
            "profile": "x86-pe32-static-reconstruction-v1",
            "status": "complete",
            "binary": {"machine": "i386", "bitness": 32, "sha256": "1" * 64},
            "structural_universe": {"units": [{"id": "u", "kind": "code"}]},
            "families": {},
            "sidecars": {
                "semantic_transfers": {
                    "path": "semantic.jsonl",
                    "sha256": "2" * 64,
                }
            },
            "issues": [],
            "counts": {"units": 1},
            "trust": {
                "executes_original_binary": False,
                "input_image_count": 1,
                "uses_cross_image_mapping": False,
                "behavioral_reachability_separate": True,
            },
        }
        for mutation in (
            {"binary": {**base["binary"], "candidate": {}}},
            {
                "structural_universe": {
                    "units": [{"id": "u", "kind": "code", "reachable": True}]
                }
            },
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(StaticProgramContractError):
                    parse_static_program_contract({**base, **mutation})

        with self.assertRaises(StaticProgramContractError):
            parse_static_program_contract(
                {**base, "profile": "x86-pe32-unreviewed-profile"}
            )

    def test_structural_cfg_edges_do_not_authorize_indirect_targets(self) -> None:
        inventory = _static_program_inventory(
            {
                "structural_universe": {
                    "roots": [],
                    "padding": [],
                    "cfg_edges": [
                        {
                            "source_unit_id": "u0",
                            "target_rvas": [0x1234],
                            "indirect": True,
                        }
                    ],
                },
                "families": {},
            }
        )

        self.assertEqual(inventory["jump_table_targets"], [])

    def test_public_inventory_round_trips_through_opaque_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            inventory = root / "inventory.json"
            output = root / "opaque"
            original.write_bytes(pe32_image(b"\x31\xc0\xc3", virtual_size=16))
            spx_inventory_binary(
                binary=original,
                linker_map=None,
                side="original",
                out=inventory,
            )

            result = export_static_reconstruction(
                original=original,
                inventory=inventory,
                out=output,
            )

            self.assertEqual(result["status"], "ready")
            self.assertTrue((output / "static-program-contract.json").is_file())
            self.assertTrue((output / "state-machine.jsonl").is_file())
            self.assertFalse((output / "opaque-self-map.json").exists())
            rows = [
                json.loads(line)
                for line in (output / "semantic-transfer-contracts.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ]
            self.assertTrue(rows)
            self.assertTrue(all("reachable" not in row for row in rows))
            self.assertTrue(
                all("reference_contract" not in row for row in rows)
            )
            self.assertTrue(all("span" in row and "original" not in row for row in rows))

            semantic_path = output / "semantic-transfer-contracts.jsonl"
            semantic_path.write_text("{}\n", encoding="ascii")
            with self.assertRaisesRegex(
                StaticProgramContractError, "semantic sidecar differs"
            ):
                load_static_program_contract_binding(
                    output / "static-program-contract.json",
                    original_pe=original,
                )

    def test_opaque_inventory_splits_nop_padding_before_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            inventory = root / "inventory.json"
            original.write_bytes(
                pe32_image(b"\x90\x90\x90\x56\xc3", virtual_size=5)
            )

            payload = spx_inventory_binary(
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
            binary = parse_pe_image(original)
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
