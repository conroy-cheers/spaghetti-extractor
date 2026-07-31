import copy
import shutil
import tempfile
import unittest
from pathlib import Path

import capstone

from spaghetti_extractor.relational.isa_requirements import (
    ISARequirementInventory,
    _lean_form_extraction_source,
    _lean_side_form_extraction_source,
    build_isa_requirement_inventory,
    extract_lean_instruction_forms,
    isa_requirement_replay_projection,
)
from spaghetti_extractor.stage_binary import StageAInputError, _parse_stage_a_pe
from tests.stage_a_relational_support import _pe32_image


def _contract(size: int) -> dict[str, object]:
    return {
        "format": "stage-a-relation-contract-v1",
        "regions": [
            {
                "id": "entry",
                "numeric_id": 0,
                "root": True,
                "original": {
                    "rva_start": 0x1000,
                    "rva_end": 0x1000 + size,
                    "size": size,
                },
                "candidate": {
                    "rva_start": 0x1000,
                    "rva_end": 0x1000 + size,
                    "size": size,
                },
            }
        ],
    }


def _product_graph(*, frontier: list[int] | None = None) -> dict[str, object]:
    frontier = [] if frontier is None else frontier
    return {
        "format": "stage-a-relational-product-graph-v1",
        "nodes": [
            {"id": 0, "target_id": 0, "root": True, "outgoing_edge_ids": []}
        ],
        "edges": [],
        "root_node_ids": [0],
        "evidence": {
            "declared_reachable_node_ids": [0],
            "potential_reachable_node_ids": [0],
            "reachable_decoded_control_frontier_node_ids": frontier,
        },
        "counts": {"declared_reachability_control_closed": not frontier},
    }


class StageAISARequirementTests(unittest.TestCase):
    def _inventory(
        self, code: bytes, *, graph: dict[str, object] | None = None
    ) -> ISARequirementInventory:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image(code))
            candidate.write_bytes(_pe32_image(code))
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            decoded = list(decoder.disasm(code, 0x401000))
            formal_rows = tuple(
                {
                    "rva": int(instruction.address - 0x400000),
                    "size": int(instruction.size),
                    "bytes": bytes(instruction.bytes).hex(),
                    "form": f"fixture.{instruction.mnemonic}.{instruction.size}",
                }
                for instruction in decoded
            )
            return build_isa_requirement_inventory(
                original=_parse_stage_a_pe(original),
                candidate=_parse_stage_a_pe(candidate),
                relation_contract=_contract(len(code)),
                product_graph=graph or _product_graph(),
                lean_forms={
                    ("original", 0): formal_rows,
                    ("candidate", 0): formal_rows,
                },
                lean_form_source_sha256="0" * 64,
                lean_form_extractor_sha256="1" * 64,
            )

    def test_inventory_binds_exact_occurrences_forms_and_rooted_scopes(self):
        inventory = self._inventory(b"\x01\xd8\x05\x01\x00\x00\x00\xc3")
        payload = inventory.to_payload()

        self.assertEqual(payload["status"], "complete")
        self.assertEqual(payload["counts"]["canonical_nodes"], 1)
        self.assertEqual(payload["counts"]["canonical_occurrences"], 6)
        self.assertEqual(payload["counts"]["canonical_forms"], 3)
        self.assertEqual(payload["counts"]["conservative_required_forms"], 3)
        self.assertTrue(payload["scope"]["control_closed"])
        self.assertFalse(payload["trust"]["proof_authority"])
        self.assertFalse(payload["trust"]["closes_stage_a_proof"])
        self.assertEqual(
            {row["side"] for row in payload["occurrences"]},
            {"original", "candidate"},
        )
        add_register_forms = [
            row
            for row in payload["forms"]
            if any(
                display["mnemonic"] == "add" and display["opcode"] == "01"
                for display in row["capstone_display_forms"]
            )
        ]
        self.assertEqual(len(add_register_forms), 1)
        self.assertEqual(
            add_register_forms[0]["counts"]["canonical_occurrences"], 2
        )

    def test_unmodeled_form_remains_an_explicit_required_gap(self):
        inventory = self._inventory(b"\x0f\xa2\xc3").to_payload()

        self.assertEqual(inventory["status"], "incomplete")
        self.assertEqual(inventory["counts"]["unsupported_occurrences"], 2)
        self.assertEqual(
            inventory["counts"]["conservative_required_unsupported_occurrences"],
            2,
        )
        self.assertEqual(
            {row["category"] for row in inventory["gaps"]},
            {"diagnostic_preflight_instruction_unsupported"},
        )

    def test_control_frontier_is_preserved_instead_of_claiming_closed_scope(self):
        inventory = self._inventory(
            b"\xc3", graph=_product_graph(frontier=[0])
        ).to_payload()

        self.assertFalse(inventory["scope"]["control_closed"])
        self.assertEqual(inventory["scope"]["control_frontier_node_ids"], [0])

    def test_tampered_scope_and_proof_authority_fail_closed(self):
        payload = self._inventory(b"\xc3").to_payload()
        bad_scope = copy.deepcopy(payload)
        bad_scope["scope"]["conservative_required_node_ids"] = [1]
        with self.assertRaises(StageAInputError):
            ISARequirementInventory.parse(bad_scope)

        bad_trust = copy.deepcopy(payload)
        bad_trust["trust"]["proof_authority"] = True
        with self.assertRaises(StageAInputError):
            ISARequirementInventory.parse(bad_trust)

    def test_replay_projection_is_canonical_and_rejects_region_drift(self):
        inventory = self._inventory(b"\x01\xd8\xc3").to_payload()
        projection = isa_requirement_replay_projection(inventory, _contract(3))

        self.assertEqual(set(projection), {"original", "candidate"})
        self.assertEqual(projection["original"][0].target_id, 0)
        self.assertEqual(
            [row.encoded for row in projection["original"][0].occurrences],
            [b"\x01\xd8", b"\xc3"],
        )

        tampered = copy.deepcopy(inventory)
        tampered["occurrences"][0]["region_id"] = "wrong-region"
        with self.assertRaises(StageAInputError):
            isa_requirement_replay_projection(tampered, _contract(3))

    def test_lea_address_operand_is_not_classified_as_a_memory_access(self):
        payload = self._inventory(b"\x8d\x03\xc3").to_payload()
        lea_form = next(
            row
            for row in payload["forms"]
            if any(
                display["mnemonic"] == "lea"
                for display in row["capstone_display_forms"]
            )
        )
        lea = next(
            display
            for display in lea_form["capstone_display_forms"]
            if display["mnemonic"] == "lea"
        )

        self.assertNotIn("memory", lea["features"])
        self.assertNotIn("may-fault", lea["features"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_formal_inventory_uses_the_lean_decoder_for_exact_spans(self):
        code = b"\x01\xd8\xc3"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image(code))
            candidate.write_bytes(_pe32_image(code))
            rows, evidence = extract_lean_instruction_forms(
                original=original,
                candidate=candidate,
                relation_contract=_contract(len(code)),
            )

        self.assertEqual(evidence["status"], "lean_extracted_untrusted")
        self.assertEqual(set(rows), {("original", 0), ("candidate", 0)})
        for occurrences in rows.values():
            self.assertEqual([row["rva"] for row in occurrences], [0x1000, 0x1002])
            self.assertEqual([row["bytes"] for row in occurrences], ["01d8", "c3"])
            self.assertIn("binary", occurrences[0]["form"])
            self.assertIn("ret", occurrences[1]["form"])

    def test_formal_inventory_source_chunks_large_request_sets(self):
        region = _contract(1)["regions"][0]
        source = _lean_form_extraction_source([
            {
                **region,
                "id": f"region-{index}",
                "numeric_id": index,
            }
            for index in range(300)
        ])

        self.assertIn("def requestChunks : List (List Request)", source)
        self.assertIn("for chunk in requestChunks do", source)
        self.assertIn("    for request in chunk do", source)
        self.assertNotIn("def requests : List Request", source)
        self.assertEqual(source.count("{ candidate :="), 600)

    def test_side_inventory_classifies_region_slices_without_reparsing_pe(self):
        source = _lean_side_form_extraction_source(
            "candidate",
            [
                {"span": {"rva_start": 0x1000, "size": 2}},
                {"span": {"rva_start": 0x2000, "size": 3}},
            ],
        )

        self.assertIn('readBinFile "artifacts/regions.bin"', source)
        self.assertIn("dataOffset := 0", source)
        self.assertIn("dataOffset := 2", source)
        self.assertIn("decodeInstructionFormsBytes request.span.start", source)
        self.assertNotIn("parsePE32", source)
        self.assertNotIn('readBinFile "artifacts/input.pe"', source)
        self.assertEqual(source.count("dataOffset :="), 2)


if __name__ == "__main__":
    unittest.main()
