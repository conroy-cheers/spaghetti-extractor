from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.isa_cli import _binary_requirements, generate_isa_corpus
from spaghetti_extractor.isa_conformance_lean import (
    lean_semantic_form_classifier_sha256 as conformance_classifier_sha256,
)
from spaghetti_extractor.isa_kernel_qualification import SemanticKernelBinding
from spaghetti_extractor.isa_semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from spaghetti_extractor.isa_side_adapter import (
    SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT,
    adapt_side_isa_qualification_inputs,
    write_side_isa_qualification_inputs,
)
from spaghetti_extractor.relational.isa_requirements import ISARequirementInventory
from spaghetti_extractor.relational.side_extraction_artifact import (
    parse_request,
    request_payload,
)
from spaghetti_extractor.relational.side_isa_artifact import side_isa_payload
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file


def _write(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class StageAISASideAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.classifier_sha256 = lean_semantic_form_classifier_sha256()
        self.hashes = {
            "classifier_sha256": self.classifier_sha256,
            "extractor_sha256": "c" * 64,
            "source_sha256": "d" * 64,
        }
        self.contract = {
            "regions": [
                {
                    "id": "entry",
                    "numeric_id": 10,
                    "original": {"rva_start": 0x1000, "size": 3},
                    "candidate": {"rva_start": 0x2000, "size": 3},
                },
                {
                    "id": "branch",
                    "numeric_id": 11,
                    "original": {"rva_start": 0x1003, "size": 2},
                    "candidate": {"rva_start": 0x2003, "size": 2},
                },
            ]
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _side(
        self,
        side: str,
        *,
        jump_bytes: str,
        classifier_sha256: str | None = None,
        region_count: int = 2,
    ) -> tuple[Path, Path, dict[str, object]]:
        binary = self.root / f"{side}.exe"
        binary.write_bytes((side + "-binary").encode("ascii"))
        contract = {"regions": self.contract["regions"][:region_count]}
        request = parse_request(
            request_payload(contract, side, sha256_file(binary))
        )
        start = 0x1000 if side == "original" else 0x2000
        forms = {
            (side, 0): (
                {
                    "rva": start,
                    "size": 1,
                    "bytes": "90",
                    "form": "StageA.Formal.InstructionSemanticForm.nop",
                },
                {
                    "rva": start + 1,
                    "size": 1,
                    "bytes": "90",
                    "form": "StageA.Formal.InstructionSemanticForm.nop",
                },
                {
                    "rva": start + 2,
                    "size": 1,
                    "bytes": "c3",
                    "form": "StageA.Formal.InstructionSemanticForm.ret",
                },
            ),
        }
        if region_count == 2:
            forms[(side, 1)] = (
                {
                    "rva": start + 3,
                    "size": 2,
                    "bytes": jump_bytes,
                    "form": "StageA.Formal.InstructionSemanticForm.jumpRel8",
                },
            )
        hashes = {
            **self.hashes,
            "classifier_sha256": (
                self.classifier_sha256
                if classifier_sha256 is None
                else classifier_sha256
            ),
        }
        payload = side_isa_payload(request, forms=forms, **hashes)
        artifact = self.root / f"{side}-isa.json"
        _write(artifact, payload)
        return artifact, binary, payload

    def test_classifier_identity_is_shared_with_the_conformance_path(self) -> None:
        self.assertEqual(
            self.classifier_sha256,
            conformance_classifier_sha256(),
        )

    def test_two_sides_preserve_occurrences_and_propose_every_encoding(self) -> None:
        original, original_binary, _ = self._side(
            "original", jump_bytes="eb00"
        )
        candidate, candidate_binary, _ = self._side(
            "candidate", jump_bytes="eb01"
        )

        requirements, catalog = adapt_side_isa_qualification_inputs([
            (candidate, candidate_binary),
            (original, original_binary),
        ])

        parsed = ISARequirementInventory.parse(requirements).to_payload()
        self.assertEqual(parsed["status"], "complete")
        self.assertEqual(parsed["counts"]["canonical_occurrences"], 8)
        self.assertEqual(parsed["counts"]["canonical_forms"], 3)
        self.assertEqual(parsed["counts"]["canonical_nodes"], 4)
        self.assertEqual(
            parsed["inputs"]["original_sha256"], sha256_file(original_binary)
        )
        self.assertEqual(
            parsed["inputs"]["candidate_sha256"], sha256_file(candidate_binary)
        )
        self.assertFalse(parsed["scope"]["control_closed"])
        self.assertEqual(
            parsed["scope"]["control_frontier_node_ids"], [0, 1, 2, 3]
        )
        self.assertFalse(parsed["trust"]["proof_authority"])
        self.assertEqual(
            {row["bytes"] for row in parsed["occurrences"]},
            {"90", "c3", "eb00", "eb01"},
        )
        nop_id = lean_semantic_form_id(
            "StageA.Formal.InstructionSemanticForm.nop",
            classifier_sha256=self.classifier_sha256,
        )
        self.assertIn(nop_id, {row["id"] for row in parsed["forms"]})
        kernel = SemanticKernelBinding(
            id="fixture-kernel",
            decoder_sha256="1" * 64,
            semantics_sha256="2" * 64,
            lean_version="fixture",
        )
        for side in ("original", "candidate"):
            selected = _binary_requirements(
                parsed,
                side=side,
                profile_id="pe32-i686-v1",
                semantic_kernel=kernel,
            )
            self.assertEqual(selected.binary_id, side)
            self.assertTrue(selected.forms)

        self.assertEqual(
            catalog["format"], SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT
        )
        self.assertEqual(
            catalog["status"], "incomplete_missing_effect_enrichment"
        )
        self.assertEqual(catalog["counts"]["forms"], 3)
        self.assertEqual(catalog["counts"]["encodings"], 4)
        self.assertEqual(catalog["counts"]["occurrences"], 8)
        self.assertFalse(
            catalog["missing_enrichment"]["corpus_generation_allowed"]
        )
        jump_form = next(
            row
            for row in catalog["forms"]
            if row["semantic_form"].endswith("jumpRel8")
        )
        representative = next(
            row
            for row in catalog["encodings"]
            if row["encoding_id"] == jump_form["representative_encoding_id"]
        )
        self.assertEqual(representative["instruction_hex"], "eb00")
        self.assertTrue(representative["representative"])
        self.assertTrue(
            all(
                row["enrichment"]["status"] == "missing"
                for row in catalog["encodings"]
            )
        )

    def test_single_side_writes_selection_compatible_requirements(self) -> None:
        original, binary, _ = self._side("original", jump_bytes="eb00")
        requirements_out = self.root / "requirements.json"
        catalog_out = self.root / "catalog.json"

        result = write_side_isa_qualification_inputs(
            side_isa_artifacts=[original],
            binaries=[binary],
            requirements_out=requirements_out,
            catalog_out=catalog_out,
        )

        self.assertEqual(result["status"], "generated")
        self.assertEqual(
            result["catalog_status"], "incomplete_missing_effect_enrichment"
        )
        requirements = ISARequirementInventory.parse(
            json.loads(requirements_out.read_text(encoding="utf-8"))
        ).to_payload()
        self.assertEqual(requirements["inputs"]["original_sha256"], sha256_file(binary))
        self.assertIsNone(requirements["inputs"]["candidate_sha256"])
        self.assertEqual(
            json.loads(catalog_out.read_text(encoding="utf-8"))["counts"][
                "encodings"
            ],
            3,
        )

    def test_two_sides_may_have_independent_region_inventories(self) -> None:
        original, original_binary, _ = self._side(
            "original", jump_bytes="eb00"
        )
        candidate, candidate_binary, _ = self._side(
            "candidate",
            jump_bytes="eb01",
            region_count=1,
        )

        requirements, _ = adapt_side_isa_qualification_inputs([
            (original, original_binary),
            (candidate, candidate_binary),
        ])

        self.assertEqual(requirements["counts"]["canonical_nodes"], 3)
        candidate_nodes = {
            row["node_id"]
            for row in requirements["occurrences"]
            if row["side"] == "candidate"
        }
        self.assertEqual(candidate_nodes, {2})

    def test_tampered_hash_form_and_rva_fail_closed(self) -> None:
        artifact, binary, payload = self._side("original", jump_bytes="eb00")
        mutations = []

        bad_hash = copy.deepcopy(payload)
        bad_hash["regions"][0]["occurrences"][0]["bytes"] = "91"
        mutations.append((bad_hash, "hash mismatch"))

        bad_form = copy.deepcopy(payload)
        bad_form["regions"][0]["occurrences"][0]["form"] = ""
        mutations.append((bad_form, "invalid"))

        bad_rva = copy.deepcopy(payload)
        bad_rva["regions"][0]["occurrences"][0]["rva"] += 1
        mutations.append((bad_rva, "invalid"))

        for index, (mutation, message) in enumerate(mutations):
            with self.subTest(index=index):
                path = self.root / f"tampered-{index}.json"
                _write(path, mutation)
                with self.assertRaisesRegex(StageAInputError, message):
                    adapt_side_isa_qualification_inputs([(path, binary)])

    def test_wrong_binary_duplicate_side_and_stale_classifier_fail_closed(self) -> None:
        artifact, binary, _ = self._side("original", jump_bytes="eb00")
        wrong_binary = self.root / "wrong.exe"
        wrong_binary.write_bytes(b"wrong")
        with self.assertRaisesRegex(StageAInputError, "different binary"):
            adapt_side_isa_qualification_inputs([(artifact, wrong_binary)])

        with self.assertRaisesRegex(StageAInputError, "duplicate side"):
            adapt_side_isa_qualification_inputs([
                (artifact, binary),
                (artifact, binary),
            ])

        stale, stale_binary, _ = self._side(
            "candidate",
            jump_bytes="eb01",
            classifier_sha256="f" * 64,
        )
        with self.assertRaisesRegex(StageAInputError, "stale semantic classifier"):
            adapt_side_isa_qualification_inputs([(stale, stale_binary)])

    def test_catalog_proposal_cannot_generate_a_corpus(self) -> None:
        artifact, binary, _ = self._side("original", jump_bytes="eb00")
        _, catalog = adapt_side_isa_qualification_inputs([(artifact, binary)])
        catalog_path = self.root / "catalog.json"
        _write(catalog_path, catalog)

        with self.assertRaisesRegex(
            StageAInputError, "effects, defined-output masks"
        ):
            generate_isa_corpus(
                catalog=catalog_path,
                seed=0,
                out=self.root / "corpus",
            )


if __name__ == "__main__":
    unittest.main()
