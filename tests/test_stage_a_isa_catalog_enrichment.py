from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.cli import _build_parser
from spaghetti_extractor.isa_catalog_enrichment import (
    SIDE_ISA_CATALOG_ENRICHMENT_FORMAT,
    _encoding_id,
    _generated_lean_module,
    enrich_side_isa_catalog,
    extract_lean_decoded_metadata,
    resolved_isa_catalog,
)
from spaghetti_extractor.isa_cli import generate_isa_corpus
from spaghetti_extractor.isa_corpus_generator import parse_generated_isa_corpus
from spaghetti_extractor.isa_semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from spaghetti_extractor.relational.schema import STAGE_A_RELATIONAL_MODEL_ID
from spaghetti_extractor.stage_binary import StageAInputError


MOV_FORM = "StageA.Formal.InstructionSemanticForm.movRegImm"
MEMORY_FORM = """StageA.Formal.InstructionSemanticForm.movFromOperand
  (StageA.Formal.Operand32SemanticForm.memory
    { hasBase := true, hasIndex := false, scaleShift := 0, hasDisplacement := true })"""
BRANCH_FORM = "StageA.Formal.InstructionSemanticForm.branchEqual false"
CALL_FORM = "StageA.Formal.InstructionSemanticForm.callRel32"
RET_FORM = "StageA.Formal.InstructionSemanticForm.ret"
DIVIDE_FORM = (
    "StageA.Formal.InstructionSemanticForm.divideUnsigned "
    "(StageA.Formal.Operand32SemanticForm.register)"
)
X87_FORM = (
    "StageA.Formal.InstructionSemanticForm.x87LoadConstant "
    "302222231531620438900736"
)
REP_FORM = "StageA.Formal.InstructionSemanticForm.moveDwords true"
FS_FORM = """StageA.Formal.InstructionSemanticForm.movFs32
  { hasBase := true, hasIndex := false, scaleShift := 0, hasDisplacement := false }"""
PUSH_ALL_FORM = "StageA.Formal.InstructionSemanticForm.pushAll"
ALIASED_LEA_FORM = """StageA.Formal.InstructionSemanticForm.leaAddress
  { hasBase := true, hasIndex := true, scaleShift := 2, hasDisplacement := false }"""
MIXED_LEA_FORM = """StageA.Formal.InstructionSemanticForm.leaAddress
  { hasBase := true, hasIndex := true, scaleShift := 0, hasDisplacement := false }"""
EXPANDED_FORM_BY_HEX = {
    "c60000": """StageA.Formal.InstructionSemanticForm.movImmediate8
  (StageA.Formal.Operand8SemanticForm.memory
    { hasBase := true, hasIndex := false, scaleShift := 0, """
    "hasDisplacement := false })",
    "668901": """StageA.Formal.InstructionSemanticForm.movToOperandWidth
  (StageA.Formal.OperandWidth.word)
  (StageA.Formal.Operand32SemanticForm.memory
    { hasBase := true, hasIndex := false, scaleShift := 0, """
    "hasDisplacement := false })",
    "3401": """StageA.Formal.InstructionSemanticForm.binary8
  (StageA.Formal.BinaryOperation.xor)
  (StageA.Formal.Operand8SemanticForm.register false)
  (StageA.Formal.Operand8SemanticForm.immediate)""",
    "662d3e40": """StageA.Formal.InstructionSemanticForm.binaryWidth
  (StageA.Formal.OperandWidth.word)
  (StageA.Formal.BinaryOperation.sub)
  (StageA.Formal.Operand32SemanticForm.register)
  (StageA.Formal.Operand32SemanticForm.immediate)""",
    "d1e1": """StageA.Formal.InstructionSemanticForm.shift
  (StageA.Formal.ShiftOperation.left)
  (StageA.Formal.Operand32SemanticForm.register)
  (StageA.Formal.ShiftCount.immediate 1)""",
    "0facef04": """StageA.Formal.InstructionSemanticForm.doubleShift
  false
  (StageA.Formal.Operand32SemanticForm.register)
  (StageA.Formal.ShiftCount.immediate 4)""",
    "0f4cc1": """StageA.Formal.InstructionSemanticForm.conditionalMove
  (StageA.Formal.Condition.less)
  (StageA.Formal.Operand32SemanticForm.register)""",
    "0f9444242b": """StageA.Formal.InstructionSemanticForm.setCondition
  (StageA.Formal.Condition.equal)
  (StageA.Formal.Operand8SemanticForm.memory
    { hasBase := true, hasIndex := false, scaleShift := 0, """
    "hasDisplacement := true })",
    "f7e9": (
        "StageA.Formal.InstructionSemanticForm.multiplyFull true "
        "(StageA.Formal.Operand32SemanticForm.register)"
    ),
    "6bc02c": (
        "StageA.Formal.InstructionSemanticForm.multiplyLow "
        "(StageA.Formal.Operand32SemanticForm.register) true"
    ),
    "0fbdc0": """StageA.Formal.InstructionSemanticForm.bitScan
  (StageA.Formal.BitScanOperation.reverse)
  (StageA.Formal.Operand32SemanticForm.register)""",
    "0fa3c2": "StageA.Formal.InstructionSemanticForm.bitTestRegister",
    "80e4f7": """StageA.Formal.InstructionSemanticForm.binary8
  (StageA.Formal.BinaryOperation.and)
  (StageA.Formal.Operand8SemanticForm.register true)
  (StageA.Formal.Operand8SemanticForm.immediate)""",
    "ff1528754200": "StageA.Formal.InstructionSemanticForm.callImport",
    "ff2500224300": "StageA.Formal.InstructionSemanticForm.jumpImport",
}


def _proposal(rows: list[tuple[str, str]]) -> dict:
    classifier = lean_semantic_form_classifier_sha256()
    encodings: list[dict] = []
    for index, (instruction_hex, semantic_form) in enumerate(rows):
        form_id = lean_semantic_form_id(
            semantic_form,
            classifier_sha256=classifier,
        )
        encodings.append(
            {
                "format": "stage-a-side-isa-executable-encoding-proposal-v1",
                "encoding_id": _encoding_id(form_id, instruction_hex),
                "form_id": form_id,
                "semantic_form": semantic_form,
                "instruction_bytes": list(bytes.fromhex(instruction_hex)),
                "instruction_hex": instruction_hex,
                "source_occurrence_ids": [
                    f"isa-occurrence-{index:024x}"
                ],
                "representative": False,
                "enrichment": {
                    "status": "missing",
                    "missing_fields": [
                        "defined_outputs",
                        "effects",
                        "required_features",
                    ],
                },
            }
        )
    encodings.sort(key=lambda row: (row["form_id"], row["instruction_hex"]))
    forms = []
    for form_id in sorted({row["form_id"] for row in encodings}):
        form_encodings = [
            row for row in encodings if row["form_id"] == form_id
        ]
        representative = min(
            form_encodings,
            key=lambda row: (
                len(row["instruction_bytes"]),
                row["instruction_hex"],
            ),
        )
        representative["representative"] = True
        forms.append(
            {
                "form_id": form_id,
                "semantic_form": representative["semantic_form"],
                "representative_encoding_id": representative["encoding_id"],
                "encoding_ids": sorted(
                    row["encoding_id"] for row in form_encodings
                ),
            }
        )
    return {
        "format": "stage-a-side-isa-executable-catalog-proposal-v1",
        "status": "incomplete_missing_effect_enrichment",
        "profile": "pe32-i686-v1",
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "classifier_sha256": classifier,
        "requirements_sha256": "1" * 64,
        "source": {
            "adapter": "fixture-side-isa-adapter-v1",
            "side_isa_artifacts": [
                {
                    "side": "original",
                    "binary_sha256": "2" * 64,
                    "artifact_sha256": "3" * 64,
                }
            ],
        },
        "forms": forms,
        "encodings": encodings,
        "missing_enrichment": {
            "status": "required",
            "fields": [
                "defined_outputs",
                "effects",
                "required_features",
            ],
            "encoding_count": len(encodings),
            "corpus_generation_allowed": False,
        },
        "counts": {
            "forms": len(forms),
            "encodings": len(encodings),
            "occurrences": len(encodings),
            "representatives": len(forms),
        },
        "trust": {
            "role": "untrusted_executable_catalog_enrichment_proposal",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }


def _decoded(
    proposal: dict,
    instructions_by_hex: dict[str, dict],
) -> dict[str, dict]:
    return {
        row["encoding_id"]: {
            "encoding_id": row["encoding_id"],
            "status": "decoded",
            "semantic_form": row["semantic_form"],
            "decoded_size": len(row["instruction_bytes"]),
            "instruction": copy.deepcopy(
                instructions_by_hex[row["instruction_hex"]]
            ),
        }
        for row in proposal["encodings"]
    }


def _binding(proposal: dict) -> dict[str, str]:
    return {
        "classifier_sha256": proposal["classifier_sha256"],
        "metadata_exporter_sha256": "4" * 64,
        "lean_version": "Lean fixture",
    }


def _fixture_instructions() -> dict[str, dict]:
    return {
        "b878563412": {
            "constructor": "movRegImm",
            "destination": "eax",
            "value": 0x12345678,
        },
        "8b4304": {
            "constructor": "movFromOperand",
            "destination": "eax",
            "source": {
                "kind": "memory",
                "address": {
                    "base": "ebx",
                    "index": None,
                    "scale_shift": 0,
                    "displacement": 4,
                },
            },
        },
        "7402": {
            "constructor": "branchEqual",
            "inverted": False,
            "displacement": 2,
        },
        "e800000000": {
            "constructor": "callRel32",
            "displacement": 0,
        },
        "c3": {"constructor": "ret"},
        "f7f1": {
            "constructor": "divideUnsigned",
            "source": {"kind": "register", "register": "ecx"},
        },
        "d9e8": {
            "constructor": "x87LoadConstant",
            "value": 302222231531620438900736,
        },
        "f3a5": {
            "constructor": "unsupported",
            "repr": "StageA.Formal.Instruction.moveDwords true",
        },
        "648b00": {
            "constructor": "unsupported",
            "repr": "StageA.Formal.Instruction.movFs32 fixture",
        },
        "60": {"constructor": "pushAll"},
        "8d0480": {
            "constructor": "leaAddress",
            "destination": "eax",
            "source": {
                "base": "eax",
                "index": "eax",
                "scale_shift": 2,
                "displacement": 0,
            },
        },
        "8d040e": {
            "constructor": "leaAddress",
            "destination": "eax",
            "source": {
                "base": "esi",
                "index": "ecx",
                "scale_shift": 0,
                "displacement": 0,
            },
        },
        "8d041b": {
            "constructor": "leaAddress",
            "destination": "eax",
            "source": {
                "base": "ebx",
                "index": "ebx",
                "scale_shift": 0,
                "displacement": 0,
            },
        },
    }


class StageAExactISACatalogEnrichmentTests(unittest.TestCase):
    def test_full_gnu_scale_export_is_split_into_bounded_lean_functions(
        self,
    ) -> None:
        source = _generated_lean_module(
            [
                {
                    "encoding_id": f"encoding-{index:05d}",
                    "instruction_bytes": [0x90],
                }
                for index in range(8_764)
            ]
        )

        self.assertIn("private def emitMetadataChunk34", source)
        self.assertNotIn("private def emitMetadataChunk35", source)
        self.assertNotIn("metadataInputs", source)
        self.assertEqual(source.count("  emitDecodedMetadata "), 8_764)

    def test_cli_wires_the_exact_proposal_enrichment_boundary(self) -> None:
        args = _build_parser(prog="fixture").parse_args(
            [
                "stage-a-enrich-side-isa-catalog",
                "--proposal",
                "proposal.json",
                "--out",
                "enriched.json",
                "--timeout-seconds",
                "17",
            ]
        )
        with mock.patch(
            "spaghetti_extractor.cli.write_enriched_side_isa_catalog",
            return_value={"status": "generated"},
        ) as write:
            self.assertEqual(args.func(args), {"status": "generated"})

        write.assert_called_once_with(
            proposal=Path("proposal.json"),
            out=Path("enriched.json"),
            timeout_seconds=17,
        )

    def test_deterministic_enrichment_and_representative_corpus_projection(
        self,
    ) -> None:
        proposal = _proposal(
            [
                ("b878563412", MOV_FORM),
                ("d9e8", X87_FORM),
                ("f3a5", REP_FORM),
                ("648b00", FS_FORM),
                ("60", PUSH_ALL_FORM),
            ]
        )
        metadata = _decoded(proposal, _fixture_instructions())

        first = enrich_side_isa_catalog(
            proposal,
            metadata,
            lean_binding=_binding(proposal),
        )
        reordered = dict(reversed(list(copy.deepcopy(proposal).items())))
        second = enrich_side_isa_catalog(
            reordered,
            copy.deepcopy(metadata),
            lean_binding=_binding(proposal),
        )

        self.assertEqual(first, second)
        self.assertEqual(first["format"], SIDE_ISA_CATALOG_ENRICHMENT_FORMAT)
        self.assertEqual(first["status"], "incomplete_unresolved_encodings")
        self.assertEqual(
            first["counts"],
            {
                "forms": 5,
                "encodings": 5,
                "resolved": 3,
                "unresolved": 2,
                "qualified_forms": 3,
                "unresolved_forms": 2,
                "corpus_entries": 3,
            },
        )
        self.assertEqual(
            first["unresolved_reasons"],
            {
                "instruction_family_not_soundly_derivable": 2,
            },
        )
        for source, enriched in zip(
            proposal["encodings"], first["encodings"], strict=True
        ):
            for field in (
                "encoding_id",
                "form_id",
                "semantic_form",
                "instruction_bytes",
                "instruction_hex",
                "source_occurrence_ids",
                "representative",
            ):
                self.assertEqual(enriched[field], source[field])
        catalog = resolved_isa_catalog(first)
        self.assertEqual(len(catalog.entries), 3)
        self.assertEqual(
            {entry.instruction_bytes for entry in catalog.entries},
            {
                bytes.fromhex("60"),
                bytes.fromhex("b878563412"),
                bytes.fromhex("d9e8"),
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog_path = root / "enriched.json"
            out = root / "corpus"
            catalog_path.write_text(
                json.dumps(first, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = generate_isa_corpus(
                catalog=catalog_path,
                seed=7,
                out=out,
            )
            generated = parse_generated_isa_corpus(
                json.loads(
                    (out / "generated-corpus.json").read_text(encoding="utf-8")
                )
            )
            manifest = json.loads(
                (out / "manifest.json").read_text(encoding="utf-8")
            )

        self.assertEqual(result["exact_decoded_encoding_count"], 5)
        self.assertEqual(result["resolved_encoding_count"], 3)
        self.assertEqual(result["unresolved_encoding_count"], 2)
        self.assertEqual(result["qualified_form_count"], 3)
        self.assertEqual(result["unresolved_form_count"], 2)
        self.assertEqual(
            {case.instruction_bytes for case in generated.cases},
            {
                bytes.fromhex("60"),
                bytes.fromhex("b878563412"),
                bytes.fromhex("d9e8"),
            },
        )
        resolved_hexes = {"60", "b878563412", "d9e8"}
        source_form_ids = {
            row["form_id"]
            for row in proposal["encodings"]
            if row["instruction_hex"] in resolved_hexes
        }
        self.assertEqual(
            {row["source_form_id"] for row in manifest["cases"]},
            source_form_ids,
        )
        self.assertEqual(
            {row["source_encoding_id"] for row in manifest["cases"]},
            {entry.encoding_id for entry in catalog.entries},
        )

    def test_proposal_and_lean_metadata_corruption_fail_closed(self) -> None:
        proposal = _proposal([("b878563412", MOV_FORM)])
        metadata = _decoded(proposal, _fixture_instructions())
        corruptions = []

        bad_bytes = copy.deepcopy(proposal)
        bad_bytes["encodings"][0]["instruction_bytes"][-1] ^= 1
        corruptions.append(bad_bytes)

        bad_encoding_id = copy.deepcopy(proposal)
        bad_encoding_id["encodings"][0]["encoding_id"] = "tampered"
        corruptions.append(bad_encoding_id)

        bad_count = copy.deepcopy(proposal)
        bad_count["counts"]["encodings"] = 2
        corruptions.append(bad_count)

        unknown = copy.deepcopy(proposal)
        unknown["surprise"] = True
        corruptions.append(unknown)

        for corrupted in corruptions:
            with self.subTest(corruption=corrupted):
                with self.assertRaises(StageAInputError):
                    enrich_side_isa_catalog(
                        corrupted,
                        metadata,
                        lean_binding=_binding(proposal),
                    )

        stale_metadata = copy.deepcopy(metadata)
        stale_metadata[next(iter(stale_metadata))]["semantic_form"] = RET_FORM
        with self.assertRaisesRegex(StageAInputError, "semantic form changed"):
            enrich_side_isa_catalog(
                proposal,
                stale_metadata,
                lean_binding=_binding(proposal),
            )

        wrong_size = copy.deepcopy(metadata)
        wrong_size[next(iter(wrong_size))]["decoded_size"] = 4
        with self.assertRaisesRegex(StageAInputError, "decoded size changed"):
            enrich_side_isa_catalog(
                proposal,
                wrong_size,
                lean_binding=_binding(proposal),
            )

        unknown_constructor = copy.deepcopy(metadata)
        unknown_constructor[next(iter(unknown_constructor))]["instruction"] = {
            "constructor": "tampered"
        }
        with self.assertRaisesRegex(StageAInputError, "reviewed Lean exporter"):
            enrich_side_isa_catalog(
                proposal,
                unknown_constructor,
                lean_binding=_binding(proposal),
            )

        enriched = enrich_side_isa_catalog(
            proposal,
            metadata,
            lean_binding=_binding(proposal),
        )
        bad_enriched_bytes = copy.deepcopy(enriched)
        bad_enriched_bytes["encodings"][0]["instruction_bytes"][-1] ^= 1
        bad_enriched_count = copy.deepcopy(enriched)
        bad_enriched_count["counts"]["resolved"] = 0
        bad_enriched_identity = copy.deepcopy(enriched)
        bad_enriched_identity["encodings"][0]["encoding_id"] = "tampered"
        for corrupted in (
            bad_enriched_bytes,
            bad_enriched_count,
            bad_enriched_identity,
        ):
            with self.subTest(enrichment_corruption=corrupted):
                with self.assertRaises(StageAInputError):
                    resolved_isa_catalog(corrupted)

    def test_unresolved_only_artifact_cannot_enter_corpus_generation(self) -> None:
        proposal = _proposal(
            [
                ("f3a5", REP_FORM),
                ("648b00", FS_FORM),
            ]
        )
        enriched = enrich_side_isa_catalog(
            proposal,
            _decoded(proposal, _fixture_instructions()),
            lean_binding=_binding(proposal),
        )

        with self.assertRaisesRegex(
            StageAInputError, "no qualified representative"
        ):
            resolved_isa_catalog(enriched)

    def test_aliased_memory_address_is_resolved_as_one_coupled_expression(
        self,
    ) -> None:
        proposal = _proposal([("8d0480", ALIASED_LEA_FORM)])
        enriched = enrich_side_isa_catalog(
            proposal,
            _decoded(proposal, _fixture_instructions()),
            lean_binding=_binding(proposal),
        )

        self.assertEqual(enriched["counts"]["resolved"], 1)
        self.assertEqual(
            enriched["encodings"][0]["enrichment"]["status"],
            "resolved",
        )

    def test_aliased_and_distinct_address_encodings_share_a_qualified_form(
        self,
    ) -> None:
        proposal = _proposal(
            [
                ("8d040e", MIXED_LEA_FORM),
                ("8d041b", MIXED_LEA_FORM),
            ]
        )
        enriched = enrich_side_isa_catalog(
            proposal,
            _decoded(proposal, _fixture_instructions()),
            lean_binding=_binding(proposal),
        )
        representative = next(
            row for row in enriched["encodings"] if row["representative"]
        )

        self.assertEqual(representative["instruction_hex"], "8d040e")
        self.assertEqual(representative["enrichment"]["status"], "resolved")
        self.assertEqual(enriched["counts"]["resolved"], 2)
        self.assertEqual(enriched["counts"]["qualified_forms"], 1)
        self.assertEqual(enriched["counts"]["corpus_entries"], 1)
        self.assertEqual(len(resolved_isa_catalog(enriched).entries), 1)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_live_lean_expands_reviewed_integer_families(self) -> None:
        proposal = _proposal(list(EXPANDED_FORM_BY_HEX.items()))
        extracted, binding = extract_lean_decoded_metadata(
            sorted(proposal["encodings"], key=lambda row: row["encoding_id"])
        )
        metadata = {
            row["encoding_id"]: extracted[row["encoding_id"]]
            for row in proposal["encodings"]
        }

        enriched = enrich_side_isa_catalog(
            proposal,
            metadata,
            lean_binding=binding,
        )
        self.assertEqual(
            enriched,
            enrich_side_isa_catalog(
                copy.deepcopy(proposal),
                copy.deepcopy(metadata),
                lean_binding=copy.deepcopy(binding),
            ),
        )
        by_hex = {
            row["instruction_hex"]: row["enrichment"]
            for row in enriched["encodings"]
        }

        self.assertEqual(
            enriched["counts"],
            {
                "forms": 15,
                "encodings": 15,
                "resolved": 15,
                "unresolved": 0,
                "qualified_forms": 15,
                "unresolved_forms": 0,
                "corpus_entries": 15,
            },
        )
        self.assertEqual(enriched["unresolved_reasons"], {})
        self.assertEqual(
            by_hex["c60000"]["effects"][0]["width_bits"],
            8,
        )
        self.assertEqual(
            by_hex["c60000"]["effects"][0]["access"],
            "write",
        )
        self.assertEqual(
            next(
                effect
                for effect in by_hex["668901"]["effects"]
                if effect["class"] == "memory"
            )["width_bits"],
            16,
        )
        self.assertEqual(by_hex["3401"]["defined_outputs"]["eflags"], 0x8C5)
        self.assertEqual(
            by_hex["3401"]["effects"],
            [
                {
                    "class": "register",
                    "id": "register-08-gpr",
                    "width_bits": 8,
                    "reads": [{"register": "eax", "lsb": 0}],
                    "writes": [{"register": "eax", "lsb": 0}],
                }
            ],
        )
        self.assertEqual(by_hex["662d3e40"]["defined_outputs"]["eflags"], 0x8D5)
        self.assertEqual(by_hex["d1e1"]["defined_outputs"]["eflags"], 0x8C5)
        self.assertEqual(
            by_hex["0facef04"]["defined_outputs"]["eflags"],
            0xC5,
        )
        self.assertEqual(
            by_hex["0f4cc1"]["effects"][0]["writes"],
            ["eax"],
        )
        self.assertEqual(
            by_hex["0f9444242b"]["effects"][0]["access"],
            "write",
        )
        self.assertEqual(
            by_hex["f7e9"]["defined_outputs"]["eflags"],
            0x801,
        )
        self.assertEqual(
            by_hex["6bc02c"]["defined_outputs"]["eflags"],
            0x801,
        )
        self.assertEqual(
            by_hex["0fbdc0"]["defined_outputs"]["gprs"]["eax"],
            0,
        )
        self.assertEqual(
            by_hex["0fbdc0"]["defined_outputs"]["eflags"],
            0x40,
        )
        self.assertEqual(
            by_hex["0fa3c2"]["defined_outputs"]["eflags"],
            0x1,
        )
        high_byte = by_hex["80e4f7"]["effects"][0]
        self.assertEqual(
            high_byte["reads"],
            [{"register": "eax", "lsb": 8}],
        )
        self.assertEqual(
            high_byte["writes"],
            [{"register": "eax", "lsb": 8}],
        )
        self.assertEqual(
            by_hex["ff1528754200"]["effects"][0]["outcomes"][0][
                "target"
            ]["kind"],
            "memory",
        )
        self.assertEqual(
            by_hex["ff2500224300"]["effects"][0]["outcomes"][0][
                "target"
            ]["kind"],
            "memory",
        )
        self.assertEqual(len(resolved_isa_catalog(enriched).entries), 15)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_live_lean_metadata_proves_generic_representative_families(
        self,
    ) -> None:
        proposal = _proposal(
            [
                ("b878563412", MOV_FORM),
                ("8b4304", MEMORY_FORM),
                ("7402", BRANCH_FORM),
                ("e800000000", CALL_FORM),
                ("c3", RET_FORM),
                ("f7f1", DIVIDE_FORM),
            ]
        )
        lean_input = sorted(
            proposal["encodings"],
            key=lambda row: row["encoding_id"],
        )
        extracted, binding = extract_lean_decoded_metadata(lean_input)
        metadata = {
            row["encoding_id"]: extracted[row["encoding_id"]]
            for row in proposal["encodings"]
        }

        enriched = enrich_side_isa_catalog(
            proposal,
            metadata,
            lean_binding=binding,
        )

        self.assertEqual(enriched["status"], "complete")
        self.assertEqual(enriched["counts"]["resolved"], 6)
        by_hex = {
            row["instruction_hex"]: row["enrichment"]
            for row in enriched["encodings"]
        }
        self.assertEqual(
            by_hex["b878563412"]["effects"],
            [
                {
                    "class": "register",
                    "id": "register-32-gpr",
                    "width_bits": 32,
                    "reads": [],
                    "writes": ["eax"],
                }
            ],
        )
        memory = by_hex["8b4304"]["effects"]
        self.assertEqual(
            next(row for row in memory if row["class"] == "memory")["address"],
            {
                "base": "ebx",
                "index": None,
                "scale": 1,
                "displacement": 4,
                "segment": "flat",
            },
        )
        branch = by_hex["7402"]["effects"][0]
        self.assertEqual(branch["class"], "branch")
        self.assertEqual(
            next(
                row for row in branch["outcomes"] if row["scenario"] == "taken"
            )["target"]["target_eip"],
            0x00401004,
        )
        call = by_hex["e800000000"]["effects"]
        self.assertEqual(
            next(row for row in call if row["class"] == "branch")[
                "outcomes"
            ][0]["target"]["target_eip"],
            0x00401005,
        )
        self.assertEqual(
            next(row for row in call if row["class"] == "memory")["access"],
            "write",
        )
        returned = by_hex["c3"]["effects"]
        self.assertEqual(
            next(row for row in returned if row["class"] == "branch")[
                "outcomes"
            ][0]["control"],
            "return",
        )
        self.assertEqual(
            next(row for row in returned if row["class"] == "memory")["access"],
            "read",
        )
        divide = by_hex["f7f1"]
        self.assertEqual(divide["effects"][0]["class"], "divide")
        self.assertEqual(
            divide["effects"][0]["divisor"],
            {
                "kind": "register",
                "location": {"register": "ecx", "lsb": 0},
            },
        )
        self.assertEqual(divide["defined_outputs"]["eflags"], 0)

        generated = generate_isa_corpus_from_enrichment(enriched)
        self.assertEqual(len(generated.entries), 6)


def generate_isa_corpus_from_enrichment(enriched: dict):
    """Return the typed resolved catalog used by the existing generator."""

    return resolved_isa_catalog(enriched)


if __name__ == "__main__":
    unittest.main()
