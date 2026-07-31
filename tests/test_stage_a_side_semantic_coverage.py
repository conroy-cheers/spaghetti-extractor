from __future__ import annotations

import copy
from dataclasses import replace
import json
import unittest

from spaghetti_extractor.relational.semantic_coverage import (
    SEMANTIC_COVERAGE_FORMAT,
    build_semantic_coverage,
    parse_semantic_coverage,
    validate_semantic_coverage,
)
from spaghetti_extractor.relational.semantic_coverage_registry import (
    DEFAULT_CPU_PROFILE,
    DEFAULT_SEMANTIC_COVERAGE_REGISTRY,
    EXACT_FORM_QUALIFIABLE_CONSTRUCTORS,
)
from spaghetti_extractor.relational.side_extraction_artifact import (
    parse_request,
    request_payload,
)
from spaghetti_extractor.relational.side_isa_artifact import side_isa_payload
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_bytes


NOP_FORM = "StageA.Formal.InstructionSemanticForm.nop"
X87_LOAD_CONSTANT_FORM = (
    "StageA.Formal.InstructionSemanticForm.x87LoadConstant 0"
)
X87_SAVE_FORM = (
    "StageA.Formal.InstructionSemanticForm.x87SaveState\n"
    "  { hasBase := false, hasIndex := false, scaleShift := 0, "
    "hasDisplacement := true }"
)
UNREGISTERED_FORM = (
    "StageA.Formal.InstructionSemanticForm.futureVector"
)
REGISTER_BIT_SCAN_FORM = (
    "StageA.Formal.InstructionSemanticForm.bitScan\n"
    "  (StageA.Formal.BitScanOperation.reverse)\n"
    "  (StageA.Formal.Operand32SemanticForm.register)"
)
MEMORY_BIT_SCAN_FORM = (
    "StageA.Formal.InstructionSemanticForm.bitScan\n"
    "  (StageA.Formal.BitScanOperation.reverse)\n"
    "  (StageA.Formal.Operand32SemanticForm.memory\n"
    "    { hasBase := true, hasIndex := false, scaleShift := 0, "
    "hasDisplacement := false })"
)
REGISTER_SHIFT_FORM = (
    "StageA.Formal.InstructionSemanticForm.shift\n"
    "  (StageA.Formal.ShiftOperation.left)\n"
    "  (StageA.Formal.Operand32SemanticForm.register)\n"
    "  (StageA.Formal.ShiftCount.immediate 1)"
)
MEMORY_SHIFT_FORM = (
    "StageA.Formal.InstructionSemanticForm.shift\n"
    "  (StageA.Formal.ShiftOperation.left)\n"
    "  (StageA.Formal.Operand32SemanticForm.memory\n"
    "    { hasBase := true, hasIndex := false, scaleShift := 0, "
    "hasDisplacement := false })\n"
    "  (StageA.Formal.ShiftCount.immediate 1)"
)
REGISTER_DOUBLE_SHIFT_FORM = (
    "StageA.Formal.InstructionSemanticForm.doubleShift\n"
    "  true\n"
    "  (StageA.Formal.Operand32SemanticForm.register)\n"
    "  (StageA.Formal.ShiftCount.cl)"
)
MEMORY_DOUBLE_SHIFT_FORM = (
    "StageA.Formal.InstructionSemanticForm.doubleShift\n"
    "  true\n"
    "  (StageA.Formal.Operand32SemanticForm.memory\n"
    "    { hasBase := true, hasIndex := false, scaleShift := 0, "
    "hasDisplacement := false })\n"
    "  (StageA.Formal.ShiftCount.cl)"
)
REP_STOSD_FORM = (
    "StageA.Formal.InstructionSemanticForm.storeDwords true"
)
BRANCH_FORM = (
    "StageA.Formal.InstructionSemanticForm.branchEqual false"
)


class StageASideSemanticCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hashes = {
            "classifier_sha256": "c" * 64,
            "extractor_sha256": "d" * 64,
            "source_sha256": "e" * 64,
        }
        self.contract = {
            "regions": [
                {
                    "id": "duplicate-a",
                    "numeric_id": 0,
                    "original": {"rva_start": 0x1000, "size": 1},
                    "candidate": {"rva_start": 0x2000, "size": 2},
                },
                {
                    "id": "duplicate-b",
                    "numeric_id": 1,
                    "original": {"rva_start": 0x1000, "size": 1},
                    "candidate": {"rva_start": 0x2000, "size": 2},
                },
                {
                    "id": "distinct",
                    "numeric_id": 2,
                    "original": {"rva_start": 0x1010, "size": 6},
                    "candidate": {"rva_start": 0x2010, "size": 1},
                },
            ]
        }
        original_request = parse_request(
            request_payload(self.contract, "original", "a" * 64)
        )
        candidate_request = parse_request(
            request_payload(self.contract, "candidate", "b" * 64)
        )
        self.original = side_isa_payload(
            original_request,
            forms={
                ("original", 0): (
                    {
                        "rva": 0x1000,
                        "size": 1,
                        "bytes": "90",
                        "form": NOP_FORM,
                    },
                ),
                ("original", 1): (
                    {
                        "rva": 0x1000,
                        "size": 1,
                        "bytes": "90",
                        "form": NOP_FORM,
                    },
                ),
                ("original", 2): (
                    {
                        "rva": 0x1010,
                        "size": 6,
                        "bytes": "dd3500100000",
                        "form": X87_SAVE_FORM,
                    },
                ),
            },
            **self.hashes,
        )
        self.candidate = side_isa_payload(
            candidate_request,
            forms={
                ("candidate", 0): (
                    {
                        "rva": 0x2000,
                        "size": 2,
                        "bytes": "d9e8",
                        "form": X87_LOAD_CONSTANT_FORM,
                    },
                ),
                ("candidate", 1): (
                    {
                        "rva": 0x2000,
                        "size": 2,
                        "bytes": "d9e8",
                        "form": X87_LOAD_CONSTANT_FORM,
                    },
                ),
                ("candidate", 2): (
                    {
                        "rva": 0x2010,
                        "size": 1,
                        "bytes": "90",
                        "form": UNREGISTERED_FORM,
                    },
                ),
            },
            **self.hashes,
        )

    def _artifact(self):
        return build_semantic_coverage(self.original, self.candidate)

    def _artifact_for_form(self, form: str, encoded: str):
        size = len(encoded) // 2
        contract = {
            "regions": [
                {
                    "id": "exact-form",
                    "numeric_id": 0,
                    "original": {"rva_start": 0x1000, "size": size},
                    "candidate": {"rva_start": 0x2000, "size": size},
                }
            ]
        }
        original_request = parse_request(
            request_payload(contract, "original", "a" * 64)
        )
        candidate_request = parse_request(
            request_payload(contract, "candidate", "b" * 64)
        )
        original = side_isa_payload(
            original_request,
            forms={
                ("original", 0): (
                    {
                        "rva": 0x1000,
                        "size": size,
                        "bytes": encoded,
                        "form": form,
                    },
                )
            },
            **self.hashes,
        )
        candidate = side_isa_payload(
            candidate_request,
            forms={
                ("candidate", 0): (
                    {
                        "rva": 0x2000,
                        "size": size,
                        "bytes": encoded,
                        "form": form,
                    },
                )
            },
            **self.hashes,
        )
        return build_semantic_coverage(original, candidate)

    def test_roundtrip_deduplicates_and_preserves_occurrence_refs(self):
        artifact = self._artifact()
        self.assertEqual(artifact["format"], SEMANTIC_COVERAGE_FORMAT)
        self.assertEqual(artifact["status"], "blocked")
        self.assertEqual(artifact["counts"]["raw_occurrences"], 6)
        self.assertEqual(artifact["counts"]["deduplicated_occurrences"], 4)
        self.assertEqual(artifact["counts"]["occurrence_refs"], 6)

        by_key = {
            (row["side"], row["rva"], row["bytes"]): row
            for row in artifact["occurrences"]
        }
        nop = by_key[("original", 0x1000, "90")]
        self.assertEqual(nop["runtime_handler"], "ordinary")
        self.assertEqual(nop["qualification"], "qualified")
        self.assertEqual(len(nop["occurrence_refs"]), 2)
        self.assertEqual(
            [ref["region_id"] for ref in nop["occurrence_refs"]],
            ["duplicate-a", "duplicate-b"],
        )

        frame = by_key[("original", 0x1010, "dd3500100000")]
        self.assertEqual(frame["runtime_handler"], "x87-frame")
        self.assertEqual(frame["qualification"], "state-partial")

        command = by_key[("candidate", 0x2000, "d9e8")]
        self.assertEqual(command["runtime_handler"], "x87-command")
        self.assertEqual(command["qualification"], "relational-parametric")

        unknown = by_key[("candidate", 0x2010, "90")]
        self.assertEqual(unknown["runtime_handler"], "unsupported")
        self.assertEqual(unknown["qualification"], "unsupported")

        self.assertEqual(parse_semantic_coverage(artifact), artifact)
        self.assertEqual(
            validate_semantic_coverage(
                artifact,
                original_side_isa=self.original,
                candidate_side_isa=self.candidate,
            ),
            artifact,
        )

    def test_side_local_region_identities_need_not_match(self):
        candidate_contract = {
            "regions": [
                {
                    "id": "candidate-only-region",
                    "numeric_id": 41,
                    "original": {"rva_start": 0x3000, "size": 1},
                    "candidate": {"rva_start": 0x4000, "size": 1},
                }
            ]
        }
        candidate_request = parse_request(
            request_payload(
                candidate_contract,
                "candidate",
                "b" * 64,
            )
        )
        candidate = side_isa_payload(
            candidate_request,
            forms={
                ("candidate", 0): (
                    {
                        "rva": 0x4000,
                        "size": 1,
                        "bytes": "90",
                        "form": NOP_FORM,
                    },
                ),
            },
            **self.hashes,
        )

        artifact = build_semantic_coverage(self.original, candidate)

        self.assertEqual(
            artifact["counts"]["by_side"]["candidate"][
                "deduplicated_occurrences"
            ],
            1,
        )
        self.assertEqual(
            artifact["occurrences"][-1]["occurrence_refs"][0]["region_id"],
            "candidate-only-region",
        )
        validate_semantic_coverage(
            artifact,
            original_side_isa=self.original,
            candidate_side_isa=candidate,
        )

    def test_frame_route_precedes_a_conflicting_ordinary_form(self):
        conflicting = copy.deepcopy(self.original)
        region = conflicting["regions"][2]
        region["occurrences"][0]["form"] = NOP_FORM
        region["occurrences_sha256"] = sha256_bytes(
            json.dumps(
                region["occurrences"],
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
        artifact = build_semantic_coverage(conflicting, self.candidate)
        frame = next(
            row
            for row in artifact["occurrences"]
            if row["bytes"] == "dd3500100000"
        )
        self.assertEqual(frame["runtime_handler"], "x87-frame")
        self.assertEqual(frame["qualification"], "unsupported")
        self.assertIn("different runtime route", frame["qualification_rationale"])

    def test_missing_x87_feature_is_profile_ambiguous_not_qualified(self):
        profile = replace(DEFAULT_CPU_PROFILE, features=())
        artifact = build_semantic_coverage(
            self.original,
            self.candidate,
            cpu_profile=profile,
        )
        x87_rows = [
            row
            for row in artifact["occurrences"]
            if row["runtime_handler"] in {"x87-frame", "x87-command"}
        ]
        self.assertEqual(len(x87_rows), 2)
        self.assertTrue(
            all(row["qualification"] == "profile-ambiguous" for row in x87_rows)
        )
        self.assertTrue(
            all(row["missing_features"] == ["x87"] for row in x87_rows)
        )
        validate_semantic_coverage(
            artifact,
            original_side_isa=self.original,
            candidate_side_isa=self.candidate,
            expected_cpu_profile=profile,
        )

    def test_profile_id_cannot_hide_changed_architecture(self):
        profile = replace(DEFAULT_CPU_PROFILE, architecture="not-x86")
        artifact = build_semantic_coverage(
            self.original,
            self.candidate,
            cpu_profile=profile,
        )
        nop = next(
            row
            for row in artifact["occurrences"]
            if row["form"] == NOP_FORM
        )
        self.assertEqual(nop["runtime_handler"], "ordinary")
        self.assertEqual(nop["qualification"], "profile-ambiguous")

    def test_default_registry_never_claims_x87_numeric_qualification(self):
        x87_entries = [
            entry
            for entry in DEFAULT_SEMANTIC_COVERAGE_REGISTRY.entries
            if entry.constructor.startswith("x87")
        ]
        self.assertTrue(x87_entries)
        self.assertNotIn(
            "qualified", {entry.qualification.value for entry in x87_entries}
        )

    def test_polymorphic_registry_families_remain_conservative(self):
        by_constructor = {
            entry.constructor: entry
            for entry in DEFAULT_SEMANTIC_COVERAGE_REGISTRY.entries
        }
        for constructor in EXACT_FORM_QUALIFIABLE_CONSTRUCTORS:
            with self.subTest(constructor=constructor):
                self.assertEqual(
                    by_constructor[constructor].qualification.value,
                    "state-partial",
                )

    def test_exact_memory_forms_fail_closed_while_register_forms_qualify(self):
        cases = (
            (MEMORY_BIT_SCAN_FORM, "0fbd00", "memory", "state-partial"),
            (REGISTER_BIT_SCAN_FORM, "0fbdc0", "pure-register", "qualified"),
            (MEMORY_SHIFT_FORM, "d120", "memory", "state-partial"),
            (REGISTER_SHIFT_FORM, "d1e0", "pure-register", "qualified"),
            (MEMORY_DOUBLE_SHIFT_FORM, "0fa500", "memory", "state-partial"),
            (
                REGISTER_DOUBLE_SHIFT_FORM,
                "0fa5c0",
                "pure-register",
                "qualified",
            ),
        )
        for form, encoded, shape, qualification in cases:
            with self.subTest(form=form, encoded=encoded):
                artifact = self._artifact_for_form(form, encoded)
                rows = artifact["occurrences"]
                self.assertEqual(len(rows), 2)
                for row in rows:
                    self.assertEqual(row["exact_form_shape"], shape)
                    self.assertEqual(
                        row["state_transition_support"], "supported"
                    )
                    self.assertEqual(row["qualification"], qualification)
                    if shape == "memory":
                        self.assertEqual(
                            row["access_fault_domain"], "requires-proof"
                        )
                        self.assertEqual(
                            row["relational_discharge"], "requires-proof"
                        )
                    else:
                        self.assertEqual(
                            row["access_fault_domain"], "not-applicable"
                        )
                        self.assertEqual(
                            row["relational_discharge"], "complete"
                        )

    def test_rep_stosd_is_string_memory_and_never_family_qualified(self):
        artifact = self._artifact_for_form(REP_STOSD_FORM, "f3ab")
        for row in artifact["occurrences"]:
            self.assertEqual(row["exact_form_shape"], "string-memory")
            self.assertEqual(row["state_transition_support"], "supported")
            self.assertEqual(row["access_fault_domain"], "requires-proof")
            self.assertEqual(row["relational_discharge"], "requires-proof")
            self.assertEqual(row["qualification"], "state-partial")

    def test_control_form_requires_relational_discharge(self):
        artifact = self._artifact_for_form(BRANCH_FORM, "7400")
        for row in artifact["occurrences"]:
            self.assertEqual(row["exact_form_shape"], "control")
            self.assertEqual(row["state_transition_support"], "supported")
            self.assertEqual(row["access_fault_domain"], "not-applicable")
            self.assertEqual(row["relational_discharge"], "requires-proof")
            self.assertEqual(row["qualification"], "relational-parametric")

    def test_artifact_mutations_fail_closed(self):
        artifact = self._artifact()
        mutations = {}

        extra_field = copy.deepcopy(artifact)
        extra_field["unexpected"] = True
        mutations["extra field"] = extra_field

        handler = copy.deepcopy(artifact)
        handler["occurrences"][0]["runtime_handler"] = "x87-command"
        mutations["handler"] = handler

        qualification = copy.deepcopy(artifact)
        qualification["occurrences"][0]["qualification_id"] = (
            "semcov-q-qualified-forged-v1"
        )
        mutations["qualification id"] = qualification

        dimension = copy.deepcopy(artifact)
        dimension["occurrences"][0]["access_fault_domain"] = "complete"
        mutations["semantic dimension"] = dimension

        missing_ref = copy.deepcopy(artifact)
        missing_ref["occurrences"][0]["occurrence_refs"].pop()
        mutations["occurrence ref"] = missing_ref

        reordered = copy.deepcopy(artifact)
        reordered["occurrences"].reverse()
        mutations["occurrence order"] = reordered

        bad_counts = copy.deepcopy(artifact)
        bad_counts["counts"]["deduplicated_occurrences"] += 1
        mutations["counts"] = bad_counts

        bad_registry = copy.deepcopy(artifact)
        bad_registry["registry"]["runtime_handler_precedence"].reverse()
        mutations["registry precedence"] = bad_registry

        bad_digest = copy.deepcopy(artifact)
        bad_digest["coverage_sha256"] = "0" * 64
        mutations["digest"] = bad_digest

        for name, mutation in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(StageAInputError):
                    validate_semantic_coverage(
                        mutation,
                        original_side_isa=self.original,
                        candidate_side_isa=self.candidate,
                    )


if __name__ == "__main__":
    unittest.main()
