import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog import cli as catalog_cli
from haloce_catalog import stage_a
from haloce_catalog import stage_binary
from haloce_catalog.stage_a import (
    STAGE_A_MODEL_ID,
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_extract_work_items,
    stage_a_export_reference_contract,
    stage_a_generate_map,
    stage_a_semantic_coverage,
    stage_a_smoke_contract,
    stage_a_validate,
    stage_a_validate_unit,
)


class StageAValidateTests(unittest.TestCase):
    def test_structural_identity_pass_writes_required_report_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            for relative in (
                "verdict.json",
                "layout.json",
                "obligations.json",
                "failures",
                "incomplete",
                "counterexamples",
                "witnesses",
                "proof-cache",
                "lean",
            ):
                self.assertTrue((out / relative).exists(), relative)
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))
            self.assertEqual(obligations["counts"]["by_status"]["proved"], 2)
            block = self._obligation(out, "block:entry")
            reachability = self._obligation(out, "reachability:entry")
            self.assertEqual(block["proof_rule"], "byte_identical_x86_pe32_block")
            self.assertEqual(reachability["proof_rule"], "entry_root_reachability_v1")
            proof_index = json.loads((out / "proof-cache" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(len(proof_index["entries"]), 1)
            lean_summary = json.loads((out / "lean" / "summary.json").read_text(encoding="utf-8"))
            self.assertTrue(lean_summary["global_soundness_checked"])
            self.assertTrue(lean_summary["final_pass_allowed"])

    def test_missing_lean_downgrades_otherwise_closed_pass_to_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            with mock.patch("haloce_catalog.stage_a.shutil.which", return_value=None):
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "lean-global-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "lean_global_summary_unchecked")
            self.assertIn("Lean executable is not available", blocker["blocker"])
            self.assertFalse(result["proof"]["lean"]["final_pass_allowed"])

    def test_supplemental_lean_input_is_copied_imported_and_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            lean_input = root / "fixture lemma.lean"
            lean_input.write_text("namespace StageAUserFixture\n\ntheorem extraChecked : True := True.intro\n\nend StageAUserFixture\n", encoding="utf-8")
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                    lean_inputs=(lean_input,),
                )

            self.assertEqual(result["verdict"], "pass")
            summary = json.loads((out / "lean" / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["supplemental_inputs"]["errors"], [])
            copied = summary["supplemental_inputs"]["copied"][0]
            self.assertEqual(copied["module"], "StageA.User.FixtureLemma")
            self.assertTrue((out / "lean" / copied["relative_path"]).exists())
            obligations_lean = (out / "lean" / "StageA" / "Obligations.lean").read_text(encoding="utf-8")
            self.assertIn("import StageA.User.FixtureLemma", obligations_lean)

    def test_supplemental_lean_input_with_unchecked_marker_blocks_final_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            lean_input = root / "unchecked.lean"
            lean_input.write_text("axiom uncheckedFact : True\n", encoding="utf-8")
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                    lean_inputs=(lean_input,),
                )

            self.assertEqual(result["verdict"], "incomplete")
            summary = json.loads((out / "lean" / "summary.json").read_text(encoding="utf-8"))
            self.assertFalse(summary["final_pass_allowed"])
            self.assertIn({"path": "StageA/User/Unchecked.lean", "line": 1, "marker": "axiom"}, summary["unchecked_markers"])

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_real_lean_summary_allows_structural_pass_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            summary = json.loads((out / "lean" / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["lean_check"]["status"], "checked")
            self.assertTrue(summary["global_soundness_checked"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_reachable_byte_mutation_fails_with_z3_counterexample_and_witness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2b\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["category"], "block_observable_mismatch")
            self.assertEqual(failure["details"]["mismatch"]["observable"], "reg:eax")
            self.assertEqual(failure["details"]["solver"], "z3")
            self.assertEqual(failure["details"]["smt_status"], "sat")
            self.assertIn("model", failure["details"])
            counterexample = json.loads((out / "counterexamples" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(counterexample["mismatch"]["mismatch"]["observable"], "reg:eax")
            self.assertTrue((out / "witnesses" / "block-entry.json").exists())

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_non_identical_flag_preserving_blocks_can_prove_equivalent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\x90\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\x90\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            self.assertEqual(obligations[0]["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligations[0]["symbolic"]["solver"], "z3")
            self.assertEqual(obligations[0]["symbolic"]["smt_status"], "unsat")
            symbolic_cache = [path for path in (out / "proof-cache").glob("*symbolic*.json")]
            self.assertEqual(len(symbolic_cache), 1)
            cache_payload = json.loads(symbolic_cache[0].read_text(encoding="utf-8"))
            self.assertIn("(check-sat)", cache_payload["symbolic"]["smt_query"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_arithmetic_equivalence_proves_registers_and_modeled_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x83\xc0\x00\xc3")  # add eax, 0; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x83\xe8\x00\xc3")  # sub eax, 0; ret
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"][0]
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertIn("flag:zf", obligation["symbolic"]["original_observables"])
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_checked_invariant_constraints_are_used_by_smt_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xc3", virtual_size=6)  # mov eax, ebx; ret
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x07\x00\x00\x00\xc3")  # mov eax, 7; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "invariant": {"checked": True, "constraints": [{"reg": "ebx", "equals": 7}]},
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 6},
                            }
                        ],
                        "waivers": [
                            {"id": "original-padding", "binary": "original", "rva": 0x1003, "size": 3, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertEqual(obligation["invariant"]["kind"], "checked_constraints")
            self.assertEqual(obligation["invariant"]["constraints"], [{"reg": "ebx", "equals": 7}])
            self.assertIn("pre_ebx", obligation["symbolic"]["smt_query"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_malformed_invariant_constraint_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xc3", virtual_size=6)
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x07\x00\x00\x00\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "invariant": {"checked": True, "constraints": [{"reg": "xmm0", "equals": 7}]},
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 6},
                            }
                        ],
                        "waivers": [
                            {"id": "original-padding", "binary": "original", "rva": 0x1003, "size": 3, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "unsupported_invariant")
            self.assertIn("unsupported invariant register", blocker["blocker"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_branch_predicate_mutation_fails_with_successor_counterexample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x83\xf8\x00\x74\x01\xc3")  # cmp eax, 0; je +1; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x83\xf8\x00\x75\x01\xc3")  # cmp eax, 0; jne +1; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=5, block_id="entry"),
                            self._mapping_entry(rva=0x1005, size=1, block_id="ret"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["category"], "block_observable_mismatch")
            self.assertEqual(failure["details"]["mismatch"]["observable"], "outcome")
            self.assertEqual(failure["details"]["smt_status"], "sat")

    def test_direct_cfg_edges_are_reported_as_proved_obligations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\x83\xf8\x00\x74\x01\xc3\xc3"  # cmp eax, 0; je 0x1006; ret; ret
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=5, block_id="entry"),
                            self._mapping_entry(rva=0x1005, size=1, block_id="fallthrough"),
                            self._mapping_entry(rva=0x1006, size=1, block_id="taken"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            edges = [item for item in obligations if item["kind"] == "cfg_edge"]
            self.assertEqual({edge["edge_kind"] for edge in edges}, {"taken", "fallthrough"})
            self.assertEqual({edge["target_block"] for edge in edges}, {"taken", "fallthrough"})
            self.assertTrue(all(edge["status"] == "proved" for edge in edges))

    def test_unmapped_direct_cfg_edge_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\xeb\x01\x90\xc3"  # jmp 0x1003; padding; ret
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [self._mapping_entry(size=2, block_id="entry")],
                        "waivers": [
                            {"id": "middle-padding", "binary": "both", "rva": 0x1002, "size": 1, "reason": "jumped-over padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            edge_blocker = json.loads((out / "incomplete" / "edge-entry-jump-1003.json").read_text(encoding="utf-8"))
            self.assertEqual(edge_blocker["category"], "unmapped_cfg_edge")
            self.assertEqual(edge_blocker["details"]["original_edge"]["target_rva"], 0x1003)

    def test_checked_generated_proof_does_not_bypass_unsplit_cfg(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\x83\xf8\x00\x74\x01\xc3\xc3"  # cmp eax, 0; je 0x1006; ret; ret
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            entry = self._mapping_entry(size=len(code), block_id="entry")
            entry["proof"] = {
                "rule": "reproducible_jq_same_source_optimization_pair_v1",
                "checked": True,
                "function": "entry",
            }
            mapping.write_text(json.dumps({"blocks": [entry]}), encoding="utf-8")
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            obligation = self._obligation(out, "structure:entry:original:unsplit:1003")
            self.assertEqual(obligation["kind"], "block_structure")
            self.assertEqual(obligation["incomplete"]["category"], "unsplit_basic_block")

    def test_checked_generated_proof_does_not_bypass_indirect_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xff\xe0")  # jmp eax
            candidate = self._write_pe(root / "candidate.exe", b"\xff\xe0")
            mapping = root / "block-map.json"
            entry = self._mapping_entry(size=2, block_id="entry")
            entry["proof"] = {
                "rule": "reproducible_jq_same_source_optimization_pair_v1",
                "checked": True,
                "function": "entry",
            }
            mapping.write_text(json.dumps({"blocks": [entry]}), encoding="utf-8")
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            obligation = self._obligation(out, "structure:entry:original:unknown-target:1000")
            self.assertEqual(obligation["incomplete"]["category"], "unknown_target")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_memory_read_equivalence_allows_different_block_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x8b\x03\xc3", virtual_size=4)  # mov eax, [ebx]; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x8b\x43\x00\xc3", virtual_size=4)  # mov eax, [ebx+0]; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 4},
                            }
                        ],
                        "waivers": [
                            {"id": "original-padding", "binary": "original", "rva": 0x1003, "size": 1, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertIn(["read", ["mem32", ["reg", "ebx"]]], obligation["symbolic"]["original_observables"]["memory_events"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_memory_write_offset_mutation_fails_with_memory_counterexample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\x43\x04\xc3")  # mov [ebx+4], eax; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x89\x43\x08\xc3")  # mov [ebx+8], eax; ret
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["details"]["mismatch"]["observable"], "memory_events")
            self.assertEqual(failure["details"]["smt_status"], "sat")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_stack_push_pop_alternate_encodings_prove_equivalent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x50\x5b\xc3", virtual_size=5)  # push eax; pop ebx; ret
            candidate = self._write_pe(root / "candidate.exe", b"\xff\xf0\x8f\xc3\xc3", virtual_size=5)  # push eax; pop ebx; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 5},
                            }
                        ],
                        "waivers": [
                            {"id": "original-padding", "binary": "original", "rva": 0x1003, "size": 2, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertIn("memory_events", obligation["symbolic"]["original_observables"])

    def test_unproved_reachability_blocks_final_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=1, block_id="entry"),
                            self._mapping_entry(rva=0x1001, size=1, block_id="orphan"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            reachability = self._obligation(out, "reachability:orphan")
            self.assertEqual(reachability["status"], "incomplete")
            self.assertEqual(reachability["incomplete"]["category"], "unproved_reachability")

    def test_checked_root_can_prove_non_entry_block_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            mapping = root / "block-map.json"
            orphan_root = self._mapping_entry(rva=0x1001, size=1, block_id="exported")
            orphan_root["root"] = {"kind": "fixture_function", "checked": True}
            mapping.write_text(
                json.dumps({"blocks": [self._mapping_entry(size=1, block_id="entry"), orphan_root]}),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            reachability = self._obligation(out, "reachability:exported")
            self.assertEqual(reachability["proof_rule"], "checked_root_reachability_v1")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_in_block_memory_write_is_visible_to_later_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\x03\x8b\x0b\xc3", virtual_size=7)  # mov [ebx], eax; mov ecx, [ebx]; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x89\x43\x00\x8b\x4b\x00\xc3", virtual_size=7)  # mov [ebx+0], eax; mov ecx, [ebx+0]; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 5},
                                "candidate": {"rva": 0x1000, "size": 7},
                            }
                        ],
                        "waivers": [
                            {"id": "padding", "binary": "original", "rva": 0x1005, "size": 2, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertEqual(obligation["symbolic"]["original_observables"]["reg:ecx"], ["reg", "eax"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_external_import_call_equivalence_is_uninterpreted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            call_import = b"\xff\x15\x40\x20\x40\x00"
            original = self._write_import_pe(root / "original.exe", b"\x31\xc0" + call_import + b"\xc3", "GetTickCount")
            candidate = self._write_import_pe(root / "candidate.exe", b"\x29\xc0" + call_import + b"\xc3", "GetTickCount")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(size=9),
                                "external_calls": [{"dll": "kernel32.dll", "symbol": "GetTickCount", "args": []}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"][0]
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertEqual(
                obligation["symbolic"]["original_observables"]["external_events"],
                [["external_call", "kernel32.dll", "GetTickCount", None, []]],
            )

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_external_import_call_argument_mutation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            call_import = b"\xff\x15\x40\x20\x40\x00"
            original = self._write_import_pe(root / "original.exe", b"\xb8\x01\x00\x00\x00" + call_import + b"\xc3", "ExitProcess")
            candidate = self._write_import_pe(root / "candidate.exe", b"\xb8\x02\x00\x00\x00" + call_import + b"\xc3", "ExitProcess")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(size=12),
                                "external_calls": [{"dll": "kernel32.dll", "symbol": "ExitProcess", "args": ["eax"]}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["details"]["mismatch"]["observable"], "external_events")
            self.assertEqual(failure["details"]["smt_status"], "sat")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_internal_direct_call_continuation_proves_with_uninterpreted_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xe8\x03\x00\x00\x00\x89\xc1\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xe8\x03\x00\x00\x00\x8d\x08\xc3\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=8),
                            self._mapping_entry(rva=0x1008, size=1, block_id="callee"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertEqual(obligation["symbolic"]["original_observables"]["reg:ecx"], ["call_response", 0, "eax"])
            self.assertEqual(obligation["symbolic"]["original_observables"]["external_events"][0][0], "internal_call")

    def test_import_thunk_equivalence_uses_import_signature_not_iat_rva_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "original.exe", b"\xff\x25\x40\x20\x40\x00", "GetTickCount", iat_offset=0x40)
            candidate = self._write_import_pe(root / "candidate.exe", b"\xff\x25\x44\x20\x40\x00", "GetTickCount", iat_offset=0x44)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(size=6),
                                "source": {
                                    "kind": "import_thunk",
                                    "import_signature": {"dll": "kernel32.dll", "symbol": "GetTickCount", "ordinal": None},
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["proof_rule"], "pe_import_thunk_equivalence_v1")
            self.assertEqual(obligation["original"]["import_signature"], obligation["candidate"]["import_signature"])
            self.assertNotEqual(obligation["original"]["sha256"], obligation["candidate"]["sha256"])

    def test_missing_z3_makes_non_identical_symbolic_obligation_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\x90\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\x90\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            with mock.patch("haloce_catalog.stage_a._import_z3", return_value=None):
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "solver_unavailable")
            self.assertEqual(blocker["details"]["smt_status"], "unavailable")

    def test_unsupported_instruction_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x0f\x0b\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x0f\x0b\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=3)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "unsupported_semantics")
            self.assertIn("unsupported instruction ud2", blocker["blocker"])

    def test_unmapped_executable_bytes_report_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=5)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            unmapped = [item for item in obligations if item["status"] == "unmapped"]
            self.assertEqual(len(unmapped), 2)
            self.assertEqual({item["binary"] for item in unmapped}, {"original", "candidate"})

    def test_hand_authored_non_padding_waiver_is_incomplete_and_unmapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [self._mapping_entry(size=1, block_id="entry")],
                        "waivers": [
                            {"id": "ret-is-not-padding", "binary": "both", "rva": 0x1001, "size": 1, "reason": "bad waiver"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            waiver = self._obligation(out, "waiver:ret-is-not-padding:both:1001-1002")
            self.assertEqual(waiver["status"], "incomplete")
            self.assertEqual(waiver["incomplete"]["category"], "unverified_noncode_waiver")
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            unmapped = [item for item in obligations if item["status"] == "unmapped"]
            self.assertEqual({(item["binary"], item["rva_start"], item["rva_end"]) for item in unmapped}, {("original", 0x1001, 0x1002), ("candidate", 0x1001, 0x1002)})

    def test_duplicate_mapping_id_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x50\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x50\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=1, block_id="dup"),
                            self._mapping_entry(rva=0x1001, size=1, block_id="dup"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "mapping-block-dup.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["category"], "invalid_mapping")

    def test_cli_stage_a_validate_uses_existing_command_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            with self._mock_lean_checked():
                code = catalog_cli.main(
                    [
                        "stage-a-validate",
                        "--original",
                        str(original),
                        "--candidate",
                        str(candidate),
                        "--mapping",
                        str(mapping),
                        "--model",
                        STAGE_A_MODEL_ID,
                        "--out",
                        str(out),
                    ],
                    prog="wincr",
                )

            self.assertEqual(code, 0)
            self.assertEqual(json.loads((out / "verdict.json").read_text(encoding="utf-8"))["verdict"], "pass")

    def test_cli_stage_a_validate_suite_runs_relative_case_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = root / "cases"
            cases.mkdir()
            original = self._write_pe(cases / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(cases / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(cases / "block-map.json", size=6)
            suite = root / "suite.json"
            suite.write_text(
                json.dumps(
                    {
                        "model": STAGE_A_MODEL_ID,
                        "cases": [
                            {
                                "id": "identity",
                                "original": str(original.relative_to(root)),
                                "candidate": str(candidate.relative_to(root)),
                                "mapping": str(mapping.relative_to(root)),
                                "expect": "pass",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "suite-report"

            with self._mock_lean_checked():
                code = catalog_cli.main(
                    [
                        "stage-a-validate-suite",
                        "--suite",
                        str(suite),
                        "--out",
                        str(out),
                    ],
                    prog="wincr",
                )

            self.assertEqual(code, 0)
            summary = json.loads((out / "suite.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "pass")
            self.assertEqual(summary["counts"], {"cases": 1, "passed": 1, "failed": 0, "incomplete": 0})
            self.assertEqual(summary["cases"][0]["actual_verdict"], "pass")
            self.assertTrue((out / "cases" / "identity" / "verdict.json").exists())

    def test_stage_a_generate_map_classifies_paired_executable_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x50\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x50\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401001                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401001                tiny\n", encoding="utf-8")
            mapping = root / "jq-block-map.json"
            layout = root / "jq-layout-contract.json"

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=mapping,
                layout_contract_out=layout,
                original_flags="-O2 test",
                candidate_flags="-O2 -falign-functions=32 test",
            )

            self.assertEqual(result["status"], "pass")
            payload = json.loads(mapping.read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["issues"], 0)
            self.assertEqual(payload["counts"]["blocks"], 2)
            self.assertIn("section-gap--text-0000", {block["id"] for block in payload["blocks"]})
            self.assertEqual(payload["blocks"][0]["proof"]["original_flags"], "-O2 test")
            self.assertEqual(payload["blocks"][0]["proof"]["candidate_flags"], "-O2 -falign-functions=32 test")
            contract = json.loads(layout.read_text(encoding="utf-8"))
            self.assertTrue(contract["facts"]["all_executable_bytes_classified"])
            self.assertTrue(contract["facts"]["matching_section_rvas"])
            self.assertTrue(contract["facts"]["matching_normalized_executable_section_spans"])

    def test_linker_map_parser_uses_split_text_fragment_as_weak_function_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary_path = self._write_pe(root / "candidate.exe", b"\xc3" * 0x60)
            linker_map = root / "candidate.map"
            linker_map.write_text(
                "\n".join(
                    [
                        " .text$dirname  0x00401000       0x20 object.o",
                        "                0x00401000                dirname",
                        " .text$dtoa_lock",
                        "                0x00401020        0xc object.o",
                        "                0x00401020                .weak._dtoa_lock.___crt_atexit",
                        " .text$isoptish",
                        "                0x0040102c        0xc object.o",
                        "                0x0040102c                .weak._isoptish.___crt_atexit",
                        " .text$process  0x00401038        0xc object.o",
                        "                0x00401038                process",
                    ]
                ),
                encoding="utf-8",
            )

            stage_a_functions = stage_a._parse_linker_map_functions(linker_map, stage_a._parse_stage_a_pe(binary_path))
            stage_binary_functions = stage_binary._parse_linker_map_functions(linker_map, stage_binary._parse_stage_a_pe(binary_path))

        for functions in (stage_a_functions, stage_binary_functions):
            by_name = {item["name"]: item for item in functions}
            self.assertEqual(by_name["dirname"]["rva_start"], 0x1000)
            self.assertEqual(by_name["dirname"]["rva_end"], 0x1020)
            self.assertEqual(by_name["dtoa_lock"]["rva_start"], 0x1020)
            self.assertEqual(by_name["dtoa_lock"]["rva_end"], 0x102C)
            self.assertEqual(by_name["isoptish"]["rva_start"], 0x102C)
            self.assertEqual(by_name["isoptish"]["rva_end"], 0x1038)
            self.assertEqual(by_name["process"]["rva_start"], 0x1038)

    def test_stage_a_generate_map_splits_basic_blocks_and_uses_cfg_reachability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\x83\xf8\x00\x74\x01\xc3\xc3"  # cmp eax, 0; je 0x1006; ret; ret
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                branchy\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                branchy\n", encoding="utf-8")
            mapping = root / "jq-block-map.json"

            generated = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=mapping,
            )

            self.assertEqual(generated["status"], "pass")
            payload = json.loads(mapping.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["blocks"]), 3)
            self.assertIn("root", payload["blocks"][0])
            self.assertNotIn("root", payload["blocks"][1])
            self.assertNotIn("root", payload["blocks"][2])

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                )

            self.assertEqual(result["verdict"], "pass")
            reachability = self._obligation(root / "report", "reachability:branchy-0001")
            self.assertEqual(reachability["proof_rule"], "direct_cfg_reachability_v1")

    def test_stage_a_generate_map_reports_block_shapes_for_ambiguous_function_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x74\x01\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                branchy\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                branchy\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            issue = next(issue for issue in result["issues"] if issue["category"] == "ambiguous_block_match")
            details = issue["details"]
            self.assertEqual(details["function"], "branchy")
            self.assertEqual(details["original_blocks"], 1)
            self.assertEqual(details["candidate_blocks"], 3)
            self.assertEqual(details["block_count_delta"], 2)
            self.assertEqual(details["original_block_shapes"]["items"][0]["terminal_instruction"]["mnemonic"], "ret")
            self.assertEqual(details["candidate_block_shapes"]["items"][0]["terminal_instruction"]["mnemonic"], "je")
            self.assertEqual(details["candidate_block_shapes"]["items"][0]["direct_edge_counts"], {"taken": 1, "fallthrough": 1})
            self.assertEqual(details["candidate_block_shapes"]["items"][0]["direct_edges"][0]["target_rva"], 0x1003)

    def test_stage_a_generate_map_rejects_duplicate_linker_map_function_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text(
                "                0x00401000                duplicate\n"
                "                0x00401001                duplicate\n",
                encoding="utf-8",
            )
            candidate_map.write_text(
                "                0x00401000                duplicate\n"
                "                0x00401001                duplicate\n",
                encoding="utf-8",
            )

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("ambiguous_linker_map", {issue["category"] for issue in result["issues"]})

    def test_stage_a_generate_map_matches_unique_decorated_function_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                __mingw_printf\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                ___mingw_printf@0\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "pass")
            block = result["blocks"][0]
            self.assertEqual(block["source"]["function"], "__mingw_printf")
            self.assertEqual(block["source"]["candidate_function"], "___mingw_printf@0")
            self.assertEqual(block["source"]["function_match_key"], "mingw_printf")

    def test_stage_a_generate_map_rejects_duplicate_canonical_function_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text(
                "                0x00401000                __same\n"
                "                0x00401001                ___same@0\n",
                encoding="utf-8",
            )
            candidate_map.write_text("                0x00401000                ____same\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            duplicate_key_issues = [
                issue
                for issue in result["issues"]
                if issue.get("obligation_id") == "jq-map:alias:same"
            ]
            self.assertEqual(len(duplicate_key_issues), 1)

    def test_stage_a_generate_map_matches_unique_import_thunks_by_import_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "original.exe", b"\xff\x25\x40\x20\x40\x00", "GetTickCount", iat_offset=0x40)
            candidate = self._write_import_pe(root / "candidate.exe", b"\xff\x25\x44\x20\x40\x00", "GetTickCount", iat_offset=0x44)
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                _GetTickCount@0\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                imported_GetTickCount\n", encoding="utf-8")
            mapping = root / "jq-block-map.json"

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=mapping,
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(len(result["blocks"]), 1)
            block = result["blocks"][0]
            self.assertEqual(block["source"]["kind"], "import_thunk")
            self.assertEqual(block["source"]["function"], "_GetTickCount@0")
            self.assertEqual(block["source"]["candidate_function"], "imported_GetTickCount")
            self.assertEqual(block["source"]["import_signature"]["symbol"], "GetTickCount")

            with self._mock_lean_checked():
                validation = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                )

            self.assertEqual(validation["verdict"], "pass")
            self.assertEqual(self._obligation(root / "report", f"block:{block['id']}")["proof_rule"], "pe_import_thunk_equivalence_v1")

    def test_stage_a_generate_map_rejects_ambiguous_import_thunk_signature_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            thunk = b"\xff\x25\x40\x20\x40\x00"
            original = self._write_import_pe(root / "original.exe", thunk + b"\x90" * 6, "GetTickCount")
            candidate = self._write_import_pe(root / "candidate.exe", thunk + thunk, "GetTickCount")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                original_import\n", encoding="utf-8")
            candidate_map.write_text(
                "                0x00401000                candidate_import_a\n"
                "                0x00401006                candidate_import_b\n",
                encoding="utf-8",
            )

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("ambiguous_import_thunk_match", {issue["category"] for issue in result["issues"]})

    def test_stage_a_generate_map_writes_reproducible_layout_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x50\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x50\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401001                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401001                tiny\n", encoding="utf-8")
            layout_a = root / "layout-a.json"
            layout_b = root / "layout-b.json"

            for out, layout in ((root / "map-a.json", layout_a), (root / "map-b.json", layout_b)):
                result = stage_a_generate_map(
                    original=original,
                    candidate=candidate,
                    linker_map_original=original_map,
                    linker_map_candidate=candidate_map,
                    out=out,
                    layout_contract_out=layout,
                )
                self.assertEqual(result["status"], "pass")

            self.assertEqual(layout_a.read_bytes(), layout_b.read_bytes())

    def test_stage_a_export_reference_contract_records_binary_faithfulness_constraints(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            self.assertEqual(result["format"], "stage-a-reference-contract-v1")
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["constraints"]["proof_obligation_inventory"]["status"], "satisfied")
            self.assertEqual(result["constraints"]["executable_byte_coverage"]["status"], "satisfied")
            self.assertEqual(result["constraints"]["layout_normalization_assumptions"]["status"], "satisfied")
            self.assertEqual(result["constraints"]["validation_report_artifact_binding"]["status"], "satisfied")
            self.assertTrue(result["constraints"]["validation_report_artifact_binding"]["facts"]["matching_mapping_payload"])
            self.assertEqual(result["constraints"]["function_ranges"]["functions"][0]["name"], "tiny")
            self.assertIn("relocations", result["original"])
            self.assertTrue((root / "reference-contract.json").exists())
            for family in result["families"]:
                self.assertIn(family["status"], {"satisfied", "incomplete", "not_applicable", "violated"})
                self.assertNotEqual(family["status"], "represented")
            self.assertEqual(
                {item["family"]: item["status"] for item in result["families"]}["proof_inventory"],
                "satisfied",
            )

            coverage_gaps = json.loads((root / "coverage_gaps.json").read_text(encoding="utf-8"))
            obligation_index = json.loads((root / "obligation_index.json").read_text(encoding="utf-8"))
            contract_summary = json.loads((root / "contract_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage_gaps["format"], "stage-a-coverage-gaps-v1")
            self.assertEqual(coverage_gaps["status"], "pass")
            self.assertEqual(coverage_gaps["counts"]["gaps"], 0)
            self.assertEqual(obligation_index["format"], "stage-a-obligation-index-v1")
            self.assertGreater(obligation_index["counts"]["obligations"], 0)
            self.assertEqual(contract_summary["format"], "stage-a-contract-summary-v1")
            by_status = contract_summary["counts"]["by_status"]
            self.assertEqual(by_status.get("incomplete", 0), 0)
            self.assertEqual(by_status.get("violated", 0), 0)
            self.assertEqual(by_status["satisfied"] + by_status["not_applicable"], len(result["families"]))

            smoke = stage_a_smoke_contract(reference_contract=root / "reference-contract.json")
            self.assertEqual(smoke["status"], "pass")

    def test_stage_a_reference_contract_records_coff_symbol_aliases_on_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe_with_coff_symbol(root / "original.exe", b"\xc3", "_tinyh")
            candidate = self._write_pe_with_coff_symbol(root / "candidate.exe", b"\xc3", "_tinyh")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            block = result["constraints"]["basic_blocks_and_cfg"]["basic_blocks"][0]
            self.assertEqual(block["id"], "tiny-0000")
            self.assertIn("_tinyh", block["symbol_aliases"]["original"])
            self.assertIn("tinyh", block["symbol_aliases"]["original"])
            self.assertIn("_tinyh", block["symbol_aliases"]["candidate"])
            self.assertIn("tinyh", block["symbol_aliases"]["candidate"])

    def test_stage_a_export_reference_contract_writes_unit_contract_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                ___dyn_tls_init@12\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                ___dyn_tls_init@12\n", encoding="utf-8")
            block_map = root / "block-map.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
            )
            units = root / "units"

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            self.assertIn("unit_contracts", result["sidecars"])
            for name in (
                "block-contracts.jsonl",
                "function-contracts.jsonl",
                "cluster-contracts.jsonl",
                "repair-units.json",
                "source-obligations.json",
                "semantic-transfer-contracts.jsonl",
                "memory-frame-contracts.json",
                "call-summary-contracts.json",
                "cluster-semantic-contracts.jsonl",
            ):
                self.assertTrue((units / name).exists(), name)
            block_contract = json.loads((units / "block-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            function_contract = json.loads((units / "function-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            cluster_contracts = [
                json.loads(line)
                for line in (units / "cluster-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual(block_contract["format"], "stage-a-block-contract-v1")
            self.assertEqual(block_contract["function"], "___dyn_tls_init@12")
            self.assertEqual(function_contract["format"], "stage-a-function-contract-v1")
            self.assertEqual(function_contract["function"], "___dyn_tls_init@12")
            self.assertIn("tls_callback_abi", {item["repair_class"] for item in cluster_contracts})

            work = stage_a_extract_work_items(
                reference_contract=root / "reference-contract.json",
                unit_contract_dir=units,
                out=root / "work-items.json",
            )
            self.assertEqual(work["format"], "stage-a-work-items-v1")
            self.assertGreater(work["counts"]["work_items"], 0)
            self.assertIn("tls_callback_abi", {item["repair_class"] for item in work["work_items"]})

    def test_reference_contract_semantic_transfer_sidecar_exports_block_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex("83c404")  # add esp, 4
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="stack-adjust")
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            transfer = json.loads((units / "semantic-transfer-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(transfer["format"], "stage-a-semantic-transfer-contract-v1")
            self.assertEqual(transfer["status"], "reimplementable")
            self.assertEqual(transfer["stack_delta"]["net_bytes"], 4)
            self.assertIn("esp", {item["register"] for item in transfer["register_writes"]})
            self.assertEqual(transfer["outcome"]["kind"], "fallthrough")

            coverage = stage_a_semantic_coverage(
                reference_contract=root / "reference-contract.json",
                unit_contract_dir=units,
                out=root / "semantic-coverage.json",
            )
            self.assertEqual(coverage["status"], "pass")
            self.assertEqual(coverage["counts"]["analysis_blocked"], 0)
            self.assertTrue(coverage["acceptance"]["jq_full_reimplementation_ready"])

    def test_reference_contract_semantic_transfer_exports_internal_call_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\xe8\x03\x00\x00\x00\x89\xc1\xc3"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="internal-call")
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            transfer = json.loads((units / "semantic-transfer-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(transfer["status"], "reimplementable")
            self.assertEqual(transfer["external_events"][0]["kind"], "internal_call")
            self.assertEqual(transfer["external_events"][0]["target_rva"], 0x1008)
            self.assertEqual(transfer["external_events"][0]["effect_model"], "uninterpreted_internal_call_response_v1")
            register_writes = {item["register"]: item["value"] for item in transfer["register_writes"]}
            self.assertEqual(register_writes["ecx"], {"op": "call_response", "width": 32, "call_index": 0, "register": "eax"})

    def test_reference_contract_semantic_transfer_fail_closed_for_unsupported_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex("0f0b")  # ud2 remains outside the executable transfer model
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="unsupported-ud2")
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            transfer = json.loads((units / "semantic-transfer-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(transfer["status"], "incomplete")
            self.assertEqual(transfer["blocker_category"], "unsupported_semantics")
            work = json.loads((units / "repair-units.json").read_text(encoding="utf-8"))["work_items"]
            self.assertIn("semantic_transfer", {item["family"] for item in work})

            coverage = stage_a_semantic_coverage(
                reference_contract=root / "reference-contract.json",
                unit_contract_dir=units,
                out=root / "semantic-coverage.json",
            )
            self.assertEqual(coverage["status"], "incomplete")
            self.assertEqual(coverage["counts"]["analysis_blocked"], 1)
            self.assertEqual(coverage["counts"]["unsupported_instruction_shapes"], 1)
            self.assertEqual(coverage["blockers"][0]["function"], "unsupported-ud2")

    def test_stage_a_validate_unit_filters_contract_focus_without_original_tracing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
                stage_a_export_reference_contract(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    validation_report=root / "report",
                    layout_contract=layout_contract,
                    model=STAGE_A_MODEL_ID,
                    out=root / "reference-contract.json",
                )
            skeleton_manifest = self._write_skeleton_manifest(
                root / "manifest.json",
                [{"function": "tiny", "file": "src/jq_stage_b_skeleton.c", "line_start": 10, "line_end": 12}],
            )

            result = stage_a_validate_unit(
                reference_contract=root / "reference-contract.json",
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_manifest,
                focus="tiny",
                model=STAGE_A_MODEL_ID,
                out=root / "unit",
            )

            self.assertEqual(result["status"], "pass")
            self.assertGreater(result["counts"]["unit_contracts"], 0)
            self.assertTrue((root / "unit" / "unit-validation.json").exists())

    def test_reference_contract_abi_callsites_ignore_prologue_pushes_and_capture_stack_slots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "55"  # push ebp
                "89e5"  # mov ebp, esp
                "83ec10"  # sub esp, 0x10
                "b878563412"  # mov eax, 0x12345678
                "89442404"  # mov [esp + 4], eax
                "c7042400204000"  # mov dword ptr [esp], 0x402000
                "e800000000"  # call next instruction
                "c9"  # leave
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="stack-args")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            abi = result["constraints"]["abi_callsites"]
            self.assertEqual(abi["counts"]["callsites"], 1)
            self.assertEqual(abi["original"]["functions"][0]["stack_delta"]["net_bytes"], 0)
            callsite = abi["original"]["functions"][0]["callsites"][0]
            sources = callsite["argument_sources"]
            self.assertEqual([source["stack_offset"] for source in sources], [4, 0])
            self.assertEqual(sources[0]["kind"], "register")
            self.assertEqual(sources[0]["register"], "eax")
            self.assertEqual(sources[1]["kind"], "immediate")
            self.assertEqual(sources[1]["value"], 0x402000)
            source_rvas = {
                source["instruction"]["rva"]
                for source in sources
                if isinstance(source.get("instruction"), dict)
            }
            self.assertNotIn(0x1000, source_rvas)
            self.assertNotIn("source", callsite["hidden_sret_or_out_param_evidence"])
            self.assertEqual(
                callsite["hidden_sret_or_out_param_evidence"]["reason"],
                "first_stack_argument_not_address_like",
            )

    def test_reference_contract_abi_stack_delta_tracks_explicit_cdecl_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "6a01"  # push 1
                "e800000000"  # call next instruction
                "83c404"  # add esp, 4
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="cdecl-cleanup")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            function = result["constraints"]["abi_callsites"]["original"]["functions"][0]
            self.assertEqual(function["stack_delta"]["net_bytes"], 0)
            self.assertEqual(function["blocks"][0]["abi"]["stack_delta"]["net_bytes"], 0)

    def test_reference_contract_abi_stack_delta_marks_multiblock_functions_block_local(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "55"  # push ebp
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=1, block_id="split-0000"),
                                "source": {"function": "split"},
                            },
                            {
                                **self._mapping_entry(rva=0x1001, size=1, block_id="split-0001"),
                                "source": {"function": "split"},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            function = result["constraints"]["abi_callsites"]["original"]["functions"][0]
            self.assertEqual(function["name"], "split")
            self.assertEqual(function["stack_delta"]["status"], "block_local")
            self.assertEqual(function["stack_delta"]["blocks"], 2)
            self.assertEqual(function["blocks"][0]["abi"]["stack_delta"]["status"], "derived")

    def test_reference_contract_abi_carries_predecessor_stack_arguments_to_split_call_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = bytes.fromhex(
                "c744240800000000"  # mov dword ptr [esp + 8], 0
                "c74424040a000000"  # mov dword ptr [esp + 4], 0xa
                "890424"  # mov dword ptr [esp], eax
                "7405"  # je branch-call
            )
            fallthrough_call = bytes.fromhex("e800000000")
            branch_call = bytes.fromhex("e800000000")
            code = setup + fallthrough_call + branch_call + b"\xc3"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=len(setup), block_id="split-call-setup"),
                                "source": {"function": "split_call"},
                            },
                            {
                                **self._mapping_entry(rva=0x1000 + len(setup), size=len(fallthrough_call), block_id="split-call-fallthrough"),
                                "source": {"function": "split_call"},
                            },
                            {
                                **self._mapping_entry(
                                    rva=0x1000 + len(setup) + len(fallthrough_call),
                                    size=len(branch_call),
                                    block_id="split-call-branch",
                                ),
                                "source": {"function": "split_call"},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            function = result["constraints"]["abi_callsites"]["original"]["functions"][0]
            self.assertEqual(function["name"], "split_call")
            self.assertEqual(len(function["callsites"]), 2)
            for callsite in function["callsites"]:
                self.assertEqual([source["stack_offset"] for source in callsite["argument_sources"]], [8, 4, 0])
                self.assertEqual(
                    [arg["source"]["stack_offset"] for arg in callsite["argument_inventory"]["stack_args"]],
                    [0, 4, 8],
                )
                self.assertEqual(callsite["argument_inventory"]["argument_count"], 3)
                self.assertEqual(callsite["predecessor_argument_sources"]["source"], "direct_cfg_predecessor_exit")
                self.assertEqual(callsite["predecessor_argument_sources"]["predecessor_block_ids"], ["split-call-setup"])

    def test_reference_contract_abi_callsites_mark_explicit_stack_address_first_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "55"  # push ebp
                "89e5"  # mov ebp, esp
                "83ec10"  # sub esp, 0x10
                "8d45fc"  # lea eax, [ebp - 4]
                "890424"  # mov [esp], eax
                "e800000000"  # call next instruction
                "c9"  # leave
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="stack-address")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            callsite = result["constraints"]["abi_callsites"]["original"]["functions"][0]["callsites"][0]
            source = callsite["argument_sources"][0]
            self.assertEqual(source["kind"], "register")
            self.assertEqual(source["register"], "eax")
            self.assertEqual(source["register_definition"]["kind"], "address")
            self.assertEqual(source["register_definition"]["address_class"], "stack_address")
            self.assertEqual(callsite["hidden_sret_or_out_param_evidence"]["status"], "candidate")
            self.assertEqual(
                callsite["hidden_sret_or_out_param_evidence"]["address_role"],
                "stack_out_param_or_scratch_buffer",
            )
            self.assertEqual(
                callsite["hidden_sret_or_out_param_evidence"]["reason"],
                "first_stack_argument_has_address_provenance",
            )

    def test_reference_contract_unit_sidecars_include_register_out_param_memory_and_clusters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "c70000000000"  # mov dword ptr [eax], 0
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="write-through-eax")
            units = root / "units"

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            function = result["constraints"]["abi_callsites"]["original"]["functions"][0]
            self.assertEqual(function["register_out_param_candidates"][0]["register"], "eax")
            self.assertEqual(function["memory_effect_summary"]["writes"], 1)
            block_contract = json.loads((units / "block-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            state = block_contract["state_contract"]
            self.assertEqual(state["register_out_param_candidates"][0]["kind"], "register_carried_out_param")
            self.assertEqual(state["memory_writes"][0]["memory_role"], "computed_memory")
            memory_frames = json.loads((units / "memory-frame-contracts.json").read_text(encoding="utf-8"))
            self.assertEqual(memory_frames["counts"]["accesses"], 1)
            self.assertEqual(memory_frames["accesses"][0]["frame_kind"], "object.pointer_candidate")
            clusters = [
                json.loads(line)
                for line in (units / "cluster-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertIn("abi_register_carried_out_param", {item["cluster_kind"] for item in clusters})
            self.assertIn("hidden_sret_or_out_param", {item["repair_class"] for item in clusters})

    def test_reference_contract_unit_sidecars_include_switch_and_loop_contract_clusters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            switch_code = bytes.fromhex("ff248500504000")  # jmp dword ptr [eax * 4 + 0x405000]
            loop_code = bytes.fromhex("ebfe")  # jmp self
            code = switch_code + loop_code
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(rva=0x1000, size=len(switch_code), block_id="switch-dispatch"),
                            self._mapping_entry(rva=0x1000 + len(switch_code), size=len(loop_code), block_id="loop-backedge"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            clusters = [
                json.loads(line)
                for line in (units / "cluster-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            kinds = {item["cluster_kind"] for item in clusters}
            repair_classes = {item["repair_class"] for item in clusters}
            self.assertIn("abi_switch_or_jump_table_candidate", kinds)
            self.assertIn("abi_loop_backedge_candidate", kinds)
            self.assertIn("switch_or_jump_table_dispatch", repair_classes)
            self.assertIn("loop_or_state_machine", repair_classes)
            semantic_clusters = [
                json.loads(line)
                for line in (units / "cluster-semantic-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            complete_kinds = {item["cluster_kind"] for item in semantic_clusters if item["status"] == "complete"}
            self.assertIn("abi_switch_or_jump_table_candidate", complete_kinds)
            self.assertIn("abi_loop_backedge_candidate", complete_kinds)
            switch_cluster = next(item for item in semantic_clusters if item["cluster_kind"] == "abi_switch_or_jump_table_candidate")
            loop_cluster = next(item for item in semantic_clusters if item["cluster_kind"] == "abi_loop_backedge_candidate")
            self.assertIn("indirect-jump contract", switch_cluster["next_action"])
            self.assertIn("low-level CFG backedges", loop_cluster["next_action"])

    def test_reference_contract_call_summary_records_import_varargs_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            call_import = b"\xff\x15\x40\x20\x40\x00"
            original = self._write_import_pe(root / "original.exe", call_import, "___mingw_fprintf")
            candidate = self._write_import_pe(root / "candidate.exe", call_import, "___mingw_fprintf")
            mapping = self._write_mapping(root / "block-map.json", size=len(call_import), block_id="fprintf-call")
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            summaries = json.loads((units / "call-summary-contracts.json").read_text(encoding="utf-8"))
            self.assertEqual(summaries["counts"]["calls"], 1)
            call = summaries["calls"][0]
            self.assertEqual(call["target"]["symbol"], "___mingw_fprintf")
            self.assertEqual(call["varargs_evidence"]["status"], "candidate")
            self.assertIn("variadic", call["next_action"])

    def test_abi_callsites_resolve_import_loaded_through_register(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "a164234100"  # mov eax, dword ptr [0x412364]
            "ffd0"  # call eax
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(
                stage_a.StageAImport(
                    dll="kernel32.dll",
                    symbol="LeaveCriticalSection",
                    ordinal=None,
                    thunk_rva=0x12364,
                ),
            ),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "iat-register-call",
        )

        self.assertEqual(len(evidence["callsites"]), 1)
        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "import")
        self.assertEqual(callsite["target"]["symbol"], "LeaveCriticalSection")
        self.assertEqual(callsite["target"]["dll"], "kernel32.dll")
        self.assertEqual(callsite["target"]["thunk_rva"], 0x12364)
        self.assertEqual(callsite["target"]["via_register"], "eax")
        self.assertEqual(callsite["target"]["source"]["memory_rva"], 0x12364)
        self.assertEqual(callsite["target"]["source"]["import"]["symbol"], "LeaveCriticalSection")
        self.assertEqual(callsite["target"]["source"]["memory_role"], "import_address_table")
        self.assertEqual(callsite["function_pointer_targets"], [])

    def test_abi_callsites_bound_known_stdcall_import_arguments(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "8944241c"  # mov dword ptr [esp + 0x1c], eax
            "c7042400104000"  # mov dword ptr [esp], 0x401000
            "ff1564234100"  # call dword ptr [0x412364]
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(
                stage_a.StageAImport(
                    dll="kernel32.dll",
                    symbol="LeaveCriticalSection",
                    ordinal=None,
                    thunk_rva=0x12364,
                ),
            ),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "stdcall-spill",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual([source["stack_offset"] for source in callsite["argument_sources"]], [0])
        inventory = callsite["argument_inventory"]
        self.assertEqual(inventory["argument_count"], 1)
        self.assertEqual(len(inventory["stack_args"]), 1)
        self.assertEqual(inventory["stack_args"][0]["source"]["stack_offset"], 0)
        self.assertEqual(inventory["stack_args"][0]["role"], "immediate")

    def test_abi_string_literals_ignore_executable_section_bytes(self):
        class FakePE:
            def get_data(self, rva: int, size: int) -> bytes:
                if rva == 0x6000:
                    return b"hello\0"
                if rva == 0xE000:
                    return b"hello\0"
                return b""

        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=0,
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(
                stage_a.StageASection(".text", 0x1000, 0xC500, 0, 0xB500, 0, True, True, False, True),
                stage_a.StageASection(".rdata", 0xE000, 0xE100, 0, 0x100, 0, False, True, False, False),
            ),
            imports=(),
            pe=FakePE(),
        )

        self.assertIsNone(stage_a._abi_string_literal_at_rva(binary, 0x6000))
        literal = stage_a._abi_string_literal_at_rva(binary, 0xE000)
        self.assertIsNotNone(literal)
        self.assertEqual(literal["text"], "hello")

    def test_abi_callsites_recover_x86_internal_register_arguments_from_direct_target_entry(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        target_rva = 0x1020
        caller = bytes.fromhex(
            "8d4c2408"  # lea ecx, [esp + 8]
            "89c2"  # mov edx, eax
            "89f8"  # mov eax, edi
        )
        call_rva = 0x1000 + len(caller)
        code = caller + b"\xe8" + struct.pack("<i", target_rva - (call_rva + 5))
        code += b"\x90" * (target_rva - (0x1000 + len(code)))
        code += bytes.fromhex(
            "55"  # push ebp
            "89d5"  # mov ebp, edx
            "89cb"  # mov ebx, ecx
            "89442404"  # mov dword ptr [esp + 4], eax
            "c3"  # ret
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(
                stage_a.StageASection(
                    name=".text",
                    rva_start=0x1000,
                    rva_end=0x1000 + len(code),
                    raw_pointer=0,
                    raw_size=len(code),
                    characteristics=0,
                    executable=True,
                    readable=True,
                    writable=False,
                    contains_code=True,
                ),
            ),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=call_rva + 5),
            "x86-register-call",
        )

        callsite = evidence["callsites"][0]
        inventory = callsite["argument_inventory"]
        self.assertEqual(inventory["calling_convention"], "x86_register_carried_internal")
        self.assertEqual(inventory["argument_count"], 3)
        self.assertEqual([arg["register"] for arg in inventory["register_args"]], ["eax", "edx", "ecx"])
        self.assertEqual([arg["role"] for arg in inventory["register_args"]], ["register", "register", "stack_out_param_or_scratch_buffer"])
        self.assertEqual(inventory["register_argument_evidence"]["source"], "direct_target_entry_read_before_write")
        self.assertEqual(inventory["register_argument_evidence"]["target_rva"], target_rva)

    def test_abi_callsites_ignore_noncontiguous_stack_spills_before_call(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "8954241c"  # mov dword ptr [esp + 0x1c], edx
            "e800000000"  # call next instruction
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "local-spill-before-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["argument_sources"], [])
        self.assertEqual(callsite["argument_inventory"]["argument_count"], 0)
        self.assertEqual(callsite["hidden_sret_or_out_param_evidence"]["reason"], "no_static_arguments")

    def test_abi_callsites_classify_global_function_pointer_slot(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "a100d04000"  # mov eax, dword ptr [0x40d000]
            "ffd0"  # call eax
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(
                stage_a.StageASection(".text", 0x1000, 0x2000, 0, 0x1000, 0, True, True, False, True),
                stage_a.StageASection(".data", 0xD000, 0xD100, 0, 0x100, 0, False, True, True, False),
            ),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "global-slot-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "function_pointer")
        self.assertEqual(callsite["target"]["memory_rva"], 0xD000)
        self.assertEqual(callsite["target"]["memory_role"], "global_writable_pointer_slot")
        self.assertEqual(callsite["target"]["source"]["memory_section"]["name"], ".data")
        self.assertEqual(callsite["function_pointer_targets"][0]["memory_role"], "global_writable_pointer_slot")

    def test_abi_callsites_classify_direct_stack_slot_function_pointer_call(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "ff542464"  # call dword ptr [esp + 0x64]
            "c3"  # ret
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "stack-slot-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "function_pointer")
        self.assertEqual(callsite["target"]["operand"], "dword ptr [esp + 0x64]")
        self.assertEqual(callsite["target"]["memory_role"], "stack_pointer_slot")
        self.assertEqual(callsite["target"]["source"]["addressing"]["disp"], 0x64)
        self.assertEqual(callsite["function_pointer_targets"][0]["memory_role"], "stack_pointer_slot")

    def test_abi_callsites_classify_argument_callback_table_deref(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "8b4508"  # mov eax, dword ptr [ebp + 8]
            "8b00"  # mov eax, dword ptr [eax]
            "ffd0"  # call eax
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "argument-table-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "function_pointer")
        self.assertEqual(callsite["target"]["memory_role"], "argument_pointer_deref")
        self.assertEqual(callsite["target"]["source"]["base_register_definition"]["memory_role"], "stack_argument_slot")
        self.assertEqual(callsite["function_pointer_targets"][0]["memory_role"], "argument_pointer_deref")

    def test_contract_candidate_abi_coverage_gaps_name_missing_functions_and_callsites(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_missing",
                        "blocks": [{"block_id": "missing", "rva_start": 0x1000, "rva_end": 0x1010, "size": 0x10}],
                        "callsites": [
                            {
                                "id": "callsite:missing:1004",
                                "block_id": "missing",
                                "instruction": {"rva": 0x1004, "mnemonic": "call", "op_str": "0x402000"},
                                "target": {"kind": "direct", "target_rva": 0x2000},
                            }
                        ],
                    },
                    {
                        "name": "_partial",
                        "blocks": [{"block_id": "partial", "rva_start": 0x1100, "rva_end": 0x1120, "size": 0x20}],
                        "callsites": [
                            {"id": "callsite:partial:1104", "block_id": "partial", "instruction": {"rva": 0x1104}},
                            {"id": "callsite:partial:1110", "block_id": "partial", "instruction": {"rva": 0x1110}},
                        ],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "partial",
                        "callsites": [
                            {"id": "callsite:partial:1104", "block_id": "partial", "instruction": {"rva": 0x1104}},
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["missing_functions"], 1)
        self.assertEqual(gaps["counts"]["incomplete_callsite_functions"], 1)
        self.assertEqual(gaps["counts"]["missing_callsites"], 1)
        self.assertEqual(gaps["missing_functions"][0]["name"], "_missing")
        self.assertEqual(gaps["missing_functions"][0]["match_key"], "missing")
        self.assertEqual(gaps["missing_functions"][0]["callsites"], 1)
        self.assertEqual(gaps["missing_functions"][0]["callsite_samples"][0]["instruction"]["op_str"], "0x402000")
        self.assertEqual(gaps["incomplete_callsites"][0]["name"], "_partial")
        self.assertEqual(gaps["incomplete_callsites"][0]["candidate_callsites"], 1)
        self.assertEqual(gaps["incomplete_callsites"][0]["reference_callsites"], 2)

    def test_contract_candidate_abi_coverage_gaps_report_missing_callsite_signatures(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_partial",
                        "callsites": [
                            {
                                "id": "callsite:partial:1104",
                                "block_id": "partial:0",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "malloc"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            },
                            {
                                "id": "callsite:partial:1110",
                                "block_id": "partial:1",
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "LeaveCriticalSection"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [
                                        {
                                            "index": 0,
                                            "role": "immediate",
                                            "source": {"kind": "immediate", "stack_offset": 0, "value": 2},
                                        }
                                    ],
                                    "register_args": [],
                                },
                            },
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "partial",
                        "callsites": [
                            {
                                "id": "callsite:partial:2104",
                                "block_id": "partial:0",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "malloc"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            },
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        gap = gaps["incomplete_callsites"][0]
        self.assertEqual(gap["matched_callsite_pairs"], 1)
        self.assertEqual(gap["unmatched_reference_callsites"], 1)
        self.assertEqual(gap["unmatched_candidate_callsites"], 0)
        missing = gap["missing_callsite_signatures"][0]
        self.assertRegex(missing["signature_id"], r"^callsite-signature:[0-9a-f]{16}$")
        self.assertEqual(missing["missing"], 1)
        self.assertEqual(missing["reference_count"], 1)
        self.assertEqual(missing["candidate_count"], 0)
        self.assertEqual(
            missing["signature"]["target"],
            {"kind": "import", "dll": "kernel32.dll", "symbol": "LeaveCriticalSection", "ordinal": ""},
        )
        self.assertEqual(missing["signature"]["argument_inventory"]["argument_count"], 1)
        self.assertEqual(missing["signature"]["argument_inventory"]["stack_roles"], ["immediate"])
        self.assertEqual(missing["signature"]["argument_inventory"]["stack_args"][0]["source"]["value"], 2)
        self.assertEqual(missing["reference_examples"][0]["callsite"]["id"], "callsite:partial:1110")
        self.assertEqual(gap["callsite_signature_delta"]["counts"]["reference_only_signatures"], 1)

    def test_contract_candidate_abi_signature_delta_matches_stack_slot_function_pointer_roles(self):
        reference_callsite = {
            "id": "callsite:umain:bcb3",
            "target": {
                "kind": "function_pointer",
                "operand": "dword ptr [esp + 0x64]",
                "memory_role": "stack_pointer_slot",
                "status": "unresolved",
                "source": {
                    "kind": "memory",
                    "addressing": {"base": "esp", "index": None, "scale": 1, "disp": 0x64},
                    "memory_role": "stack_pointer_slot",
                },
            },
            "argument_inventory": {
                "calling_convention": "cdecl_or_stdcall_stack",
                "argument_count": 1,
                "stack_args": [
                    {
                        "index": 0,
                        "role": "immediate",
                        "source": {"kind": "immediate", "stack_offset": 0, "value": 2},
                    }
                ],
                "register_args": [],
            },
        }
        candidate_callsite = copy.deepcopy(reference_callsite)
        candidate_callsite["id"] = "callsite:umain:bcb3-candidate"
        candidate_callsite["target"]["operand"] = "dword ptr [esp + 0x88]"
        candidate_callsite["target"]["source"]["addressing"]["disp"] = 0x88

        delta = stage_a._contract_candidate_abi_callsite_signature_delta(
            [reference_callsite],
            [candidate_callsite],
            [],
            reference_function_index=[],
            candidate_function_index=[],
        )

        self.assertEqual(delta["counts"]["reference_only_signatures"], 0)
        self.assertEqual(delta["counts"]["candidate_only_signatures"], 0)
        signature = stage_a._abi_callsite_contract_signature(reference_callsite, [])
        self.assertEqual(
            signature["target"],
            {
                "kind": "function_pointer",
                "memory_role": "stack_pointer_slot",
                "status": "unresolved",
                "source": {"kind": "memory", "memory_role": "stack_pointer_slot"},
            },
        )

    def test_contract_candidate_abi_signature_delta_canonicalizes_implicit_stack_offsets(self):
        reference_callsite = {
            "id": "callsite:foo:1000",
            "target": {"kind": "direct", "target_rva": 0x2000},
            "argument_inventory": {
                "calling_convention": "cdecl_or_stdcall_stack",
                "argument_count": 2,
                "stack_args": [
                    {
                        "index": 0,
                        "role": "register",
                        "source": {"kind": "register", "stack_offset": 0},
                    },
                    {
                        "index": 1,
                        "role": "immediate",
                        "source": {"kind": "immediate", "stack_offset": 4, "value": 7},
                    },
                ],
                "register_args": [],
            },
        }
        candidate_callsite = copy.deepcopy(reference_callsite)
        candidate_callsite["id"] = "callsite:foo:push-candidate"
        for argument in candidate_callsite["argument_inventory"]["stack_args"]:
            argument["source"].pop("stack_offset", None)

        delta = stage_a._contract_candidate_abi_callsite_signature_delta(
            [reference_callsite],
            [candidate_callsite],
            [(0, 0, reference_callsite, candidate_callsite)],
            reference_function_index=[],
            candidate_function_index=[],
        )

        self.assertEqual(delta["counts"]["reference_only_signatures"], 0)
        self.assertEqual(delta["counts"]["candidate_only_signatures"], 0)
        signature = stage_a._abi_callsite_contract_signature(candidate_callsite, [])
        stack_args = signature["argument_inventory"]["stack_args"]
        self.assertEqual(stack_args[0]["source"]["stack_offset"], 0)
        self.assertEqual(stack_args[1]["source"]["stack_offset"], 4)

    def test_contract_candidate_abi_signature_delta_keeps_nonstandard_stack_offsets_distinct(self):
        reference_callsite = {
            "id": "callsite:foo:1000",
            "target": {"kind": "direct", "target_rva": 0x2000},
            "argument_inventory": {
                "calling_convention": "cdecl_or_stdcall_stack",
                "argument_count": 1,
                "stack_args": [
                    {
                        "index": 0,
                        "role": "immediate",
                        "source": {"kind": "immediate", "stack_offset": 0, "value": 2},
                    }
                ],
                "register_args": [],
            },
        }
        candidate_callsite = copy.deepcopy(reference_callsite)
        candidate_callsite["id"] = "callsite:foo:offset-candidate"
        candidate_callsite["argument_inventory"]["stack_args"][0]["source"]["stack_offset"] = 4

        delta = stage_a._contract_candidate_abi_callsite_signature_delta(
            [reference_callsite],
            [candidate_callsite],
            [(0, 0, reference_callsite, candidate_callsite)],
            reference_function_index=[],
            candidate_function_index=[],
        )

        self.assertEqual(delta["counts"]["reference_only_signatures"], 1)
        self.assertEqual(delta["counts"]["candidate_only_signatures"], 1)

    def test_contract_candidate_abi_coverage_gaps_report_global_signature_shortages_first(self):
        def stack_slot_callsite(callsite_id: str, value: int) -> dict[str, object]:
            return {
                "id": callsite_id,
                "target": {
                    "kind": "function_pointer",
                    "operand": "dword ptr [esp + 0x64]",
                    "memory_role": "stack_pointer_slot",
                    "status": "unresolved",
                    "source": {"kind": "memory", "memory_role": "stack_pointer_slot"},
                },
                "argument_inventory": {
                    "calling_convention": "cdecl_or_stdcall_stack",
                    "argument_count": 1,
                    "stack_args": [
                        {
                            "index": 0,
                            "role": "immediate",
                            "source": {"kind": "immediate", "stack_offset": 0, "value": value},
                        }
                    ],
                    "register_args": [],
                },
            }

        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "umain",
                        "callsites": [
                            stack_slot_callsite("callsite:umain:arg1", 1),
                            stack_slot_callsite("callsite:umain:arg2", 2),
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "umain",
                        "callsites": [stack_slot_callsite("callsite:umain:candidate-arg2", 2)],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        gap = gaps["incomplete_callsites"][0]
        missing = gap["missing_callsite_signatures"][0]
        self.assertEqual(missing["signature"]["argument_inventory"]["stack_args"][0]["source"]["value"], 1)
        unmatched = gap["unmatched_reference_callsite_signatures"][0]
        self.assertEqual(unmatched["signature"]["argument_inventory"]["stack_args"][0]["source"]["value"], 2)
        self.assertEqual(gap["callsite_signature_delta"]["counts"]["reference_only_signatures"], 1)

    def test_contract_candidate_abi_signature_delta_keeps_global_function_pointer_identity(self):
        reference_callsite = {
            "id": "callsite:global:d000",
            "target": {
                "kind": "function_pointer",
                "operand": "eax",
                "memory_role": "global_writable_pointer_slot",
                "memory_rva": 0xD000,
                "status": "unresolved",
                "source": {
                    "kind": "memory",
                    "memory_role": "global_writable_pointer_slot",
                    "memory_rva": 0xD000,
                },
            },
        }
        candidate_callsite = copy.deepcopy(reference_callsite)
        candidate_callsite["id"] = "callsite:global:e000"
        candidate_callsite["target"]["memory_rva"] = 0xE000
        candidate_callsite["target"]["source"]["memory_rva"] = 0xE000

        delta = stage_a._contract_candidate_abi_callsite_signature_delta(
            [reference_callsite],
            [candidate_callsite],
            [],
            reference_function_index=[],
            candidate_function_index=[],
        )

        self.assertEqual(delta["counts"]["reference_only_signatures"], 1)
        self.assertEqual(delta["counts"]["candidate_only_signatures"], 1)
        self.assertEqual(delta["reference_only"][0]["signature"]["target"]["memory_rva"], 0xD000)
        self.assertEqual(delta["candidate_only"][0]["signature"]["target"]["memory_rva"], 0xE000)

    def test_contract_candidate_abi_coverage_gaps_report_function_and_callsite_mismatches(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_jq_init",
                        "memory_effect_summary": {
                            "reads": 0,
                            "writes": 1,
                            "read_roles": {},
                            "write_roles": {"computed_memory": 1},
                        },
                        "register_out_param_candidates": [{"register": "eax"}],
                        "callsites": [
                            {
                                "id": "callsite:jq_init:1004",
                                "block_id": "jq_init:0",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "___mingw_fprintf"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 2,
                                    "stack_args": [
                                        {"index": 0, "role": "memory"},
                                        {"index": 1, "role": "string_literal"},
                                    ],
                                    "register_args": [],
                                },
                                "varargs_evidence": {
                                    "status": "candidate",
                                    "format_string": {
                                        "status": "derived",
                                        "required_varargs": 1,
                                        "observed_varargs": 0,
                                        "missing_varargs": 1,
                                    },
                                },
                            }
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "jq_init",
                        "memory_effect_summary": {
                            "reads": 0,
                            "writes": 0,
                            "read_roles": {},
                            "write_roles": {},
                        },
                        "register_out_param_candidates": [],
                        "callsites": [
                            {
                                "id": "callsite:jq_init:1004",
                                "block_id": "jq_init:0",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "___mingw_fprintf"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "memory"}],
                                    "register_args": [],
                                },
                                "varargs_evidence": {"status": "not_observed"},
                            }
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["function_mismatches"], 1)
        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(gaps["function_mismatches"][0]["repair_class"], "hidden_sret_or_out_param")
        self.assertEqual(gaps["callsite_mismatches"][0]["repair_class"], "varargs_or_stdio_bridge")
        self.assertIn("varargs", gaps["callsite_mismatches"][0]["next_action"])

    def test_contract_candidate_abi_coverage_gaps_match_callsites_by_signature_before_index(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_allocator",
                        "callsites": [
                            {
                                "id": "callsite:allocator:1004",
                                "block_id": "allocator:0",
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "LeaveCriticalSection"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "immediate"}],
                                    "register_args": [],
                                },
                            },
                            {
                                "id": "callsite:allocator:1020",
                                "block_id": "allocator:1",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "malloc"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            },
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "allocator",
                        "callsites": [
                            {
                                "id": "callsite:allocator:2020",
                                "block_id": "allocator:1",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "malloc"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            },
                            {
                                "id": "callsite:allocator:2004",
                                "block_id": "allocator:0",
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "LeaveCriticalSection"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "immediate"}],
                                    "register_args": [],
                                },
                            },
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_match_direct_import_thunks_before_index(self):
        def import_thunk_function(name, rva):
            return {
                "name": name,
                "blocks": [
                    {
                        "block_id": f"{name}:0",
                        "rva_start": rva,
                        "rva_end": rva + 8,
                        "abi": {
                            "callsites": [],
                            "memory_reads": [
                                {
                                    "memory_role": "global_readonly_pointer_slot",
                                    "memory_section": {"name": ".idata"},
                                    "instruction": {"mnemonic": "jmp"},
                                }
                            ],
                        },
                    }
                ],
                "callsites": [],
            }

        reference_abi = {
            "original": {
                "import_prototypes": [
                    {"dll": "msvcrt.dll", "symbol": "_fileno"},
                    {"dll": "msvcrt.dll", "symbol": "_get_osfhandle"},
                    {"dll": "kernel32.dll", "symbol": "WriteFile"},
                ],
                "functions": [
                    {
                        "name": "section-gap--text-0068",
                        "callsites": [
                            {
                                "id": "callsite:section-gap--text-0068:15ee",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "direct", "target_rva": 0x2000},
                            },
                            {
                                "id": "callsite:section-gap--text-0068:15fa",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "_get_osfhandle"},
                            },
                            {
                                "id": "callsite:section-gap--text-0068:1624",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "WriteFile"},
                            },
                        ],
                    },
                    import_thunk_function("_fileno", 0x2000),
                ],
            }
        }
        candidate_abi = {
            "candidate": {
                "import_prototypes": [
                    {"dll": "msvcrt.dll", "symbol": "_get_osfhandle"},
                    {"dll": "kernel32.dll", "symbol": "WriteFile"},
                ],
                "functions": [
                    {
                        "name": "section-gap--text-0068",
                        "callsites": [
                            {
                                "id": "callsite:section-gap--text-0068:15fa",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                            },
                            {
                                "id": "callsite:section-gap--text-0068:1624",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "direct", "target_rva": 0x6000},
                            },
                        ],
                    },
                    import_thunk_function("_get_osfhandle", 0x5000),
                    import_thunk_function("_WriteFile@20", 0x6000),
                ],
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["incomplete_callsite_functions"], 1)
        self.assertEqual(gaps["counts"]["missing_callsites"], 1)
        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)
        self.assertEqual(gaps["incomplete_callsites"][0]["name"], "section-gap--text-0068")

    def test_contract_candidate_abi_coverage_gaps_normalize_direct_targets_by_resolved_alias(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x1000, "rva_end": 0x1010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:1004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x2000},
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x2000, "rva_end": 0x2010}],
                        "callsites": [],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x3000, "rva_end": 0x3010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:3004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x4000},
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x4000, "rva_end": 0x4010}],
                        "callsites": [],
                    },
                ]
            }
        }
        alias_evidence = {
            "matches_by_reference": {
                "_target": {
                    "reference_name": "_target",
                    "source_function": "target",
                    "candidate": {"name": "target", "rva_start": 0x4000, "rva_end": 0x4010},
                }
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi, alias_evidence=alias_evidence)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_keep_different_resolved_direct_targets_incomplete(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x1000, "rva_end": 0x1010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:1004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x2000},
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x2000, "rva_end": 0x2010}],
                        "callsites": [],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x3000, "rva_end": 0x3010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:3004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                            }
                        ],
                    },
                    {
                        "name": "other",
                        "blocks": [{"block_id": "other", "rva_start": 0x5000, "rva_end": 0x5010}],
                        "callsites": [],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)
        mismatch = gaps["callsite_mismatches"][0]

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(mismatch["issues"][0]["category"], "call_target_mismatch")
        self.assertEqual(mismatch["repair_class"], "call_target_mismatch")
        self.assertEqual(mismatch["issues"][0]["expected"]["resolved_functions"][0]["name"], "_target")
        self.assertEqual(mismatch["issues"][0]["observed"]["resolved_functions"][0]["name"], "other")

    def test_contract_candidate_abi_coverage_gaps_classify_call_target_before_argument_roles(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x1000, "rva_end": 0x1010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:1004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x2000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 2,
                                    "stack_args": [
                                        {"index": 0, "role": "register"},
                                        {"index": 1, "role": "memory"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x2000, "rva_end": 0x2010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x3000, "rva_end": 0x3010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:3004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "other",
                        "blocks": [{"block_id": "other", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)
        mismatch = gaps["callsite_mismatches"][0]

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(mismatch["repair_class"], "call_target_mismatch")
        self.assertIn("call target", mismatch["next_action"])
        self.assertNotIn("save/restore", mismatch["next_action"])

    def test_contract_candidate_abi_coverage_gaps_classify_argument_inventory_before_register_text(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_caller",
                        "callsites": [
                            {
                                "id": "callsite:caller:1004",
                                "block_id": "caller",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "memcmp"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "memory"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:caller:3004",
                                "block_id": "caller",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "memcmp"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)
        mismatch = gaps["callsite_mismatches"][0]

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(mismatch["issues"][0]["category"], "callsite_argument_inventory_mismatch")
        self.assertEqual(mismatch["repair_class"], "callsite_argument_inventory_mismatch")
        self.assertIn("argument order/count/roles", mismatch["next_action"])
        self.assertNotIn("save/restore", mismatch["next_action"])

    def test_contract_candidate_abi_coverage_gaps_accept_candidate_specific_stack_out_param_role(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_FindPESectionByName",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "_FindPESectionByName-0008",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "register"},
                                        {"index": 1, "role": "register"},
                                        {"index": 2, "role": "immediate"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "_FindPESectionByName",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "_FindPESectionByName",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "stack_out_param_or_scratch_buffer"},
                                        {"index": 1, "role": "register"},
                                        {"index": 2, "role": "immediate"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_accept_by_value_argument_role_shape_changes(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "__gdtoa",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "__gdtoa-0005",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "register"},
                                        {"index": 1, "role": "stack_pointer_slot"},
                                        {"index": 2, "role": "computed_memory"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "__dtoa_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "__gdtoa",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "___gdtoa",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "stack_local_slot"},
                                        {"index": 1, "role": "stack_argument_slot"},
                                        {"index": 2, "role": "computed_pointer_deref"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "__dtoa_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_reports_underconstrained_reference_arguments(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "__gdtoa",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "__gdtoa-0155",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 0,
                                    "stack_args": [],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "__multadd_D2A",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "___gdtoa",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "___gdtoa",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "stack_pointer_slot"},
                                        {"index": 1, "role": "immediate"},
                                        {"index": 2, "role": "immediate"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "___multadd_D2A",
                        "aliases": ["__multadd_D2A", "___multadd_D2A"],
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)
        mismatch = gaps["callsite_mismatches"][0]

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(mismatch["issues"][0]["category"], "reference_argument_inventory_underconstrained")
        self.assertEqual(mismatch["repair_class"], "stage_a_argument_inventory_underconstrained")
        self.assertIn("improve Stage A argument recovery", mismatch["next_action"])

    def test_contract_candidate_abi_coverage_gaps_reject_literal_and_address_role_loss(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 2,
                                    "stack_args": [
                                        {"index": 0, "role": "string_literal"},
                                        {"index": 1, "role": "computed_out_param_or_hidden_sret"},
                                    ],
                                    "register_args": [],
                                },
                                "hidden_sret_or_out_param_evidence": {"status": "candidate"},
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 2,
                                    "stack_args": [
                                        {"index": 0, "role": "immediate"},
                                        {"index": 1, "role": "register"},
                                    ],
                                    "register_args": [],
                                },
                                "hidden_sret_or_out_param_evidence": {"status": "unknown"},
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(gaps["callsite_mismatches"][0]["issues"][0]["category"], "hidden_sret_or_out_param_missing")
        self.assertEqual(gaps["callsite_mismatches"][0]["issues"][1]["category"], "callsite_argument_inventory_mismatch")

    def test_contract_candidate_abi_coverage_gaps_reject_lost_stack_out_param_role(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "stack_out_param_or_scratch_buffer"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(gaps["callsite_mismatches"][0]["issues"][0]["category"], "callsite_argument_inventory_mismatch")

    def test_contract_candidate_abi_coverage_gaps_use_explicit_skeleton_aliases(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "__dyn_tls_dtor@12",
                        "blocks": [{"block_id": "dyn", "rva_start": 0x1000, "rva_end": 0x1001, "size": 1}],
                        "callsites": [],
                    }
                ]
            },
            "counts": {"functions": 1, "callsites": 0},
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "___dyn_tls_dtor_12",
                        "callsites": [],
                    }
                ]
            },
            "counts": {"functions": 1, "callsites": 0},
        }
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "___dyn_tls_dtor_12",
                            "aliases": ["__dyn_tls_dtor@12"],
                            "source_kind": "decompiled_function",
                        }
                    ]
                },
            },
            [{"name": "___dyn_tls_dtor_12", "rva_start": 0x1000, "rva_end": 0x1001, "section": ".text"}],
        )

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi, alias_evidence=alias_evidence)

        self.assertEqual(gaps["counts"]["missing_functions"], 0)
        self.assertEqual(gaps["counts"]["ambiguous_functions"], 0)
        self.assertEqual(alias_evidence["matches_by_reference"]["__dyn_tls_dtor@12"]["source_function"], "___dyn_tls_dtor_12")

    def test_candidate_abi_probes_reference_section_gap_units_at_same_rva(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            candidate_bin = stage_a._parse_stage_a_pe(candidate)
            reference_abi = {
                "original": {
                    "functions": [
                        {
                            "name": "section-gap--text-0000",
                            "blocks": [
                                {
                                    "block_id": "section-gap--text-0000",
                                    "rva_start": 0x1000,
                                    "rva_end": 0x1001,
                                    "size": 1,
                                }
                            ],
                            "callsites": [],
                        },
                        {
                            "name": "ordinary_missing",
                            "blocks": [
                                {
                                    "block_id": "ordinary_missing-0000",
                                    "rva_start": 0x1000,
                                    "rva_end": 0x1001,
                                    "size": 1,
                                }
                            ],
                            "callsites": [],
                        },
                    ]
                },
                "counts": {"functions": 2, "callsites": 0},
            }

            candidate_abi = stage_a._candidate_abi_constraint_from_functions(candidate_bin, [], reference_abi=reference_abi)
            gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        by_name = {item["name"]: item for item in candidate_abi["candidate"]["functions"]}
        self.assertIn("section-gap--text-0000", by_name)
        self.assertEqual(by_name["section-gap--text-0000"]["blocks"][0]["block_id"], "section-gap--text-0000")
        self.assertEqual(by_name["section-gap--text-0000"]["stack_delta"]["status"], "block_local")
        self.assertNotIn("ordinary_missing", by_name)
        self.assertEqual(gaps["counts"]["missing_functions"], 1)
        self.assertEqual(gaps["missing_functions"][0]["name"], "ordinary_missing")

    def test_contract_candidate_alias_evidence_matches_generated_c_identifier_alias(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "_gnu_exception_handler@4",
                            "aliases": ["_gnu_exception_handler@4", "_gnu_exception_handler_4"],
                            "source_kind": "generated_contract_placeholder",
                        }
                    ]
                },
            },
            [{"name": "_gnu_exception_handler_4", "rva_start": 0x3414, "rva_end": 0x3420, "section": ".text"}],
        )

        match = alias_evidence["matches_by_reference"]["_gnu_exception_handler@4"]

        self.assertEqual(alias_evidence["status"], "satisfied")
        self.assertEqual(match["source_function"], "_gnu_exception_handler@4")
        self.assertEqual(match["candidate"]["name"], "_gnu_exception_handler_4")

    def test_contract_candidate_alias_evidence_prefers_unique_exact_source_function(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "__crt_atexit",
                            "aliases": ["_crt_atexit", "__crt_atexit"],
                            "source_kind": "omitted_import_thunk",
                        }
                    ]
                },
            },
            [
                {"name": "__crt_atexit", "rva_start": 0x86A8, "rva_end": 0x86B0, "section": ".text"},
                {"name": "_crt_atexit", "rva_start": 0x27E8, "rva_end": 0x27F0, "section": ".text"},
            ],
        )

        match = alias_evidence["matches_by_reference"]["__crt_atexit"]

        self.assertEqual(alias_evidence["status"], "satisfied")
        self.assertEqual(alias_evidence["counts"]["ambiguities"], 0)
        self.assertEqual(match["candidate"]["name"], "__crt_atexit")
        self.assertEqual(match["resolution"], "unique_exact_source_function")
        self.assertEqual(alias_evidence["matches_by_reference"]["_crt_atexit"]["candidate"]["name"], "__crt_atexit")

    def test_contract_candidate_alias_evidence_ignores_section_symbol_aliases(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "___mbrtowc_cp",
                            "aliases": ["section-gap--text-0747", "mbrtowc_cp", ".text"],
                            "source_kind": "generated_contract_placeholder_from_section_gap_alias",
                        },
                        {
                            "function": "___wcrtomb_cp",
                            "aliases": ["section-gap--text-0740", "wcrtomb_cp", ".text"],
                            "source_kind": "generated_contract_placeholder_from_section_gap_alias",
                        },
                    ]
                },
            },
            [
                {"name": "___mbrtowc_cp", "rva_start": 0x464C, "rva_end": 0x4650, "section": ".text"},
                {"name": "___wcrtomb_cp", "rva_start": 0x5650, "rva_end": 0x5654, "section": ".text"},
            ],
        )

        self.assertEqual(alias_evidence["status"], "satisfied")
        self.assertEqual(alias_evidence["counts"]["ambiguities"], 0)
        self.assertNotIn(".text", alias_evidence["matches_by_reference"])
        self.assertNotIn(".text", alias_evidence["ambiguities_by_reference"])
        self.assertEqual(alias_evidence["matches_by_reference"]["section-gap--text-0747"]["candidate"]["name"], "___mbrtowc_cp")
        self.assertEqual(alias_evidence["matches_by_reference"]["section-gap--text-0740"]["candidate"]["name"], "___wcrtomb_cp")

    def test_contract_candidate_alias_evidence_keeps_duplicate_exact_source_function_incomplete(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "__crt_atexit",
                            "aliases": ["_crt_atexit", "__crt_atexit"],
                            "source_kind": "omitted_import_thunk",
                        }
                    ]
                },
            },
            [
                {"name": "__crt_atexit", "rva_start": 0x86A8, "rva_end": 0x86B0, "section": ".text"},
                {"name": "__crt_atexit", "rva_start": 0x96A8, "rva_end": 0x96B0, "section": ".text"},
                {"name": "_crt_atexit", "rva_start": 0x27E8, "rva_end": 0x27F0, "section": ".text"},
            ],
        )

        self.assertEqual(alias_evidence["status"], "incomplete")
        self.assertEqual(alias_evidence["counts"]["ambiguities"], 2)
        self.assertIn("__crt_atexit", alias_evidence["ambiguities_by_reference"])

    def test_contract_candidate_alias_evidence_records_unmatched_source_aliases(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "___iob_func",
                            "aliases": ["__iob_func"],
                            "source_kind": "omitted_import_thunk",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 2305,
                            "line_end": 2308,
                        }
                    ]
                },
            },
            [],
        )

        unmatched = alias_evidence["unmatched_by_reference"]["__iob_func"][0]

        self.assertEqual(alias_evidence["status"], "satisfied")
        self.assertEqual(alias_evidence["counts"]["unmatched_aliases"], 2)
        self.assertEqual(unmatched["source_function"], "___iob_func")
        self.assertEqual(unmatched["source_kind"], "omitted_import_thunk")
        self.assertEqual(unmatched["file"], "src/jq_stage_b_skeleton.c")

    def test_contract_candidate_missing_function_details_classify_import_thunk_and_runtime_entry(self):
        alias_evidence = {
            "unmatched_by_reference": {
                "__iob_func": [
                    {
                        "reference_name": "__iob_func",
                        "source_function": "___iob_func",
                        "source_kind": "omitted_import_thunk",
                        "source_aliases": ["__iob_func"],
                    }
                ],
                "wmain": [
                    {
                        "reference_name": "wmain",
                        "source_function": "_wmain",
                        "source_kind": "omitted_runtime_entry",
                        "source_aliases": ["wmain"],
                    }
                ],
            }
        }
        constraints = {
            "import_thunks": {
                "mapped_import_thunks": [
                    {
                        "id": "__iob_func-import-thunk",
                        "source": {
                            "function": "__iob_func",
                            "kind": "import_thunk",
                            "import_signature": {"dll": "msvcrt.dll", "symbol": "__p__iob", "ordinal": None},
                        },
                        "original": {"rva_start": 0x2000, "rva_end": 0x2006},
                    }
                ]
            }
        }

        details = stage_a._contract_candidate_missing_function_details(
            ["__iob_func", "wmain"],
            constraints=constraints,
            candidate_imports=[{"dll": "MSVCRT.dll", "symbol": "__p__iob", "ordinal": None}],
            alias_evidence=alias_evidence,
        )

        by_function = {item["function"]: item for item in details}
        self.assertEqual(by_function["__iob_func"]["category"], "import_thunk_symbol_missing_with_matching_import")
        self.assertEqual(by_function["__iob_func"]["candidate_import_match"]["symbol"], "__p__iob")
        self.assertEqual(by_function["__iob_func"]["source_evidence"]["source_kind"], "omitted_import_thunk")
        self.assertIn("import thunk symbol", by_function["__iob_func"]["next_action"])
        self.assertEqual(by_function["wmain"]["category"], "runtime_entry_replaced_by_generated_bridge")
        self.assertIn("runtime/CRT", by_function["wmain"]["next_action"])

    def test_contract_candidate_abi_coverage_gaps_fail_closed_on_ambiguous_skeleton_aliases(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "__dup@4",
                        "blocks": [{"block_id": "dup", "rva_start": 0x1000, "rva_end": 0x1001, "size": 1}],
                        "callsites": [],
                    }
                ]
            },
            "counts": {"functions": 1, "callsites": 0},
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {"name": "___first_4", "callsites": []},
                    {"name": "___second_4", "callsites": []},
                ]
            },
            "counts": {"functions": 2, "callsites": 0},
        }
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {"function": "___first_4", "aliases": ["__dup@4"]},
                        {"function": "___second_4", "aliases": ["__dup@4"]},
                    ]
                },
            },
            [
                {"name": "___first_4", "rva_start": 0x1000, "rva_end": 0x1001, "section": ".text"},
                {"name": "___second_4", "rva_start": 0x1001, "rva_end": 0x1002, "section": ".text"},
            ],
        )

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi, alias_evidence=alias_evidence)

        self.assertEqual(alias_evidence["status"], "incomplete")
        self.assertEqual(gaps["counts"]["missing_functions"], 0)
        self.assertEqual(gaps["counts"]["ambiguous_functions"], 1)
        self.assertEqual(gaps["ambiguous_functions"][0]["name"], "__dup@4")

    def test_validate_contract_candidate_satisfies_function_ranges_with_explicit_skeleton_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            candidate_bin = stage_a._parse_stage_a_pe(candidate)
            contract = self._write_reference_contract(
                root / "reference-contract.json",
                candidate_bin,
                functions=["__dyn_tls_init@12"],
            )
            linker_map = root / "candidate.map"
            linker_map.write_text("0x401000 @___dyn_tls_init_12@16\n", encoding="utf-8")
            skeleton_manifest = self._write_skeleton_manifest(
                root / "manifest.json",
                [
                    {
                        "function": "___dyn_tls_init_12",
                        "aliases": ["__dyn_tls_init@12"],
                        "source_kind": "decompiled_function",
                    }
                ],
            )

            result = stage_a.stage_a_validate_contract_candidate(
                reference_contract=contract,
                candidate=candidate,
                linker_map_candidate=linker_map,
                skeleton_manifest=skeleton_manifest,
                out=root / "out",
            )

        families = {item["family"]: item for item in result["families"]}
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(families["function_ranges"]["status"], "satisfied")
        self.assertEqual(families["abi_callsites"]["status"], "satisfied")
        self.assertEqual(families["function_ranges"]["evidence"]["alias_matches"][0]["reference_name"], "__dyn_tls_init@12")
        self.assertEqual(result["counts"]["alias_matches"], 2)

    def test_validate_contract_candidate_keeps_duplicate_skeleton_alias_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            candidate_bin = stage_a._parse_stage_a_pe(candidate)
            contract = self._write_reference_contract(root / "reference-contract.json", candidate_bin, functions=["__dup@4"])
            linker_map = root / "candidate.map"
            linker_map.write_text("0x401000 ___first_4\n0x401001 ___second_4\n", encoding="utf-8")
            skeleton_manifest = self._write_skeleton_manifest(
                root / "manifest.json",
                [
                    {"function": "___first_4", "aliases": ["__dup@4"]},
                    {"function": "___second_4", "aliases": ["__dup@4"]},
                ],
            )

            result = stage_a.stage_a_validate_contract_candidate(
                reference_contract=contract,
                candidate=candidate,
                linker_map_candidate=linker_map,
                skeleton_manifest=skeleton_manifest,
                out=root / "out",
            )

        families = {item["family"]: item for item in result["families"]}
        self.assertEqual(result["verdict"], "incomplete")
        self.assertEqual(families["function_ranges"]["status"], "incomplete")
        self.assertEqual(families["abi_callsites"]["status"], "incomplete")
        self.assertEqual(families["function_ranges"]["evidence"]["missing_functions"], [])
        self.assertEqual(families["function_ranges"]["evidence"]["ambiguous_aliases"][0]["matches_total"], 2)

    def test_stage_a_export_reference_contract_rejects_stale_validation_report_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )

            self._write_pe(candidate, b"\x90")
            mutated_map = json.loads(block_map.read_text(encoding="utf-8"))
            mutated_map["blocks"][0]["id"] = "tiny-stale-map"
            block_map.write_text(json.dumps(mutated_map, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            self.assertEqual(result["status"], "incomplete")
            binding = result["constraints"]["validation_report_artifact_binding"]
            self.assertEqual(binding["status"], "incomplete")
            self.assertFalse(binding["facts"]["matching_candidate_sha256"])
            self.assertFalse(binding["facts"]["matching_mapping_payload"])
            self.assertIn(
                "validation_report_binary_mismatch",
                {issue["category"] for issue in binding["issues"]},
            )
            self.assertIn(
                "validation_report_mapping_mismatch",
                {issue["category"] for issue in binding["issues"]},
            )

            gaps = json.loads((root / "coverage_gaps.json").read_text(encoding="utf-8"))
            self.assertEqual(gaps["status"], "incomplete")
            self.assertIn(
                "validation_report_artifact_binding",
                {gap["family"] for gap in gaps["gaps"]},
            )
            self.assertEqual(gaps["next_work"][0]["family"], "validation_report_artifact_binding")

            explanation = stage_a_explain_obligations(
                reference_contract=root / "reference-contract.json",
                focus="validation_report_binary_mismatch",
            )
            self.assertEqual(explanation["status"], "pass")
            self.assertTrue(explanation["gaps"])

            self._write_pe(candidate, b"\xc3")
            smoke = stage_a_smoke_contract(reference_contract=root / "reference-contract.json")
            self.assertEqual(smoke["status"], "incomplete")
            self.assertIn("stale_bound_artifact", {issue["category"] for issue in smoke["issues"]})

    def test_stage_a_diff_obligations_reports_resolved_contract_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            before = root / "before" / "reference-contract.json"
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                layout_contract=layout_contract,
                out=before,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            after = root / "after" / "reference-contract.json"
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                out=after,
            )

            diff = stage_a_diff_obligations(before=before, after=after)
            self.assertEqual(diff["status"], "pass")
            self.assertGreater(diff["counts"]["resolved"], 0)
            self.assertEqual(diff["counts"]["new"], 0)
            self.assertIn(
                "validation_report_artifact_binding",
                {gap["family"] for gap in diff["resolved"]},
            )

    def test_stage_a_generate_map_rejects_import_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            call_import = b"\xff\x15\x40\x20\x40\x00\xc3"
            original = self._write_import_pe(root / "original.exe", call_import, "GetTickCount")
            candidate = self._write_import_pe(root / "candidate.exe", call_import, "ExitProcess")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("layout_mismatch", {issue["category"] for issue in result["issues"]})

    def test_checked_generated_jq_mapping_rule_can_close_unsupported_local_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x0f\x0b\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x0f\x0b\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "format": "stage-a-block-map-v1",
                        "generator": "stage-a-generate-map",
                        "status": "pass",
                        "blocks": [
                            {
                                "id": "jq-function",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "linker_map_function", "checked": True, "symbol": "tiny"},
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 3},
                                "source": {"kind": "linker_map_capstone_block_match_v1", "function": "tiny"},
                                "proof": {
                                    "rule": "reproducible_jq_same_source_optimization_pair_v1",
                                    "checked": True,
                                    "function": "tiny",
                                    "original_flags": "-O2",
                                    "candidate_flags": "-O2 -falign-functions=32",
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:jq-function")
            self.assertEqual(obligation["proof_rule"], "reproducible_jq_same_source_optimization_pair_v1")

    def test_recovered_cfg_block_root_marker_does_not_prove_reachability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            orphan = self._mapping_entry(rva=0x1001, size=1, block_id="orphan")
            orphan["root"] = {"kind": "recovered_cfg_block", "checked": True}
            mapping = root / "block-map.json"
            mapping.write_text(json.dumps({"blocks": [self._mapping_entry(size=1, block_id="entry"), orphan]}), encoding="utf-8")

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                )

            self.assertEqual(result["verdict"], "incomplete")
            reachability = self._obligation(root / "report", "reachability:orphan")
            self.assertEqual(reachability["status"], "incomplete")
            self.assertEqual(reachability["incomplete"]["category"], "unproved_reachability")

    def test_generated_map_issues_block_final_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "format": "stage-a-block-map-v1",
                        "generator": "stage-a-generate-map",
                        "status": "incomplete",
                        "issues": [{"category": "layout_mismatch", "blocker": "test"}],
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 0x200},
                                "candidate": {"rva": 0x1000, "size": 0x200},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "mapping-generated-map.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "generated_map_incomplete")

    def _mock_lean_checked(self):
        return _LeanCheckedMock()

    def _write_mapping(self, path: Path, *, rva: int = 0x1000, size: int, block_id: str = "entry") -> Path:
        path.write_text(json.dumps({"blocks": [self._mapping_entry(rva=rva, size=size, block_id=block_id)]}), encoding="utf-8")
        return path

    def _obligation(self, out: Path, obligation_id: str) -> dict:
        obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
        for obligation in obligations:
            if obligation["id"] == obligation_id:
                return obligation
        self.fail(f"missing obligation {obligation_id}")

    def _mapping_entry(self, *, rva: int = 0x1000, size: int, block_id: str = "entry") -> dict:
        return {
            "id": block_id,
            "kind": "code",
            "reachable": rva == 0x1000,
            "original": {"rva": rva, "size": size},
            "candidate": {"rva": rva, "size": size},
        }

    def _write_pe(self, path: Path, code: bytes, *, virtual_size: int | None = None) -> Path:
        path.write_bytes(_pe32_image(code, virtual_size=virtual_size))
        return path

    def _write_pe_with_coff_symbol(self, path: Path, code: bytes, symbol: str) -> Path:
        image = bytearray(_pe32_image(code))
        pointer_to_symbol_table = len(image)
        name = symbol.encode("ascii")
        if len(name) > 8:
            raise AssertionError("test COFF symbol helper only supports short names")
        symbol_entry = name.ljust(8, b"\0") + struct.pack("<IhHBB", 0, 1, 0x20, 3, 0)
        image.extend(symbol_entry)
        image.extend(struct.pack("<I", 4))
        struct.pack_into("<I", image, 0x8C, pointer_to_symbol_table)
        struct.pack_into("<I", image, 0x90, 1)
        path.write_bytes(bytes(image))
        return path

    def _write_reference_contract(self, path: Path, binary: stage_a.StageABinary, *, functions: list[str]) -> Path:
        layout = stage_a._binary_reference_layout(binary)
        function_rows = [
            {
                "name": name,
                "rva_start": 0x1000 + index,
                "rva_end": 0x1000 + index + 1,
                "section": ".text",
                "bytes_sha256": "",
            }
            for index, name in enumerate(functions)
        ]
        abi_functions = [
            {
                "name": name,
                "blocks": [
                    {
                        "block_id": f"block-{index}",
                        "rva_start": 0x1000 + index,
                        "rva_end": 0x1000 + index + 1,
                        "size": 1,
                    }
                ],
                "callsites": [],
            }
            for index, name in enumerate(functions)
        ]
        sidecars = {
            "coverage_gaps": {"path": "coverage_gaps.json"},
            "obligation_index": {"path": "obligation_index.json"},
            "contract_summary": {"path": "contract_summary.json"},
            "abi_callsites": {"path": "abi_callsites.json"},
        }
        payload = {
            "format": "stage-a-reference-contract-v1",
            "model": STAGE_A_MODEL_ID,
            "status": "pass",
            "original": layout,
            "constraints": {
                "function_ranges": {"status": "satisfied", "functions": function_rows},
                "abi_callsites": {
                    "status": "satisfied",
                    "original": {"functions": abi_functions, "import_prototypes": []},
                    "counts": {"functions": len(functions), "callsites": 0, "import_prototypes": 0},
                },
            },
            "families": [
                {"family": "binary_faithfulness", "status": "satisfied"},
                {"family": "function_ranges", "status": "satisfied"},
                {"family": "abi_callsites", "status": "satisfied"},
                {"family": "import_thunks", "status": "satisfied"},
                {"family": "proof_inventory", "status": "satisfied"},
            ],
            "inputs": {},
            "sidecars": sidecars,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        contract_ref = {"path": str(path), "sha256": stage_a.sha256_file(path), "exists": True}
        for sidecar in sidecars.values():
            sidecar_path = path.parent / str(sidecar["path"])
            sidecar_path.write_text(json.dumps({"reference_contract": contract_ref}), encoding="utf-8")
        return path

    def _write_skeleton_manifest(self, path: Path, functions: list[dict]) -> Path:
        payload = {
            "format": "stage-b-skeleton-v1",
            "source_map": {
                "format": "stage-b-source-map-v1",
                "functions": functions,
            },
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _write_import_pe(self, path: Path, code: bytes, symbol: str, *, iat_offset: int = 0x40) -> Path:
        path.write_bytes(_pe32_import_image(code, symbol=symbol, iat_offset=iat_offset))
        return path


def _pe32_image(code: bytes, *, virtual_size: int | None = None) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_raw = 0x200
    text_raw_size = _align(len(code), file_alignment)
    text_virtual_size = virtual_size if virtual_size is not None else len(code)
    size_of_image = _align(text_rva + text_virtual_size, section_alignment)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        224,
        0x010F,
    )
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        text_raw_size,
        0,
        0,
        text_rva,
        text_rva,
        0,
        0x400000,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        text_virtual_size,
        text_rva,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos) + b"PE\0\0" + coff + optional + section
    headers = headers.ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0")


def _pe32_import_image(code: bytes, *, symbol: str, dll: str = "KERNEL32.dll", iat_offset: int = 0x40) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    idata_rva = 0x2000
    text_raw = 0x200
    text_raw_size = _align(len(code), file_alignment)
    idata_raw = text_raw + text_raw_size
    idata_raw_size = 0x200
    size_of_image = _align(idata_rva + idata_raw_size, section_alignment)

    int_rva = idata_rva + 0x30
    iat_rva = idata_rva + iat_offset
    dll_name_rva = idata_rva + 0x50
    import_name_rva = idata_rva + 0x80
    idata = bytearray(idata_raw_size)
    struct.pack_into("<IIIII", idata, 0x00, int_rva, 0, 0, dll_name_rva, iat_rva)
    struct.pack_into("<II", idata, 0x30, import_name_rva, 0)
    struct.pack_into("<II", idata, iat_offset, import_name_rva, 0)
    idata[0x50 : 0x50 + len(dll) + 1] = dll.encode("ascii") + b"\0"
    name = symbol.encode("ascii")
    struct.pack_into("<H", idata, 0x80, 0)
    idata[0x82 : 0x82 + len(name) + 1] = name + b"\0"

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        2,
        0,
        0,
        0,
        224,
        0x010F,
    )
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        text_raw_size,
        idata_raw_size,
        0,
        text_rva,
        text_rva,
        idata_rva,
        image_base,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional = bytearray(optional_prefix + (b"\0" * (16 * 8)))
    struct.pack_into("<II", optional, len(optional_prefix) + 8, idata_rva, 40)
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        len(code),
        text_rva,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    idata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".idata\0\0",
        idata_raw_size,
        idata_rva,
        idata_raw_size,
        idata_raw,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + text_section + idata_section
    headers = headers.ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0") + bytes(idata)


class _LeanCheckedMock:
    def __enter__(self):
        self._which = mock.patch("haloce_catalog.stage_a.shutil.which", return_value="/nix/store/lean/bin/lean")
        self._check = mock.patch(
            "haloce_catalog.stage_a._run_lean_check",
            return_value={
                "status": "checked",
                "command": ["/nix/store/lean/bin/lean", "StageA/Obligations.lean"],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
            },
        )
        self._which.start()
        self._check.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._check.stop()
        self._which.stop()
        return False


def _align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment
