import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog import cli as catalog_cli
from haloce_catalog import stage_a
from haloce_catalog.stage_a import STAGE_A_MODEL_ID, stage_a_generate_map, stage_a_validate


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
                candidate_flags="-O0 test",
            )

            self.assertEqual(result["status"], "pass")
            payload = json.loads(mapping.read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["issues"], 0)
            self.assertEqual(payload["counts"]["blocks"], 2)
            self.assertIn("section-gap--text-0000", {block["id"] for block in payload["blocks"]})
            self.assertEqual(payload["blocks"][0]["proof"]["original_flags"], "-O2 test")
            self.assertEqual(payload["blocks"][0]["proof"]["candidate_flags"], "-O0 test")
            contract = json.loads(layout.read_text(encoding="utf-8"))
            self.assertTrue(contract["facts"]["all_executable_bytes_classified"])

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

    def test_checked_generated_jq_mapping_rule_can_close_large_unsupported_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x0f\x0b")
            candidate = self._write_pe(root / "candidate.exe", b"\xcc\xc3")
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
                                "original": {"rva": 0x1000, "size": 0x200},
                                "candidate": {"rva": 0x1000, "size": 0x200},
                                "source": {"kind": "linker_map_capstone_block_match_v1", "function": "tiny"},
                                "proof": {
                                    "rule": "reproducible_jq_same_source_optimization_pair_v1",
                                    "checked": True,
                                    "function": "tiny",
                                    "original_flags": "-O2",
                                    "candidate_flags": "-O0",
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

    def _write_import_pe(self, path: Path, code: bytes, symbol: str) -> Path:
        path.write_bytes(_pe32_import_image(code, symbol=symbol))
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


def _pe32_import_image(code: bytes, *, symbol: str, dll: str = "KERNEL32.dll") -> bytes:
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
    iat_rva = idata_rva + 0x40
    dll_name_rva = idata_rva + 0x50
    import_name_rva = idata_rva + 0x80
    idata = bytearray(idata_raw_size)
    struct.pack_into("<IIIII", idata, 0x00, int_rva, 0, 0, dll_name_rva, iat_rva)
    struct.pack_into("<II", idata, 0x30, import_name_rva, 0)
    struct.pack_into("<II", idata, 0x40, import_name_rva, 0)
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
