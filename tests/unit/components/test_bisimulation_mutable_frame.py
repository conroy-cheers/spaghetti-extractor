"""Original/source proofs distinguish writable footprints from final equality."""
from __future__ import annotations

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_mutable_frame import (
    FRAME, BASES, mutable_frame_declarations, validate_mutable_frame, checked_fixed_writable_frame_operations)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.bisimulation_readonly_evidence import checked_connected_source_contract
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload


TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


class MutableFrameRangeTests(unittest.TestCase):
    def test_bytewise_union_includes_adjacent_grants_and_excludes_gaps_and_overflow(self):
        if not shutil.which("cbmc"):
            self.skipTest("CBMC is unavailable")
        source = ('typedef unsigned int uint32_t; typedef unsigned long long uint64_t;\n'
                  '#define UINT64_C(x) x##ULL\n' + mutable_frame_declarations((("a", 1), ("b", 3))) + f'''
void main(void) {{
  uint32_t address, width;
  {BASES}[0]=100U; {BASES}[1]=101U;
  __CPROVER_assert(spx_proof_mutable_write_permitted(address,width) ==
      (width>=1U && width<=4U && address>=100U && (uint64_t)address+width<=104U), "adjacent byte union");
  {BASES}[1]=102U;
  __CPROVER_assert(!spx_proof_mutable_write_permitted(100U,2U), "gap is not granted");
  __CPROVER_assert(spx_proof_mutable_write_permitted(102U,3U), "second grant remains writable");
  {BASES}[0]=4294967295U;
  __CPROVER_assert(spx_proof_mutable_write_permitted(4294967295U,1U), "last byte");
  __CPROVER_assert(!spx_proof_mutable_write_permitted(4294967295U,2U), "overflow is not granted");
}}
''')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frame.c"
            path.write_text(source)
            result = run_cbmc_properties(command=[shutil.which("cbmc"), str(path), "--function", "main",
                "--json-ui", "--bounds-check", "--pointer-check", "--unwind", "2", "--unwinding-assertions"], timeout_seconds=30)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))


class MutableFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument", "cbmc", "jq")):
            raise unittest.SkipTest("CBMC and receipt-reader tools are unavailable")
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.root = Path(directory.name)
        cls.cases = {}
        for name, options in (("positive", {}), ("private", {"private_write": True}),
                              ("restored", {"restored_outside_write": True})):
            root = cls.root / name
            root.mkdir()
            result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")), reference_view=True,
                read_buffer=True, write_buffer=True, return_to_caller=True,
                reference_authority=authority_payload(), source_contracts=True, **options)
            if result["status"] != "satisfied":
                raise AssertionError(result["issues"])
            cls.cases[name] = json.loads((root / "contextual-refinement-result.json").read_text())
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    def readers(self, case):
        proof = case["proof"]
        for shard in proof["shards"]:
            frame = shard.get(FRAME.field)
            if frame is not None:
                frame["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in frame.items() if k != "receipt_sha256"})
        proof["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in proof.items() if k != "receipt_sha256"})
        try:
            validate_contextual_refinement_v2(proof, proof_plan=case["proof_plan"], exact_c_slice=case["exact_c_slice"])
            python = True
        except ValueError:
            python = False
        jq = run_jq_reader([shutil.which("jq"), "-e", self.program + "\nspx_contextual_proof_system"],
                            input=json.dumps(case), capture_output=True, text=True)
        return python, jq.returncode == 0

    def test_segment_frames_and_retained_bytes_are_checked(self):
        for name, case in self.cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                proof = case["proof"]
                self.assertEqual([s[FRAME.field]["result"]["status"] for s in proof["shards"]],
                                 ["satisfied", "satisfied" if name == "positive" else "violated"])
                for index, (model, shard) in enumerate(zip(proof["models"]["operation_models"][0]["obligation_models"], proof["shards"], strict=True)):
                    options = dict(model=model, shard=shard, checker=proof["checker"],
                        artifacts=self.root / name / "diagnostics" / f"operation-0000-obligation-{index:04d}")
                    if name != "positive" and index == 1:
                        with self.assertRaisesRegex(ValueError, "satisfied frame"):
                            validate_mutable_frame(shard[FRAME.field], **options)
                    else:
                        validate_mutable_frame(shard[FRAME.field], **options)

    def test_positive_auxiliary_evidence_keeps_connected_replay(self):
        bound = self.cases["positive"]["proof"]["models"]["source_summary_contracts"]
        certificate = bound["certificate"]
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(certificate["interface_intent"]))
        arguments = dict(bound=bound, bundle=bundle, source=certificate["source_package"],
            source_profile_sha256=bound["source_profile_sha256"], operation_symbols=certificate["operation_symbols"],
            headers=render_component_c_headers_v5(bundle, certificate["operation_symbols"]))
        self.assertIsNone(checked_connected_source_contract(**arguments,
            readonly_artifacts=self.root / "positive" / "local-contract"))
        with self.assertRaisesRegex(ValueError, "retained models"):
            checked_connected_source_contract(**arguments)

    def test_both_readers_reject_rehashed_weakened_frame_claims(self):
        for mutation in ("policy", "authority", "entry", "model", "command", "tool", "property", "count-type", "guard"):
            with self.subTest(mutation=mutation):
                case = copy.deepcopy(self.cases["positive"])
                shard = case["proof"]["shards"][-1]
                frame = shard[FRAME.field]
                if mutation == "policy": frame["policy"] = "original-physical-empty-write-frame-v1"
                elif mutation == "authority": frame["authorizing"] = True
                elif mutation == "entry": frame["proof_function"] = "other"
                elif mutation == "model": frame["bindings"]["goto_model_sha256"] = "a" * 64
                elif mutation == "command": frame["command"][-1] = "other.assertion.1"
                elif mutation == "tool": frame["tools"]["cbmc_sha256"] = "a" * 64
                elif mutation == "property": frame["result"]["property_ids"] = []
                elif mutation == "count-type": frame["result"]["properties"] = True
                else:
                    next(r for r in shard["partitioned_evidence"]["assertions"]
                         if r["description"] == FRAME.description)["source_function"] = "other"
                self.assertEqual(self.readers(case), (False, False))

    def test_missing_frame_is_not_an_operation_guarantee(self):
        case = copy.deepcopy(self.cases["positive"])
        del case["proof"]["shards"][0][FRAME.field]
        # The wider entry theorem consumes this physical fact. Keeping that
        # theorem after deleting its prerequisite must reject, even if rehashed.
        self.assertEqual(self.readers(case), (False, False))
        del case["proof"]["shards"][0]["mutable_entry_contract"]
        self.assertEqual(self.readers(case), (False, False))
        for field in ("exact_mutable_cut_machine_frame", "exact_mutable_exit_machine_frame"):
            del case["proof"]["shards"][0][field]
        # Remove the dependent claim as well: ordinary correspondence remains,
        # but the supplier no longer exports a whole-operation write frame.
        self.assertEqual(self.readers(case), (True, True))
        self.assertEqual(checked_fixed_writable_frame_operations(case["proof"],
            artifacts=self.root / "positive" / "diagnostics"), ())
