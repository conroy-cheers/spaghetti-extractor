"""Borrowed initial state requires current memory and a checked entry binding."""

import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract
from .borrowed_state_fixture import check_borrowed_state, prepare_borrowed_state
from .test_hand_defined_boundaries import shared_buffer_bundle

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "tests/fixtures/hand-defined-boundaries/resource-text",
)}


class BorrowedStateAdmissionTests(unittest.TestCase):
    def test_real_helper_borrowed_state_stays_without_an_initializer(self):
        payload = _logical_projection(shared_buffer_bundle())
        interface = ProofKernelComponentInterface.parse(payload)
        self.assertEqual([row.initial_value.to_value() for row in interface.state], [None, None])
        self.assertEqual(interface.to_payload(), payload)
        for mutation in ("scalar", "malformed-view", "nullable"):
            altered = copy.deepcopy(payload)
            field = altered["state"][0]
            if mutation == "scalar": field["type_id"] = "u32"
            elif mutation == "malformed-view": field["initial"] = {}
            else:
                next(row for row in altered["types"] if row["id"] == field["type_id"])["nullable"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ProofKernelComponentInterface.parse(altered)

    def test_normalization_requires_the_supported_borrowed_entry_binding(self):
        bundle, binding, contract, *_ = prepare_borrowed_state()
        self.assertIsNotNone(ProofKernelComponentInterface.parse(_logical_projection(bundle, contract=contract)))
        incomplete = NormalizedComponentContract.create(interface=bundle.interface, machine_semantics=[])
        with self.assertRaisesRegex(ValueError, "total operation bindings"):
            _logical_projection(bundle, contract=incomplete)
        semantics = binding.operations[0].semantics.to_payload()
        entry = semantics["machine_projection"]["operation"]["state"][0]["entry"]
        entry["base"] = {**entry["base"], "value": entry["base"]["value"] + 1}
        semantics["semantic_sha256"] = canonical_sha256_v3({key: value for key, value in semantics.items() if key != "semantic_sha256"})
        changed = type(binding.operations[0].semantics).parse(semantics)
        altered = NormalizedComponentContract.create(interface=bundle.interface, machine_semantics=[changed])
        with self.assertRaisesRegex(ValueError, "unchanged fixed image bindings"):
            _logical_projection(bundle, contract=altered)

    def test_paired_proof_reads_arbitrary_current_contents_and_retains_alias(self):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as directory:
            result, artifact = check_borrowed_state(Path(directory), cbmc=Path(cbmc))
            self.assertEqual(result["status"], "satisfied", result["issues"])
            validate_contextual_refinement_v2(artifact["proof"], proof_plan=artifact["proof_plan"],
                exact_c_slice=artifact["exact_c_slice"])
            # The whole test operation satisfies its fixture-world gate. It
            # supplies no linked provider or authority for the real helper.
            self.assertTrue(artifact["proof"]["activation_authorized"])

    def test_zero_substitution_and_missing_authority_do_not_prove(self):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as directory:
            result, _ = check_borrowed_state(Path(directory), cbmc=Path(cbmc), zero_contents=True)
            self.assertEqual(result["status"], "violated", result["issues"])
            details = [row.get("detail", "") for row in result["issues"]]
            self.assertTrue(any("memory" in text for text in details), details)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, "bound overlay authority selectors"):
            check_borrowed_state(Path(directory), cbmc=Path(cbmc), authority_missing=True)


if __name__ == "__main__":
    unittest.main()
