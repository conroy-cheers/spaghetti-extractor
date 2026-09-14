"""Bound mutable local proofs remain distinct from qualified composition."""
from __future__ import annotations

import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readonly_contracts import (
    check_mutable_source_contracts, check_optional_memory_source_contracts, check_optional_readonly_source_contracts,
)
from spaghetti_extractor.components.bisimulation_readonly_evidence import (
    validate_mutable_source_contracts, validate_readonly_source_contracts, checked_connected_source_contract,
)
from tests.unit.components.test_bisimulation_readonly_contracts import check_source
from tests.unit.components.test_bisimulation_mutable_model import COPY, mutable_bundle


TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}


def check_mutable(root, body=COPY, **kwargs):
    return check_source(root, body, bundle=mutable_bundle(), checker=check_mutable_source_contracts, **kwargs)


class MutableContractTests(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument", "cbmc")):
            self.skipTest("CBMC tools are unavailable")

    def test_loop_evidence_binds_memory_model_and_retained_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            timings = []
            result = check_mutable(root, timings=timings)
            self.assertEqual(result["status"], "satisfied", [(r.get("kind"), r.get("detail"), r.get("issues")) for r in result["checks"]])
            self.assertIs(result["authorizing"], False)
            validate_mutable_source_contracts(result)
            validate_mutable_source_contracts(result, artifacts=root / "proof")
            self.assertEqual({r["phase"] for r in timings}, {"preparation", "compiler", "model", "solver"})
            with self.assertRaisesRegex(ValueError, "policy"):
                validate_readonly_source_contracts(result, artifacts=root / "proof")
            with self.assertRaises(ValueError):
                checked_connected_source_contract(bound={"certificate": result}, bundle=mutable_bundle(),
                    source=result["source_package"], source_profile_sha256=result["source_profile"]["receipt_sha256"],
                    operation_symbols=result["operation_symbols"], headers={}, readonly_artifacts=root / "proof")
            changed = copy.deepcopy(result)
            changed["checker_options"].remove("--unwinding-assertions")
            changed["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in changed.items() if k != "receipt_sha256"})
            with self.assertRaisesRegex(ValueError, "checker options"):
                validate_mutable_source_contracts(changed)
            changed = copy.deepcopy(result)
            check = next(r for r in changed["checks"] if r["kind"] == "input_dependence")
            check["property_ids"].remove("spx_mutable_input_dependence_compare.assertion.2")
            check["properties"] -= 1
            changed["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in changed.items() if k != "receipt_sha256"})
            with self.assertRaisesRegex(ValueError, "post-memory assertion"):
                validate_mutable_source_contracts(changed)
            (root / "proof" / "compare-input_dependence.c").write_text("void stale(void) {}\n")
            with self.assertRaisesRegex(ValueError, "model meaning"):
                validate_mutable_source_contracts(result, artifacts=root / "proof")

    def test_transport_and_forged_callback_context_reject_before_solver(self):
        bodies = (
            'return left->context == right->context;',
            'return left->write_u8(right->context,0,1);',
            'return left->write(left->access_context,right->base,0,1,1);',
            'return context->state.reserved;',
        )
        for body in bodies:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                timings = []
                result = check_mutable(Path(directory), body, timings=timings)
                self.assertEqual(result["status"], "incomplete")
                self.assertFalse(any(r["phase"] == "solver" for r in timings))

    def test_direct_write_callbacks_use_their_own_transport(self):
        for call in ('left->write_u8(left->context,0,42)',
                     'left->write(left->access_context,left->base,0,1,42)'):
            with self.subTest(call=call), tempfile.TemporaryDirectory() as directory:
                result = check_mutable(Path(directory), f'(void)context; return {call};')
                self.assertEqual(result["status"], "satisfied", [(r.get("kind"), r.get("detail"), r.get("issues")) for r in result["checks"]])

    def test_provider_auxiliary_path_retains_mutable_bytes_with_strict_readonly_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            check_mutable(root)
            arguments = dict(bundle=mutable_bundle(), package=root / "source", cbmc=Path(shutil.which("cbmc")),
                output=root / "retained", workspace=root / "work", timeout_seconds=30)
            self.assertIsNone(check_optional_readonly_source_contracts(**arguments))
            certificate = check_optional_memory_source_contracts(**arguments)
            self.assertIsNotNone(certificate)
            validate_mutable_source_contracts(certificate, artifacts=root / "retained")
