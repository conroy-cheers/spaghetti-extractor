"""Retained-byte and rehashed-certificate adversaries for local contracts."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readonly_evidence import (
    validate_readonly_source_contracts, checked_readonly_summary_certificate, checked_connected_source_contract,
)
from spaghetti_extractor.components.bisimulation_readonly_contracts import check_optional_readonly_source_contracts
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from tests.unit.components.test_bisimulation_readonly_model import fixed_readonly_bundle
from tests.unit.components.test_bisimulation_readonly_contracts import check_source

TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}


class ReadonlyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument", "cbmc")):
            raise unittest.SkipTest("CBMC tools are unavailable")
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.certificate = check_source(cls.root)

    def validate(self, value, *, root=None):
        value["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"})
        validate_readonly_source_contracts(value, artifacts=root or self.root / "proof")

    def test_relocated_retained_evidence_rechecks_without_running_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "retained"
            shutil.copytree(self.root / "proof", destination)
            self.validate(copy.deepcopy(self.certificate), root=destination)

    def test_rehashing_cannot_omit_or_weaken_proof_premises(self):
        for mutation in ("options", "instrumentation", "model", "opacity", "inventory", "tool",
                         "dependencies", "support", "source", "authority", "duplicate"):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(self.certificate)
                if mutation == "options":
                    value["checker_options"].remove("--unwinding-assertions")
                elif mutation == "instrumentation":
                    value["commands"] = [r for r in value["commands"] if not r["step"].endswith("-instrument")]
                elif mutation == "model":
                    value["models"].pop()
                elif mutation == "opacity":
                    value["checks"][0]["inventory_sha256"] = "a" * 64
                elif mutation == "inventory":
                    value["inventories"].pop()
                elif mutation == "tool":
                    value["tools"]["cbmc"] = "a" * 64
                elif mutation == "dependencies":
                    value["source_dependencies"][0]["inputs"].pop()
                elif mutation == "support":
                    value["support_headers"]["stdint.h"] = "a" * 64
                elif mutation == "source":
                    value["source_package"]["implementation_sha256"] = "a" * 64
                elif mutation == "authority":
                    value["authorizing"] = True
                else:
                    value["commands"].append(value["commands"][0])
                with self.assertRaises(ValueError):
                    self.validate(value)

    def test_certificate_claims_validate_without_access_to_models_or_tools(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("receipt reader accessed an artifact")):
            validate_readonly_source_contracts(self.certificate)

    def test_certificate_only_reader_rejects_rehashed_weakened_claims(self):
        for mutation in ("frame", "source_model", "source_profile", "commands", "results", "raw_goto", "inventory"):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(self.certificate)
                if mutation == "frame":
                    next(r for r in value["commands"] if r["step"].endswith("-instrument"))["command"].remove("--enforce-contract")
                elif mutation == "source_model":
                    value["models"][1]["source_sha256"] = "a" * 64
                elif mutation == "source_profile":
                    value["source_profile"]["policy"]["operator_behavior_examples_used"] = True
                elif mutation == "commands":
                    value["commands"].pop()
                elif mutation == "results":
                    value["checks"][-1]["status"] = "violated"
                elif mutation == "raw_goto":
                    value["models"][-1]["checked_goto_sha256"] = "a" * 64
                else:
                    value["inventories"][0]["sha256"] = "a" * 64
                value["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"})
                with self.assertRaises(ValueError):
                    validate_readonly_source_contracts(value)

    def test_supplier_binding_requires_current_interface_source_and_retained_bytes(self):
        certificate = self.certificate
        bundle = fixed_readonly_bundle()
        arguments = dict(bound={"certificate": certificate,
                "implementation_sha256": certificate["source_package"]["implementation_sha256"],
                "source_profile_sha256": certificate["source_profile"]["receipt_sha256"]},
            bundle=bundle, source=certificate["source_package"],
            source_profile_sha256=certificate["source_profile"]["receipt_sha256"],
            operation_symbols=certificate["operation_symbols"],
            headers=render_component_c_headers_v5(bundle, certificate["operation_symbols"]),
            artifacts=self.root / "proof")
        self.assertIs(checked_readonly_summary_certificate(**arguments), certificate)
        connected = {k: v for k, v in arguments.items() if k != "artifacts"}
        self.assertIsNone(checked_connected_source_contract(**connected, readonly_artifacts=arguments["artifacts"]))
        with self.assertRaisesRegex(ValueError, "retained models"):
            checked_connected_source_contract(**connected)
        for changes in ({"source_profile_sha256": "a" * 64}, {"bundle": fixed_readonly_bundle((3, 4))},
                        {"artifacts": self.root / "absent"}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError):
                checked_readonly_summary_certificate(**{**arguments, **changes})

    def test_auxiliary_staging_preserves_bytes_and_failed_proofs_remain_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = dict(bundle=fixed_readonly_bundle(), package=self.root / "source",
                output=root / "retained", workspace=root / "work", cbmc=Path(shutil.which("cbmc")),
                timeout_seconds=30)
            certificate = check_optional_readonly_source_contracts(**arguments)
            self.assertIsNotNone(certificate)
            validate_readonly_source_contracts(certificate, artifacts=root / "retained")
            with self.assertRaisesRegex(ValueError, "disjoint"):
                check_optional_readonly_source_contracts(**{**arguments, "workspace": root / "retained" / "work"})
            failed = root / "failed"
            check_source(failed, body="return context->state.reserved;")
            self.assertIsNone(check_optional_readonly_source_contracts(**{
                **arguments, "package": failed / "source", "output": root / "failed-retained",
                "workspace": root / "failed-work"}))
            self.assertTrue((root / "failed-retained" / "local-contract-result.json").is_file())

    def test_changed_retained_bytes_reject(self):
        for name in ("authored.goto", "compare-frame-checked.goto", "include/stdint.h",
                     "inputs/authored.c", "compare-input_dependence-check.stdout"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / "retained"
                shutil.copytree(self.root / "proof", destination)
                path = destination / name
                path.write_bytes(path.read_bytes() + b"changed")
                with self.assertRaises(ValueError):
                    self.validate(copy.deepcopy(self.certificate), root=destination)

    def test_model_is_reconstructed_from_the_bound_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "retained"
            shutil.copytree(self.root / "proof", destination)
            value = copy.deepcopy(self.certificate)
            model = destination / "compare-input_dependence.c"
            model.write_text(model.read_text().replace("spx_result_left == spx_result_right", "1"))
            value["models"][1]["source_sha256"] = hashlib.sha256(model.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "generated model meaning changed"):
                self.validate(value, root=destination)

    def test_rehashed_failing_solver_output_does_not_establish_the_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "retained"
            shutil.copytree(self.root / "proof", destination)
            value = copy.deepcopy(self.certificate)
            step = "compare-input_dependence-check"
            path = destination / (step + ".stdout")
            payload = json.loads(path.read_text())
            statuses = next(row["result"] for row in payload if "result" in row)
            statuses[0]["status"] = "FAILURE"
            path.write_text(json.dumps(payload))
            digest = hashlib.sha256(path.read_bytes() + b"\0" + (destination / (step + ".stderr")).read_bytes()).hexdigest()
            next(row for row in value["commands"] if row["step"] == step)["output_sha256"] = digest
            value["checks"][-1]["output_sha256"] = digest
            with self.assertRaisesRegex(ValueError, "solver output does not establish"):
                self.validate(value, root=destination)
