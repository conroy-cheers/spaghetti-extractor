from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.cli import main
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.operator.proof_diagnostics import component_failure_details

TESTKIT = {"commands": ("component check",)}


def _failure() -> dict:
    return {
        "shard_id": "compare:sync:scan", "status": "counterexample",
        "code": "cbmc_property_failed", "detail": "spx-bisimulation-capture:scan:n",
        "source": {"file": "/build/operation-0000-obligation-0001/harness.c", "line": "80"},
        "counterexample": [{"sourceLocation": {"file": "/store/source/sources/compare.c", "line": "12"}}],
    }


def _bind(root: Path, shards: list[dict], *, continuation: bool = False,
          connected: list[dict] | None = None) -> tuple[Path, dict, dict]:
    # Only the recorded sidecar identity is relevant to display. This fixture
    # deliberately is not a valid qualification or an authorizing proof.
    digest = "a" * 64
    value = {
        "qualification_input_sha256": digest, "source_package_sha256": digest,
        "proof_plan": {"bindings": {"semantic_contract_sha256": digest}, "plan_sha256": digest},
        "proof": {"component_id": "leaf", "checker": {"cbmc_sha256": digest}, "shards": shards},
        "relation_evidence": [], "exact_c_slice": {"slice_sha256": digest},
    }
    if continuation:
        value["proof"].update(status="satisfied", activation_authorized=False)
        value["proof_plan"]["operations"] = [{"operation_id": "run", "continuation": {"unit_ids": ["context"]}}]
    if connected is not None:
        value["proof"]["models"] = {"connected_components": connected}
    value["receipt_sha256"] = canonical_sha256_v3({
        "qualification_input_sha256": digest, "source_package_sha256": digest,
        "semantic_contract_sha256": digest, "cbmc_sha256": digest,
        "proof": value["proof"], "relation_evidence": [],
        "proof_plan_sha256": digest, "exact_c_slice_sha256": digest,
    })
    (root / "contextual-refinement-result.json").write_text(json.dumps(value))
    qualification = {"status": "incomplete", "blockers": [{"code": "contextual_incomplete"}],
                     "dependencies": ["contextual-refinement:" + value["receipt_sha256"]]}
    return root / "semantic-provider-qualification.json", qualification, value


class ProofDiagnosticTests(unittest.TestCase):
    def test_supplier_navigation_uses_declared_clobber_and_private_frame_premises(self) -> None:
        satisfied = {"result": {"status": "satisfied"}}
        supplier = {"component_id": "counter", "receipt_sha256": "b" * 64,
            "models": {"operation_models": [{"operation_id": "run", "machine_clobbers": ["ecx"],
                "private_stack_writes": [{"offset": -8, "bytes": 1}]}]},
            "shards": [{"operation_id": "run", "obligation_id": "scan", "mutable_entry_contract": satisfied,
                "exact_mutable_cut_clobber_frame": satisfied, "exact_mutable_exit_clobber_frame": satisfied,
                "exact_private_cut_frame": satisfied,
                "exact_private_write_frame": {"result": {"status": "violated"}}}]}
        connected = [{"component_id": "counter", "entry_contract": {
            "policy": "checked-mutable-callee-stack-entry-v1", "operations": [{"operation_id": "run"}],
            "proof_system": {"proof": supplier}}}]
        failure = {**_failure(), "detail": "spx-bisimulation-connected-callee-machine-state:counter:run"}
        with tempfile.TemporaryDirectory() as directory:
            path, qualification, _ = _bind(Path(directory), [failure], connected=connected)
            message = "\n".join(component_failure_details(qualification_path=path,
                qualification=qualification, component_id="leaf"))
            self.assertIn("private write frame violated", message)
            self.assertNotIn("machine frame not supplied", message)
            self.assertNotIn("clobber frame not supplied", message)

    def test_public_check_identifies_the_bound_suppliers_failed_machine_premise(self) -> None:
        satisfied = {"result": {"status": "satisfied"}}
        supplier = {"component_id": "counter", "status": "satisfied", "receipt_sha256": "b" * 64,
            "shards": [{"operation_id": "run", "obligation_id": "sync:scan",
                "mutable_entry_contract": satisfied, "exact_mutable_cut_machine_frame": satisfied,
                "exact_mutable_exit_machine_frame": {"result": {"status": "violated"}}},
                {"operation_id": "unrelated", "obligation_id": "foreign-obligation"}]}
        connected = [{"component_id": "counter", "entry_contract": {
            "policy": "checked-mutable-callee-stack-entry-v1", "operations": [{"operation_id": "run"}],
            "proof_system": {"proof": supplier}}}]
        failure = {**_failure(), "detail": "spx-bisimulation-connected-callee-machine-state:counter:run"}
        with tempfile.TemporaryDirectory() as directory:
            path, qualification, _ = _bind(Path(directory), [failure], connected=connected)
            output = io.StringIO()
            with patch("spaghetti_extractor.commands.workflows._operator_index", return_value={
                "components": {"units": {"leaf": {"products": ["qualification"]}}},
            }), patch("spaghetti_extractor.commands.workflows._realize_artifact", return_value=(path, {})), patch(
                "spaghetti_extractor.semantic_providers.qualification_v2.SemanticProviderQualificationV2.parse",
                return_value=SimpleNamespace(provider_id="fixture.leaf.portable-c", payload=qualification),
            ), contextlib.redirect_stderr(output):
                self.assertEqual(main(["component", "check", "fixture", "leaf"]), 2)
            message = output.getvalue()
            self.assertIn("Supplier counter / run / sync:scan: exit machine frame violated", message)
            self.assertIn("Recorded supplier proof: " + "b" * 64, message)
            self.assertIn("does not disprove the supplier's ordinary equivalence", message)
            self.assertNotIn("foreign-obligation", message)
            self.assertNotIn("wider entry not supplied", message)
            qualification["dependencies"] = []
            self.assertNotIn("Supplier counter", "\n".join(component_failure_details(
                qualification_path=path, qualification=qualification, component_id="leaf")))

    def test_supplier_premise_navigation_is_bounded_and_does_not_invent_mutable_facts(self) -> None:
        for policy, component, operations, expected in (
            ("checked-mutable-callee-stack-entry-v1", "counter", ["run"], True),
            ("checked-readable-callee-stack-entry-v1", "counter", ["run"], False),
            ("checked-mutable-callee-stack-entry-v1", "foreign", ["run"], False),
            ("checked-mutable-callee-stack-entry-v1", "counter", ["other"], False),
        ):
            with self.subTest(policy=policy, component=component, operations=operations), tempfile.TemporaryDirectory() as directory:
                supplier = {"component_id": component, "shards": [{"operation_id": "run", "obligation_id": "scan"}]}
                connected = [{"component_id": "counter", "entry_contract": {"policy": policy,
                    "operations": [{"operation_id": name} for name in operations], "proof_system": {"proof": supplier}}}]
                failure = {**_failure(), "detail": "spx-bisimulation-connected-callee-machine-state:counter:run"}
                path, qualification, _ = _bind(Path(directory), [failure], connected=connected)
                message = "\n".join(component_failure_details(qualification_path=path,
                    qualification=qualification, component_id="leaf", maximum=1))
                self.assertEqual("Supplier counter" in message, expected)
                if expected:
                    self.assertIn("wider entry not supplied", message)
                    self.assertIn("2 further supplier premise(s)", message)

    def test_conditional_success_reports_missing_selection_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, qualification, _ = _bind(Path(directory), [], continuation=True)
            text = "\n".join(component_failure_details(qualification_path=path, qualification=qualification, component_id="leaf"))
            self.assertIn("continuation selection is required", text)
            self.assertIn("local proof obligations pass", text)
            self.assertIn("Dispatch/link proof", text)

    def test_public_check_explains_captured_view_memory_and_admission_failures(self) -> None:
        for description, hint in (
            ("spx-bisimulation-private-stack-scope:scan", "changing ESP must not reclassify live memory"),
            ("spx-bisimulation-private-stack-scope-input:scan", "predecessor register relation"),
            ("spx-bisimulation-public-write-capacity", "proof model exhausted its event history"),
            ("spx-bisimulation-private-write-capacity", "proof model exhausted its event history"),
            ("spx-bisimulation-call-public-memory", "Public memory differs at this call"),
            ("spx-bisimulation-connected-callee-machine-state:counter:run", "callee lacks a checked machine-state guarantee"),
            ("spx-bisimulation-connected-callee-private-poststate:counter:run", "residual stack writes faults"),
            ("spx-bisimulation-private-write-frame:m8n1", "original store escapes"),
            ("spx-bisimulation-derived:cut:frame-base", "predecessor does not establish"),
            ("spx-bisimulation-private-cut-frame:m8n1", "stack anchor changes"),
            ("spx-bisimulation-typed-service-reference:find_character:0", "issued origin, generation, permissions"),
            ("spx-bisimulation-typed-service-termination:find_character:0", "preceding writes through aliases"),
            ("spx-bisimulation-typed-call-public-memory:0", "narrower read footprints may be needed"),
            ("spx-bisimulation-capture-memory:scan:text", "preceding writes and aliases"),
            ("spx-bisimulation-capture-reference-memory:scan:text", "preceding writes and aliases"),
            ("spx-bisimulation-capture-methods:scan:text", "access methods intact"),
            ("spx-bisimulation-capture-metadata:scan:text", "offset, permissions and element width"),
            ("spx-bisimulation-capture-context:scan:text", "runtime dispatch"),
            ("spx-bisimulation-capture-extent:scan:text", "aliases and terminating byte"),
            ("spx-bisimulation-source-frame-preservation:normalize:entry", "reconstructed frame changes borrowed memory"),
            ("spx-bisimulation-exit-continuation-state:normalize:entry", "continuation receives different machine state"),
            ("spx-bisimulation-continuation-bound:normalize:entry", "within its checked bound"),
            ("spx-bisimulation-continuation-memory:normalize:entry", "continuation exposes a memory difference"),
            ("spx-bisimulation-resumed-view-admission:scan:count", "extent and ownership"),
        ):
            with self.subTest(description=description), tempfile.TemporaryDirectory() as directory:
                failure = {**_failure(), "detail": description}
                path, qualification, _ = _bind(Path(directory), [failure])
                output = io.StringIO()
                with patch("spaghetti_extractor.commands.workflows._operator_index", return_value={
                    "components": {"units": {"leaf": {"products": ["qualification"]}}},
                }), patch("spaghetti_extractor.commands.workflows._realize_artifact", return_value=(path, {})), patch(
                    "spaghetti_extractor.semantic_providers.qualification_v2.SemanticProviderQualificationV2.parse",
                    return_value=SimpleNamespace(provider_id="fixture.leaf.portable-c", payload=qualification),
                ), contextlib.redirect_stderr(output):
                    self.assertEqual(main(["component", "check", "fixture", "leaf"]), 2)
                self.assertIn(description, output.getvalue())
                self.assertIn(hint, output.getvalue())
                if description.endswith("write-capacity"):
                    self.assertIn("proof_model_capacity_exhausted", output.getvalue())
                if "callee-machine-state:" in description:
                    self.assertIn("proof_callee_machine_state_unproved", output.getvalue())
                self.assertIn("/store/source/sources/compare.c:12", output.getvalue())

    def test_public_check_explains_missing_qualification_with_bound_draft_blockers(self) -> None:
        binding = ComponentMachineBindingIntentV1.create(component_id="leaf", operations=[],
            blockers=[{"code": "caller_contract_missing", "detail": "Review the caller's input range."}]).to_payload()
        for case in ("valid", "foreign", "tampered", "no_binding"):
            with self.subTest(case=case):
                value = json.loads(json.dumps(binding))
                if case == "foreign":
                    value = ComponentMachineBindingIntentV1.create(component_id="other", operations=[],
                        blockers=[{"code": "foreign_detail"}]).to_payload()
                elif case == "tampered":
                    value["blockers"][0]["code"] = "tampered_detail"
                products = [] if case == "no_binding" else ["bindingIntent"]
                error = io.StringIO()
                with patch("spaghetti_extractor.commands.workflows._operator_index", return_value={
                        "components": {"units": {"leaf": {"products": products}}}}), patch(
                        "spaghetti_extractor.commands.workflows._realize_artifact",
                        return_value=(Path("/store/intent/leaf.json"), value)) as realize, contextlib.redirect_stderr(error):
                    self.assertEqual(main(["component", "check", "fixture", "leaf",
                        "--target-flake", "path:/tmp/external trial", "--local"]), 2)
                message = error.getvalue()
                if case == "valid":
                    self.assertIn("caller_contract_missing", message)
                    self.assertIn("Review the caller's input range.", message)
                    self.assertIn("/store/intent/leaf.json", message)
                    self.assertIn("component status fixture leaf --development", message)
                    self.assertIn("--target-flake 'path:/tmp/external trial' --local", message)
                    self.assertEqual(realize.call_args.args[1], 'components.units."leaf".bindingIntent')
                elif case == "no_binding":
                    realize.assert_not_called()
                    self.assertIn("no provider qualification product", message)
                else:
                    self.assertNotIn("Declared blocker:", message)

    def test_public_check_keeps_failure_and_explains_bound_source_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, qualification, _ = _bind(Path(directory), [_failure()])
            output = io.StringIO()
            with patch("spaghetti_extractor.commands.workflows._operator_index", return_value={
                "components": {"units": {"leaf": {"products": ["qualification"]}}},
            }), patch("spaghetti_extractor.commands.workflows._realize_artifact", return_value=(path, {})), patch(
                "spaghetti_extractor.semantic_providers.qualification_v2.SemanticProviderQualificationV2.parse",
                return_value=SimpleNamespace(provider_id="fixture.leaf.portable-c", payload=qualification),
            ), contextlib.redirect_stderr(output):
                self.assertEqual(main(["component", "check", "fixture", "leaf"]), 2)
            message = output.getvalue()
            self.assertIn("incomplete with 1 blocker(s)", message)
            self.assertIn("compare:sync:scan", message)
            self.assertIn("spx-bisimulation-capture:scan:n", message)
            self.assertIn("/store/source/sources/compare.c:12", message)
            self.assertIn("source value and machine projection", message)
            self.assertNotIn("harness.c:80", message)

    def test_timeout_uses_property_inventory_and_bounds_obligation_count(self) -> None:
        failure = {**_failure(), "code": "cbmc_assertion_timeout", "detail": "300 seconds",
                   "partitioned_evidence": {"assertions": [{"property_id": "check.6", "description": "spx:exit-value:result"}],
                                            "queries": [{"property_id": "check.6", "status": "timeout"}]}}
        with tempfile.TemporaryDirectory() as directory:
            path, qualification, _ = _bind(Path(directory), [failure] * 5)
            lines = component_failure_details(qualification=qualification, qualification_path=path, component_id="leaf")
        message = "\n".join(lines)
        self.assertEqual(message.count("spx:exit-value:result"), 3)
        self.assertIn("query timings", message)
        self.assertIn("2 further failed obligation(s)", message)
        self.assertNotIn("300 seconds", message)

    def test_unbound_or_changed_diagnostics_do_not_display_foreign_details(self) -> None:
        for case in ("component", "dependency", "tampered"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                path, qualification, value = _bind(Path(directory), [_failure()])
                if case == "dependency":
                    qualification["dependencies"] = []
                if case == "tampered":
                    value["proof"]["shards"][0]["detail"] = "unbound content"
                    (path.parent / "contextual-refinement-result.json").write_text(json.dumps(value))
                result = component_failure_details(qualification=qualification, qualification_path=path,
                                                   component_id="other" if case == "component" else "leaf")
                self.assertEqual(result, ["Proof diagnostics do not match this qualification; regenerate the component check."])

    def test_missing_or_malformed_sidecar_never_replaces_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "semantic-provider-qualification.json"
            kwargs = {"qualification": {"status": "incomplete"}, "qualification_path": path, "component_id": "leaf"}
            self.assertEqual(component_failure_details(**kwargs), [])
            for malformed in ("{", "null", "[]", '{"proof": null}'):
                (path.parent / "contextual-refinement-result.json").write_text(malformed)
                result = component_failure_details(**kwargs)
                self.assertEqual(len(result), 1)
                self.assertIn("could not be read", result[0])

    def test_control_characters_and_bad_optional_inventory_stay_bounded(self) -> None:
        failure = {**_failure(), "detail": "\x1b\n\x85" + "x" * 1000,
                   "partitioned_evidence": {"assertions": [{"property_id": []}], "queries": [{"property_id": []}]}}
        with tempfile.TemporaryDirectory() as directory:
            path, qualification, _ = _bind(Path(directory), [failure])
            result = component_failure_details(qualification=qualification, qualification_path=path, component_id="leaf")
        self.assertLess(len(result[0]), 400)
        for character in ("\x1b", "\n", "\x85"):
            self.assertNotIn(character, result[0])

    def test_location_resolves_only_inside_retained_proof_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "proof-diagnostics/operation-0000-obligation-0001/harness.c"
            harness.parent.mkdir(parents=True)
            harness.write_text("retained proof input")
            failure = {**_failure(), "counterexample": []}
            path, qualification, _ = _bind(root, [failure])
            result = component_failure_details(qualification=qualification, qualification_path=path, component_id="leaf")
            self.assertIn("  Artifact source/proof location: " + str(harness) + ":80", result)


if __name__ == "__main__":
    unittest.main()
