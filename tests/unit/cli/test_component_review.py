"""Edited canonical inputs stay non-authorizing and bound to their selected region."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.cli import main
from spaghetti_extractor.commands.component_review import reviewed_component_inputs, write_reviewed_component_inputs
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.formats import COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT
from spaghetti_extractor.components.indexes_v5 import load_component_intent_index_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1

TESTKIT = {"commands": ("boundary adopt",)}


def review_fixture(root: Path) -> dict:
    schema = BoundarySchemaV1.create(schema_id="leaf", types=[
        {"id": "unit", "kind": "void"},
        {"id": "run.fn", "kind": "function", "calling_convention": "cdecl",
         "parameter_type_ids": [], "result_type_id": "unit", "variadic": False}],
        signatures=[{"id": "run", "function_type_id": "run.fn", "parameters": [], "results": []}])
    interface = ComponentInterfaceIntentV1.create(component_id="leaf", schema=schema,
        state=[], services=[], effects=[], protocol_states=["ready"], initial_protocol_state="ready",
        operations=[{"id": "run", "signature_id": "run", "source_values": [],
                     "projection_entries": [], "lifecycle_bindings": [],
                     "lifecycle_additional_roots": {"state": []}, "checked_interaction_contract_ids": [],
                     "effect_ids": [], "allowed_service_ids": [], "pre_states": ["ready"], "post_states": ["ready"]}]).to_payload()
    projection = {"operation_id": "run", "entry_unit_ids": ["u"], "exit_unit_ids": ["u"],
                  "parameters": [], "results": [], "state": [], "preserved_state_ids": [],
                  "effects": [], "callback_operation_ids": [], "continuation_unit_ids": []}
    binding = ComponentMachineBindingIntentV1.create(component_id="leaf", operations=[{
        "id": "run", "kind": "operation", "unit_ids": ["u"], "entry_rvas": [4096],
        "transfer_ids": ["u"], "effect_ids": [], "service_ids": [], "callback_ids": [],
        "outcome_protocol_ids": [], "machine_projection": {"operation": projection},
        "object_authority_selectors": [], "pointer_views": [], "relation_receipt_sha256s": [],
        "induction_evidence_sha256": None}], blockers=[{"code": "effects_unreviewed"}]).to_payload()
    proposal = {"id": "component-proposal:a", "membership": {"unit_ids": ["u"]},
                "boundary": {"entries": [{"rva": 4096, "unit_id": "u"}],
                             "exits": [{"source_unit_id": "u"}]}}
    for name, value in (("interface.json", interface), ("binding.json", binding),
                        ("component-proposal-inspection.json", {"format": COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT,
                                                               "authority": False, "proposal": proposal})):
        (root / name).write_text(json.dumps(value))
    return proposal


class ComponentReviewTests(unittest.TestCase):
    def test_review_retains_unowned_continuation_context_as_draft(self) -> None:
        path = self.draft / "binding.json"
        raw = json.loads(path.read_text())
        operation = raw["operations"][0]
        operation["transfer_ids"] = ["u", "v"]
        operation["machine_projection"]["operation"]["continuation_unit_ids"] = ["v"]
        path.write_text(json.dumps(raw))
        result = reviewed_component_inputs(draft=self.draft, proposal=self.proposal, program_id="fixture")
        binding = ComponentMachineBindingIntentV1.parse(result["bindings-v5/leaf.json"])
        self.assertEqual(binding.operations[0].semantics.unit_ids, ("u",))
        self.assertEqual(binding.operations[0].semantics.transfer_ids, ("u", "v"))
        self.assertEqual(result["components.json"]["configurations"][0]["selections"][0]["activation"], "draft")
        operation["machine_projection"]["operation"]["continuation_unit_ids"] = ["u", "v"]
        path.write_text(json.dumps(raw))
        with self.assertRaisesRegex(ValueError, "selected boundary"):
            reviewed_component_inputs(draft=self.draft, proposal=self.proposal, program_id="fixture")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.draft = self.root / "draft"
        self.draft.mkdir()
        self.proposal = review_fixture(self.draft)

    def write_bisimulation(self) -> dict:
        intent = ComponentBisimulationIntentV1.create(component_id="leaf", operations=[{
            "operation_id": "run", "syncs": [{"id": "scan", "exact_unit_id": "u",
                "captures": [{"kind": "source_state", "id": "current", "mode": "logical_definition",
                              "projection": None, "encoding": {"op": "const", "width": 32, "value": 0},
                              "decoding": None}],
                "derived": [], "invariant": {"op": "false"}}]}]).to_payload()
        (self.draft / "bisimulation.json").write_text(json.dumps(intent))
        return intent

    def test_public_review_exports_optional_proof_intent_without_proving_it(self) -> None:
        intent = self.write_bisimulation()
        del intent["intent_sha256"]
        (self.draft / "bisimulation.json").write_text(json.dumps(intent))
        output = self.root / "inputs"
        with patch("spaghetti_extractor.commands.workflows._boundary_subject",
                   return_value={"kind": "component", "canonicalSubject": "component:leaf"}), patch(
                "spaghetti_extractor.commands.workflows._component_seed_proposal",
                return_value=(4096, self.proposal)), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["boundary", "adopt", "fixture", "component-seed:0x1000",
                                   "--input", str(self.draft), "--output", str(output)]), 0)
        lifting = json.loads((output / "components.json").read_text())
        proof_path = lifting["components"][0]["bisimulation_intent"]
        parsed = ComponentBisimulationIntentV1.parse(json.loads((output / proof_path).read_text()))
        self.assertEqual(parsed.operations[0].syncs[0].invariant, {"op": "false"})
        binding = load_component_intent_index_v5(output / "bindings-v5/index.json", kind="machine_binding")
        self.assertEqual(binding.status, "incomplete")
        self.assertEqual(binding.blockers[0]["code"], "effects_unreviewed")
        self.assertEqual(lifting["configurations"][0]["selections"][0]["activation"], "draft")
        self.assertEqual(json.loads((self.draft / "bisimulation.json").read_text()), intent)

    def test_foreign_or_malformed_proof_intent_rejects_before_export(self) -> None:
        original = self.write_bisimulation()
        for mutation in ("component", "operation", "cut", "format", "extra", "missing"):
            value = copy.deepcopy(original)
            if mutation == "component": value["component_id"] = "other"
            elif mutation == "operation": value["operations"][0]["operation_id"] = "other"
            elif mutation == "cut": value["operations"][0]["syncs"][0]["exact_unit_id"] = "outside"
            elif mutation == "format": value["format"] = "unknown"
            elif mutation == "extra": value["assume_proved"] = True
            else: del value["operations"]
            (self.draft / "bisimulation.json").write_text(json.dumps(value))
            output = self.root / mutation
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                write_reviewed_component_inputs(draft=self.draft, proposal=self.proposal,
                                               program_id="fixture", output=output)
            self.assertFalse(output.exists())

    def test_optional_proof_symlink_is_not_silently_ignored(self) -> None:
        (self.draft / "bisimulation.json").symlink_to(self.root / "absent")
        with self.assertRaisesRegex(ValueError, "absent or not regular"):
            reviewed_component_inputs(draft=self.draft, proposal=self.proposal, program_id="fixture")

    def test_public_adoption_rebuilds_digests_and_keeps_draft_activation(self) -> None:
        path = self.draft / "interface.json"
        edited = json.loads(path.read_text())
        edited.pop("intent_sha256")
        edited["schema"].pop("schema_sha256")
        edited["schema"]["schema_id"] = "reviewed_names"
        path.write_text(json.dumps(edited))
        output = self.root / "inputs"
        with patch("spaghetti_extractor.commands.workflows._boundary_subject",
                   return_value={"dynamic": True, "canonicalSubject": "component-seed:0x1000"}), patch(
                "spaghetti_extractor.commands.workflows._component_seed_proposal",
                return_value=(4096, self.proposal)), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["boundary", "adopt", "fixture", "component-seed:0x1000",
                                   "--input", str(self.draft), "--output", str(output)]), 0)
        interface = load_component_intent_index_v5(output / "interfaces-v5/index.json", kind="interface")
        binding = load_component_intent_index_v5(output / "bindings-v5/index.json", kind="machine_binding")
        self.assertEqual(interface.status, "complete")
        self.assertEqual(binding.status, "incomplete")
        self.assertEqual(binding.blockers[0]["code"], "effects_unreviewed")
        intent = json.loads((output / "components.json").read_text())
        self.assertEqual(intent["configurations"][0]["selections"][0]["activation"], "draft")
        self.assertNotIn("source", intent["components"][0])

    def test_configured_seed_revision_preserves_its_component_identity(self) -> None:
        for component_id, expected in (("leaf", 0), ("another", 2)):
            output = self.root / component_id
            with patch("spaghetti_extractor.commands.workflows._boundary_subject",
                       return_value={"kind": "component", "canonicalSubject": "component:" + component_id}), patch(
                    "spaghetti_extractor.commands.workflows._component_seed_proposal",
                    return_value=(4096, self.proposal)), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["boundary", "adopt", "fixture", "component-seed:0x1000",
                                       "--input", str(self.draft), "--output", str(output)]), expected)
            self.assertEqual(output.exists(), expected == 0)
        before = {p.relative_to(self.draft): p.read_bytes() for p in self.draft.rglob("*") if p.is_file()}
        with self.assertRaisesRegex(ValueError, "new or empty"):
            write_reviewed_component_inputs(draft=self.draft, proposal=self.proposal,
                program_id="fixture", output=self.root / "leaf", expected_component_id="leaf")
        self.assertEqual(before, {p.relative_to(self.draft): p.read_bytes() for p in self.draft.rglob("*") if p.is_file()})

    def test_stale_boundary_and_changed_unit_membership_reject(self) -> None:
        stale = copy.deepcopy(self.proposal)
        stale["id"] = "component-proposal:changed"
        with self.assertRaisesRegex(ValueError, "stale"):
            reviewed_component_inputs(draft=self.draft, proposal=stale, program_id="fixture")
        path = self.draft / "binding.json"
        value = json.loads(path.read_text())
        value["operations"][0]["unit_ids"] = ["other"]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "changes the selected boundary"):
            reviewed_component_inputs(draft=self.draft, proposal=self.proposal, program_id="fixture")

    def test_unmapped_source_value_rejects_before_export(self) -> None:
        path = self.draft / "binding.json"
        value = json.loads(path.read_text())
        value["operations"][0]["machine_projection"]["operation"]["parameters"] = [
            {"id": "unmapped", "projection": {"kind": "register", "register": "eax",
                                              "width": 32, "at": "entry"}}]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "parameters do not match"):
            reviewed_component_inputs(draft=self.draft, proposal=self.proposal, program_id="fixture")

    def test_failed_staging_leaves_output_absent(self) -> None:
        output = self.root / "inputs"
        with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                write_reviewed_component_inputs(draft=self.draft, proposal=self.proposal,
                                               program_id="fixture", output=output)
        self.assertFalse(output.exists())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["draft"])

    def test_extra_fields_are_not_silently_discarded(self) -> None:
        path = self.draft / "interface.json"
        value = json.loads(path.read_text())
        value["assume_proved"] = True
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            reviewed_component_inputs(draft=self.draft, proposal=self.proposal, program_id="fixture")
