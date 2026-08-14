"""Active component inputs and native v3 configuration authority tests."""

from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    COMPONENT_PROPOSAL_SET_FORMAT,
    RECONSTRUCTION_PLAN_FORMAT,
)
from spaghetti_extractor.components.formats import (
    COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
    COMPONENT_CATALOG_INTENT_V2_FORMAT,
    COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_QUALIFICATION_V3_FORMAT,
    COMPONENT_RESOLUTION_V2_FORMAT,
)
from spaghetti_extractor.components.contracts import build_lift_unit_contract
from spaghetti_extractor.components.configuration import compose_component_configuration
from spaghetti_extractor.components.intent import (
    ComponentIntentError,
    load_component_catalog_intent,
)
from spaghetti_extractor.components.resolution import resolve_component_catalog
from spaghetti_extractor.components.source import (
    build_component_source_package,
    load_component_source_package,
)
from spaghetti_extractor.reconstruction_ir import MACHINE_IR_FORMAT


class ComponentInputsAndConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "a.c").write_text("int a(void) { return 1; }\n", encoding="ascii")
        (self.root / "b.c").write_text("int b(void) { return 2; }\n", encoding="ascii")
        self.intent = self.root / "components.json"
        self.proposals = self.root / "proposals.json"
        self.machine = self.root / "machine"
        self.machine.mkdir()
        self.plan = self.root / "reconstruction-plan.json"
        self._write_intent()
        self._write_machine_inputs()
        self._write_proposals()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_alternative_groups_resolve_but_overlapping_configuration_fails(self) -> None:
        payload = json.loads(self.intent.read_text(encoding="utf-8"))
        payload["groups"].append(
            {
                "id": "second-view",
                "label": "Second view",
                "members": ["a"],
                "evidence_profile": "structural-draft-v1",
            }
        )
        self.intent.write_text(json.dumps(payload), encoding="utf-8")

        parsed = load_component_catalog_intent(self.intent)
        self.assertEqual([item.identity for item in parsed.groups], ["all", "second-view"])

        payload["configurations"].append(
            {
                "id": "invalid-overlap",
                "label": "Invalid overlap",
                "selections": [
                    {"kind": "group", "id": "all", "activation": "draft"},
                    {"kind": "group", "id": "second-view", "activation": "draft"},
                ],
            }
        )
        self.intent.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ComponentIntentError, "overlaps"):
            resolve_component_catalog(
                proposals=self.proposals,
                intent=self.intent,
                out=self.root / "out.json",
            )

    def test_split_and_grouped_configurations_have_exact_ownership(self) -> None:
        result = resolve_component_catalog(
            proposals=self.proposals,
            intent=self.intent,
            out=self.root / "out.json",
        )

        self.assertEqual(result["format"], COMPONENT_RESOLUTION_V2_FORMAT)
        configurations = {row["id"]: row for row in result["configurations"]}
        self.assertEqual(
            configurations["split"]["unit_owners"],
            {"unit:a": "a", "unit:b": "b"},
        )
        self.assertEqual(
            configurations["grouped"]["unit_owners"],
            {"unit:a": "all", "unit:b": "all"},
        )

    def test_generated_fields_are_rejected_from_authored_intent(self) -> None:
        payload = json.loads(self.intent.read_text(encoding="utf-8"))
        payload["components"][0]["status"] = "qualified"
        self.intent.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(ComponentIntentError, "generated fields"):
            load_component_catalog_intent(self.intent)

    def test_enabled_draft_profile_is_rejected(self) -> None:
        payload = json.loads(self.intent.read_text(encoding="utf-8"))
        payload["configurations"][0]["selections"][0]["activation"] = "enabled"
        payload["components"][0]["evidence_profile"] = "structural-draft-v1"
        self.intent.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(ComponentIntentError, "disallowed profile"):
            load_component_catalog_intent(self.intent)

    def test_group_cycles_are_rejected(self) -> None:
        payload = json.loads(self.intent.read_text(encoding="utf-8"))
        payload["groups"] = [
            {
                "id": "left",
                "label": "Left",
                "members": ["right"],
                "evidence_profile": "structural-draft-v1",
            },
            {
                "id": "right",
                "label": "Right",
                "members": ["left"],
                "evidence_profile": "structural-draft-v1",
            },
        ]
        payload["configurations"] = [
            {
                "id": "cycle",
                "label": "Cycle",
                "selections": [
                    {"kind": "group", "id": "left", "activation": "draft"}
                ],
            }
        ]
        self.intent.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(ComponentIntentError, "group cycle"):
            load_component_catalog_intent(self.intent)

    def test_group_contract_hides_internal_edges_and_requires_review(self) -> None:
        resolution = resolve_component_catalog(
            proposals=self.proposals,
            intent=self.intent,
            out=self.root / "resolution.json",
        )
        draft = build_lift_unit_contract(
            machine_ir=self.machine,
            reconstruction_plan=self.plan,
            resolution=resolution,
            lift_unit_id="all",
            out_dir=self.root / "draft-contract",
        )
        self.assertEqual(draft["status"], "incomplete")
        self.assertEqual(
            draft["blockers"][0]["code"], "operator_boundary_review_missing"
        )
        catalog = json.loads(
            (self.root / "draft-contract" / "semantic-component-catalog.json").read_text()
        )
        boundary = catalog["components"][0]["machine_boundary"]
        self.assertEqual([row["unit_id"] for row in boundary["entries"]], ["unit:a"])
        self.assertEqual([row["kind"] for row in boundary["exits"]], ["return"])

        review = {
            "format": COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
            "lift_unit_id": "all",
            "accept_derived_machine_boundary": True,
            "overrides": {},
        }
        checked = build_lift_unit_contract(
            machine_ir=self.machine,
            reconstruction_plan=self.plan,
            resolution=resolution,
            lift_unit_id="all",
            review=review,
            out_dir=self.root / "checked-contract",
        )
        self.assertEqual(checked["format"], COMPONENT_CONTRACT_PACKAGE_V2_FORMAT)
        self.assertEqual(checked["status"], "checked")
        self.assertEqual(checked["blockers"], [])
        self.assertTrue(checked["authority"]["logical_interface"].startswith("operator"))

    def test_review_cannot_hide_a_machine_effect(self) -> None:
        resolution = resolve_component_catalog(
            proposals=self.proposals,
            intent=self.intent,
            out=self.root / "resolution.json",
        )
        review = {
            "format": COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
            "lift_unit_id": "all",
            "accept_derived_machine_boundary": True,
            "overrides": {"results": []},
        }
        result = build_lift_unit_contract(
            machine_ir=self.machine,
            reconstruction_plan=self.plan,
            resolution=resolution,
            lift_unit_id="all",
            review=review,
            out_dir=self.root / "bad-contract",
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "unrepresented_machine_effect",
            {row["code"] for row in result["blockers"]},
        )

    def test_enabled_group_activates_only_after_exact_qualification(self) -> None:
        payload = json.loads(self.intent.read_text(encoding="utf-8"))
        payload["configurations"][1]["selections"][0]["activation"] = "enabled"
        self.intent.write_text(json.dumps(payload), encoding="utf-8")
        resolution = resolve_component_catalog(
            proposals=self.proposals,
            intent=self.intent,
            out=self.root / "resolution.json",
        )
        contract = build_lift_unit_contract(
            machine_ir=self.machine,
            reconstruction_plan=self.plan,
            resolution=resolution,
            lift_unit_id="all",
            review={
                "format": COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
                "lift_unit_id": "all",
                "accept_derived_machine_boundary": True,
                "overrides": {},
            },
            out_dir=self.root / "contract",
        )
        implementation = build_component_source_package(
            lift_unit_id="all",
            files={"a.c": self.root / "a.c", "b.c": self.root / "b.c"},
            shared_inputs={},
            entry={"abi": "logical-c-v1", "symbol": "a"},
            out_dir=self.root / "source-package",
        )
        qualification = self._qualification(contract, implementation)
        plan = compose_component_configuration(
            machine_ir=self.machine,
            resolution=resolution,
            configuration_id="grouped",
            contracts={"all": contract},
            implementations={"all": self.root / "source-package"},
            qualifications={"all": qualification},
            out=self.root / "activation-plan.json",
        )
        self.assertEqual(plan["format"], COMPONENT_ACTIVATION_PLAN_V3_FORMAT)
        self.assertEqual(plan["status"], "checked")
        self.assertEqual(plan["counts"]["portable_replacement"], 2)
        self.assertEqual(plan["counts"]["machine_ir_fallback"], 0)
        self.assertEqual(plan["counts"]["blocked"], 0)
        self.assertEqual(
            {row["implementation_kind"] for row in plan["entries"]},
            {"portable_replacement"},
        )

    def test_source_change_blocks_enabled_component_without_fallback(self) -> None:
        payload = json.loads(self.intent.read_text(encoding="utf-8"))
        payload["configurations"][1]["selections"][0]["activation"] = "enabled"
        self.intent.write_text(json.dumps(payload), encoding="utf-8")
        resolution = resolve_component_catalog(
            proposals=self.proposals,
            intent=self.intent,
            out=self.root / "resolution.json",
        )
        contract = build_lift_unit_contract(
            machine_ir=self.machine,
            reconstruction_plan=self.plan,
            resolution=resolution,
            lift_unit_id="all",
            review={
                "format": COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
                "lift_unit_id": "all",
                "accept_derived_machine_boundary": True,
                "overrides": {},
            },
            out_dir=self.root / "contract",
        )
        original = build_component_source_package(
            lift_unit_id="all",
            files={"a.c": self.root / "a.c", "b.c": self.root / "b.c"},
            shared_inputs={},
            entry={"abi": "logical-c-v1", "symbol": "a"},
            out_dir=self.root / "source-original",
        )
        qualification = self._qualification(contract, original)
        (self.root / "a.c").write_text(
            "int a(void) { return 7; }\n", encoding="ascii"
        )
        build_component_source_package(
            lift_unit_id="all",
            files={"a.c": self.root / "a.c", "b.c": self.root / "b.c"},
            shared_inputs={},
            entry={"abi": "logical-c-v1", "symbol": "a"},
            out_dir=self.root / "source-changed",
        )
        plan = compose_component_configuration(
            machine_ir=self.machine,
            resolution=resolution,
            configuration_id="grouped",
            contracts={"all": contract},
            implementations={"all": self.root / "source-changed"},
            qualifications={"all": qualification},
            out=self.root / "activation-stale.json",
        )
        self.assertEqual(plan["status"], "violated")
        self.assertEqual(plan["counts"]["portable_replacement"], 0)
        self.assertEqual(plan["counts"]["machine_ir_fallback"], 0)
        self.assertEqual(plan["counts"]["blocked"], 2)
        self.assertFalse(plan["hybrid"]["structurally_executable"])
        self.assertIn(
            "enabled_component_source_binding_stale",
            {row["code"] for row in plan["issues"]},
        )

    def test_source_package_loader_rejects_tampered_or_unlisted_files(self) -> None:
        package = self.root / "source-validation"
        build_component_source_package(
            lift_unit_id="a",
            files={"a.c": self.root / "a.c"},
            shared_inputs={},
            entry={"abi": "logical-c-v1", "symbol": "a"},
            out_dir=package,
        )
        (package / "sources" / "a.c").write_text(
            "int a(void) { return 9; }\n", encoding="ascii"
        )
        with self.assertRaisesRegex(ComponentIntentError, "hash is stale"):
            load_component_source_package(package)

        build_component_source_package(
            lift_unit_id="a",
            files={"a.c": self.root / "a.c"},
            shared_inputs={},
            entry={"abi": "logical-c-v1", "symbol": "a"},
            out_dir=package,
        )
        (package / "sources" / "extra.h").write_text("#define EXTRA 1\n")
        with self.assertRaisesRegex(ComponentIntentError, "unlisted files"):
            load_component_source_package(package)

    def test_missing_enabled_qualification_is_blocked(self) -> None:
        payload = json.loads(self.intent.read_text(encoding="utf-8"))
        payload["configurations"][1]["selections"][0]["activation"] = "enabled"
        self.intent.write_text(json.dumps(payload), encoding="utf-8")
        resolution = resolve_component_catalog(
            proposals=self.proposals,
            intent=self.intent,
            out=self.root / "resolution.json",
        )
        contract = build_lift_unit_contract(
            machine_ir=self.machine,
            reconstruction_plan=self.plan,
            resolution=resolution,
            lift_unit_id="all",
            review={
                "format": COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
                "lift_unit_id": "all",
                "accept_derived_machine_boundary": True,
                "overrides": {},
            },
            out_dir=self.root / "contract",
        )
        plan = compose_component_configuration(
            machine_ir=self.machine,
            resolution=resolution,
            configuration_id="grouped",
            contracts={"all": contract},
            implementations={},
            qualifications={},
            out=self.root / "activation-plan.json",
        )
        self.assertEqual(plan["status"], "incomplete")
        self.assertTrue(plan["ownership"]["complete"])
        self.assertTrue(plan["ownership"]["exclusive"])
        self.assertFalse(plan["hybrid"]["structurally_executable"])
        self.assertFalse(plan["hybrid"]["release_ready"])
        self.assertEqual(plan["counts"]["portable_replacement"], 0)
        self.assertEqual(plan["counts"]["machine_ir_fallback"], 0)
        self.assertEqual(plan["counts"]["blocked"], 2)

    def test_draft_and_unselected_units_use_machine_ir_fallback(self) -> None:
        resolution = resolve_component_catalog(
            proposals=self.proposals,
            intent=self.intent,
            out=self.root / "resolution.json",
        )
        contracts = {
            identity: build_lift_unit_contract(
                machine_ir=self.machine,
                reconstruction_plan=self.plan,
                resolution=resolution,
                lift_unit_id=identity,
                out_dir=self.root / f"contract-{identity}",
            )
            for identity in ("a", "b")
        }
        plan = compose_component_configuration(
            machine_ir=self.machine,
            resolution=resolution,
            configuration_id="split",
            contracts=contracts,
            implementations={},
            qualifications={},
            out=self.root / "draft-activation-plan.json",
        )
        self.assertEqual(plan["status"], "checked")
        self.assertEqual(plan["counts"]["machine_ir_fallback"], 2)
        self.assertEqual(plan["counts"]["blocked"], 0)

    def test_v2_qualification_cannot_authorize_v3_configuration(self) -> None:
        payload = json.loads(self.intent.read_text(encoding="utf-8"))
        payload["configurations"][1]["selections"][0]["activation"] = "enabled"
        self.intent.write_text(json.dumps(payload), encoding="utf-8")
        resolution = resolve_component_catalog(
            proposals=self.proposals,
            intent=self.intent,
            out=self.root / "resolution.json",
        )
        contract = build_lift_unit_contract(
            machine_ir=self.machine,
            reconstruction_plan=self.plan,
            resolution=resolution,
            lift_unit_id="all",
            review={
                "format": COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
                "lift_unit_id": "all",
                "accept_derived_machine_boundary": True,
                "overrides": {},
            },
            out_dir=self.root / "contract",
        )
        implementation = build_component_source_package(
            lift_unit_id="all",
            files={"a.c": self.root / "a.c", "b.c": self.root / "b.c"},
            shared_inputs={},
            entry={"abi": "logical-c-v1", "symbol": "a"},
            out_dir=self.root / "source-package",
        )
        qualification = self._qualification(contract, implementation)
        qualification["format"] = "spaghetti-extractor-component-qualification-v2"
        qualification.pop("qualification_sha256")
        qualification["qualification_sha256"] = _canonical_sha256(qualification)
        with self.assertRaisesRegex(
            ComponentIntentError, "unsupported component qualification format"
        ):
            compose_component_configuration(
                machine_ir=self.machine,
                resolution=resolution,
                configuration_id="grouped",
                contracts={"all": contract},
                implementations={"all": self.root / "source-package"},
                qualifications={"all": qualification},
                out=self.root / "v2-activation-plan.json",
            )

    def _qualification(
        self,
        contract: dict[str, object],
        implementation: dict[str, object],
    ) -> dict[str, object]:
        core: dict[str, object] = {
            "format": COMPONENT_QUALIFICATION_V3_FORMAT,
            "status": "qualified",
            "lift_unit_id": "all",
            "evidence_profile": "bounded-equivalence-v1",
            "bindings": {
                "contract_sha256": contract["contract_sha256"],
                "evidence_sha256": "4" * 64,
                "implementation_sha256": implementation["implementation_sha256"],
                "machine_ir_sha256": "5" * 64,
                "domain_sha256": "6" * 64,
                "source_entry": implementation["entry"],
                "tool_id": "fixture",
                "tool_version": 1,
            },
            "assurance": {},
            "activation": {
                "authorized": True,
                "requires_exact_configuration_ownership": True,
                "fallback_on_unimplemented": False,
            },
            "issues": [],
        }
        return {**core, "qualification_sha256": _canonical_sha256(core)}

    def _write_intent(self) -> None:
        self.intent.write_text(
            json.dumps(
                {
                    "format": COMPONENT_CATALOG_INTENT_V2_FORMAT,
                    "program_id": "fixture",
                    "permitted_activation_profiles": ["bounded-equivalence-v1"],
                    "components": [
                        {
                            "id": "a",
                            "label": "A",
                            "selector": {"entry_rva": 0x1000},
                            "evidence_profile": "bounded-equivalence-v1",
                            "source": {
                                "files": ["a.c"],
                                "entry": {"abi": "logical-c-v1", "symbol": "a"},
                            },
                        },
                        {
                            "id": "b",
                            "label": "B",
                            "selector": {"entry_rva": 0x1010},
                            "evidence_profile": "bounded-equivalence-v1",
                            "source": {
                                "files": ["b.c"],
                                "entry": {"abi": "logical-c-v1", "symbol": "b"},
                            },
                        },
                    ],
                    "groups": [
                        {
                            "id": "all",
                            "label": "All",
                            "members": ["a", "b"],
                            "evidence_profile": "bounded-equivalence-v1",
                            "source": {
                                "files": ["a.c", "b.c"],
                                "entry": {"abi": "logical-c-v1", "symbol": "a"},
                            },
                            "verification": {
                                "producer": "exhaustive-finite-domain-v1",
                                "parameter_domains": [
                                    {
                                        "parameter_id": "input_eax",
                                        "kind": "integer-range",
                                        "minimum": 0,
                                        "maximum": 1,
                                    }
                                ],
                            },
                        }
                    ],
                    "configurations": [
                        {
                            "id": "split",
                            "label": "Split",
                            "selections": [
                                {"kind": "component", "id": "a", "activation": "draft"},
                                {"kind": "component", "id": "b", "activation": "draft"},
                            ],
                        },
                        {
                            "id": "grouped",
                            "label": "Grouped",
                            "selections": [
                                {"kind": "group", "id": "all", "activation": "draft"}
                            ],
                        },
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def _write_proposals(self) -> None:
        manifest_path = self.machine / "machine-ir-manifest.json"
        ir_path = self.machine / "machine-ir.jsonl"
        plan = json.loads(self.plan.read_text(encoding="utf-8"))
        core = {
                    "format": COMPONENT_PROPOSAL_SET_FORMAT,
                    "executes_original_binary": False,
                    "bindings": {
                        "machine_ir_sha256": _file_sha256(ir_path),
                        "machine_ir_manifest_sha256": _file_sha256(manifest_path),
                        "reconstruction_plan_sha256": plan["plan_sha256"],
                        "original_binary_sha256": "1" * 64,
                    },
                    "proposals": [
                        {
                            "id": "proposal:a",
                            "proposal_kinds": ["singleton"],
                            "membership": {
                                "unit_ids": ["unit:a"],
                                "rva_start": 0x1000,
                                "rva_end": 0x1010,
                            },
                            "bindings": {"membership_bindings_sha256": "2" * 64},
                        },
                        {
                            "id": "proposal:b",
                            "proposal_kinds": ["singleton"],
                            "membership": {
                                "unit_ids": ["unit:b"],
                                "rva_start": 0x1010,
                                "rva_end": 0x1020,
                            },
                            "bindings": {"membership_bindings_sha256": "3" * 64},
                        },
                    ],
                }
        payload = {**core, "proposal_set_sha256": _canonical_sha256(core)}
        self.proposals.write_text(json.dumps(payload), encoding="utf-8")

    def _write_machine_inputs(self) -> None:
        units = [
            {
                "id": "unit:a",
                "reachability": "reachable",
                "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1010}},
                "semantics": {
                    "outcome": {"kind": "fallthrough", "target_rva": 0x1010},
                    "memory_events": [],
                    "external_events": [],
                    "faults": [],
                    "register_writes": [],
                    "flag_writes": [],
                },
            },
            {
                "id": "unit:b",
                "reachability": "reachable",
                "source": {"original": {"rva_start": 0x1010, "rva_end": 0x1020}},
                "semantics": {
                    "outcome": {
                        "kind": "return",
                        "value": {
                            "op": "load",
                            "width": 4,
                            "address": {"op": "reg", "name": "esp", "width": 32},
                        },
                    },
                    "memory_events": [],
                    "external_events": [],
                    "faults": [],
                    "register_writes": [],
                    "flag_writes": [],
                },
            },
        ]
        ir_path = self.machine / "machine-ir.jsonl"
        ir_path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in units),
            encoding="utf-8",
        )
        manifest = {
            "format": MACHINE_IR_FORMAT,
            "artifacts": {
                "machine_ir": {
                    "path": "machine-ir.jsonl",
                    "sha256": _file_sha256(ir_path),
                }
            },
            "binary": {"sha256": "1" * 64},
            "control": {
                "roots": [{"kind": "pe_entrypoint", "rva": 0x1000, "checked": True}]
            },
        }
        _write_json(self.machine / "machine-ir-manifest.json", manifest)
        plan = {
            "format": RECONSTRUCTION_PLAN_FORMAT,
            "status": "incomplete",
            "inputs": {
                "machine_ir": {
                    "format": MACHINE_IR_FORMAT,
                    "sha256": _file_sha256(ir_path),
                    "manifest_sha256": _file_sha256(
                        self.machine / "machine-ir-manifest.json"
                    ),
                }
            },
            "clusters": [],
        }
        plan["plan_sha256"] = _canonical_sha256(plan)
        _write_json(self.plan, plan)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    unittest.main()
