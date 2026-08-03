from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    COMPONENT_EVIDENCE_FORMAT,
    COMPONENT_INTERFACE_REFINEMENT_FORMAT,
    COMPONENT_REFINEMENT_FORMAT,
    COMPONENT_WORKSPACE_FORMAT,
    COMPONENT_SLICE_FORMAT,
)
from spaghetti_extractor.component_workspace import (
    _canonical_sha256,
    _cbmc_violations,
    _component_proof_contract_from_refinement,
    _component_execution_cluster,
    _enforce_portable_symbol,
    _finite_contract_from_refinement,
    _load_checked_interface_refinement,
    _load_component_slice,
    _needs_component_execution_cluster,
    _normalized_component_call_plan,
    _select_machine_units,
    _select_plan_cluster,
    qualify_component,
)
from spaghetti_extractor.bounded_component_contract import (
    BOUNDED_STRING_CONTRACT_FORMAT,
    validate_bounded_string_contract,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json


class ComponentWorkspaceTests(unittest.TestCase):
    def test_checked_profile_owns_projection_for_coextensive_cluster(self) -> None:
        unit_ids = {"unit:a", "unit:b"}

        self.assertTrue(
            _needs_component_execution_cluster(
                has_profile=True,
                component_unit_ids=unit_ids,
                cluster_unit_ids=unit_ids,
                has_dependencies=False,
            )
        )
        self.assertFalse(
            _needs_component_execution_cluster(
                has_profile=False,
                component_unit_ids=unit_ids,
                cluster_unit_ids=unit_ids,
                has_dependencies=False,
            )
        )

    def test_indirect_call_is_a_canonical_external_trace_event(self) -> None:
        component = {
            "machine_boundary": {
                "effects": {
                    "external_events": [
                        {
                            "unit_id": "unit:callback",
                            "event": {
                                "kind": "indirect_call",
                                "effect_model": "uninterpreted_indirect_call_response_v1",
                                "return_rva": 0x1200,
                                "register_inputs": {"eax": {"op": "reg", "name": "eax"}},
                                "stack_inputs": [],
                            },
                        }
                    ]
                },
                "exits": [],
            }
        }

        plan = _normalized_component_call_plan(
            component=component,
            component_dependencies=[],
        )

        self.assertEqual(
            plan["external_trace"],
            [{"kind": "indirect_call", "identity": "indirect-call"}],
        )

    def test_indirect_call_without_machine_descriptor_fails_closed(self) -> None:
        component = {
            "machine_boundary": {
                "effects": {
                    "external_events": [
                        {"unit_id": "unit:callback", "event": {"kind": "indirect_call"}}
                    ]
                },
                "exits": [],
            }
        }

        with self.assertRaisesRegex(StageAInputError, "machine-boundary descriptor"):
            _normalized_component_call_plan(
                component=component,
                component_dependencies=[],
            )

    def test_component_profiles_receive_only_declared_units_from_slice(self) -> None:
        selected = _select_machine_units(
            [
                {"id": "unit:support"},
                {"id": "unit:second"},
                {"id": "unit:first"},
            ],
            ["unit:first", "unit:second"],
            "component slice machine units",
        )

        self.assertEqual(
            [unit["id"] for unit in selected],
            ["unit:first", "unit:second"],
        )

    def test_component_unit_selection_rejects_missing_or_duplicate_units(self) -> None:
        with self.assertRaisesRegex(StageAInputError, "omit declared"):
            _select_machine_units(
                [{"id": "unit:first"}],
                ["unit:first", "unit:missing"],
                "component slice machine units",
            )
        with self.assertRaisesRegex(StageAInputError, "duplicate unit ID"):
            _select_machine_units(
                [{"id": "unit:first"}, {"id": "unit:first"}],
                ["unit:first"],
                "component slice machine units",
            )

    def test_selected_child_replaces_internal_call_in_external_trace(self) -> None:
        component = {
            "machine_boundary": {
                "effects": {
                    "external_events": [
                        {
                            "unit_id": "unit:search",
                            "event": {
                                "kind": "external_call",
                                "dll": "msvcrt.dll",
                                "symbol": "strrchr",
                            },
                        },
                        {
                            "unit_id": "unit:child",
                            "event": {
                                "kind": "internal_call",
                                "target_rva": 0x8D60,
                            },
                        },
                        {
                            "unit_id": "unit:write",
                            "event": {
                                "kind": "external_call",
                                "dll": "kernel32.dll",
                                "symbol": "WriteFile",
                            },
                        },
                    ]
                },
                "exits": [
                    {
                        "kind": "internal_call",
                        "source_unit_id": "unit:child",
                        "target_rva": 0x8D60,
                    }
                ],
            },
            "component_calls": [
                {
                    "target_component_id": "memory-regions-equal",
                    "target_rva": 0x8D60,
                    "callsites": [{"source_unit_id": "unit:child"}],
                }
            ],
        }
        dependency = {
            "target_component_id": "memory-regions-equal",
            "target_rva": 0x8D60,
            "callsites": [{"source_unit_id": "unit:child"}],
            "external_trace": [
                {"kind": "external_call", "identity": "msvcrt.dll!memcmp"}
            ],
        }

        plan = _normalized_component_call_plan(
            component=component,
            component_dependencies=[dependency],
        )

        self.assertEqual(
            [event["identity"] for event in plan["external_trace"]],
            [
                "msvcrt.dll!strrchr",
                "msvcrt.dll!memcmp",
                "kernel32.dll!WriteFile",
            ],
        )
        self.assertEqual(
            [
                event["event"]["symbol"]
                for event in plan["remaining_events"]
            ],
            ["strrchr", "WriteFile"],
        )
        self.assertEqual(plan["remaining_exits"], [])

    def test_generic_component_contract_binding_fails_closed(self) -> None:
        payload_core = {
            "format": "stage-b-example-component-contract-v1",
            "status": "checked",
            "executes_original_binary": False,
            "semantics": {"result": "zero predicate"},
        }
        payload = {
            **payload_core,
            "contract_sha256": _canonical_sha256(payload_core),
        }
        refinement = {
            "component_contract": {
                "field": "example_contract",
                "format": payload["format"],
                "contract_sha256": payload["contract_sha256"],
            },
            "example_contract": payload,
        }
        self.assertEqual(
            _component_proof_contract_from_refinement(refinement)["payload"],
            payload,
        )

        corrupted = json.loads(json.dumps(refinement))
        corrupted["example_contract"]["semantics"]["result"] = "nonzero"
        with self.assertRaisesRegex(StageAInputError, "payload is stale"):
            _component_proof_contract_from_refinement(corrupted)

    def test_bounded_string_contract_corruption_fails_closed(self) -> None:
        core = {
            "format": BOUNDED_STRING_CONTRACT_FORMAT,
            "status": "checked",
            "executes_original_binary": False,
            "domain": {"kind": "guarded_partial", "max_bytes": 16},
        }
        contract = {**core, "contract_sha256": _canonical_sha256(core)}
        validate_bounded_string_contract(contract)

        corrupted = json.loads(json.dumps(contract))
        corrupted["domain"]["max_bytes"] = 32
        with self.assertRaisesRegex(StageAInputError, "self-hash is stale"):
            validate_bounded_string_contract(corrupted)

    def test_plan_cluster_can_be_selected_by_semantic_entry_containment(self) -> None:
        cluster = {
            "id": "cluster:local-epilogue",
            "entry_rva": 0x1100,
            "unit_ids": ["unit:entry", "unit:return"],
        }
        component = {
            "id": "bounded-loop",
            "membership": {"cluster_ids": []},
            "machine_boundary": {
                "entries": [{"rva": 0x1000, "unit_id": "unit:entry"}]
            },
        }
        self.assertEqual(
            _select_plan_cluster(
                {"clusters": [cluster]}, component, entry_rva=0x1000
            ),
            cluster,
        )

    def test_finite_component_contract_corruption_fails_closed(self) -> None:
        core = {
            "format": "stage-b-finite-component-contract-v1",
            "status": "derived",
            "executes_original_binary": False,
            "address_space": {
                "kind": "pe32_image_rva_v1",
                "image_base": 0x400000,
                "size_of_image": 0x10000,
            },
        }
        contract = {**core, "contract_sha256": _canonical_sha256(core)}
        self.assertEqual(
            _finite_contract_from_refinement(
                {"finite_component_contract": contract}
            ),
            contract,
        )

        corrupted = json.loads(json.dumps(contract))
        corrupted["address_space"]["image_base"] = 0x500000
        with self.assertRaisesRegex(StageAInputError, "self-hash is stale"):
            _finite_contract_from_refinement(
                {"finite_component_contract": corrupted}
            )

    def test_component_execution_cluster_uses_full_declared_membership(self) -> None:
        units = [
            {
                "id": "unit:a",
                "source": {
                    "original": {"rva_start": 0x1000, "rva_end": 0x1004}
                },
            },
            {
                "id": "unit:b",
                "source": {
                    "original": {"rva_start": 0x1004, "rva_end": 0x1008}
                },
            },
        ]
        selected = {
            "id": "cluster:first",
            "contract_sha256": "old",
            "inputs": [],
            "unit_ids": ["unit:a"],
            "entry_unit_id": "unit:a",
            "entry_rva": 0x1000,
            "control": [{"kind": "jump"}],
        }
        component = {
            "id": "worker",
            "component_sha256": "component-hash",
            "membership": {"resolved_unit_ids": ["unit:a", "unit:b"]},
            "machine_boundary": {
                "entries": [{"rva": 0x1000, "unit_id": "unit:a"}],
                "exits": [{"kind": "return", "source_unit_id": "unit:b"}],
                "effects": {
                    "external_events": [
                        {
                            "unit_id": "unit:a",
                            "event_index": 0,
                            "event": {
                                "kind": "external_call",
                                "dll": "kernel32.dll",
                                "symbol": "Sleep",
                            },
                        }
                    ]
                },
            },
        }

        cluster = _component_execution_cluster(
            selected_cluster=selected,
            component=component,
            units=units,
            observable_memory=[
                {
                    "semantic_expression": {
                        "op": "reg",
                        "name": "eax",
                        "width": 32,
                    },
                    "width": 16,
                    "access": "read_write",
                }
            ],
        )

        self.assertEqual(cluster["unit_ids"], ["unit:a", "unit:b"])
        self.assertEqual(
            cluster["rva_spans"],
            [{"start": 0x1000, "end": 0x1004}, {"start": 0x1004, "end": 0x1008}],
        )
        self.assertEqual(cluster["control"][0]["kind"], "return")
        self.assertEqual(cluster["memory"][0]["width"], 16)
        self.assertEqual(
            cluster["external_events"],
            [{"kind": "external_call", "identity": "kernel32.dll!Sleep"}],
        )
        self.assertEqual(
            cluster["composition"]["status"],
            "checked_by_component_interface",
        )

    def test_component_execution_cluster_preserves_direct_exit_semantics(self) -> None:
        units = [
            {
                "id": "unit:a",
                "source": {
                    "original": {"rva_start": 0x1000, "rva_end": 0x1004}
                },
                "semantics": {
                    "outcome": {"kind": "fallthrough", "target_rva": 0x1004}
                },
            },
            {
                "id": "unit:b",
                "source": {
                    "original": {"rva_start": 0x2000, "rva_end": 0x2004}
                },
                "semantics": {"outcome": {"kind": "return"}},
            },
        ]
        selected = {
            "id": "cluster:first",
            "contract_sha256": "old",
            "inputs": [],
            "unit_ids": ["unit:a"],
            "entry_unit_id": "unit:a",
            "entry_rva": 0x1000,
            "control": [{"kind": "fallthrough"}],
        }
        component = {
            "id": "worker",
            "component_sha256": "component-hash",
            "membership": {"resolved_unit_ids": ["unit:a", "unit:b"]},
            "machine_boundary": {
                "entries": [{"rva": 0x1000, "unit_id": "unit:a"}],
                "exits": [
                    {
                        "kind": "direct_control",
                        "source_unit_id": "unit:a",
                        "target_rva": 0x1004,
                        "target_unit_id": "unit:outside",
                    }
                ],
            },
        }

        cluster = _component_execution_cluster(
            selected_cluster=selected,
            component=component,
            units=units,
            observable_memory=[],
        )

        self.assertEqual(
            cluster["control"],
            [
                {
                    "kind": "fallthrough",
                    "source_unit_id": "unit:a",
                    "target_rvas": [0x1004],
                    "target_unit_ids": ["unit:outside"],
                }
            ],
        )

    def test_qualification_rejects_partial_component_membership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "contract").mkdir()
            source = root / "src" / "implementation.c"
            header = root / "src" / "implementation.h"
            adapter = root / "src" / "replacement.c"
            adapter_reference = root / "contract" / "generated-machine-adapter.c"
            source.write_text("int component(void) { return 0; }\n", encoding="ascii")
            header.write_text("int component(void);\n", encoding="ascii")
            adapter.write_text("int adapter(void) { return 0; }\n", encoding="ascii")
            adapter_reference.write_text(adapter.read_text(encoding="ascii"), encoding="ascii")
            write_json(
                root / "region-replacement.json",
                {
                    "format": "stage-b-region-replacement-v2",
                    "manifest_sha256": "manifest-binding",
                    "cluster": {"unit_ids": ["unit:a"]},
                },
            )
            interface_core = {
                "format": COMPONENT_INTERFACE_REFINEMENT_FORMAT,
                "status": "checked",
                "executes_original_binary": False,
                "component": {"id": "test-component", "sha256": "component"},
                "bindings": {"catalog_artifact_sha256": "catalog", "machine_ir_sha256": "machine"},
                "issues": [],
                "logical_interface": {"parameters": [], "results": [], "objects": [], "services": [], "adapter_effects": [], "claims": [], "policy": {}},
            }
            interface = {**interface_core, "refinement_sha256": _canonical_sha256(interface_core)}
            interface_path = root / "contract" / "checked-logical-interface.json"
            write_json(interface_path, interface)
            refinement_core = {
                "format": COMPONENT_REFINEMENT_FORMAT,
                "status": "checked",
                "portable_symbol": "component",
                "component": {"unit_ids": ["unit:a", "unit:b"]},
                "machine_projection": {"status": "checked", "call_closure": {}},
                "adapter_effect_plan": {"internal_call_frames": []},
                "logical_interface_refinement": {"status": "checked", "refinement_sha256": interface["refinement_sha256"]},
                "bindings": {
                    "generated_adapter_sha256": sha256_file(adapter),
                    "portable_source_sha256": sha256_file(source),
                    "logical_interface_artifact_sha256": sha256_file(interface_path),
                    "logical_interface_refinement_sha256": interface["refinement_sha256"],
                },
            }
            refinement = {**refinement_core, "refinement_sha256": _canonical_sha256(refinement_core)}
            write_json(root / "contract" / "component-refinement.json", refinement)
            workspace_core = {
                "format": COMPONENT_WORKSPACE_FORMAT,
                "status": "editable",
                "component_id": "test-component",
                "proof_profile": "compare_branch_v1",
                "bindings": {"refinement_sha256": refinement["refinement_sha256"], "logical_interface_refinement_sha256": interface["refinement_sha256"]},
                "files": {
                    "refinement": "contract/component-refinement.json",
                    "portable_source": "src/implementation.c",
                    "portable_header": "src/implementation.h",
                    "machine_adapter_source": "src/replacement.c",
                    "generated_adapter_reference": "contract/generated-machine-adapter.c",
                    "logical_interface_refinement": "contract/checked-logical-interface.json",
                    "replacement_manifest": "region-replacement.json",
                },
                "activation": {"status": "blocked_pending_qualification"},
            }
            workspace = {**workspace_core, "workspace_sha256": _canonical_sha256(workspace_core)}
            write_json(root / "component-workspace.json", workspace)
            evidence = {
                "format": COMPONENT_EVIDENCE_FORMAT,
                "status": "satisfied",
                "bindings": {"portable_source_sha256": sha256_file(source), "refinement_sha256": refinement["refinement_sha256"]},
            }
            evidence_path = root / "source-evidence.json"
            write_json(evidence_path, evidence)
            write_json(root / "validation-report.json", {"status": "qualified", "bindings": {"replacement_manifest_sha256": "manifest-binding"}})

            result = qualify_component(
                workspace=root,
                source_evidence=evidence_path,
                out=root / "qualification.json",
            )
            membership = next(item for item in result["checks"] if item["family"] == "exact_component_membership")
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(membership["status"], "incomplete")

    def test_component_slice_is_self_bound_and_requires_all_machine_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "slice.json"
            core = {
                "format": COMPONENT_SLICE_FORMAT,
                "status": "checked",
                "executes_original_binary": False,
                "component_id": "worker",
                "bindings": {
                    "catalog_artifact_sha256": "a" * 64,
                    "reconstruction_plan_sha256": "b" * 64,
                    "machine_ir_sha256": "c" * 64,
                },
                "component": {
                    "id": "worker",
                    "membership": {"resolved_unit_ids": ["unit:a", "unit:b"]},
                },
                "cluster": {
                    "id": "cluster:worker",
                    "entry_unit_id": "unit:a",
                    "unit_ids": ["unit:a"],
                },
                "units": [{"id": "unit:a"}, {"id": "unit:b"}],
            }
            write_json(path, {**core, "slice_sha256": _canonical_sha256(core)})
            self.assertEqual(_load_component_slice(path, "worker")["component_id"], "worker")

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["units"] = [{"id": "unit:a"}]
            payload.pop("slice_sha256")
            payload["slice_sha256"] = _canonical_sha256(payload)
            write_json(path, payload)
            with self.assertRaisesRegex(StageAInputError, "omits required"):
                _load_component_slice(path, "worker")

    def test_portable_symbol_rebinding_is_component_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "implementation.c"
            source.write_text(
                "bool reconstruct_region(void *a, void *b) { return a == b; }\n",
                encoding="ascii",
            )
            _enforce_portable_symbol(
                source, "component_00001050_reconstruct_region"
            )
            text = source.read_text(encoding="ascii")
            self.assertIn("component_00001050_reconstruct_region", text)
            self.assertNotIn("bool reconstruct_region", text)

    def test_portable_symbol_rebinding_accepts_profile_declared_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "implementation.c"
            source.write_text(
                "int match_token_cursor(void *services) { return services != 0; }\n",
                encoding="ascii",
            )
            _enforce_portable_symbol(
                source, "component_00001440_match_token_cursor"
            )
            text = source.read_text(encoding="ascii")
            self.assertIn("component_00001440_match_token_cursor", text)
            self.assertNotIn("int match_token_cursor", text)

    def test_cbmc_failure_retains_source_location(self) -> None:
        report = json.dumps(
            [
                {
                    "result": [
                        {
                            "property": "main.assertion.1",
                            "status": "FAILURE",
                            "description": "wrong result",
                            "sourceLocation": {
                                "file": "implementation.c",
                                "line": "17",
                                "function": "main",
                            },
                        }
                    ]
                }
            ]
        )
        self.assertEqual(
            _cbmc_violations(report),
            [
                {
                    "property": "main.assertion.1",
                    "description": "wrong result",
                    "location": {
                        "file": "implementation.c",
                        "line": "17",
                        "function": "main",
                    },
                }
            ],
        )

    def test_component_creation_rejects_incomplete_logical_interface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "interface.json"
            core = {
                "format": COMPONENT_INTERFACE_REFINEMENT_FORMAT,
                "status": "incomplete",
                "executes_original_binary": False,
                "component": {"id": "worker", "sha256": "component-hash"},
                "bindings": {
                    "catalog_artifact_sha256": "catalog-hash",
                    "machine_ir_sha256": "machine-hash",
                },
                "issues": [{"code": "unrepresented_machine_effect"}],
                "logical_interface": {},
            }
            write_json(path, {**core, "refinement_sha256": _canonical_sha256(core)})
            with self.assertRaisesRegex(
                StageAInputError, "logical interface is not checked"
            ):
                _load_checked_interface_refinement(
                    path,
                    component={"id": "worker", "component_sha256": "component-hash"},
                    machine_ir_sha256="machine-hash",
                )

    def test_qualification_rejects_modified_generated_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "contract").mkdir()
            source = root / "src" / "implementation.c"
            header = root / "src" / "implementation.h"
            adapter = root / "src" / "replacement.c"
            adapter_reference = root / "contract" / "generated-machine-adapter.c"
            source.write_text("int component(void) { return 0; }\n", encoding="ascii")
            header.write_text("int component(void);\n", encoding="ascii")
            adapter.write_text("int adapter(void) { return 0; }\n", encoding="ascii")
            adapter_reference.write_text(adapter.read_text(encoding="ascii"), encoding="ascii")
            manifest = {
                "format": "stage-b-region-replacement-v2",
                "manifest_sha256": "manifest-binding",
                "cluster": {"unit_ids": ["unit:a"]},
            }
            write_json(root / "region-replacement.json", manifest)
            interface_core = {
                "format": COMPONENT_INTERFACE_REFINEMENT_FORMAT,
                "status": "checked",
                "executes_original_binary": False,
                "component": {"id": "test-component", "sha256": "component"},
                "bindings": {
                    "catalog_artifact_sha256": "catalog",
                    "machine_ir_sha256": "machine",
                },
                "issues": [],
                "logical_interface": {
                    "parameters": [],
                    "results": [],
                    "objects": [],
                    "services": [],
                    "adapter_effects": [],
                    "claims": [],
                    "policy": {},
                },
            }
            interface = {
                **interface_core,
                "refinement_sha256": _canonical_sha256(interface_core),
            }
            interface_path = root / "contract" / "checked-logical-interface.json"
            write_json(interface_path, interface)
            refinement_core = {
                "format": COMPONENT_REFINEMENT_FORMAT,
                "status": "checked",
                "portable_symbol": "component",
                "component": {"unit_ids": ["unit:a"]},
                "machine_projection": {"status": "checked", "call_closure": {}},
                "adapter_effect_plan": {"internal_call_frames": []},
                "logical_interface_refinement": {
                    "status": "checked",
                    "refinement_sha256": interface["refinement_sha256"],
                },
                "bindings": {
                    "generated_adapter_sha256": sha256_file(adapter),
                    "portable_source_sha256": sha256_file(source),
                    "logical_interface_artifact_sha256": sha256_file(
                        interface_path
                    ),
                    "logical_interface_refinement_sha256": interface[
                        "refinement_sha256"
                    ],
                },
            }
            refinement = {
                **refinement_core,
                "refinement_sha256": _canonical_sha256(refinement_core),
            }
            write_json(root / "contract" / "component-refinement.json", refinement)
            workspace_core = {
                "format": COMPONENT_WORKSPACE_FORMAT,
                "status": "editable",
                "component_id": "test-component",
                "proof_profile": "compare_branch_v1",
                "bindings": {
                    "refinement_sha256": refinement["refinement_sha256"],
                    "logical_interface_refinement_sha256": interface[
                        "refinement_sha256"
                    ],
                },
                "files": {
                    "refinement": "contract/component-refinement.json",
                    "portable_source": "src/implementation.c",
                    "portable_header": "src/implementation.h",
                    "machine_adapter_source": "src/replacement.c",
                    "generated_adapter_reference": "contract/generated-machine-adapter.c",
                    "logical_interface_refinement": (
                        "contract/checked-logical-interface.json"
                    ),
                    "replacement_manifest": "region-replacement.json",
                },
                "activation": {"status": "blocked_pending_qualification"},
            }
            workspace = {
                **workspace_core,
                "workspace_sha256": _canonical_sha256(workspace_core),
            }
            write_json(root / "component-workspace.json", workspace)
            evidence = {
                "format": COMPONENT_EVIDENCE_FORMAT,
                "status": "satisfied",
                "bindings": {
                    "portable_source_sha256": sha256_file(source),
                    "refinement_sha256": refinement["refinement_sha256"],
                },
            }
            evidence_path = root / "source-evidence.json"
            write_json(evidence_path, evidence)
            write_json(
                root / "validation-report.json",
                {
                    "status": "qualified",
                    "bindings": {
                        "replacement_manifest_sha256": "manifest-binding"
                    },
                },
            )

            qualified = qualify_component(
                workspace=root,
                source_evidence=evidence_path,
                out=root / "qualification.json",
            )
            self.assertEqual(qualified["status"], "qualified")
            logical = next(
                item
                for item in qualified["checks"]
                if item["family"] == "logical_interface_refinement"
            )
            self.assertEqual(logical["status"], "satisfied")

            adapter.write_text("int adapter(void) { return 1; }\n", encoding="ascii")
            rejected = qualify_component(
                workspace=root,
                source_evidence=evidence_path,
                out=root / "qualification-tampered.json",
            )
            self.assertEqual(rejected["status"], "incomplete")
            generated = next(
                item for item in rejected["checks"] if item["family"] == "generated_adapter"
            )
            self.assertEqual(generated["observed"], "modified")


if __name__ == "__main__":
    unittest.main()
