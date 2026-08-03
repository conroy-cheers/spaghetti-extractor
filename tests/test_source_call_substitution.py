from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    CALLABLE_INTERFACE_CATALOG_FORMAT,
    CALL_SUBSTITUTION_ASSIGNMENTS_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    MACHINE_IR_FORMAT,
    LINKED_ISLAND_MANIFEST_V2_FORMAT,
    SOURCE_CALL_BINDINGS_FORMAT,
    SOURCE_SUBSTITUTION_CATALOG_FORMAT,
)
from spaghetti_extractor.source_call_substitution import (
    audit_candidate_dependencies,
    bind_allowed_runtime_imports,
    bind_call_substitution_assignments,
    bind_callable_interface_catalog,
    bind_source_call_bindings,
    bind_source_substitution_catalog,
    check_source_call_bindings,
    derive_static_indirect_call_targets,
    generate_call_frontier,
    inventory_clang_source_calls,
    plan_call_substitutions,
    propose_source_component_artifacts,
    propose_source_component_bindings,
)
from spaghetti_extractor.source_project import SOURCE_PROJECT_BINDING_FORMAT
from spaghetti_extractor.source_graph import source_function_closure
from spaghetti_extractor.util import sha256_file, write_json
from tests.pe_fixtures import pe32_image, pe32_import_image


_ORIGINAL = "a" * 64
_MACHINE = "b" * 64
_MANIFEST = "c" * 64
_UNIT_A = "semantic-transfer:original-cutpoint-00001000-00001010"
_UNIT_B = "semantic-transfer:original-cutpoint-00001100-00001110"
_THUNK = "semantic-transfer:original-cutpoint-00002000-00002006"


class SourceCallSubstitutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source_binding = self.root / "source-binding.json"
        self.linked_islands = self.root / "linked-islands.json"
        self.dynamic = self.root / "dynamic.json"
        self.indirect = self.root / "indirect.json"
        self._write_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_frontier_is_total_across_project_import_and_indirect_calls(self) -> None:
        frontier = generate_call_frontier(
            source_binding=self.source_binding,
            linked_islands=self.linked_islands,
            dynamic_requirements=self.dynamic,
            indirect_targets=self.indirect,
            out=self.root / "frontier.json",
        )

        self.assertEqual(frontier["status"], "complete")
        self.assertEqual(frontier["counts"]["calls"], 3)
        self.assertEqual(
            frontier["counts"]["by_target_kind"],
            {"dynamic_import": 1, "indirect": 1, "project_internal": 1},
        )

    def test_missing_indirect_certificate_is_incomplete(self) -> None:
        frontier = generate_call_frontier(
            source_binding=self.source_binding,
            linked_islands=self.linked_islands,
            dynamic_requirements=self.dynamic,
            out=self.root / "frontier.json",
        )

        self.assertEqual(frontier["status"], "incomplete")
        self.assertEqual(frontier["counts"]["incomplete"], 1)
        self.assertEqual(frontier["issues"][0]["target_kind"], "indirect")

    def test_qualified_plan_binds_to_clang_source_call(self) -> None:
        frontier = generate_call_frontier(
            source_binding=self.source_binding,
            linked_islands=self.linked_islands,
            dynamic_requirements=self.dynamic,
            out=self.root / "frontier.json",
        )
        dynamic_call = next(
            call for call in frontier["calls"] if call["target"]["kind"] == "dynamic_import"
        )
        logical = {"format": "fixture-write-v1", "contract_sha256": "d" * 64}
        interfaces = bind_callable_interface_catalog(
            {
                "format": CALLABLE_INTERFACE_CATALOG_FORMAT,
                "catalog_id": "fixture-interfaces",
                "interfaces": [
                    {
                        "id": "write-file",
                        "selector": {
                            "kind": "dynamic_import",
                            "dll": "kernel32.dll",
                            "symbol": "WriteFile",
                            "ordinal": None,
                        },
                        "logical_contract": logical,
                        "qualification": {
                            "kind": "checked_machine_import_contract",
                            "status": "qualified",
                        },
                    }
                ],
            }
        )
        substitutions = bind_source_substitution_catalog(
            {
                "format": SOURCE_SUBSTITUTION_CATALOG_FORMAT,
                "catalog_id": "fixture-source",
                "substitutions": [
                    {
                        "id": "write-file-c",
                        "interface_id": "write-file",
                        "assurance_class": "machine_exact",
                        "implementation": {
                            "symbol": "WriteFile",
                            "prototype": {
                                "return_type": "int",
                                "parameters": [],
                            },
                            "headers": ["windows.h"],
                            "link_inputs": ["kernel32"],
                            "expected_import": {
                                "dll": "kernel32.dll",
                                "symbol": "WriteFile",
                                "ordinal": None,
                            },
                        },
                    }
                ],
            }
        )
        assignments = bind_call_substitution_assignments(
            {
                "format": CALL_SUBSTITUTION_ASSIGNMENTS_FORMAT,
                "frontier_sha256": frontier["frontier_sha256"],
                "assignments": [
                    {
                        "id": "write-call",
                        "call_ids": [dynamic_call["id"]],
                        "interface_id": "write-file",
                        "substitution_id": "write-file-c",
                    }
                ],
            }
        )
        plan = plan_call_substitutions(
            frontier=self.root / "frontier.json",
            interface_catalog=interfaces,
            substitution_catalog=substitutions,
            assignments=assignments,
            out=self.root / "plan.json",
        )
        self.assertEqual(plan["status"], "incomplete")
        write_plan = next(item for item in plan["assignments"] if item["id"] == "write-call")
        self.assertEqual(write_plan["status"], "ready")

        source = self.root / "hello.c"
        source.write_text("int f(void) { return WriteFile(); }\n", encoding="ascii")
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "f",
                    "inner": [
                        {
                            "kind": "CallExpr",
                            "range": {
                                "begin": {
                                    "file": str(source),
                                    "offset": 21,
                                    "line": 1,
                                    "col": 22,
                                }
                            },
                            "inner": [
                                {
                                    "kind": "ImplicitCastExpr",
                                    "inner": [
                                        {
                                            "kind": "DeclRefExpr",
                                            "referencedDecl": {
                                                "kind": "FunctionDecl",
                                                "name": "WriteFile",
                                            },
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        write_json(self.root / "ast.json", ast)
        inventory = inventory_clang_source_calls(
            ast_json=self.root / "ast.json",
            source_root=self.root,
            source_hashes=[{"path": "hello.c", "sha256": sha256_file(source)}],
            out=self.root / "source-inventory.json",
        )
        bindings = bind_source_call_bindings(
            {
                "format": SOURCE_CALL_BINDINGS_FORMAT,
                "call_plan_sha256": plan["plan_sha256"],
                "source_inventory_sha256": inventory["inventory_sha256"],
                "bindings": [
                    {
                        "plan_id": "write-call",
                        "source_call_id": inventory["calls"][0]["id"],
                    }
                ],
            }
        )
        report = check_source_call_bindings(
            call_plan=self.root / "plan.json",
            source_inventory=self.root / "source-inventory.json",
            bindings=bindings,
            out=self.root / "source-report.json",
        )
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["results"][0]["status"], "satisfied")

    def test_candidate_import_audit_rejects_unexpected_dependency(self) -> None:
        candidate = self.root / "candidate.exe"
        candidate.write_bytes(pe32_import_image(b"\xc3", symbol="WriteFile"))
        plan_core = {
            "format": "stage-b-call-substitution-plan-v1",
            "status": "complete",
            "executes_original_binary": False,
            "bindings": {},
            "assignments": [],
            "issues": [],
            "counts": {},
            "authority": {},
        }
        write_json(
            self.root / "empty-plan.json",
            {**plan_core, "plan_sha256": _canonical_sha256(plan_core)},
        )

        audit = audit_candidate_dependencies(
            candidate=candidate,
            call_plan=self.root / "empty-plan.json",
            allowed_runtime_imports=[],
            out=self.root / "audit.json",
        )

        self.assertEqual(audit["status"], "violated")
        self.assertEqual(audit["unexpected_imports"][0]["symbol"], "WriteFile")

    def test_allowed_runtime_import_envelope_is_canonical_and_bound(self) -> None:
        envelope = bind_allowed_runtime_imports(
            {
                "format": "stage-b-allowed-runtime-imports-v1",
                "profile_id": "fixture-runtime",
                "imports": [
                    {
                        "dll": "KERNEL32.dll",
                        "symbol": "WriteFile",
                        "ordinal": None,
                    }
                ],
            }
        )

        self.assertEqual(envelope["imports"][0]["dll"], "kernel32.dll")
        self.assertEqual(len(envelope["envelope_sha256"]), 64)

    def test_candidate_import_audit_accepts_component_import_inventory(self) -> None:
        candidate = self.root / "candidate.exe"
        candidate.write_bytes(pe32_import_image(b"\xc3", symbol="WriteFile"))
        plan_core = {
            "format": "stage-b-call-substitution-plan-v1",
            "status": "complete",
            "executes_original_binary": False,
            "bindings": {},
            "assignments": [
                {
                    "id": "component",
                    "source_implementation": {
                        "kind": "source_component",
                        "expected_imports": [
                            {
                                "dll": "kernel32.dll",
                                "symbol": "WriteFile",
                                "ordinal": None,
                            }
                        ],
                    },
                }
            ],
            "issues": [],
            "counts": {},
            "authority": {},
        }
        write_json(
            self.root / "component-plan.json",
            {**plan_core, "plan_sha256": _canonical_sha256(plan_core)},
        )

        audit = audit_candidate_dependencies(
            candidate=candidate,
            call_plan=self.root / "component-plan.json",
            allowed_runtime_imports=[],
            out=self.root / "component-audit.json",
        )

        self.assertEqual(audit["status"], "pass")
        self.assertEqual(audit["counts"]["unexpected"], 0)

    def test_static_indirect_target_without_relocation_is_incomplete(self) -> None:
        original = self.root / "static-slot.exe"
        original.write_bytes(pe32_image(b"\xc3\0\0\0"))
        machine = self.root / "machine"
        machine.mkdir()
        ir = machine / "machine-ir.jsonl"
        unit = {
            "id": _UNIT_A,
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1001}},
        }
        ir.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="utf-8")
        write_json(
            machine / "machine-ir-manifest.json",
            {
                "format": MACHINE_IR_FORMAT,
                "artifacts": {
                    "machine_ir": {
                        "path": "machine-ir.jsonl",
                        "sha256": sha256_file(ir),
                    }
                },
            },
        )
        binding_core = {
            "format": SOURCE_PROJECT_BINDING_FORMAT,
            "bindings": {
                "original_binary_sha256": sha256_file(original),
                "machine_ir_sha256": sha256_file(ir),
            },
            "islands": [
                {
                    "id": "caller",
                    "boundary": {
                        "external_events": [
                            {
                                "kind": "indirect_call",
                                "source_unit_id": _UNIT_A,
                                "target": {
                                    "op": "load",
                                    "width": 4,
                                    "address": {
                                        "op": "const",
                                        "width": 32,
                                        "value": 0x401000,
                                    },
                                },
                            }
                        ]
                    },
                }
            ],
        }
        write_json(
            self.root / "static-binding.json",
            {**binding_core, "binding_sha256": _canonical_sha256(binding_core)},
        )

        inventory = derive_static_indirect_call_targets(
            original=original,
            machine_ir=machine,
            source_binding=self.root / "static-binding.json",
            out=self.root / "static-targets.json",
        )

        self.assertEqual(inventory["status"], "incomplete")
        self.assertEqual(inventory["counts"]["qualified"], 0)
        self.assertEqual(
            inventory["issues"][0]["code"],
            "indirect_target_slot_not_highlow_relocated",
        )

    def test_source_inventory_uses_expansion_location_and_elided_file(self) -> None:
        source = self.root / "hello.c"
        source.write_text("int f(void) { return CALLEE(); }\n", encoding="ascii")
        ast_source = self.root / "separate-store-snapshot" / "hello.c"
        ast_source.parent.mkdir()
        ast_source.write_bytes(source.read_bytes())
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "f",
                    "inner": [
                        {
                            "kind": "CallExpr",
                            "range": {"begin": {"offset": 21, "line": 1, "col": 22}},
                            "inner": [
                                {
                                    "kind": "DeclRefExpr",
                                    "referencedDecl": {
                                        "kind": "FunctionDecl",
                                        "name": "direct_call",
                                    },
                                }
                            ],
                        },
                        {
                            "kind": "CallExpr",
                            "range": {
                                "begin": {
                                    "spellingLoc": {
                                        "file": "/sdk/header.h",
                                        "offset": 7,
                                    },
                                    "expansionLoc": {
                                        "file": str(ast_source),
                                        "offset": 21,
                                        "line": 1,
                                        "col": 22,
                                    },
                                }
                            },
                            "inner": [
                                {
                                    "kind": "DeclRefExpr",
                                    "referencedDecl": {
                                        "kind": "FunctionDecl",
                                        "name": "macro_call",
                                    },
                                }
                            ],
                        },
                    ],
                }
            ],
        }
        write_json(self.root / "ast.json", ast)

        inventory = inventory_clang_source_calls(
            ast_json=self.root / "ast.json",
            source_root=self.root,
            source_hashes=[{"path": "hello.c", "sha256": sha256_file(source)}],
            out=self.root / "source-inventory.json",
        )

        self.assertEqual(
            inventory["counts"],
            {"calls": 2, "direct": 2, "indirect": 0, "function_references": 0},
        )
        self.assertEqual(
            {call["callee"] for call in inventory["calls"]},
            {"direct_call", "macro_call"},
        )
        self.assertTrue(all(call["source"]["path"] == "hello.c" for call in inventory["calls"]))

    def test_source_inventory_tracks_address_taken_local_callback(self) -> None:
        source = self.root / "callback.c"
        source.write_text(
            "static void callback(void) {}\n"
            "void register_callback(void (*callback)(void));\n"
            "int caller(void) { register_callback(callback); return 0; }\n",
            encoding="ascii",
        )
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "callback",
                    "range": {"begin": {"file": str(source), "offset": 0}},
                    "inner": [{"kind": "CompoundStmt"}],
                },
                {
                    "kind": "FunctionDecl",
                    "name": "caller",
                    "range": {"begin": {"file": str(source), "offset": 82}},
                    "inner": [
                        {
                            "kind": "CompoundStmt",
                            "inner": [
                                {
                                    "kind": "CallExpr",
                                    "range": {
                                        "begin": {"file": str(source), "offset": 101}
                                    },
                                    "inner": [
                                        {
                                            "kind": "DeclRefExpr",
                                            "range": {
                                                "begin": {
                                                    "file": str(source),
                                                    "offset": 101,
                                                }
                                            },
                                            "referencedDecl": {
                                                "kind": "FunctionDecl",
                                                "name": "register_callback",
                                            },
                                        },
                                        {
                                            "kind": "DeclRefExpr",
                                            "range": {
                                                "begin": {
                                                    "file": str(source),
                                                    "offset": 119,
                                                }
                                            },
                                            "referencedDecl": {
                                                "kind": "FunctionDecl",
                                                "name": "callback",
                                            },
                                        },
                                    ],
                                }
                            ],
                        }
                    ],
                },
            ],
        }
        write_json(self.root / "callback-ast.json", ast)

        inventory = inventory_clang_source_calls(
            ast_json=self.root / "callback-ast.json",
            source_root=self.root,
            source_hashes=[{"path": "callback.c", "sha256": sha256_file(source)}],
            out=self.root / "callback-inventory.json",
        )

        self.assertEqual(inventory["counts"]["function_references"], 1)
        self.assertEqual(
            inventory["function_references"][0]["target_symbol"], "callback"
        )
        self.assertEqual(
            source_function_closure(
                ["caller"], inventory["calls"], inventory["function_references"]
            ),
            {"caller", "callback"},
        )

    def test_source_inventory_disambiguates_macro_expansion_calls(self) -> None:
        source = self.root / "macro.c"
        source.write_text("int caller(void) { return TWO_CALLS(foo()); }\n", encoding="ascii")
        call = {
            "kind": "CallExpr",
            "range": {"begin": {"file": str(source), "offset": 26}},
            "inner": [
                {
                    "kind": "DeclRefExpr",
                    "referencedDecl": {"kind": "FunctionDecl", "name": "foo"},
                }
            ],
        }
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "caller",
                    "range": {"begin": {"file": str(source), "offset": 0}},
                    "inner": [
                        {
                            "kind": "CompoundStmt",
                            "inner": [call, json.loads(json.dumps(call))],
                        }
                    ],
                }
            ],
        }
        write_json(self.root / "macro-ast.json", ast)

        inventory = inventory_clang_source_calls(
            ast_json=self.root / "macro-ast.json",
            source_root=self.root,
            source_hashes=[{"path": "macro.c", "sha256": sha256_file(source)}],
            out=self.root / "macro-inventory.json",
        )

        self.assertEqual(inventory["counts"]["calls"], 2)
        self.assertEqual(len({row["id"] for row in inventory["calls"]}), 2)
        self.assertEqual(
            sorted(
                (row["source_occurrence"] for row in inventory["calls"]),
                key=lambda row: row["ordinal"],
            ),
            [{"ordinal": 0, "count": 2}, {"ordinal": 1, "count": 2}],
        )

    def test_qualified_cluster_can_bind_to_source_component(self) -> None:
        frontier = generate_call_frontier(
            source_binding=self.source_binding,
            linked_islands=self.linked_islands,
            dynamic_requirements=self.dynamic,
            indirect_targets=self.indirect,
            out=self.root / "frontier.json",
        )
        call_ids = [call["id"] for call in frontier["calls"]]
        interfaces = bind_callable_interface_catalog(
            {
                "format": CALLABLE_INTERFACE_CATALOG_FORMAT,
                "catalog_id": "component-cluster",
                "interfaces": [
                    {
                        "id": "caller-component-contract",
                        "selector": {
                            "kind": "exact_cluster",
                            "endpoint_ids": call_ids,
                        },
                        "logical_contract": {
                            "format": "fixture-component-contract-v1",
                            "contract_sha256": "d" * 64,
                        },
                        "qualification": {
                            "kind": "component_qualification",
                            "status": "qualified",
                        },
                    }
                ],
            }
        )
        substitutions = bind_source_substitution_catalog(
            {
                "format": SOURCE_SUBSTITUTION_CATALOG_FORMAT,
                "catalog_id": "component-source",
                "substitutions": [
                    {
                        "id": "caller-source-component",
                        "interface_id": "caller-component-contract",
                        "assurance_class": "contract_equivalent",
                        "implementation": {
                            "kind": "source_component",
                            "symbol": "caller",
                            "source_paths": ["hello.c"],
                        },
                    }
                ],
            }
        )
        assignments = bind_call_substitution_assignments(
            {
                "format": CALL_SUBSTITUTION_ASSIGNMENTS_FORMAT,
                "frontier_sha256": frontier["frontier_sha256"],
                "assignments": [
                    {
                        "id": "caller-cluster",
                        "call_ids": call_ids,
                        "interface_id": "caller-component-contract",
                        "substitution_id": "caller-source-component",
                        "composition": "qualified_cluster",
                    }
                ],
            }
        )
        plan = plan_call_substitutions(
            frontier=self.root / "frontier.json",
            interface_catalog=interfaces,
            substitution_catalog=substitutions,
            assignments=assignments,
            out=self.root / "plan.json",
        )
        self.assertEqual(plan["status"], "complete")

        source = self.root / "hello.c"
        source.write_text(
            "static int helper(void) { return 1; }\n"
            "int caller(void) { return helper(); }\n",
            encoding="ascii",
        )
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "helper",
                    "range": {"begin": {"file": str(source), "offset": 0}},
                    "inner": [{"kind": "CompoundStmt"}],
                },
                {
                    "kind": "FunctionDecl",
                    "name": "caller",
                    "range": {"begin": {"file": str(source), "offset": 39}},
                    "inner": [
                        {
                            "kind": "CompoundStmt",
                            "inner": [
                                {
                                    "kind": "CallExpr",
                                    "range": {
                                        "begin": {"file": str(source), "offset": 65}
                                    },
                                    "inner": [
                                        {
                                            "kind": "DeclRefExpr",
                                            "referencedDecl": {
                                                "kind": "FunctionDecl",
                                                "name": "helper",
                                            },
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            ],
        }
        write_json(self.root / "component-ast.json", ast)
        inventory = inventory_clang_source_calls(
            ast_json=self.root / "component-ast.json",
            source_root=self.root,
            source_hashes=[{"path": "hello.c", "sha256": sha256_file(source)}],
            project_symbols=["caller"],
            out=self.root / "component-inventory.json",
        )
        self.assertEqual(inventory["calls"][0]["callee_scope"], "source_local")
        bindings = bind_source_call_bindings(
            {
                "format": SOURCE_CALL_BINDINGS_FORMAT,
                "call_plan_sha256": plan["plan_sha256"],
                "source_inventory_sha256": inventory["inventory_sha256"],
                "bindings": [
                    {
                        "plan_id": "caller-cluster",
                        "source_component_symbol": "caller",
                    }
                ],
            }
        )
        report = check_source_call_bindings(
            call_plan=self.root / "plan.json",
            source_inventory=self.root / "component-inventory.json",
            bindings=bindings,
            out=self.root / "component-report.json",
        )
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["counts"]["unbound_source_local"], 0)
        self.assertEqual(report["counts"]["covered_by_source_component"], 1)

    def test_source_component_proposal_collapses_frontier_fail_closed(self) -> None:
        binding = json.loads(self.source_binding.read_text(encoding="utf-8"))
        binding.pop("binding_sha256")
        binding["sources"] = [{"path": "hello.c", "sha256": "f" * 64}]
        write_json(
            self.source_binding,
            {**binding, "binding_sha256": _canonical_sha256(binding)},
        )
        frontier = generate_call_frontier(
            source_binding=self.source_binding,
            linked_islands=self.linked_islands,
            dynamic_requirements=self.dynamic,
            out=self.root / "frontier.json",
        )
        proposed = propose_source_component_artifacts(
            frontier=self.root / "frontier.json",
            source_binding=self.source_binding,
            interfaces_out=self.root / "interfaces.json",
            substitutions_out=self.root / "substitutions.json",
            assignments_out=self.root / "assignments.json",
        )

        self.assertEqual(len(proposed["interfaces"]["interfaces"]), 1)
        interface = proposed["interfaces"]["interfaces"][0]
        self.assertEqual(interface["qualification"]["status"], "incomplete")
        self.assertEqual(
            interface["logical_contract"]["specification"]["source_symbol"],
            "caller",
        )
        self.assertEqual(
            interface["qualification"]["blockers"][0]["code"],
            "source_component_semantics_not_qualified",
        )
        self.assertEqual(
            set(interface["selector"]["endpoint_ids"]),
            {call["id"] for call in frontier["calls"] if call["source"]["island_id"] == "caller"},
        )

    def test_source_component_binding_proposal_uses_component_symbol(self) -> None:
        plan_core = {
            "format": "stage-b-call-substitution-plan-v1",
            "status": "incomplete",
            "executes_original_binary": False,
            "bindings": {},
            "assignments": [
                {
                    "id": "component-plan",
                    "source_implementation": {
                        "kind": "source_component",
                        "symbol": "caller",
                    },
                }
            ],
            "issues": [],
            "counts": {},
            "authority": {},
        }
        inventory_core = {
            "format": "stage-b-source-call-inventory-v1",
            "status": "inventoried",
            "executes_original_binary": False,
            "bindings": {"sources": []},
            "definitions": [{"symbol": "caller", "source": {}}],
            "calls": [],
            "counts": {},
        }
        write_json(
            self.root / "proposal-plan.json",
            {**plan_core, "plan_sha256": _canonical_sha256(plan_core)},
        )
        write_json(
            self.root / "proposal-inventory.json",
            {**inventory_core, "inventory_sha256": _canonical_sha256(inventory_core)},
        )

        bindings = propose_source_component_bindings(
            call_plan=self.root / "proposal-plan.json",
            source_inventory=self.root / "proposal-inventory.json",
            out=self.root / "proposal-bindings.json",
        )

        self.assertEqual(
            bindings["bindings"],
            [
                {
                    "plan_id": "component-plan",
                    "source_component_symbol": "caller",
                }
            ],
        )

    def _write_inputs(self) -> None:
        binding_core = {
            "format": SOURCE_PROJECT_BINDING_FORMAT,
            "status": "bound",
            "equivalence_status": "not_proven",
            "executes_original_binary": False,
            "program_id": "fixture",
            "bindings": {
                "original_binary_sha256": _ORIGINAL,
                "machine_ir_sha256": _MACHINE,
                "machine_ir_manifest_sha256": _MANIFEST,
                "specification_sha256": "e" * 64,
                "linked_island_manifest_sha256": None,
            },
            "sources": [],
            "islands": [
                {
                    "id": "caller",
                    "source_symbol": "caller",
                    "unit_ids": [_UNIT_A],
                    "boundary": {
                        "internal_calls": [
                            {"source_unit_id": _UNIT_A, "target_rva": 0x1100}
                        ],
                        "external_events": [
                            {
                                "source_unit_id": _UNIT_A,
                                "event_index": 0,
                                "kind": "external_call",
                                "dll": "KERNEL32.dll",
                                "symbol": "WriteFile",
                                "ordinal": None,
                            },
                            {
                                "source_unit_id": _UNIT_A,
                                "event_index": 1,
                                "kind": "indirect_call",
                            },
                        ],
                    },
                },
                {
                    "id": "callee",
                    "source_symbol": "callee",
                    "unit_ids": [_UNIT_B],
                    "boundary": {"internal_calls": [], "external_events": []},
                },
            ],
            "coverage": {},
            "authority": {},
        }
        write_json(
            self.source_binding,
            {**binding_core, "binding_sha256": _canonical_sha256(binding_core)},
        )
        islands = [
            _island("application:fixture", "application", [_UNIT_A, _UNIT_B], 0x1000, 0x1200),
            _island("import:write", "import_thunk", [_THUNK], 0x2000, 0x2006),
        ]
        manifest_core = {
            "format": LINKED_ISLAND_MANIFEST_V2_FORMAT,
            "status": "classified",
            "executes_original_binary": False,
            "bindings": {
                "original_binary_sha256": _ORIGINAL,
                "machine_ir_sha256": _MACHINE,
                "machine_ir_manifest_sha256": _MANIFEST,
            },
            "islands": islands,
            "coverage": {
                "machine_units": 3,
                "classified_units": 3,
                "classified_exactly_once": True,
                "units_by_kind": {"application": 2, "import_thunk": 1},
                "unknown_units": 0,
            },
            "counts": {},
            "issues": [],
            "authority": {
                "artifact_recognition_authorizes_replacement": False,
                "semantic_qualification_required": True,
            },
        }
        write_json(
            self.linked_islands,
            {**manifest_core, "manifest_sha256": _canonical_sha256(manifest_core)},
        )
        dynamic_core = {
            "format": DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
            "status": "qualified",
            "executes_original_binary": False,
            "bindings": {
                "machine_ir_sha256": _MACHINE,
                "machine_ir_manifest_sha256": _MANIFEST,
            },
            "libraries": [],
            "imports": [],
            "callsites": [
                {
                    "id": "dynamic:write",
                    "unit_id": _UNIT_A,
                    "import": {
                        "dll": "kernel32.dll",
                        "symbol": "WriteFile",
                        "ordinal": None,
                    },
                    "status": "qualified",
                    "argument_words": 5,
                    "abi_contract": {"contract_id": "win32:WriteFile"},
                }
            ],
            "issues": [],
            "counts": {},
            "authority": {},
        }
        write_json(
            self.dynamic,
            {**dynamic_core, "requirements_sha256": _canonical_sha256(dynamic_core)},
        )
        indirect_core = {
            "format": "stage-b-indirect-call-targets-v1",
            "source_project_binding_sha256": _canonical_sha256(binding_core),
            "targets": [
                {
                    "source_unit_id": _UNIT_A,
                    "event_index": 1,
                    "target_rvas": [0x1100],
                    "certificate_id": "fixture-indirect",
                    "status": "qualified",
                }
            ],
        }
        write_json(
            self.indirect,
            {**indirect_core, "inventory_sha256": _canonical_sha256(indirect_core)},
        )


def _island(
    island_id: str, kind: str, units: list[str], start: int, end: int
) -> dict[str, object]:
    return {
        "id": island_id,
        "kind": kind,
        "unit_ids": units,
        "unit_count": len(units),
        "rva_spans": [{"rva_start": start, "rva_end": end}],
        "replacement_authorized": False,
        "match": {
            "authority": "none" if kind == "application" else "exact_artifact",
            "identity_status": "reviewed_ownership" if kind == "application" else "exact_import_identity",
        },
    }


def _canonical_sha256(payload: object) -> str:
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


if __name__ == "__main__":
    unittest.main()
