from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.semantic_link.errors import LinkedSemanticModuleError
from spaghetti_extractor.semantic_link.diagnostics import (
    semantic_status_projection_v2,
)
from spaghetti_extractor.semantic_link.module_v2 import (
    LinkedSemanticModuleV2,
    SemanticLinkFactsV2,
    _callable_external_contracts,
    _definition_catalog,
    _definition_requirements,
    _external_contract_effects_v2,
    external_service_obligations_v2,
    _import_code_use_subject,
    _normalized_roots_and_may_symbols,
    _transfer_plan_holes_v2,
    build_linked_semantic_module_v2,
    linked_execution_view_v2,
    write_linked_semantic_module_from_inputs_v2,
)
from spaghetti_extractor.semantic_link.may_link import (
    compile_semantic_may_link_facts_v2,
)
from spaghetti_extractor.semantic_link.replay import (
    verify_linked_semantic_module_v2,
)
from spaghetti_extractor.semantic_link.worklist import (
    INCOMPLETE_PLAN_WORKLIST_STEPS,
    _effective_worklist_steps,
)
from spaghetti_extractor.semantic_objects.semantic_object import SemanticObjectV1
from spaghetti_extractor.target_bundles.project_status import build_project_status
from spaghetti_extractor.util import sha256_file, write_json
from tests.unit.semantic_link.fixture import SemanticLinkFixture

class LinkedSemanticModuleV2Tests(unittest.TestCase):
    def test_incomplete_plan_precision_worklist_is_bounded(self) -> None:
        requested = 1_000_000
        self.assertEqual(
            _effective_worklist_steps({"status": "complete"}, requested),
            requested,
        )
        self.assertEqual(
            _effective_worklist_steps({"status": "incomplete"}, requested),
            INCOMPLETE_PLAN_WORKLIST_STEPS,
        )

    def test_transfer_plan_blockers_are_semantic_completion_holes(self) -> None:
        blocker = {
            "code": "machine_ir_semantics_incomplete",
            "transfer_id": "semantic-transfer:omitted-fixture",
        }
        holes = _transfer_plan_holes_v2({"semantic_blockers": [blocker]})
        self.assertEqual(len(holes), 1)
        self.assertEqual(holes[0]["code"], "upstream_transfer_plan_incomplete")
        self.assertEqual(holes[0]["subject"], blocker["transfer_id"])
        self.assertEqual(
            holes[0]["evidence_sha256"], canonical_sha256_v3(blocker)
        )

    def test_callable_catalog_excludes_unresolved_import_identities(self) -> None:
        checked = {
            "identity": {
                "dll": "kernel32.dll", "symbol": "WriteFile",
                "ordinal": None,
            },
            "boundary": {
                "physical_call_frame_v3": {
                    "id": "physical-call-frame-v3:write-file",
                },
            },
        }
        unresolved = {
            "identity": {
                "dll": "fixture.dll", "symbol": "Unknown",
                "ordinal": None,
            },
            "boundary": None,
        }
        self.assertEqual(_callable_external_contracts({
            "machine_import_contracts": [checked, unresolved],
            "loader_service_contracts": [],
        }), [checked])

    def _module(
        self, root: Path, *, native_provenance: bool = False,
        corrupt_external_declaration: bool = False,
        extra_checked_external: bool = False,
    ) -> dict[str, object]:
        SemanticLinkFixture().linked_facts(
            root, native_provenance=native_provenance,
            corrupt_external_declaration=corrupt_external_declaration,
            extra_checked_external=extra_checked_external,
        )
        semantic, link_facts = compile_semantic_may_link_facts_v2(
            semantic_object=root / "semantic-object.json"
        )
        return build_linked_semantic_module_v2(
            semantic=semantic, link_facts=link_facts,
        )

    def test_v2_carrier_cannot_expose_v1_effect_projections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            SemanticLinkFixture().linked_facts(root)
            _semantic, facts = compile_semantic_may_link_facts_v2(
                semantic_object=root / "semantic-object.json"
            )

        self.assertNotIn("effects", facts.payload)
        self.assertEqual(set(facts.payload), {
            "bindings", "blockers", "link_provenance", "objects",
            "relocations", "roots", "symbols",
        })

    def test_v2_is_non_authorizing_and_binds_definition_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._module(Path(temporary))

        self.assertEqual(
            payload["format"],
            "spaghetti-extractor-linked-semantic-module-v2",
        )
        self.assertIs(payload["authority"], False)
        self.assertNotIn("authorizes_execution", payload)
        self.assertNotIn("edges", payload)
        self.assertEqual(
            len(payload["may_reach"]["direct_control_edges_sha256"]), 64
        )
        self.assertEqual(
            payload["counts"]["definitions"], len(payload["definitions"])
        )
        self.assertTrue(all(
            len(row["definition_sha256"]) == 64
            and row["definition_id"].startswith("semantic-definition-v2:")
            for row in payload["definitions"]
        ))
        self.assertEqual(
            {
                frozenset(row)
                for row in payload["definitions"]
            },
            {frozenset({
                "definition_id",
                "symbol_id",
                "definition_kind",
                "definition_sha256",
                "dependency_contract_sha256s",
            })},
        )
        self.assertEqual(
            {row["symbol_id"] for row in payload["definition_requirements"]},
            {row["symbol_id"] for row in payload["active_symbols"]},
        )

    def test_status_is_derived_from_semantic_holes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._module(Path(temporary))

        # The fixture intentionally has several genuine semantic/provider
        # failures.  Analysis status remains separate provenance; only the
        # semantic-hole inventory defines the V2 completeness bit.
        self.assertEqual(
            payload["status"] == "complete",
            not payload["semantic_holes"],
        )
        self.assertTrue(payload["semantic_holes"])

    def test_runtime_view_binds_v2_without_promoting_analysis_frontiers(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self._module(root)
            semantic = SemanticObjectV1.load(root / "semantic-object.json")
            linked = LinkedSemanticModuleV2(
                payload=payload,
                package_root=root,
                semantic_object=semantic,
            )

            view = linked_execution_view_v2(linked)
            transfer_content_sha256 = sha256_file(
                semantic.transfer_plan_path
            )
            environment_content_sha256 = sha256_file(
                semantic.resolved_external_environment_path
            )

        self.assertEqual(
            view["linked_semantic_module_sha256"], linked.identity
        )
        self.assertNotIn("source_execution_closure_sha256", view)
        self.assertEqual(view["blockers"], payload["semantic_holes"])
        self.assertNotEqual(
            view["blockers"], payload["analysis_frontiers"]
        )
        self.assertEqual(
            view["bindings"]["executable_transfer_plan_sha256"],
            transfer_content_sha256,
        )
        self.assertEqual(
            view["bindings"]["resolved_external_environment_sha256"],
            environment_content_sha256,
        )
        self.assertEqual(
            {row["unit_id"] for row in view["reachable_units"]},
            {
                row["symbol_id"].removeprefix("original:function:")
                for row in payload["active_symbols"]
                if row["kind"] == "function"
                and row["symbol_id"].startswith("original:function:")
            },
        )

    def test_optional_reference_analysis_is_not_a_semantic_hole(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._module(Path(temporary))

        self.assertNotIn(
            "semantic_reference_facts_unavailable",
            {row["code"] for row in payload["semantic_holes"]},
        )

    def test_external_effects_cover_callable_and_loader_slot_definitions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._module(
                Path(temporary), corrupt_external_declaration=True
            )

        effects = payload["effects"]["external_contracts"]
        self.assertEqual(
            {row["semantic_role"] for row in effects},
            {"external_function", "loader_import_slot"},
        )
        self.assertEqual(len(payload["effects"]["import_uses"]), 1)
        self.assertEqual(
            payload["effects"]["import_uses"][0]["use_kind"], "code"
        )
        stale = copy.deepcopy(payload)
        stale["effects"]["external_contracts"] = effects[:-1]
        stale["linked_semantic_module_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "linked_semantic_module_sha256"
        })
        with self.assertRaisesRegex(
            LinkedSemanticModuleError, "external effects are not total"
        ):
            LinkedSemanticModuleV2.parse(stale)

        stale = copy.deepcopy(payload)
        stale["effects"]["import_uses"] = []
        stale["linked_semantic_module_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "linked_semantic_module_sha256"
        })
        with self.assertRaisesRegex(
            LinkedSemanticModuleError, "import code-use effects are not total"
        ):
            LinkedSemanticModuleV2.parse(stale)

        blocked = copy.deepcopy(payload)
        removed_effect = blocked["effects"]["import_uses"].pop()
        site = next(
            row for row in removed_effect["sites"]
            if row["kind"] == "code_call"
        )
        hole_core = {
            "code": "checked_import_code_contract_unresolved",
            "subject": _import_code_use_subject(
                source_symbol_id=site["source_symbol_id"],
                call_id=site["call_id"],
                instruction_rva=site["instruction_rva"],
            ),
            "evidence_sha256": canonical_sha256_v3({
                "slot_id": removed_effect["slot_id"],
                "identity": removed_effect["identity"],
                "site": site,
            }),
        }
        blocked["semantic_holes"].append({
            "hole_id": "semantic-hole-v2:" + canonical_sha256_v3(hole_core),
            **hole_core,
        })
        blocked["semantic_holes"].sort(key=lambda row: row["hole_id"])
        blocked["counts"]["semantic_holes"] = len(
            blocked["semantic_holes"]
        )
        blocked["status"] = "incomplete"
        blocked["linked_semantic_module_sha256"] = canonical_sha256_v3({
            key: value for key, value in blocked.items()
            if key != "linked_semantic_module_sha256"
        })
        LinkedSemanticModuleV2.parse(blocked)

        stale = copy.deepcopy(payload)
        import_effect = stale["effects"]["import_uses"][0]
        import_effect["external_contract_sha256"] = None
        import_effect["effect_id"] = (
            "import-use-effect-v2:"
            + canonical_sha256_v3({
                key: value for key, value in import_effect.items()
                if key != "effect_id"
            })
        )
        stale["linked_semantic_module_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "linked_semantic_module_sha256"
        })
        with self.assertRaisesRegex(
            LinkedSemanticModuleError, "import-use effect is malformed"
        ):
            LinkedSemanticModuleV2.parse(stale)

    def test_checked_external_services_are_runtime_obligations_not_holes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            SemanticLinkFixture().linked_facts(root)
            semantic = SemanticObjectV1.load(root / "semantic-object.json")
            protocol = {
                "format": (
                    "spaghetti-extractor-checked-external-service-protocol-v1"
                ),
                "id": "win32-rtl-unwind-v1",
                "kind": "nonlocal_unwind",
                "arguments": {
                    "target_frame": 0,
                    "target_instruction": 1,
                    "exception_record": 2,
                    "return_value": 3,
                },
                "behavior": {
                    "frame_selection": "registered_seh_ancestor",
                    "target_selection": "checked_guest_code_capability",
                    "exception_record": "nullable_checked_exception_record",
                    "return_value": "eax_word",
                    "unwind": "x86_seh_unwind",
                    "abandoned_lifetimes": "invalidate",
                    "outcome": "nonlocal",
                },
            }
            effect = {
                "effect_id": "external-contract-effect-v2:fixture",
                "semantic_role": "external_function",
                "symbol_id": "external:function:rtl-unwind",
                "identity": {
                    "dll": "kernel32.dll",
                    "symbol": "RtlUnwind",
                    "ordinal": None,
                },
                "contract_sha256": "a" * 64,
                "external_service_protocol": protocol,
                "root_ids": ["module:process-entry"],
                "domain_ids": [],
            }
            import_use = {
                "external_contract_sha256": "a" * 64,
                "use_kind": "code",
                "sites": [{
                    "kind": "code_call",
                    "source_symbol_id": "original:function:fixture",
                    "call_id": 0,
                    "instruction_rva": 0x1234,
                    "root_ids": ["module:process-entry"],
                    "domain_ids": [],
                }],
            }
            obligations = external_service_obligations_v2(
                semantic=semantic,
                external_contract_effects=[effect],
                import_use_effects=[import_use],
            )

        self.assertEqual(len(obligations), 1)
        self.assertEqual(
            obligations[0]["class"],
            "checked_external_nonlocal_service",
        )
        self.assertEqual(
            obligations[0]["allowed_provider_kinds"],
            ["qualified_runtime"],
        )
        self.assertEqual(
            obligations[0]["admitted_domain"]["protocol"], protocol
        )

    def test_callable_domain_activates_every_checked_external_member(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked = SemanticLinkFixture().linked_facts(
                root,
                corrupt_external_declaration=True,
                extra_checked_external=True,
            )
            semantic = SemanticObjectV1.load(root / "semantic-object.json")
            definitions = _definition_catalog(semantic)
            paired_contract = next(
                row
                for row in semantic.resolved_external_environment.payload[
                    "machine_import_contracts"
                ]
                if row["identity"]["symbol"] == "GetProcAddress"
            )
            contract_sha256 = canonical_sha256_v3(paired_contract)
            frame = paired_contract["boundary"]["physical_call_frame_v3"]
            domain_core = {
                "kind": "checked_indirect_callable_targets_v3",
                "logical_guest_frame": "logical_machine_state_v2",
                "resolved_environment_sha256": (
                    semantic.resolved_external_environment.identity
                ),
                "guest_transfer_entry_rvas": [0x1000],
                "external_loader_targets": [{
                    "identity": dict(paired_contract["identity"]),
                    "import_kind": paired_contract["import_kind"],
                    "cell_index": paired_contract["cell_index"],
                    "iat_rva": paired_contract["iat_rva"],
                    "contract_sha256": contract_sha256,
                    "physical_frame_id": frame["id"],
                    "physical_frame_sha256": canonical_sha256_v3(frame),
                }],
                "external_interface_targets": [],
                "selection": {
                    "guest": "active_code_capability_address",
                    "external": "checked_loader_code_capability",
                    "interface": (
                        "live_factory_interface_vtable_method_capability"
                    ),
                    "ambiguity": "reject",
                    "no_match": "reject",
                },
            }
            domain = {
                **domain_core,
                "domain_sha256": canonical_sha256_v3(domain_core),
            }
            _, active_symbols = _normalized_roots_and_may_symbols(
                linked, definitions, [domain], semantic
            )

            callable_symbol = next(
                row for row in active_symbols
                if row["resolution"].get("contract_sha256")
                == contract_sha256
                and row["kind"] == "external_function"
            )
            self.assertIn(
                domain["domain_sha256"], callable_symbol["domain_ids"]
            )
            loader_slot = next(
                row for row in active_symbols
                if row["kind"] == "unclassified_import"
                and row["resolution"].get("contract_sha256")
                == contract_sha256
            )
            self.assertIn(domain["domain_sha256"], loader_slot["domain_ids"])
            requirement = next(
                row for row in _definition_requirements(
                    definitions, active_symbols
                )
                if row["symbol_id"] == callable_symbol["symbol_id"]
            )
            self.assertEqual(
                requirement["allowed_provider_kinds"],
                ["external_environment"],
            )
            effect = next(
                row for row in _external_contract_effects_v2(
                    semantic=semantic, active_symbols=active_symbols
                )
                if row["symbol_id"] == callable_symbol["symbol_id"]
            )
            self.assertEqual(effect["contract_sha256"], contract_sha256)
            # This fixture deliberately corrupts the worklist declaration's
            # outcome catalog. Pairing the callable and its loader slot must
            # preserve that fail-closed empty outcome set rather than repair
            # it while closing may-reach provenance.
            self.assertEqual(effect["allowed_outcomes"], [])

            stale = copy.deepcopy(linked)
            stale["symbols"] = [
                row for row in stale["symbols"]
                if row["symbol_id"] != callable_symbol["symbol_id"]
            ]
            with self.assertRaisesRegex(
                LinkedSemanticModuleError,
                "runtime admitted external target has no unique definition",
            ):
                _normalized_roots_and_may_symbols(
                    stale, definitions, [domain], semantic
                )

    def test_loader_owned_iat_cell_does_not_activate_unused_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked = SemanticLinkFixture().linked_facts(root)
            semantic = SemanticObjectV1.load(root / "semantic-object.json")
            definitions = _definition_catalog(semantic)
            unused = {
                **copy.deepcopy(linked["symbols"][0]),
                "symbol_id": "external:import:fixture.exe:iat:00002000",
                "kind": "unclassified_import",
                "linkage": "external",
                "visibility": "loader",
                "storage_class": "iat_slot",
                "original_rva": 0x2000,
                "declaration": {
                    "slot_id": "fixture.exe:iat:00002000",
                    "dll": "kernel32.dll",
                    "symbol": "UnusedImport",
                    "environment_contract_sha256": None,
                },
                "resolution": {"kind": "unresolved_external"},
                "reachable": False,
                "root_ids": [],
            }
            linked["symbols"].append(unused)

            roots, active_symbols = _normalized_roots_and_may_symbols(
                linked, definitions, [], semantic
            )

        self.assertFalse(any(
            row["kind"] == "loader_storage"
            and row["target_symbol"] == unused["symbol_id"]
            for row in roots
        ))
        self.assertNotIn(
            unused["symbol_id"],
            {row["symbol_id"] for row in active_symbols},
        )

    def test_may_closure_activates_runtime_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            SemanticLinkFixture().linked_facts(root)
            semantic, facts = compile_semantic_may_link_facts_v2(
                semantic_object=root / "semantic-object.json"
            )
            linked = copy.deepcopy(facts.payload)
            dependency = semantic.payload["effect_index"][
                "runtime_primitive_dependencies"
            ][0]
            target_id = dependency["target_symbol"]
            target = next(
                row for row in linked["symbols"]
                if row["symbol_id"] == target_id
            )
            # Simulate a primitive required only after a later may-domain
            # admission. The final closure must not depend on the narrower
            # static seed carried by the construction facts.
            target["reachable"] = False
            target["root_ids"] = []
            definitions = _definition_catalog(semantic)
            _roots, active_symbols = _normalized_roots_and_may_symbols(
                linked, definitions, [], semantic
            )

        active = {
            row["symbol_id"]: row for row in active_symbols
        }
        self.assertIn(target_id, active)
        self.assertTrue(active[target_id]["root_ids"])

    def test_content_addressed_definition_and_module_tampering_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = self._module(Path(temporary))
        stale = copy.deepcopy(payload)
        stale["definitions"][0]["definition_kind"] = "invented"
        with self.assertRaisesRegex(LinkedSemanticModuleError, "self hash"):
            LinkedSemanticModuleV2.parse(stale)

        stale["linked_semantic_module_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "linked_semantic_module_sha256"
        })
        with self.assertRaisesRegex(LinkedSemanticModuleError, "definition_id"):
            LinkedSemanticModuleV2.parse(stale)

    def test_operator_status_separates_semantics_from_execution_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self._module(root)
            module_path = root / "linked-semantic-module-v2.json"
            write_json(module_path, payload)
            status = build_project_status(
                target_id="fixture",
                linked_semantic_module=module_path,
                out=root / "status.json",
            )
            diagnostic = semantic_status_projection_v2(module_path)

        subject = status["subjects"][0]
        self.assertIs(subject["authority"], False)
        self.assertEqual(subject["state"], payload["status"])
        self.assertEqual(
            subject["blockers"], payload["semantic_holes"]
        )
        self.assertEqual(
            subject["bindings"][0]["residual_obligations"],
            len(payload["residual_obligations"]),
        )
        self.assertIs(diagnostic["authority"], False)
        self.assertEqual(
            diagnostic["counts"]["semantic_holes"],
            len(payload["semantic_holes"]),
        )

    def test_direct_may_link_matches_the_packaged_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = self._module(root)
            actual = write_linked_semantic_module_from_inputs_v2(
                semantic_object=root / "semantic-object.json",
                out=root / "v2-package",
            )

        self.assertEqual(actual, expected)

    def test_direct_v2_package_passes_independent_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._module(root)
            write_linked_semantic_module_from_inputs_v2(
                semantic_object=root / "semantic-object.json",
                out=root / "v2-package",
            )
            linked = verify_linked_semantic_module_v2(
                linked_semantic_module=(
                    root / "v2-package" / "linked-semantic-module.json"
                ),
            )

        self.assertEqual(linked.payload["format"], (
            "spaghetti-extractor-linked-semantic-module-v2"
        ))


if __name__ == "__main__":
    unittest.main()
