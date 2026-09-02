"""Canonical artifact and locator validation cases for module runtimes."""

from __future__ import annotations

import unittest

from .test_runtime_canonical import (
    Path,
    _inputs,
    canonical_sha256_v3,
    json,
    sha256_file,
    tempfile,
    write_json,
    write_shared_module_runtime_package,
    write_spx_behavioral_c_package,
)


class CanonicalRuntimeArtifactTests(unittest.TestCase):
    def test_canonical_artifacts_emit_the_shared_runtime_vertical_slice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _inputs(root)
            behavioral = root / "behavioral"
            write_spx_behavioral_c_package(
                transfer_plan=inputs["transfer_plan"],
                out=behavioral,
            )
            shared = write_shared_module_runtime_package(
                behavioral_c_package=behavioral,
                transfer_plan=inputs["transfer_plan"],
                execution_closure=inputs["execution_closure"],
                resolved_external_environment=inputs["resolved_external_environment"],
                native_ingress_plan=inputs["native_ingress_plan"],
                object_authority=root / "machine-object-authority.json",
                out=root / "shared-runtime",
            )
            self.assertEqual(shared["status"], "ready", shared["blockers"])
            self.assertEqual(
                shared["policy"]["execution_scope"],
                "module-execution-closure-v2",
            )
            self.assertFalse(shared["policy"]["structural_execution_receipt_required"])
            self.assertFalse(
                any(
                    source["role"] == "portable_semantic_provider"
                    for source in shared["sources"]
                )
            )
            self.assertFalse(
                any(
                    source["role"] == "external_profile" for source in shared["sources"]
                )
            )
            self.assertEqual(shared["counts"]["guest_dispatch_sites"], 1)
            self.assertEqual(shared["counts"]["guest_dispatch_domains"], 1)
            self.assertEqual(shared["counts"]["guest_dispatch_domain_targets"], 1)
            self.assertEqual(shared["counts"]["nonlocal_transitions"], 0)
            self.assertEqual(shared["counts"]["transfers"], 2)
            runtime_source = (
                root / "shared-runtime" / "shared-module-runtime.c"
            ).read_text(encoding="ascii")
            self.assertEqual(runtime_source.count("uint32_t spx_ref_derive("), 1)
            self.assertEqual(runtime_source.count("uint32_t spx_ref_difference("), 1)
            self.assertEqual(runtime_source.count("uint32_t spx_view_read_u8("), 1)
            self.assertIn(
                "static const spx_native_guest_dispatch_site",
                runtime_source,
            )
            self.assertIn(
                "spx_native_guest_dispatch_external_iats",
                runtime_source,
            )
            self.assertIn(
                "site->external_target_count",
                runtime_source,
            )
            self.assertIn(
                "spx_native_loader_code_target_matches",
                runtime_source,
            )
            self.assertIn("spx_native_ascii_text_matches", runtime_source)
            self.assertIn("event->dll, narrowed_module->dll", runtime_source)
            self.assertIn(
                "spx_native_loader_target_words",
                runtime_source,
            )
            self.assertIn("__atomic_compare_exchange_n", runtime_source)
            self.assertIn("__ATOMIC_ACQUIRE", runtime_source)
            self.assertIn("spx_code_site_kind site_kind", runtime_source)
            guest_table = runtime_source.split(
                "static const uint32_t spx_native_guest_dispatch_targets[] = {",
                1,
            )[1].split("};", 1)[0]
            self.assertIn("0x00001000U", guest_table)
            self.assertNotIn("0x00002000U", guest_table)
            resolver = runtime_source.split(
                "static uint32_t spx_native_resolve_code_target(", 1
            )[1].split("static uint32_t spx_native_callable_argument_value(", 1)[0]
            self.assertNotIn("spx_native_transfer_count", resolver)
            self.assertIn("rule->locator_kind == 3U", runtime_source)
            self.assertIn("rule->locator_kind == 4U", runtime_source)
            self.assertIn("spx_native_captured_stack_rule_base", runtime_source)
            self.assertIn("static uint32_t spx_native_route_nonlocal(", runtime_source)
            self.assertIn("spx_native_runtime_begin_exception_object(", runtime_source)
            self.assertIn("spx_native_runtime_finish_exception_object(", runtime_source)
            self.assertIn("SPX_NATIVE_EXCEPTION_RECORD_LIMIT 16U", runtime_source)
            self.assertIn(
                "spx_native_exception_service_memory_access(",
                runtime_source,
            )
            self.assertIn("spx_native_physical_frame_memory_access(", runtime_source)
            self.assertIn("if (found == 0U) return 2U;", runtime_source)
            self.assertIn("if (target_rva == 0U) return 2U;", runtime_source)
            self.assertIn(
                "context->image_base + rule->locator_subject_rva",
                runtime_source,
            )
            object_table = runtime_source.split(
                "spx_native_object_authority_rules[] = {", 1
            )[1].split("};", 1)[0]
            self.assertIn("0x00003000U", object_table)
            self.assertIn('"fixture-image-data"', object_table)
            self.assertIn("const char *identity", runtime_source)
            self.assertIn(
                "uint32_t permissions, const char *authority_selector",
                runtime_source,
            )
            self.assertIn(
                "if (selector_known == 0U) return SPX_BOUNDARY_TYPE_MISMATCH;",
                runtime_source,
            )
            self.assertIn("spx_native_dynamic_external_object_instance", runtime_source)
            self.assertIn("external_range_rule_selector", runtime_source)
            read_gate = runtime_source.split(
                "static uint32_t spx_native_read_allowed(", 1
            )[1].split("static uint32_t spx_native_u32(", 1)[0]
            self.assertLess(
                read_gate.index("spx_native_exception_memory_access("),
                read_gate.index("context->stack_low"),
            )
            runtime_header = (
                root / "behavioral" / "state-machine-runtime.h"
            ).read_text(encoding="ascii")
            self.assertIn("SPX_CODE_SITE_INDIRECT_JUMP", runtime_header)
            module_runtime_source = (
                root / "shared-runtime" / "module-runtime.c"
            ).read_text(encoding="ascii")
            self.assertIn("external_service_kind", module_runtime_source)
            self.assertIn(
                "spx_native_runtime_begin_exception_object(",
                module_runtime_source,
            )
            self.assertIn(
                "spx_native_runtime_finish_exception_object(",
                module_runtime_source,
            )
            ingress_source = (
                root / "shared-runtime" / "native-ingress-runtime.c"
            ).read_text(encoding="ascii")
            self.assertIn(
                "uint32_t spx_native_captured_stack_rule_base(",
                ingress_source,
            )
            self.assertIn("*generation = frame->generation", ingress_source)
            self.assertIn(
                "uint32_t spx_native_exception_memory_access(",
                ingress_source,
            )
            self.assertIn(
                "uint32_t spx_native_physical_frame_memory_access(",
                ingress_source,
            )
            self.assertIn(
                "spx_native_runtime_bind_exception_filter_callback(",
                ingress_source,
            )
            self.assertIn("descriptor->exception_filter_callback", ingress_source)
            self.assertIn(
                "projection_mask & bit",
                ingress_source,
            )
            self.assertIn("spx_native_apply_exception_context(", ingress_source)

    def test_canonical_planning_blocker_emits_no_runtime_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _inputs(root)
            environment_path = inputs["resolved_external_environment"]
            environment = json.loads(environment_path.read_text(encoding="utf-8"))
            environment["original_semantic_imports"] = []
            environment["generated_runtime_support_imports"] = []
            environment.pop("resolved_environment_sha256")
            environment["resolved_environment_sha256"] = canonical_sha256_v3(
                environment
            )
            write_json(environment_path, environment)

            closure_path = inputs["execution_closure"]
            closure = json.loads(closure_path.read_text(encoding="utf-8"))
            closure["bindings"]["resolved_external_environment_sha256"] = sha256_file(
                environment_path
            )
            closure.pop("closure_sha256")
            closure["closure_sha256"] = canonical_sha256_v3(closure)
            write_json(closure_path, closure)

            ingress_path = inputs["native_ingress_plan"]
            ingress = json.loads(ingress_path.read_text(encoding="utf-8"))
            ingress["module"]["resolved_external_environment_sha256"] = sha256_file(
                environment_path
            )
            ingress["module"]["module_execution_closure_sha256"] = sha256_file(
                closure_path
            )
            ingress.pop("plan_sha256")
            ingress["plan_sha256"] = canonical_sha256_v3(ingress)
            write_json(ingress_path, ingress)

            behavioral = root / "behavioral"
            write_spx_behavioral_c_package(
                transfer_plan=inputs["transfer_plan"],
                out=behavioral,
            )
            output = root / "shared-runtime"
            manifest = write_shared_module_runtime_package(
                behavioral_c_package=behavioral,
                transfer_plan=inputs["transfer_plan"],
                execution_closure=closure_path,
                resolved_external_environment=environment_path,
                native_ingress_plan=ingress_path,
                object_authority=root / "machine-object-authority.json",
                out=output,
            )

            self.assertEqual(manifest["status"], "incomplete")
            self.assertEqual(
                {row["category"] for row in manifest["blockers"]},
                {"process_entry_termination_support_missing"},
            )
            self.assertEqual(
                {row["path"] for row in manifest["sources"]},
                {"module-runtime-plan.json", "native-ingress-plan.json"},
            )
            self.assertFalse((output / "module-runtime.c").exists())

    def test_unknown_data_import_locator_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _inputs(root)
            authority_path = root / "machine-object-authority.json"
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            imported = next(
                row
                for row in authority["rules"]
                if row["locator"]["kind"] == "resolved_data_import"
            )
            imported["locator"]["slot_id"] = "fixture.exe:iat:00004000"
            authority.pop("authority_sha256")
            authority["authority_sha256"] = canonical_sha256_v3(authority)
            write_json(authority_path, authority)

            ingress_path = inputs["native_ingress_plan"]
            ingress = json.loads(ingress_path.read_text(encoding="utf-8"))
            ingress["module"]["object_authority_sha256"] = authority["authority_sha256"]
            ingress.pop("plan_sha256")
            ingress["plan_sha256"] = canonical_sha256_v3(ingress)
            write_json(ingress_path, ingress)

            behavioral = root / "behavioral"
            write_spx_behavioral_c_package(
                transfer_plan=inputs["transfer_plan"],
                out=behavioral,
            )
            manifest = write_shared_module_runtime_package(
                behavioral_c_package=behavioral,
                transfer_plan=inputs["transfer_plan"],
                execution_closure=inputs["execution_closure"],
                resolved_external_environment=inputs["resolved_external_environment"],
                native_ingress_plan=inputs["native_ingress_plan"],
                object_authority=authority_path,
                out=root / "shared-runtime",
            )
            self.assertEqual(manifest["status"], "incomplete")
            self.assertIn(
                "runtime_data_import_locator_unresolved",
                {row["category"] for row in manifest["blockers"]},
            )

    def test_unknown_captured_stack_frame_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _inputs(root)
            authority_path = root / "machine-object-authority.json"
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            captured = next(
                row
                for row in authority["rules"]
                if row["locator"]["kind"] == "captured_stack"
            )
            captured["locator"]["frame_id"] = "physical-frame:unknown"
            authority.pop("authority_sha256")
            authority["authority_sha256"] = canonical_sha256_v3(authority)
            write_json(authority_path, authority)

            ingress_path = inputs["native_ingress_plan"]
            ingress = json.loads(ingress_path.read_text(encoding="utf-8"))
            ingress["module"]["object_authority_sha256"] = authority["authority_sha256"]
            ingress.pop("plan_sha256")
            ingress["plan_sha256"] = canonical_sha256_v3(ingress)
            write_json(ingress_path, ingress)

            behavioral = root / "behavioral"
            write_spx_behavioral_c_package(
                transfer_plan=inputs["transfer_plan"],
                out=behavioral,
            )
            manifest = write_shared_module_runtime_package(
                behavioral_c_package=behavioral,
                transfer_plan=inputs["transfer_plan"],
                execution_closure=inputs["execution_closure"],
                resolved_external_environment=inputs["resolved_external_environment"],
                native_ingress_plan=inputs["native_ingress_plan"],
                object_authority=authority_path,
                out=root / "shared-runtime",
            )
            self.assertEqual(manifest["status"], "incomplete")
            self.assertIn(
                "runtime_captured_stack_frame_unresolved",
                {row["category"] for row in manifest["blockers"]},
            )

    def test_unknown_external_allocation_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _inputs(root)
            authority_path = root / "machine-object-authority.json"
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            authority["rules"].append(
                {
                    "id": "fixture-allocation",
                    "kind": "external",
                    "domain": 3,
                    "object": 41,
                    "generation": 1,
                    "extent": 16,
                    "permissions": 3,
                    "lifetime": "allocation",
                    "locator": {
                        "kind": "external_allocation",
                        "allocation_id": "contract:missing",
                        "offset": 0,
                    },
                    "interior_pointers": True,
                    "evidence_sha256": "c" * 64,
                }
            )
            authority["rules"].sort(key=lambda row: row["id"])
            authority.pop("authority_sha256")
            authority["authority_sha256"] = canonical_sha256_v3(authority)
            write_json(authority_path, authority)

            ingress_path = inputs["native_ingress_plan"]
            ingress = json.loads(ingress_path.read_text(encoding="utf-8"))
            ingress["module"]["object_authority_sha256"] = authority["authority_sha256"]
            ingress.pop("plan_sha256")
            ingress["plan_sha256"] = canonical_sha256_v3(ingress)
            write_json(ingress_path, ingress)

            behavioral = root / "behavioral"
            write_spx_behavioral_c_package(
                transfer_plan=inputs["transfer_plan"],
                out=behavioral,
            )
            manifest = write_shared_module_runtime_package(
                behavioral_c_package=behavioral,
                transfer_plan=inputs["transfer_plan"],
                execution_closure=inputs["execution_closure"],
                resolved_external_environment=inputs["resolved_external_environment"],
                native_ingress_plan=inputs["native_ingress_plan"],
                object_authority=authority_path,
                out=root / "shared-runtime",
            )
            self.assertEqual(manifest["status"], "incomplete")
            self.assertIn(
                "runtime_external_allocation_locator_unresolved",
                {row["category"] for row in manifest["blockers"]},
            )
