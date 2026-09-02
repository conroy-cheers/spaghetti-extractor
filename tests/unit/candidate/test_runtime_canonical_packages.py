"""Source-package and callback-capability cases for canonical runtimes."""

from __future__ import annotations

import unittest

from spaghetti_extractor.semantic_link.errors import LinkedSemanticModuleError

from .test_runtime_canonical import (
    CandidateRuntimeError,
    CanonicalRuntimeError,
    Path,
    PhysicalCallFrameV2,
    _callback_capability_index,
    _inputs,
    canonical_sha256_v3,
    json,
    patch,
    plan_module_runtime_from_canonical,
    sha256_file,
    tempfile,
    write_json,
    write_shared_module_runtime_package,
    write_shared_module_runtime_package_from_linked_module,
    write_spx_behavioral_c_package,
)


class CanonicalRuntimePackageTests(unittest.TestCase):
    def test_shared_runtime_emits_canonical_sources_without_a_core_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _inputs(root)
            behavioral = root / "behavioral"
            write_spx_behavioral_c_package(
                transfer_plan=inputs["transfer_plan"], out=behavioral,
            )
            output = root / "shared-runtime-direct"
            manifest = write_shared_module_runtime_package(
                behavioral_c_package=behavioral,
                transfer_plan=inputs["transfer_plan"],
                execution_closure=inputs["execution_closure"],
                resolved_external_environment=inputs[
                    "resolved_external_environment"
                ],
                native_ingress_plan=inputs["native_ingress_plan"],
                object_authority=root / "machine-object-authority.json",
                out=output,
            )
            self.assertEqual(manifest["status"], "ready", manifest["blockers"])
            self.assertNotIn("runtime_core_manifest", manifest["inputs"])
            self.assertFalse(
                (output / "module-runtime-core-package.json").exists()
            )
            roles = {row["role"] for row in manifest["sources"]}
            self.assertTrue({
                "module_runtime_source",
                "module_runtime_bridge_assembly",
                "module_runtime_layout_source",
                "native_ingress_source",
                "native_ingress_bridge_assembly",
                "shared_module_runtime_source",
            } <= roles)
            module_runtime_source = (
                output / "module-runtime.c"
            ).read_text(encoding="ascii")
            self.assertIn("spx_native_capability_commit(", module_runtime_source)
            self.assertIn(
                "uint32_t spx_native_code_bridge_address(",
                module_runtime_source,
            )
            self.assertIn(
                "uint32_t spx_native_publish_registered_code_result(",
                module_runtime_source,
            )
            self.assertIn(
                "spx_native_compact_code_capability_for(",
                module_runtime_source,
            )
            self.assertIn(
                "callback_capability_generation =\n"
                "            spx_native_compact_callback_activate(",
                module_runtime_source,
            )
            self.assertIn(
                "spx_native_compact_callback_commit(",
                module_runtime_source,
            )
            self.assertIn(
                "spx_native_compact_callback_revoke(",
                module_runtime_source,
            )
            module_runtime_header = (
                output / "module-runtime.h"
            ).read_text(encoding="ascii")
            bridge_assembly = (
                output / "module-ingress-bridges.S"
            ).read_text(encoding="ascii")
            native_ingress_source = (
                output / "native-ingress-runtime.c"
            ).read_text(encoding="ascii")
            self.assertIn(
                "authorized complete variadic suffix", bridge_assembly
            )
            self.assertIn("rep movsd", bridge_assembly)
            self.assertIn("expected_capture_esp", module_runtime_header)
            self.assertIn("logical_result_esp", module_runtime_header)
            self.assertIn("uint32_t tail_jump;", module_runtime_header)
            self.assertNotIn("continuation_replaced", module_runtime_header)
            self.assertNotIn("continuation_replaced", module_runtime_source)
            self.assertNotIn(
                "_spx_native_outgoing_stack_enter_host", bridge_assembly
            )
            self.assertNotIn(
                "_spx_native_outgoing_stack_leave_host", bridge_assembly
            )
            self.assertNotIn(
                "mov esp, DWORD PTR [ecx + 28]", bridge_assembly
            )
            self.assertIn(
                "A root owns the complete qualified stack reserve",
                native_ingress_source,
            )
            self.assertIn(
                "scratch_address = private_stack_base -",
                native_ingress_source,
            )
            self.assertIn(
                "scratch_address = capture_address -",
                native_ingress_source,
            )
            self.assertIn(
                "host_stack_limit != private_stack_limit",
                native_ingress_source,
            )
            self.assertNotIn("header->stack_bump", native_ingress_source)
            self.assertIn("SPX_MODULE_RUNTIME_H", module_runtime_header)
            self.assertIn(
                "spx_native_code_bridge_address(uint32_t target_rva)",
                module_runtime_header,
            )
            self.assertNotIn("SPX_MODULE_RUNTIME_CORE_H", module_runtime_header)
            generated_assembly = "\n".join(
                path.read_text(encoding="ascii")
                for path in output.glob("*.s")
            )
            self.assertNotIn("ud2", generated_assembly)
            canonical_inputs = manifest["inputs"]["canonical_inputs"]
            self.assertEqual(
                canonical_inputs["module_execution_closure"]["sha256"],
                sha256_file(inputs["execution_closure"]),
            )
            self.assertEqual(
                canonical_inputs["resolved_external_environment"]["sha256"],
                sha256_file(inputs["resolved_external_environment"]),
            )
            self.assertNotIn("portable_semantic_provider", canonical_inputs)

    def test_stale_environment_binding_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = _inputs(Path(temporary))
            closure = json.loads(
                inputs["execution_closure"].read_text(encoding="utf-8")
            )
            closure["bindings"]["resolved_external_environment_sha256"] = "0" * 64
            core = {
                key: value for key, value in closure.items()
                if key != "closure_sha256"
            }
            write_json(inputs["execution_closure"], {
                **core, "closure_sha256": canonical_sha256_v3(core),
            })
            with self.assertRaisesRegex(
                CanonicalRuntimeError, "does not bind the canonical runtime inputs"
            ):
                plan_module_runtime_from_canonical(**inputs)

    def test_callback_capabilities_preserve_registration_site_identity(self) -> None:
        image_id = "fixture.dll"
        target = 0x2200
        escapes = [
            {
                "instruction_rva": instruction,
                "dll": "user32.dll",
                "identity": symbol,
                "protocol_id": protocol,
                "targets": [target],
                "action": "register",
                "lifetime": lifetime,
                "delivery": {"thread": "same_or_foreign"},
            }
            for instruction, symbol, protocol, lifetime in (
                (0x1010, "SetTimer", "callback:timer", "during_call"),
                (
                    0x1020, "SetWindowsHookExA", "callback:hook",
                    "until_resource_event_or_process_exit:hook_removed",
                ),
            )
        ]
        ingresses = []
        expected = {}
        for escape in escapes:
            root_id = "callback-escape-v1:" + canonical_sha256_v3(escape)
            capability_id = "code-capability-v1:" + canonical_sha256_v3({
                "module": image_id,
                "escape": escape,
                "target_rva": target,
            })
            ingresses.append({
                "role": "callback",
                "root_ids": [root_id],
                "target_rva": target,
                "capability_id": capability_id,
                "capability_lifetime": escape["lifetime"],
            })
            expected[(
                escape["instruction_rva"], escape["protocol_id"], target,
            )] = capability_id
        observed = _callback_capability_index(
            closure={"callback_escapes": escapes},
            ingress={"ingresses": ingresses},
            image_id=image_id,
        )
        self.assertEqual(observed.eager, expected)
        self.assertEqual(len(set(observed.eager.values())), 2)

        ingresses[0]["capability_id"] = ingresses[1]["capability_id"]
        with self.assertRaisesRegex(
            CanonicalRuntimeError, "stale or changes lifetime"
        ):
            _callback_capability_index(
                closure={"callback_escapes": escapes},
                ingress={"ingresses": ingresses},
                image_id=image_id,
            )

    def test_callback_capability_index_consumes_compact_domains_once(self) -> None:
        image_id = "fixture-image"
        targets = [0x2010, 0x2020, 0x2030]
        escape = {
            "instruction_rva": 0x1010,
            "dll": "fixture.dll",
            "identity": "Register",
            "protocol_id": "callback:fixture",
            "targets": targets,
            "action": "register",
            "lifetime": "until_replaced_or_process_exit",
            "delivery": {"thread": "same_or_foreign"},
        }
        escape_id = "callback-escape-v1:" + canonical_sha256_v3(escape)
        transport = PhysicalCallFrameV2.create(
            subject={
                "kind": "callback", "id": "callback:fixture",
                "image_selector": image_id,
            },
            transfer_kind="callback",
            target="i686-pc-windows-gnu",
            abi_dialect="pe32-i386-gnu-v1",
            calling_convention="stdcall",
            arguments=[], results=[],
            stack={
                "coordinate": "callee-entry-esp", "alignment_bytes": 4,
                "cleanup": "callee", "cleanup_bytes": 4,
                "reserved_bytes": 0,
            },
            preserved_state=["ebx", "ebp", "esi", "edi"],
            clobbered_state=["eax", "ecx", "edx", "eflags"],
            outcomes=["normal"],
        )
        domain_id = "callback-domain-v1:" + "a" * 64
        family_id = "callback-bridge-family-v1:" + "b" * 64
        publication_id = "callback-publication-v1:" + "c" * 64
        ingress = {
            "ingresses": [],
            "outcome_protocols": [{
                "id": "outcome:normal", "outcomes": ["normal"],
            }],
            "callback_domains": [{
                "id": domain_id,
                "protocol_id": "callback:fixture",
                "target_rvas": targets,
                "physical_frame": {
                    "id": transport.frame_id,
                    "transport": transport.to_payload(),
                },
                "outcome_groups": [{
                    "outcome_protocol_id": "outcome:normal",
                    "target_rvas": targets,
                }],
                "bridge_family_id": family_id,
                "trampoline_table_symbol": "spx_callback_trampolines_0000",
                "trampoline_stride_bytes": 10,
            }],
            "callback_bridge_families": [{
                "id": family_id,
                "symbol": "spx_callback_bridge_family_0000",
                "cleanup_bytes": 4,
                "physical_frame_ids": [transport.frame_id],
                "domain_ids": [domain_id],
            }],
            "callback_publications": [{
                "id": publication_id,
                "domain_id": domain_id,
                "escape_id": escape_id,
                "instruction_rva": 0x1010,
                "lifetime": "until_replaced_or_process_exit",
            }],
        }
        observed = _callback_capability_index(
            closure={"callback_escapes": [escape]},
            ingress=ingress,
            image_id=image_id,
        )
        self.assertEqual(observed.eager, {})
        self.assertEqual(
            observed.compact[(0x1010, "callback:fixture")]["id"],
            publication_id,
        )
        self.assertEqual(
            [row.target_rva for row in observed.compact_runtime.targets],
            targets,
        )
        self.assertEqual(
            [row.global_target_index for row in observed.compact_runtime.targets],
            [0, 1, 2],
        )

    def test_linked_runtime_rejects_malformed_linked_execution_view(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "linked-semantic-module.json", {
                "format": "spaghetti-extractor-linked-semantic-module-v2",
            })
            with (
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "LinkedSemanticModuleV2.load",
                    side_effect=LinkedSemanticModuleError(
                        "linked-module effects must be an object"
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    CandidateRuntimeError,
                    "linked-module effects must be an object",
                ):
                    write_shared_module_runtime_package_from_linked_module(
                        linked_semantic_module=root,
                        behavioral_c_package=root / "behavioral",
                        out=root / "out",
                    )
