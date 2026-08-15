from __future__ import annotations

from tests.unit.candidate.native_runtime._support import *


class NativeRuntimeFailurePolicyTests(unittest.TestCase):
    def test_uncontracted_variadic_site_prevents_candidate_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "external-profile.json"
            profile.write_text(
                json.dumps({
                    "format": "stage-a-external-environment-profile-v1",
                    "id": "fixture-variadic-profile-v1",
                    "machine_import_signatures": [{
                        "import": {
                            "dll": "msvcrt.dll",
                            "symbol": "__p__commode",
                        },
                        "abi_template": "pe32-cdecl-v1",
                        "arity": {
                            "kind": "variadic",
                            "minimum_words": 1,
                            "format_argument": 0,
                            "format_unit_bytes": 1,
                        },
                        "memory_effect": "relationalState",
                        "memory_footprints": [],
                        "world_effect": "none",
                    }],
                }, sort_keys=True),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                StageAInputError, "native engine plan is incomplete"
            ):
                _packages(
                    root,
                    rows=_machine_ir_indirect_external_result_rows(),
                    import_iat_vas={("msvcrt.dll", "__p__commode"): 0x43219C},
                )

    def test_qualified_unobserved_undefined_slot_uses_recorded_zero_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_undefined_transfer()])
            slot = _attach_definedness_metadata(
                interpreter,
                classification="unconstrained_noninterfering",
            )
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            definedness = package["inputs"]["definedness_use"]
            self.assertEqual(definedness["format"], DEFINEDNESS_USE_FORMAT)
            self.assertRegex(definedness["metadata_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(definedness["slots"], [{
                "slot": slot,
                "undefined_id": "fixture:undefined:eax",
                "classification": "unconstrained_noninterfering",
                "witness_policy": "zero",
                "choice_kind": "noninterfering_zero",
                "input_location": None,
                "obligation_count": 0,
                "use_count": 1,
            }])
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn(f"{{ 0x{slot:08x}U, 0U, 0U }}", source)
            undefined_body = source.split(
                "static uint32_t stage_b_native_undefined_value", 1
            )[1].split("static uint32_t stage_b_native_resolve_code_target", 1)[0]
            self.assertIn("return 0U;", undefined_body)
            self.assertNotIn("stage_b_native_halt", undefined_body)

    def test_unknown_slot_latches_and_returns_unimplemented(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_undefined_transfer()])
            slot = _attach_definedness_metadata(
                interpreter,
                classification="unknown",
                include_defined_value=True,
            )
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn(f"{{ 0x{slot:08x}U, 2U, 0U }}", source)
            self.assertIn("context->undefined_fault = 1U", source)
            self.assertIn(
                "stage_b_native_diagnostic_reason = 0x5001U;",
                source,
            )
            self.assertIn("context->undefined_fault_slot = slot;", source)
            self.assertIn(
                "context->undefined_fault_rva = input != 0 ? input->original_rva : 0U;",
                source,
            )
            undefined_body = source.split(
                "static uint32_t stage_b_native_undefined_value", 1
            )[1].split("static uint32_t stage_b_native_resolve_code_target", 1)[0]
            self.assertNotIn("stage_b_native_halt", undefined_body)

    def test_synchronized_slot_uses_checked_machine_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_undefined_transfer()])
            slot = _attach_definedness_metadata(
                interpreter, classification="synchronized_behavior_relevant"
            )
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            self.assertEqual(
                package["inputs"]["definedness_use"]["slots"][0]["choice_kind"],
                "related_machine_input",
            )
            self.assertEqual(
                package["inputs"]["definedness_use"]["slots"][0]["input_location"],
                "eax",
            )
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn(f"{{ 0x{slot:08x}U, 1U, 0U }}", source)
            undefined_body = source.split(
                "static uint32_t stage_b_native_undefined_value", 1
            )[1].split("static uint32_t stage_b_native_resolve_code_target", 1)[0]
            self.assertIn("return defined_value;", undefined_body)
            self.assertIn("context->undefined_fault = 1U", undefined_body)
            self.assertNotIn("undefined_choice_provider", source)


if __name__ == "__main__":
    unittest.main()
