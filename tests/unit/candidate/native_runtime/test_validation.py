from __future__ import annotations

from tests.unit.candidate.native_runtime._support import *
from tests.unit.candidate.native_runtime._callback_support import *


class NativeRuntimeValidationTests(unittest.TestCase):
    def test_code_capability_registration_tampering_fails_closed(self) -> None:
        def missing_registration(plan: dict[str, object]) -> None:
            plan["code_capability_registrations"] = []
            plan["counts"]["code_capability_registrations"] = 0

        def extra_registration(plan: dict[str, object]) -> None:
            registration = dict(plan["code_capability_registrations"][0])
            registration["instruction_rva"] = 0x2000
            plan["code_capability_registrations"].append(registration)
            plan["counts"]["code_capability_registrations"] = 2

        def duplicate_registration(plan: dict[str, object]) -> None:
            registration = dict(plan["code_capability_registrations"][0])
            plan["code_capability_registrations"].append(registration)
            plan["counts"]["code_capability_registrations"] = 2

        def mismatched_target(plan: dict[str, object]) -> None:
            plan["code_capability_registrations"][0]["logical_target_rva"] = 0x3010

        def mismatched_metadata(plan: dict[str, object]) -> None:
            plan["code_capability_registrations"][0]["lifetime"] = {
                "kind": "process"
            }

        def mismatched_contract(plan: dict[str, object]) -> None:
            plan["code_capability_registrations"][0][
                "checked_external_contract_sha256"
            ] = "0" * 64

        def mismatched_invocation(plan: dict[str, object]) -> None:
            plan["code_capability_registrations"][0]["invocation"] = (
                "direct-native-callback"
            )

        cases = {
            "missing": missing_registration,
            "extra": extra_registration,
            "duplicate": duplicate_registration,
            "target mismatch": mismatched_target,
            "lifetime mismatch": mismatched_metadata,
            "contract mismatch": mismatched_contract,
            "invocation mismatch": mismatched_invocation,
        }
        for label, mutate in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                interpreter, engine, profile = _callback_adapter_packages(root)
                _rewrite_callback_engine_plan(engine, mutate)
                with self.assertRaises(CandidateRuntimeError):
                    plan_spx_native_runtime(
                        interpreter_package=interpreter,
                        native_engine_package=engine,
                        external_profile=profile,
                    )

    def test_external_result_range_rejects_unknown_size_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "external-profile.json"
            _write_external_profile(profile, size_kind="unknown")
            interpreter, engine = _packages(
                root, rows=_external_result_rows(), external_profile=profile
            )
            with self.assertRaisesRegex(
                CandidateRuntimeError, "unsupported range size"
            ):
                plan_spx_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                    external_profile=profile,
                )

    def test_undefined_nodes_require_complete_hash_bound_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_undefined_transfer()])
            program_path = interpreter / "state-machine-interpreter-program.json"
            program = json.loads(program_path.read_text(encoding="utf-8"))
            del program["definedness_use"]
            program_path.write_text(
                json.dumps(program, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path = interpreter / "state-machine-interpreter-package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["program"]["sha256"] = sha256_file(program_path)
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CandidateRuntimeError,
                "uses undefined_bv/undefined_flag but has no complete",
            ):
                plan_spx_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    def test_manifest_or_artifact_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            (interpreter / "state-machine-program.c").write_text(
                "tampered\n", encoding="ascii"
            )

            with self.assertRaisesRegex(
                CandidateRuntimeError, "interpreter source .* SHA-256 mismatch"
            ):
                plan_spx_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    def test_typed_x87_inventory_rejects_reintroduced_instruction_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit = _qualified_x87_transfer()
            unit["x87_micro_ops"][0]["bytes"] = "d9e8"
            with self.assertRaisesRegex(
                CandidateInterpreterError, "raw instruction material"
            ):
                _packages(root, [unit])


if __name__ == "__main__":
    unittest.main()
