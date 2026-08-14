from __future__ import annotations

from tests.unit.candidate.native_runtime._support import *


class NativeRuntimeValidationTests(unittest.TestCase):
    def test_callback_adapter_receipt_tampering_fails_closed(self) -> None:
        def missing_receipt(plan: dict[str, object]) -> None:
            plan["callback_adapter_receipts"] = []
            plan["counts"]["callback_adapter_receipts"] = 0

        def missing_adapter(plan: dict[str, object]) -> None:
            plan["callback_adapters"] = []
            plan["counts"]["callback_adapters"] = 0

        def extra_adapter(plan: dict[str, object]) -> None:
            adapter = dict(plan["callback_adapters"][0])
            adapter["id"] = 1
            adapter["instruction_rva"] = 0x2000
            plan["callback_adapters"].append(adapter)
            plan["counts"]["callback_adapters"] = 2

        def duplicate_adapter(plan: dict[str, object]) -> None:
            adapter = dict(plan["callback_adapters"][0])
            adapter["id"] = 1
            plan["callback_adapters"].append(adapter)
            plan["counts"]["callback_adapters"] = 2

        def mismatched_adapter(plan: dict[str, object]) -> None:
            receipt = plan["callback_adapter_receipts"][0]
            receipt["adapter_entries"][0]["original_rva"] = 0x3010
            _rehash_callback_receipt(receipt)

        def mismatched_metadata(plan: dict[str, object]) -> None:
            receipt = plan["callback_adapter_receipts"][0]
            receipt["lifetime"] = "until-process-exit"
            _rehash_callback_receipt(receipt)

        def mismatched_abi(plan: dict[str, object]) -> None:
            receipt = plan["callback_adapter_receipts"][0]
            receipt["abi"]["stack_cleanup_bytes"] = 12
            _rehash_callback_receipt(receipt)

        def mismatched_invocation(plan: dict[str, object]) -> None:
            receipt = plan["callback_adapter_receipts"][0]
            receipt["invocation"] = "direct-native-callback"
            _rehash_callback_receipt(receipt)

        cases = {
            "missing receipt": missing_receipt,
            "missing adapter": missing_adapter,
            "extra": extra_adapter,
            "duplicate": duplicate_adapter,
            "adapter mismatch": mismatched_adapter,
            "lifetime mismatch": mismatched_metadata,
            "ABI mismatch": mismatched_abi,
            "invocation mismatch": mismatched_invocation,
        }
        for label, mutate in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                interpreter, engine, profile = _callback_adapter_packages(root)
                _rewrite_callback_engine_plan(engine, mutate)
                with self.assertRaises(StageBNativeRuntimeError):
                    plan_stage_b_native_runtime(
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
                StageBNativeRuntimeError, "unsupported range size"
            ):
                plan_stage_b_native_runtime(
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
                StageBNativeRuntimeError,
                "uses undefined_bv/undefined_flag but has no complete",
            ):
                plan_stage_b_native_runtime(
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
                StageBNativeRuntimeError, "interpreter source .* SHA-256 mismatch"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    def test_typed_x87_inventory_rejects_reintroduced_instruction_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_qualified_x87_transfer()])
            plan_path = engine / "native-engine-plan.json"
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            plan["x87_operations"][0]["instruction_bytes"] = "d9e8"
            plan_path.write_text(
                json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path = engine / "native-engine-package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["plan"]["sha256"] = sha256_file(plan_path)
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "forbidden instruction payload"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )


if __name__ == "__main__":
    unittest.main()
