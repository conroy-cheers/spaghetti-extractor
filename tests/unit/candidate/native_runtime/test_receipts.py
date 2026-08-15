from __future__ import annotations

from tests.unit.candidate.native_runtime._support import *
from tests.unit.candidate.native_runtime._callback_support import *


class NativeRuntimeReceiptTests(unittest.TestCase):
    def test_callback_adapter_receipt_is_bound_into_runtime_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine, profile = _callback_adapter_packages(root)
            plan = plan_stage_b_native_runtime(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
            )

            self.assertEqual(len(plan.callback_adapter_receipts), 1)
            receipt = plan.callback_adapter_receipts[0]
            self.assertEqual(receipt["target_rvas"], [0x3000])
            self.assertEqual(len(receipt["adapter_entries"]), 1)
            self.assertEqual(
                receipt["invocation"],
                "nested-machine-ir-callback-adapter-v1",
            )
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )
            self.assertEqual(
                package["inputs"]["callback_adapter_receipts"],
                [receipt],
            )

    def test_package_binds_both_manifests_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            first = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "first",
            )
            second = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "second",
            )

            self.assertEqual(first, second)
            self.assertEqual(first["status"], "ready")
            self.assertFalse(first["acceptance_authority"])
            self.assertEqual(
                first["counts"],
                {
                    "transfers": 1,
                    "implementation_dispatches": 1,
                    "authorized_external_sites": 0,
                    "blocked_external_sites": 0,
                },
            )
            self.assertEqual(first["inputs"]["entry_rva"], 0x1000)
            self.assertEqual(first["inputs"]["transfer_rvas"], [0x1000])
            for name in (
                "native-runtime.h",
                "native-runtime.c",
                "native-runtime-bindings.c",
            ):
                self.assertEqual(
                    (root / "first" / name).read_bytes(),
                    (root / "second" / name).read_bytes(),
                )

    def test_runtime_rejects_omitted_implementation_dispatch_with_valid_receipt_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            interpreter, engine = _packages(root, [_transfer(0x1000), _transfer(0x2000)])

            def omit(receipt: dict[str, object]) -> None:
                entries = receipt["entries"]
                assert isinstance(entries, list)
                entries.pop()
                counts = receipt["counts"]
                assert isinstance(counts, dict)
                counts["dispatch_entries"] = 1
                counts["machine_ir_fallback"] = 1

            _rewrite_implementation_engine_plan(engine, omit)
            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "omits or adds interpreter transfers"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    def test_runtime_rejects_duplicate_implementation_dispatch_with_valid_receipt_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            interpreter, engine = _packages(root)

            def duplicate(receipt: dict[str, object]) -> None:
                entries = receipt["entries"]
                assert isinstance(entries, list)
                entries.append(dict(entries[0]))
                counts = receipt["counts"]
                assert isinstance(counts, dict)
                counts["dispatch_entries"] = 2
                counts["machine_ir_fallback"] = 2

            _rewrite_implementation_engine_plan(engine, duplicate)
            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "omits or adds interpreter transfers"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    def test_runtime_rejects_mismatched_implementation_class_after_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            interpreter, engine = _packages(root)

            def mismatch(receipt: dict[str, object]) -> None:
                entries = receipt["entries"]
                assert isinstance(entries, list)
                entry = entries[0]
                entry["implementation_class"] = "selected_portable_component"
                entry["dispatch_lookup"] = "stage_b_region_override_lookup"
                _rehash_implementation_entry(entry)
                counts = receipt["counts"]
                assert isinstance(counts, dict)
                counts["machine_ir_fallback"] = 0
                counts["selected_portable_component"] = 1

            _rewrite_implementation_engine_plan(engine, mismatch)
            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "portable component replacement id"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    def test_runtime_rejects_manifest_plan_implementation_receipt_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            interpreter, engine = _packages(root)
            manifest_path = engine / "native-engine-package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["implementation_dispatch_receipt"]["status"] = "incomplete"
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "different implementation dispatch receipts"
            ):
                plan_stage_b_native_runtime(
                    interpreter_package=interpreter,
                    native_engine_package=engine,
                )

    def test_portable_dispatch_is_bound_into_runtime_startup_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = {
                "unit_id": "semantic-transfer:00001000",
                "rva": 0x1000,
                "replacement_id": "portable-entry",
                "cluster_id": "entry-cluster",
                "component_manifest_sha256": "c" * 64,
                "fallback_on_unimplemented": False,
            }
            interpreter, engine = _packages(
                root, selected_portable_components=[selection]
            )
            runtime = root / "runtime"
            result = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )
            source = (runtime / "native-runtime.c").read_text(encoding="ascii")
            self.assertEqual(result["counts"]["implementation_dispatches"], 1)
            self.assertIn('"portable-entry", "entry-cluster"', source)
            self.assertIn("override->fallback_on_unimplemented != 0U", source)
            self.assertIn("stage_b_region_override_lookup == 0", source)
            self.assertIn(
                "stage_b_program_transfer_count != stage_b_native_transfer_count",
                source,
            )
            self.assertIn(
                "stage_b_region_override_count != stage_b_native_portable_dispatch_count",
                source,
            )


if __name__ == "__main__":
    unittest.main()
