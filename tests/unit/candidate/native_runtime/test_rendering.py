from __future__ import annotations

from tests.unit.candidate.native_runtime._support import *


class NativeRuntimeRenderingTests(unittest.TestCase):
    def test_generated_runtime_is_generic_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            bindings = (
                root / "runtime/native-runtime-bindings.c"
            ).read_text(encoding="ascii")
            header = (root / "runtime/native-runtime.h").read_text(encoding="ascii")

            self.assertNotIn("stage_b_native_engine_manifest_sha256[65] =", source)
            self.assertIn("stage_b_native_engine_manifest_sha256[65] =", bindings)

            self.assertIn("stage_b_native_flat_read", source)
            self.assertIn("stage_b_native_flat_write", source)
            self.assertIn("stage_b_native_atomic_compare_exchange", source)
            self.assertIn("stage_b_runtime_atomic_compare_exchange", source)
            self.assertIn("stage_b_native_atomic_exchange", source)
            self.assertIn("stage_b_runtime_atomic_exchange", source)
            self.assertIn(
                ".atomic_compare_exchange = "
                "stage_b_native_atomic_compare_exchange",
                source,
            )
            self.assertIn(
                ".atomic_exchange = stage_b_native_atomic_exchange",
                source,
            )
            self.assertIn("__atomic_compare_exchange_n", source)
            self.assertIn("__atomic_exchange_n", source)
            self.assertIn("STAGE_B_NATIVE_IMAGE_SCN_MEM_EXECUTE", source)
            self.assertIn("stage_b_native_transfer_rvas", source)
            self.assertIn("stage_b_program_lookup(rva)", source)
            self.assertIn("target_word - context->image_base", source)
            self.assertIn("STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE", source)
            self.assertIn("context->undefined_fault = 1U", source)
            self.assertNotIn(
                "stage_b_native_halt(STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE)",
                source,
            )
            self.assertIn("__sync_lock_test_and_set", source)
            self.assertIn("stage_b_run_function(", source)
            self.assertIn("stage_b_native_runtime_run_at_rva(", source)
            self.assertIn("stage_b_native_runtime_run_nested_callback(", source)
            self.assertIn("stage_b_runtime stage_b_native_runtime_instance", source)
            self.assertNotIn("static stage_b_runtime stage_b_native_runtime", source)
            self.assertNotIn("stage_b_native_replay_checked_x87_command", source)
            self.assertIn(
                "stage_b_native_terminate(stage_b_native_terminal_status)", source
            )
            self.assertIn("__attribute__((noreturn))", header)
            self.assertNotIn("hello", source.lower())
            self.assertNotIn("ExitProcess", source)
            self.assertEqual(
                package["policy"]["terminal_control"],
                "record-status-and-unsupported-native-halt",
            )
            self.assertTrue(
                package["inputs"]["runtime_abi"][
                    "atomic_compare_exchange_handler"
                ]
            )
            self.assertTrue(
                package["inputs"]["runtime_abi"]["atomic_exchange_handler"]
            )

    def test_generated_source_compiles_as_freestanding_i686(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        if compiler is None or nm is None:
            self.skipTest("i686 MinGW compiler/nm is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            runtime = root / "runtime"
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )

            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Os",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-I",
                    str(runtime),
                    "-I",
                    str(interpreter),
                    "-c",
                    str(runtime / "native-runtime.c"),
                    "-o",
                    str(runtime / "native-runtime.o"),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            runtime_symbols = subprocess.run(
                [nm, str(runtime / "native-runtime.o")],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            self.assertNotIn("stage_b_native_replay_checked_x87_command", runtime_symbols)
            stub = runtime / "interpreter-stub.c"
            stub.write_text(
                """#include "native-runtime.h"
const stage_b_program_transfer *stage_b_program_lookup(uint32_t source_rva) {
  return source_rva == 0x1000U ? (const stage_b_program_transfer *)1 : 0;
}
stage_b_call_status stage_b_run_function(
    stage_b_runtime *runtime, uint32_t entry_rva,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime;
  (void)entry_rva;
  *output = *input;
  return STAGE_B_CALL_OK;
}
stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime;
  (void)event;
  *output = *input;
  return STAGE_B_CALL_UNIMPLEMENTED;
}
void stage_b_native_terminate(stage_b_native_terminal_kind status) {
  (void)status;
  for (;;) {}
}
""",
                encoding="ascii",
            )
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Os",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-I",
                    str(runtime),
                    "-I",
                    str(interpreter),
                    "-c",
                    str(stub),
                    "-o",
                    str(runtime / "interpreter-stub.o"),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    compiler,
                    "-nostdlib",
                    "-Wl,--entry,_stage_b_native_runtime_coordinate",
                    "-Wl,--subsystem,console",
                    "-Wl,--disable-runtime-pseudo-reloc",
                    str(runtime / "native-runtime.o"),
                    str(runtime / "interpreter-stub.o"),
                    "-o",
                    str(runtime / "native-runtime.exe"),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            linked_symbols = subprocess.run(
                [nm, str(runtime / "native-runtime.exe")],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ [BD] _stage_b_native_runtime_instance$",
                    linked_symbols,
                )),
                1,
            )


if __name__ == "__main__":
    unittest.main()
