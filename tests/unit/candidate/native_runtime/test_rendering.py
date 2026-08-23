from __future__ import annotations

from tests.unit.candidate.native_runtime._support import *


class NativeRuntimeRenderingTests(unittest.TestCase):
    def test_generated_runtime_is_generic_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root)
            package = write_spx_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=root / "runtime",
            )
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            bindings = (
                root / "runtime/native-runtime-bindings.c"
            ).read_text(encoding="ascii")
            header = (root / "runtime/native-runtime.h").read_text(encoding="ascii")

            self.assertNotIn("spx_native_engine_manifest_sha256[65] =", source)
            self.assertIn("spx_native_engine_manifest_sha256[65] =", bindings)

            self.assertIn("spx_native_flat_read", source)
            self.assertIn("spx_native_flat_write", source)
            self.assertIn("spx_native_atomic_compare_exchange", source)
            self.assertIn("spx_runtime_atomic_compare_exchange", source)
            self.assertIn("spx_native_atomic_exchange", source)
            self.assertIn("spx_runtime_atomic_exchange", source)
            self.assertIn(
                ".atomic_compare_exchange = "
                "spx_native_atomic_compare_exchange",
                source,
            )
            self.assertIn(
                ".atomic_exchange = spx_native_atomic_exchange",
                source,
            )
            self.assertIn("__atomic_compare_exchange_n", source)
            self.assertIn("__atomic_exchange_n", source)
            self.assertIn("SPX_NATIVE_IMAGE_SCN_MEM_EXECUTE", source)
            self.assertIn("spx_native_transfer_rvas", source)
            self.assertIn("spx_program_lookup(rva)", source)
            self.assertIn("target_word - context->image_base", source)
            self.assertIn("context->undefined_fault = 1U", source)
            self.assertNotIn(
                "spx_native_halt(SPX_NATIVE_TERMINAL_UNDEFINED_VALUE)",
                source,
            )
            self.assertNotIn("__sync_lock_test_and_set", source)
            self.assertIn("spx_native_runtime_context_current", source)
            self.assertIn("spx_run_function(", source)
            self.assertIn("spx_native_runtime_run_at_rva(", source)
            self.assertNotIn("spx_native_runtime_run_nested_callback(", source)
            self.assertIn("spx_runtime spx_native_runtime_instance", source)
            self.assertNotIn("static spx_runtime spx_native_runtime", source)
            self.assertNotIn("spx_native_replay_checked_x87_command", source)
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
            write_spx_native_runtime_package(
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
            self.assertNotIn("spx_native_replay_checked_x87_command", runtime_symbols)
            stub = runtime / "interpreter-stub.c"
            stub.write_text(
                """#include "native-runtime.h"
#include "native-ingress-runtime.h"
static uint32_t fixture_runtime_context[0x60000U / 4U];
static volatile uint32_t fixture_diagnostics[4];
void *spx_native_runtime_context_current(void) {
  return fixture_runtime_context;
}
volatile uint32_t *spx_native_runtime_diagnostic_slot(uint32_t index) {
  return index < 4U ? &fixture_diagnostics[index] : 0;
}
const spx_program_transfer *spx_program_lookup(uint32_t source_rva) {
  return source_rva == 0x1000U ? (const spx_program_transfer *)1 : 0;
}
spx_call_status spx_run_function(
    spx_runtime *runtime, uint32_t entry_rva,
    const spx_machine_state *input, spx_machine_state *output) {
  (void)runtime;
  (void)entry_rva;
  *output = *input;
  return SPX_CALL_OK;
}
spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {
  (void)runtime;
  (void)event;
  *output = *input;
  return SPX_CALL_UNIMPLEMENTED;
}
void spx_native_terminate(spx_native_terminal_kind status) {
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
                    "-Wl,--entry,_spx_native_runtime_run_at_rva",
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
                    r"(?m)^\S+ [BD] _spx_native_runtime_instance$",
                    linked_symbols,
                )),
                1,
            )


if __name__ == "__main__":
    unittest.main()
