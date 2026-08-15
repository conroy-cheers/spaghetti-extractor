from __future__ import annotations

from tests.unit.candidate.interpreter._support import *


class InterpreterRenderingTests(unittest.TestCase):
    def test_deterministic_package_compiles_as_freestanding_pe32_objects(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if compiler is None:
            self.skipTest("i686 MinGW compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_row()])
            first = root / "first"
            second = root / "second"
            package = write_stage_b_interpreter_package(
                machine_ir=machine, out=first
            )
            write_stage_b_interpreter_package(machine_ir=machine, out=second)

            self.assertEqual(package["status"], "ready")
            self.assertEqual(package["counts"]["transfers"], 1)
            names = (
                "state-machine-runtime.h",
                "state-machine-interpreter.h",
                "state-machine-interpreter-internal.h",
                "state-machine-interpreter.c",
                "state-machine-program.c",
                "state-machine-interpreter-program.json",
                "state-machine-interpreter-package.json",
            )
            for name in names:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            self.assertNotIn(
                "long double",
                (first / "state-machine-interpreter.c").read_text(encoding="ascii"),
            )
            interpreter_header = (
                first / "state-machine-interpreter.h"
            ).read_text(encoding="ascii")
            interpreter_source = (
                first / "state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            self.assertIn("uint32_t fallback_on_unimplemented;", interpreter_header)
            self.assertIn(
                "result.kind==STAGE_B_UNIMPLEMENTED&&override->fallback_on_unimplemented",
                interpreter_source,
            )
            self.assertIn("t=stage_b_program_lookup(source_rva);", interpreter_source)
            self.assertIn(
                "rt->trace_transfer(rt->context, rva, &s)", interpreter_source
            )
            for source in ("state-machine-interpreter.c", "state-machine-program.c"):
                subprocess.run(
                    [
                        compiler,
                        "-std=c11",
                        "-Os",
                        "-ffreestanding",
                        "-fno-builtin",
                        "-I",
                        str(first),
                        "-c",
                        str(first / source),
                        "-o",
                        str(first / (source + ".o")),
                    ],
                    check=True,
                    text=True,
                    capture_output=True,
                )


if __name__ == "__main__":
    unittest.main()
