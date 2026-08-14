from __future__ import annotations

from tests.unit.candidate.native_engine._support import *


class NativeEngineRenderingTests(NativeEngineTestCase):
    def test_generated_bridge_switch_is_direct_complete_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            higher = _transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x202A,
                "return_rva": 0x2030,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })
            higher["id"] = "semantic-transfer:higher"
            higher["original"] = {"rva_start": 0x2000, "rva_end": 0x2030}
            lower = _transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "msvcrt.dll",
                "symbol": "atexit",
                "ordinal": None,
            })
            machine = self._write(root, [higher, lower])
            first = root / "first"
            second = root / "second"
            write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=first
            )
            write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=second
            )
            source = (first / "native-engine-wrapper.c").read_text(encoding="ascii")
            repeated = (second / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            assembly = (first / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertEqual(source, repeated)
            self.assertNotIn("entry->bridge", source.split(
                "stage_b_call_status stage_b_dispatch_external_call", 1
            )[1])
            self.assertNotIn("runtime->read", source)
            self.assertNotIn("stage_b_native_bridge_fn", source)
            self.assertEqual(source.count("stage_b_native_bridge();"), 1)
            self.assertIn(
                "stage_b_native_runtime_record_external_result(",
                source,
            )
            self.assertIn(
                "stage_b_native_runtime_capture_external_call(", source
            )
            self.assertIn(
                "stage_b_native_runtime_write_diagnostic((uint32_t)status, rva, state)",
                source,
            )
            self.assertIn("event, &external_snapshot, output", source)
            self.assertIn(
                "event->target_rva != stage_b_native_original_iat_target",
                source,
            )
            self.assertIn("output->edi != preserved_edi", source)
            self.assertIn(
                "stage_b_native_dispatch_bridge();",
                source,
            )
            self.assertNotIn("switch (instruction_rva)", source)
            self.assertEqual(assembly.count("_stage_b_native_bridge:\n"), 1)
            self.assertEqual(assembly.count("_stage_b_native_capture:\n"), 1)
            self.assertNotIn("_stage_b_native_bridge_0000", assembly)
            self.assertNotIn("_stage_b_native_bridge_0001", assembly)
            self.assertNotIn(".stgbcl", assembly)

    def test_typed_x87_memory_form_uses_reviewed_mnemonic_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _x87_replay_transfer()
            encoded = bytes.fromhex("d94004")
            digest = sha256_bytes(encoded)
            row["instruction_bytes_sha256"] = digest
            row["original"] = {"rva_start": 0x1420, "rva_end": 0x1423, "size": 3}
            row["instructions"] = [{
                "rva": 0x1420, "size": 3, "bytes": encoded.hex(),
                "mnemonic": "fld", "op_str": "dword ptr [eax + 4]",
            }]
            row["outcome"] = {"kind": "fallthrough", "target_rva": 0x1423}
            replay = row["fpu_state"]["replay"]
            replay.update({
                "rva_end": 0x1423,
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [{"rva": 0x1420, "size": 3, "bytes": encoded.hex()}],
            })
            package = root / "package"
            result = write_stage_b_native_engine_package(
                state_machine=self._write(root, [row]), entry_rva=0x1420, out=package
            )
            self.assertEqual(result["status"], "ready", result["blockers"])
            assembly = (package / "native-engine-bridges.S").read_text(encoding="ascii")
            self.assertIn("fld DWORD PTR [eax + 0x4]", assembly)
            self.assertNotIn(".byte", assembly)

    def test_reviewed_x87_form_renderings_assemble(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        assert compiler is not None
        forms = (
            ("d8c1", "fadd", "st(1)", "fadd st(1)"),
            ("dff1", "fcompi", "st(1)", "fcompi st(1)"),
            ("dfe9", "fucompi", "st(1)", "fucompi st(1)"),
            ("dfe0", "fnstsw", "ax", "fnstsw ax"),
            ("db28", "fld", "xword ptr [eax]", "fld TBYTE PTR [eax]"),
            ("d920", "fldenv", "[eax]", "fldenv [eax]"),
            ("dd30", "fnsave", "dword ptr [eax]", "fnsave [eax]"),
            (
                "da4d20",
                "fimul",
                "dword ptr [ebp + 0x20]",
                "fimul DWORD PTR [ebp + 0x20]",
            ),
            (
                "da642404",
                "fisub",
                "dword ptr [esp + 4]",
                "fisub DWORD PTR [esp + 0x4]",
            ),
            ("dc18", "fcomp", "qword ptr [eax]", "fcomp QWORD PTR [eax]"),
            ("d9fe", "fsin", "", "fsin"),
            ("d9ff", "fcos", "", "fcos"),
            ("dbe2", "fnclex", "", "fnclex"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, (raw_hex, mnemonic, op_str, rendered) in enumerate(forms):
                encoded = bytes.fromhex(raw_hex)
                digest = sha256_bytes(encoded)
                row = _x87_replay_transfer()
                row["instruction_bytes_sha256"] = digest
                row["original"] = {
                    "rva_start": 0x1420,
                    "rva_end": 0x1420 + len(encoded),
                    "size": len(encoded),
                }
                row["instructions"] = [{
                    "rva": 0x1420,
                    "size": len(encoded),
                    "bytes": raw_hex,
                    "mnemonic": mnemonic,
                    "op_str": op_str,
                }]
                row["outcome"] = {
                    "kind": "fallthrough",
                    "target_rva": 0x1420 + len(encoded),
                }
                replay = row["fpu_state"]["replay"]
                replay.update({
                    "rva_end": 0x1420 + len(encoded),
                    "bytes": raw_hex,
                    "bytes_sha256": digest,
                    "instructions": [{
                        "rva": 0x1420,
                        "size": len(encoded),
                        "bytes": raw_hex,
                    }],
                })
                package = root / f"package-{index}"
                result = write_stage_b_native_engine_package(
                    state_machine=self._write(root, [row]),
                    entry_rva=0x1420,
                    out=package,
                )
                self.assertEqual(result["status"], "ready", result["blockers"])
                assembly = package / "native-engine-bridges.S"
                self.assertIn(rendered, assembly.read_text(encoding="ascii"))
                subprocess.run(
                    [
                        compiler,
                        "-c",
                        str(assembly),
                        "-o",
                        str(root / f"typed-form-{index}.o"),
                    ],
                    check=True,
                    text=True,
                    capture_output=True,
                )

    def test_byte_free_machine_ir_compare_forms_assemble(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        assert compiler is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine_ir = self._write(root, [
                _machine_ir_x87_transfer(
                    rva=0x1420, mnemonic="fcompi", encoded=bytes.fromhex("dff1")
                ),
                _machine_ir_x87_transfer(
                    rva=0x1430, mnemonic="fucompi", encoded=bytes.fromhex("dfe9")
                ),
            ])
            package = root / "package"
            result = write_stage_b_native_engine_package(
                machine_ir=machine_ir, entry_rva=0x1420, out=package
            )
            self.assertEqual(result["status"], "ready", result["blockers"])
            assembly = package / "native-engine-bridges.S"
            rendered = assembly.read_text(encoding="ascii")
            self.assertIn("fcompi st(1)", rendered)
            self.assertIn("fucompi st(1)", rendered)
            self.assertNotIn(".byte", rendered)
            subprocess.run(
                [compiler, "-c", str(assembly), "-o", str(root / "compare.o")],
                check=True,
                text=True,
                capture_output=True,
            )

    def test_byte_free_machine_ir_fxch_complete_operands_assemble(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        assert compiler is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unit = _machine_ir_x87_transfer(
                rva=0x1420, mnemonic="fxch", encoded=bytes.fromhex("d9c9")
            )
            operands = [
                {
                    "kind": "register", "name": "st(0)",
                    "width_bits": 80, "access": "read_write",
                },
                {
                    "kind": "register", "name": "st(1)",
                    "width_bits": 80, "access": "read_write",
                },
            ]
            unit["instructions"][0]["operands"] = operands
            unit["x87_micro_ops"][0]["operands"] = operands
            machine_ir = self._write(root, [unit])
            package = root / "package"
            result = write_stage_b_native_engine_package(
                machine_ir=machine_ir, entry_rva=0x1420, out=package
            )
            self.assertEqual(result["status"], "ready", result["blockers"])
            assembly = package / "native-engine-bridges.S"
            rendered = assembly.read_text(encoding="ascii")
            self.assertIn("fxch st(1)", rendered)
            self.assertNotIn("fxch st(0), st(1)", rendered)
            subprocess.run(
                [compiler, "-c", str(assembly), "-o", str(root / "fxch.o")],
                check=True,
                text=True,
                capture_output=True,
            )

    def test_generated_sources_compile_and_link_as_freestanding_pe32(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        assert compiler is not None and nm is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })])
            package = root / "package"
            result = write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 12,
                }],
                out=package,
            )
            self.assertEqual(result["status"], "ready", result)
            (package / "state-machine-runtime.h").write_text(
                _RUNTIME_HEADER, encoding="ascii"
            )
            stub = package / "semantic-stub.c"
            stub.write_text(
                """#include \"native-engine-wrapper.h\"
stage_b_runtime stage_b_native_runtime_instance;
volatile uint32_t stage_b_native_diagnostic_reason;
volatile uint32_t stage_b_native_diagnostic_value;
volatile uint32_t stage_b_native_diagnostic_aux;
volatile uint32_t stage_b_native_diagnostic_detail;
stage_b_call_status stage_b_native_runtime_capture_external_call(
    const stage_b_call_event *event, const stage_b_machine_state *input,
    stage_b_external_call_snapshot *snapshot) {
  (void)input;
  snapshot->instruction_rva = event->instruction_rva;
  snapshot->target_iat_rva = 0U;
  snapshot->argument_base_offset = 0U;
  snapshot->argument_count = 0U;
  return STAGE_B_CALL_OK;
}
stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)entry_rva;
  *output = *input;
  return STAGE_B_CALL_OK;
}
stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)callback_rva;
  *output = *input;
  output->esp += 4U + stack_cleanup_bytes;
  return STAGE_B_CALL_OK;
}
stage_b_call_status stage_b_native_runtime_record_external_result(
    const stage_b_call_event *event,
    const stage_b_external_call_snapshot *snapshot,
    const stage_b_machine_state *output) {
  (void)event;
  (void)snapshot;
  (void)output;
  return STAGE_B_CALL_OK;
}
""",
                encoding="ascii",
            )
            sources = (
                package / "native-engine-bridges.S",
                package / "native-engine-wrapper.c",
                package / "native-engine-layout.c",
                stub,
            )
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = package / f"{index}.o"
                command = [
                    compiler,
                    "-std=c11",
                    "-Os",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-I",
                    str(package),
                    "-c",
                    str(source),
                    "-o",
                    str(target),
                ]
                subprocess.run(command, check=True, text=True, capture_output=True)
                objects.append(target)
            payload = package / "payload.exe"
            subprocess.run(
                [
                    compiler,
                    "-nostdlib",
                    "-Wl,--entry,_stage_b_payload_entry",
                    "-Wl,--subsystem,console",
                    "-Wl,--dynamicbase",
                    "-Wl,--enable-reloc-section",
                    "-Wl,--disable-auto-import",
                    "-Wl,--disable-runtime-pseudo-reloc",
                    "-Wl,--no-insert-timestamp",
                    *(str(path) for path in objects),
                    "-o",
                    str(payload),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            symbols = subprocess.run(
                [nm, str(payload)], check=True, text=True, capture_output=True
            ).stdout
            self.assertRegex(
                symbols, re.compile(r"(?m)^[0-9a-fA-F]+ T _stage_b_payload_entry$")
            )
            self.assertRegex(
                symbols,
                re.compile(
                    r"(?m)^[0-9a-fA-F]+ T _?stage_b_payload_callback_00001420$"
                ),
            )

    def test_relocated_x87_replay_links_one_payload_highlow(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        assert compiler is not None and nm is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_absolute_x87_replay_transfer()])
            package = root / "package"
            result = write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                base_relocation_evidence=_relocation_evidence(),
                out=package,
            )
            self.assertEqual(result["status"], "ready", result)
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            replay_bridge = assembly.split(
                "_stage_b_native_x87_bridge_0000:", maxsplit=1
            )[1].split("_stage_b_native_x87_capture_0000:", maxsplit=1)[0]
            self.assertNotIn("popad", replay_bridge)
            for instruction in (
                "mov ebx, DWORD PTR [eax + 4]",
                "mov ecx, DWORD PTR [eax + 8]",
                "mov edx, DWORD PTR [eax + 12]",
                "mov esi, DWORD PTR [eax + 16]",
                "mov edi, DWORD PTR [eax + 20]",
                "mov ebp, DWORD PTR [eax + 24]",
                "mov esp, DWORD PTR [eax + 28]",
                "push DWORD PTR [eax + 240]",
                "push DWORD PTR [eax + 0]",
            ):
                self.assertIn(instruction, replay_bridge)
            replay_capture = assembly.split(
                "_stage_b_native_x87_capture_0000:", maxsplit=1
            )[1].split("_stage_b_native_x87_return_0000:", maxsplit=1)[0]
            for instruction in (
                "sets BYTE PTR [edx + 40]",
                "seto BYTE PTR [edx + 44]",
                "and ecx, 0xfffff32a",
                "and ebx, 0x00000cd5",
            ):
                self.assertIn(instruction, replay_capture)
            (package / "state-machine-runtime.h").write_text(
                _x87_runtime_header(), encoding="ascii"
            )
            stub = package / "semantic-stub.c"
            stub.write_text(
                """#include "native-engine-wrapper.h"
stage_b_runtime stage_b_native_runtime_instance;
volatile uint32_t stage_b_native_diagnostic_reason;
volatile uint32_t stage_b_native_diagnostic_value;
volatile uint32_t stage_b_native_diagnostic_aux;
volatile uint32_t stage_b_native_diagnostic_detail;
stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t rva, const stage_b_machine_state *input,
    stage_b_machine_state *output) {
  (void)rva; *output = *input; return STAGE_B_CALL_OK;
}
stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t rva, uint32_t cleanup, const stage_b_machine_state *input,
    stage_b_machine_state *output) {
  (void)rva; *output = *input; output->esp += 4U + cleanup;
  return STAGE_B_CALL_OK;
}
""",
                encoding="ascii",
            )
            sources = (
                package / "native-engine-bridges.S",
                package / "native-engine-wrapper.c",
                package / "native-engine-layout.c",
                stub,
            )
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = package / f"relocated-{index}.o"
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
                        str(package),
                        "-c",
                        str(source),
                        "-o",
                        str(target),
                    ],
                    check=True,
                    text=True,
                    capture_output=True,
                )
                objects.append(target)
            payload = package / "relocated-x87.exe"
            subprocess.run(
                [
                    compiler,
                    "-nostdlib",
                    "-Wl,--entry,_stage_b_payload_entry",
                    "-Wl,--subsystem,console",
                    "-Wl,--dynamicbase",
                    "-Wl,--enable-reloc-section",
                    "-Wl,--disable-auto-import",
                    "-Wl,--disable-runtime-pseudo-reloc",
                    "-Wl,--no-insert-timestamp",
                    *(str(path) for path in objects),
                    "-o",
                    str(payload),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            symbols = subprocess.run(
                [nm, str(payload)], check=True, text=True, capture_output=True
            ).stdout
            match = re.search(
                r"(?m)^([0-9a-fA-F]+) T _stage_b_native_x87_instruction_0000$",
                symbols,
            )
            self.assertIsNotNone(match)
            assert match is not None
            pe = pefile.PE(str(payload))
            try:
                image_base = int(pe.OPTIONAL_HEADER.ImageBase)
                instruction_rva = int(match.group(1), 16) - image_base
                relocation_rva = instruction_rva + 2
                highlow_rvas = {
                    int(block.struct.VirtualAddress) + int(entry.rva) % 0x1000
                    for block in pe.DIRECTORY_ENTRY_BASERELOC
                    for entry in block.entries
                    if int(entry.type) == 3
                }
                self.assertIn(relocation_rva, highlow_rvas)
                self.assertEqual(
                    int.from_bytes(pe.get_data(relocation_rva, 4), "little"),
                    image_base + 0x1234,
                )
            finally:
                pe.close()


if __name__ == "__main__":
    unittest.main()
