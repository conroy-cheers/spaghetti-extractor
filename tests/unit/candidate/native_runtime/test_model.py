from __future__ import annotations

from tests.unit.candidate.native_runtime._support import *


class NativeRuntimeModelTests(unittest.TestCase):
    def test_external_interface_output_registers_object_and_vtable_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = _external_result_rows()
            event = rows[0]["ordered_events"][0]
            event["arguments"] = [
                {"op": "const", "value": 0, "width": 32},
                {"op": "const", "value": 0x500000, "width": 32},
            ]
            profile = root / "external-profile.json"
            _write_out_interface_profile(profile)
            interpreter, engine = _packages(
                root, rows=rows, external_profile=profile
            )

            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )

            rules = package["inputs"]["external_range_contracts"]["rules"]
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["action"], "add_argument_interface_ranges")
            self.assertEqual(rules[0]["argument"], 1)
            self.assertEqual(rules[0]["minimum_size"], 4)
            self.assertEqual(rules[0]["size_value"], 24)
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn("stage_b_native_add_external_interface_ranges", source)
            self.assertIn("if ((int32_t)output->eax < 0) continue;", source)

    def test_external_result_ranges_are_profile_bound_and_generic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "external-profile.json"
            _write_external_profile(profile)
            interpreter, engine = _packages(
                root, rows=_external_result_rows(), external_profile=profile
            )
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )

            rules = package["inputs"]["external_range_contracts"]["rules"]
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["instruction_rva"], 0x1000)
            self.assertEqual(rules[0]["action"], "add_result_range")
            self.assertEqual(rules[0]["register"], "eax")
            self.assertEqual(rules[0]["argument_base_offset"], 0)
            self.assertEqual(rules[0]["argument_count"], 0)
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn("STAGE_B_NATIVE_MAX_EXTERNAL_RANGES 8192U", source)
            self.assertIn("stage_b_native_inside_external_range", source)
            self.assertIn("stage_b_native_runtime_record_external_result", source)
            self.assertIn("stage_b_native_diagnostic_value", source)
            self.assertIn("stage_b_native_diagnostic_aux", source)
            self.assertIn("stage_b_native_diagnostic_detail", source)
            self.assertIn(
                "STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS 64U", source
            )
            self.assertIn("producer_rva, producer_action, generation", source)
            self.assertIn("stage_b_native_record_external_lifecycle", source)
            self.assertIn("stage_b_native_runtime_write_diagnostic", source)
            self.assertIn("stage_b_native_runtime_write_external_probe", source)
            self.assertIn("stage_b_native_diagnostic_reason = 0x4001U", source)
            self.assertIn("movl %%fs:0x34", source)
            self.assertIn("spaghetti-extractor-diagnostic.bin", source)
            self.assertIn("header.magic = 0x31444553U", source)
            self.assertIn("header.version = 4U", source)
            self.assertIn("uint32_t stack_words[16]", source)
            self.assertIn(
                "STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS 128U", source
            )
            self.assertIn(
                "sequence, phase, instruction_rva, target_rva, target_iat_rva",
                source,
            )
            self.assertIn("stage_b_native_record_external_trace", source)
            self.assertIn(
                "STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS 1024U", source
            )
            self.assertIn(
                "uint32_t sequence, rva, df, esp", source
            )
            self.assertIn("stage_b_native_trace_transfer", source)
            self.assertIn("STAGE_B_NATIVE_DIAGNOSTIC_WRITER_AVAILABLE", source)
            self.assertIn("operation == 5U ? 0x2204U", source)
            self.assertIn("operation == 6U ? 0x2203U", source)
            self.assertIn("uint32_t process_world_initialized;", source)
            self.assertIn(
                "if (context->process_world_initialized == 0U)", source
            )
            self.assertIn("context->process_world_initialized = 1U", source)
            self.assertIn(
                "stage_b_native_context_value.external_range_count", source
            )
            self.assertIn(
                "stage_b_native_diagnostic_reason = 0x3001U", source
            )
            self.assertIn(
                "stage_b_native_diagnostic_reason = 0x3002U", source
            )
            self.assertNotIn("__p__commode", source)

    def test_iat_loaded_dynamic_call_uses_the_same_result_range_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "external-profile.json"
            _write_external_profile(profile)
            interpreter, engine = _packages(
                root,
                rows=_machine_ir_indirect_external_result_rows(),
                import_iat_vas={("msvcrt.dll", "__p__commode"): 0x43219C},
                machine_ir=True,
                external_profile=profile,
            )

            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )

            plan = json.loads(
                (engine / "native-engine-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(plan["external_sites"][0]["site_kind"], "dynamic_target")
            self.assertEqual(plan["external_sites"][0]["import"], {
                "dll": "msvcrt.dll",
                "symbol": "__p__commode",
                "ordinal": None,
            })
            self.assertEqual(plan["external_sites"][0]["iat_va"], 0x43219C)
            rules = package["inputs"]["external_range_contracts"]["rules"]
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["action"], "add_result_range")
            self.assertEqual(rules[0]["instruction_rva"], 0x1000)
            self.assertEqual(rules[0]["target_iat_rva"], 0x3219C)
            self.assertEqual(
                package["inputs"]["external_dispatch"][
                    "authorized_instruction_rvas"
                ],
                [0x1000],
            )
            self.assertEqual(
                package["inputs"]["external_dispatch"]["blocked_sites"],
                [],
            )

    def test_anonymous_dynamic_call_is_not_expanded_across_import_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(
                root,
                rows=_internal_indirect_rows(),
                import_iat_vas={("msvcrt.dll", "__p__commode"): 0x43219C},
            )
            profile = root / "external-profile.json"
            _write_external_profile(profile)

            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )

            plan = json.loads(
                (engine / "native-engine-plan.json").read_text(encoding="utf-8")
            )
            self.assertIsNone(plan["external_sites"][0]["import"])
            self.assertEqual(plan["import_bindings"], [{
                "dll": "msvcrt.dll",
                "symbol": "__p__commode",
                "ordinal": None,
                "iat_va": 0x43219C,
                "iat_rva": 0x3219C,
            }])
            rules = package["inputs"]["external_range_contracts"]["rules"]
            self.assertEqual(rules, [])
            dispatch = package["inputs"]["external_dispatch"]
            self.assertEqual(dispatch["authorized_instruction_rvas"], [])
            self.assertEqual(dispatch["unknown_site_disposition"], "fail-closed-before-call")
            self.assertEqual(len(dispatch["blocked_sites"]), 1)
            self.assertEqual(
                dispatch["blocked_sites"][0]["category"],
                "uncontracted_dynamic_external_target",
            )
            self.assertEqual(
                dispatch["blocked_sites"][0]["runtime_disposition"],
                "fail-closed-as-unimplemented-before-call",
            )
            source = (root / "runtime/native-runtime.c").read_text(
                encoding="ascii"
            )
            self.assertIn("stage_b_native_external_site_authorized", source)
            self.assertIn("stage_b_native_diagnostic_reason = 0x2009U", source)
            self.assertIn("stage_b_native_diagnostic_reason = 0x200aU", source)

    def test_external_range_size_can_be_read_from_checked_call_stack(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "external-profile.json"
            _write_external_profile(profile, size_kind="argument")
            interpreter, engine = _packages(
                root,
                rows=_machine_ir_indirect_external_result_rows(),
                import_iat_vas={("msvcrt.dll", "__p__commode"): 0x43219C},
                machine_ir=True,
                external_profile=profile,
            )

            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )

            rule = package["inputs"]["external_range_contracts"]["rules"][0]
            self.assertEqual(rule["argument_count"], 2)
            self.assertEqual(rule["size_argument"], 1)
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn("stage_b_native_external_argument(", source)
            self.assertIn(
                "stage_b_native_runtime_capture_external_call(", source
            )
            self.assertIn(
                "input->esp + snapshot->argument_base_offset", source
            )
            self.assertIn(
                "event->arguments[i] != value", source
            )

    def test_external_result_range_supports_bounded_zero_run_extent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "external-profile.json"
            _write_external_profile(profile, size_kind="bounded_zero_run")
            interpreter, engine = _packages(
                root, rows=_external_result_rows(), external_profile=profile
            )

            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=root / "runtime",
            )

            rule = package["inputs"]["external_range_contracts"]["rules"][0]
            self.assertEqual(rule["termination_unit_bytes"], 2)
            self.assertEqual(rule["termination_zero_units"], 2)
            self.assertEqual(rule["termination_max_units"], 4096)
            source = (root / "runtime/native-runtime.c").read_text(encoding="ascii")
            self.assertIn("stage_b_native_zero_run_extent(", source)
            self.assertIn("run == zero_units", source)

    def test_modeled_termination_and_root_callback_buffers_are_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(
                root,
                rows=[_transfer(0x1000), _transfer(0x2000)],
                callback_targets=[{
                    "rva": 0x2000,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 12,
                }],
                modeled_termination=True,
            )
            runtime = root / "runtime"
            package = write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )

            plan = json.loads(
                (engine / "native-engine-plan.json").read_text(encoding="utf-8")
            )
            engine_package = json.loads(
                (engine / "native-engine-package.json").read_text(encoding="utf-8")
            )
            assembly = (engine / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertEqual(
                plan["termination_import"],
                {
                    "argument_source": "cdecl-stack-word-0-from-eax",
                    "dll": "msvcrt.dll",
                    "iat_va": 0x4321D8,
                    "ordinal": None,
                    "required_disposition": "terminates",
                    "symbol": "_amsg_exit",
                    "transfer": "tail_jump",
                },
            )
            self.assertIn("jmp DWORD PTR ds:0x004321d8", assembly)
            self.assertNotIn("ud2", assembly)
            self.assertIn("_stage_b_native_entry_dispatch_return:", assembly)
            self.assertIn("_stage_b_native_entry_return:", assembly)
            self.assertIn("_stage_b_native_termination:", assembly)
            self.assertIn(
                "_stage_b_native_callback_dispatch_return_00002000:",
                assembly,
            )
            self.assertIn(
                "mov edx, OFFSET FLAT:_stage_b_native_launch_state", assembly
            )
            self.assertIn(
                "mov ebx, OFFSET FLAT:_stage_b_native_launch_output", assembly
            )
            self.assertIn(
                "mov DWORD PTR [edx + 248], 0x00001000", assembly
            )
            self.assertIn(
                "mov DWORD PTR [edx + 248], 0x00002000", assembly
            )
            self.assertIn(
                "mov DWORD PTR [edx + 44], ecx", assembly
            )
            self.assertEqual(
                engine_package["policy"]["nested_callback_engine_buffers"],
                "stack-local-requires-checked-runtime-frame",
            )
            self.assertEqual(
                plan["launch_wrapper_symbols"],
                {
                    "entry_dispatch_return":
                        "stage_b_native_entry_dispatch_return",
                    "entry_return": "stage_b_native_entry_return",
                    "termination": "stage_b_native_termination",
                    "callback_dispatch_returns": [
                        "stage_b_native_callback_dispatch_return_00002000"
                    ],
                },
            )
            self.assertEqual(
                package["policy"]["terminal_control"],
                "record-status-and-modeled-environment-termination",
            )

    def test_internal_indirect_target_uses_authoritative_interpreter_runtime(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        assert compiler is not None and nm is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, _internal_indirect_rows())
            runtime = root / "runtime"
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )

            interpreter_source = (
                interpreter / "state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            invoke = interpreter_source.split(
                "stage_b_call_status stage_b_invoke_call", 1
            )[1]
            resolve_index = invoke.index("resolve_code_target")
            indirect_invoke_index = invoke.index(
                "return stage_b_invoke_internal_call(", resolve_index
            )
            self.assertLess(resolve_index, indirect_invoke_index)
            self.assertLess(
                indirect_invoke_index,
                invoke.index("return stage_b_dispatch_external_call"),
            )
            self.assertIn("call_input.esp -= 4U;", interpreter_source)
            self.assertIn("event->return_rva, &memory_fault", interpreter_source)
            runtime_source = (runtime / "native-runtime.c").read_text(encoding="ascii")
            engine_source = (engine / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            self.assertIn("0x00002000U", runtime_source)
            self.assertIn(
                ".resolve_code_target = stage_b_native_resolve_code_target",
                runtime_source,
            )
            self.assertIn("stage_b_native_runtime_run_at_rva(", engine_source)
            self.assertIn("stage_b_native_read_allowed", runtime_source)
            self.assertIn("context->headers_size = headers_size;", runtime_source)
            self.assertIn(
                "STAGE_B_NATIVE_THREAD_ENVIRONMENT_BYTES 0x1000U",
                runtime_source,
            )
            self.assertIn(
                "stage_b_native_inside_thread_environment(context, address, end)",
                runtime_source,
            )
            write_policy = runtime_source.split(
                "static uint32_t stage_b_native_write_allowed", 1
            )[1].split("static uint32_t stage_b_native_read_allowed", 1)[0]
            self.assertIn(
                "stage_b_native_inside_thread_environment", write_policy
            )
            self.assertNotIn("static stage_b_runtime", engine_source)
            self.assertNotIn(".resolve_code_target = 0", engine_source)

            sources = [
                interpreter / "state-machine-interpreter.c",
                interpreter / "state-machine-program.c",
                engine / "native-engine-bridges.S",
                engine / "native-engine-wrapper.c",
                engine / "native-engine-layout.c",
                runtime / "native-runtime.c",
            ]
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = root / f"unified-{index}.o"
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
                        "-mno-stack-arg-probe",
                        "-I",
                        str(interpreter),
                        "-I",
                        str(engine),
                        "-I",
                        str(runtime),
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
            payload = root / "unified-runtime.exe"
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
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ [BD] _stage_b_native_runtime_instance$", symbols
                )),
                1,
            )
            self.assertRegex(
                symbols,
                r"(?m)^\S+ T _stage_b_native_runtime_run_at_rva$",
            )
            self.assertRegex(
                symbols,
                r"(?m)^\S+ T _stage_b_native_runtime_run_nested_callback$",
            )
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ T _stage_b_dispatch_external_call$", symbols
                )),
                1,
            )
            self.assertNotIn("stage_b_native_replay_checked_x87_command", symbols)

    def test_nonzero_x87_inventory_links_exactly_one_engine_handler(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        nm = shutil.which("i686-w64-mingw32-nm")
        assert compiler is not None and nm is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interpreter, engine = _packages(root, [_qualified_x87_transfer()])
            runtime = root / "runtime"
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                out=runtime,
            )
            runtime_source = (runtime / "native-runtime.c").read_text(encoding="ascii")
            bridge_source = (engine / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertIn("mov WORD PTR [edx + 216], ax", bridge_source)
            self.assertIn("mov BYTE PTR [edx + 220], al", bridge_source)
            self.assertIn("mov WORD PTR [edx + 236], ax", bridge_source)
            self.assertIn("shr ecx, 11", bridge_source)
            self.assertIn("imul ecx, ecx, 10", bridge_source)
            self.assertIn(
                "extern stage_b_call_status stage_b_native_execute_typed_x87_operation",
                runtime_source,
            )
            self.assertIn(
                ".execute_typed_x87_operation = "
                "stage_b_native_execute_typed_x87_operation",
                runtime_source,
            )

            sources = [
                interpreter / "state-machine-interpreter.c",
                interpreter / "state-machine-program.c",
                engine / "native-engine-bridges.S",
                engine / "native-engine-wrapper.c",
                engine / "native-engine-layout.c",
                runtime / "native-runtime.c",
            ]
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = root / f"x87-{index}.o"
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
                        "-mno-stack-arg-probe",
                        "-I",
                        str(interpreter),
                        "-I",
                        str(engine),
                        "-I",
                        str(runtime),
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
            runtime_object_symbols = subprocess.run(
                [nm, str(objects[-1])], check=True, text=True, capture_output=True
            ).stdout
            self.assertRegex(
                runtime_object_symbols,
                r"(?m)^\s+U _stage_b_native_execute_typed_x87_operation$",
            )
            payload = root / "x87-runtime.exe"
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
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ T _stage_b_native_execute_typed_x87_operation$",
                    symbols,
                )),
                1,
            )
            self.assertEqual(
                len(re.findall(
                    r"(?m)^\S+ [BD] _stage_b_native_runtime_instance$", symbols
                )),
                1,
            )

    def test_internal_call_to_tail_import_thunk_links_without_callsite_shift(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        assert compiler is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "external-profile.json"
            _write_sleep_profile(profile)
            interpreter, engine = _packages(
                root,
                _internal_tail_import_rows(),
                external_profile=profile,
            )
            runtime = root / "runtime"
            write_stage_b_native_runtime_package(
                interpreter_package=interpreter,
                native_engine_package=engine,
                external_profile=profile,
                out=runtime,
            )
            plan = json.loads(
                (engine / "native-engine-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(plan["status"], "ready", plan["blockers"])
            self.assertEqual(len(plan["external_sites"]), 1)
            self.assertEqual(plan["external_sites"][0]["instruction_rva"], 0x2000)
            self.assertEqual(plan["external_sites"][0]["disposition"], "tail_jump")
            assembly = (engine / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertIn("mov DWORD PTR [ecx - 4], ebx", assembly)
            self.assertIn("sub esp, 4", assembly)
            self.assertNotIn("add esp, 4", assembly)

            sources = [
                interpreter / "state-machine-interpreter.c",
                interpreter / "state-machine-program.c",
                engine / "native-engine-bridges.S",
                engine / "native-engine-wrapper.c",
                engine / "native-engine-layout.c",
                runtime / "native-runtime.c",
            ]
            objects: list[Path] = []
            for index, source in enumerate(sources):
                target = root / f"tail-{index}.o"
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
                        "-mno-stack-arg-probe",
                        "-I",
                        str(interpreter),
                        "-I",
                        str(engine),
                        "-I",
                        str(runtime),
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
                    str(root / "tail-runtime.exe"),
                ],
                check=True,
                text=True,
                capture_output=True,
            )


if __name__ == "__main__":
    unittest.main()
