"""SEH projection cases for the generic native-ingress runtime."""

from __future__ import annotations

import unittest

from .test_native_ingress_protocols import (
    Path,
    ToolkitInputError,
    _exception_record_projection_masks_v1,
    _native_ingress_plan,
    _seh_projection_masks,
    render_native_ingress_assembly,
    render_native_ingress_source,
    shutil,
    subprocess,
    tempfile,
)


class NativeIngressSehProjectionTests(unittest.TestCase):
    def test_seh_x87_context_projection_is_typed_and_complete(self) -> None:
        self.assertEqual(
            _seh_projection_masks({
                "projections": {
                    "registers": ["eax"],
                    "flags": ["eflags"],
                    "stack": ["esp"],
                    "context": [],
                    "x87": ["control_word", "status_word", "stack", "environment"],
                }
            }),
            (0x20, 1, 1, 0xFF, 0, 0),
        )
        plan = _native_ingress_plan(0x1010)
        plan["outcome_protocols"][0].update({
            "outcomes": ["normal", "exceptional"],
            "seh_protocol_ids": ["fixture-seh-divide"],
        })
        plan["seh_protocols"] = [{
            "id": "fixture-seh-divide",
            "exception": {
                "code": 0xC0000094,
                "flags_mask": 0,
                "flags_value": 0,
                "parameter_count": 0,
                "continuable": True,
                "access_violation": None,
            },
            "projections": {
                "registers": ["eax"],
                "flags": ["eflags"],
                "stack": ["esp"],
                "context": [],
                "x87": ["all"],
            },
            "escape_disposition": "escape_callable_root",
            "handler_rva": 0x1100,
            "resumption_rva": 0x1120,
            "gateway_handler_symbol": "spx_seh_gateway_divide",
            "portals": [{
                "source_rva": 0x1010,
                "candidate_symbol": "spx_exception_1010",
            }],
        }]
        source = render_native_ingress_source(plan)
        self.assertIn("if (seh->resumption_rva == 0U) return 0U;", source)
        self.assertIn("spx_native_import_context_x87", source)
        self.assertIn("spx_native_capture_current_x87", source)
        self.assertIn("spx_native_restore_current_x87", source)
        self.assertIn("spx_native_capture_current_x87(frame->input, 0xffU);", source)
        self.assertIn("spx_native_restore_capture(capture, frame->input);", source)
        assembly_source = render_native_ingress_assembly(plan)
        self.assertNotIn("int3", assembly_source.lower())
        self.assertNotIn("diagnostic_trap", assembly_source)
        self.assertNotIn("ud2", assembly_source)
        self.assertIn("_spx_exception_1010:\n    int 0x29", assembly_source)
        self.assertIn(
            ".Lspx_exception_recovery_trap:\n"
            "    test edi, edi\n"
            "    jz .Lspx_exception_recovery_fast_fail\n"
            "    mov esp, edi",
            assembly_source,
        )
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if compiler is not None:
            with tempfile.TemporaryDirectory() as temporary:
                assembly = Path(temporary) / "seh-ingress.s"
                assembly.write_text(
                    assembly_source, encoding="ascii"
                )
                subprocess.run(
                    [compiler, "-c", str(assembly), "-o", str(assembly.with_suffix(".o"))],
                    check=True,
                    text=True,
                    capture_output=True,
                )

    def test_primary_exception_record_pointer_is_checked_null(self) -> None:
        self.assertEqual(
            _seh_projection_masks({
                "handler_rva": 0x1100,
                "resumption_rva": 0x1120,
                "projections": {
                    "registers": [],
                    "flags": [],
                    "stack": [],
                    "context": [],
                    "x87": [],
                    "exception_record": ["ExceptionRecord"],
                },
            }),
            (0, 0, 0, 0, 0x004, 0),
        )
        source = render_native_ingress_source(_native_ingress_plan(0x1010))
        self.assertIn(
            "(seh->exception_record_projection_mask & 0x004U) == 0U",
            source,
        )
        self.assertIn("record[2] == 0U", source)
        self.assertIn(
            "records[depth][2] = depth + 1U < "
            "seh->exception_record_count",
            source,
        )

    def test_nested_exception_record_masks_include_checked_chain_links(
        self,
    ) -> None:
        protocol = {
            "handler_rva": 0x1100,
            "resumption_rva": 0x1120,
            "projections": {
                "registers": [],
                "flags": [],
                "stack": [],
                "context": [],
                "x87": [],
                "exception_record": [
                    "ExceptionRecord[1].ExceptionCode",
                    "ExceptionRecord[2].ExceptionInformation[3]",
                ],
            },
        }
        self.assertEqual(
            _exception_record_projection_masks_v1(protocol),
            (0x004, 0x005, 0x100),
        )
        self.assertEqual(
            _seh_projection_masks(protocol),
            (0, 0, 0, 0, 0x004, 0),
        )
        source = render_native_ingress_source(_native_ingress_plan(0x1010))
        self.assertIn("spx_native_copy_exception_chain(", source)
        self.assertIn("source == 0 ? 1U : 0U", source)

    def test_guest_handler_exception_objects_fail_closed_until_realized(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ToolkitInputError,
            "require an authorized guest resumption",
        ):
            _seh_projection_masks({
                "handler_rva": 0x1100,
                "projections": {
                    "registers": [],
                    "flags": [],
                    "stack": [],
                    "exception_record": ["ExceptionCode"],
                    "context": ["eax"],
                    "x87": [],
                },
            })
