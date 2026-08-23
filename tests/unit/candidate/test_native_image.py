from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image

from spaghetti_extractor.roundtrip_fuzz.image_io import (
    write_spx_load_image_contract,
)
from spaghetti_extractor.candidate.image import (
    derive_native_image_inputs,
    select_native_termination_import,
)
from spaghetti_extractor.candidate.imports import NativeImportSlot
from spaghetti_extractor.errors import ToolkitInputError


class NativeImageTests(unittest.TestCase):
    def test_exact_import_slot_rejects_boolean_integer_fields(self) -> None:
        with self.assertRaisesRegex(ToolkitInputError, "ordinal"):
            NativeImportSlot(
                image_id="main",
                descriptor_index=0,
                cell_index=0,
                dll="fixture.dll",
                symbol=None,
                ordinal=True,
                iat_rva=0x2040,
                iat_va=0x402040,
            )

    def test_derives_fixed_base_entry_and_exact_iat_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            contract = root / "load-image-contract.json"
            original.write_bytes(
                pe32_import_image(b"\xc3", symbol="ExitProcess")
            )
            write_spx_load_image_contract(original_pe=original, out=contract)

            inputs = derive_native_image_inputs(load_image_contract=contract)
            termination = select_native_termination_import(
                profile_paths=[
                    Path("profiles/pe32-kernel32-lockstep-v1.json").resolve()
                ],
                import_slots=inputs.import_slots,
            )

            self.assertEqual(inputs.entry_rva, 0x1000)
            self.assertEqual(inputs.fixed_image_base, 0x400000)
            self.assertEqual(inputs.initial_zero_ranges, ())
            self.assertEqual(
                inputs.import_slots,
                (inputs.import_slots[0],),
            )
            self.assertEqual(inputs.import_slots[0].iat_va, 0x402040)
            self.assertEqual(termination, {
                "dll": "kernel32.dll",
                "symbol": "ExitProcess",
                "ordinal": None,
                "disposition": "terminates",
                "slot_id": inputs.import_slots[0].slot_id,
            })

    def test_preserves_duplicate_physical_slots_for_one_logical_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "duplicate.exe"
            contract = root / "load-image-contract.json"
            original.write_bytes(
                pe32_import_image(
                    b"\xc3", symbol="_fileno", dll="msvcrt.dll", cell_count=2
                )
            )
            write_spx_load_image_contract(original_pe=original, out=contract)

            inputs = derive_native_image_inputs(load_image_contract=contract)

            self.assertEqual(len(inputs.import_slots), 2)
            self.assertEqual(
                [slot.identity for slot in inputs.import_slots],
                [("msvcrt.dll", "_fileno"), ("msvcrt.dll", "_fileno")],
            )
            self.assertEqual(
                [slot.iat_va for slot in inputs.import_slots],
                [0x402040, 0x402044],
            )
            self.assertNotEqual(
                inputs.import_slots[0].slot_id, inputs.import_slots[1].slot_id
            )


if __name__ == "__main__":
    unittest.main()
