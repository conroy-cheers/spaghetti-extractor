from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image

from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.stage_b_native_image import (
    derive_native_image_inputs,
    select_native_termination_import,
)


class StageBNativeImageTests(unittest.TestCase):
    def test_derives_fixed_base_entry_and_exact_iat_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            contract = root / "load-image-contract.json"
            original.write_bytes(
                pe32_import_image(b"\xc3", symbol="ExitProcess")
            )
            write_stage_a_load_image_contract(original_pe=original, out=contract)

            inputs = derive_native_image_inputs(load_image_contract=contract)
            termination = select_native_termination_import(
                profile_paths=[
                    Path("profiles/pe32-kernel32-lockstep-v1.json").resolve()
                ],
                import_iat_vas=inputs.import_iat_vas,
            )

            self.assertEqual(inputs.entry_rva, 0x1000)
            self.assertEqual(inputs.fixed_image_base, 0x400000)
            self.assertEqual(inputs.initial_zero_ranges, ())
            self.assertEqual(
                inputs.import_iat_vas[("kernel32.dll", "ExitProcess")],
                0x402040,
            )
            self.assertEqual(termination, {
                "dll": "kernel32.dll",
                "symbol": "ExitProcess",
                "ordinal": None,
                "disposition": "terminates",
            })


if __name__ == "__main__":
    unittest.main()
