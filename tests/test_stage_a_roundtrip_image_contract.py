from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_image, pe32_import_image
from tests.stage_a_relational_support import (
    _pe32_image_with_relocated_data,
    _pe32_tls_image,
)

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT,
    StageALoadImageContract,
    build_stage_a_load_image_contract,
    load_stage_a_load_image_contract,
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.util import sha256_bytes


PE_OFFSET = 0x80
OPTIONAL_OFFSET = PE_OFFSET + 4 + 20
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 224


class StageARoundTripImageContractTests(unittest.TestCase):
    def test_contract_binds_image_and_carries_opaque_safe_runtime_bytes(self) -> None:
        image = pe32_import_image(b"\xb8\x07\x00\x00\x00\xc3", symbol="ExitProcess")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.exe"
            second = root / "different-name.exe"
            first.write_bytes(image)
            second.write_bytes(image)

            contract = build_stage_a_load_image_contract(first)
            same_bytes = build_stage_a_load_image_contract(second)

        self.assertEqual(contract, same_bytes)
        self.assertEqual(contract.format, STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT)
        self.assertEqual(contract.identity.pe_sha256, sha256_bytes(image))
        self.assertEqual(contract.identity.preferred_base, 0x400000)
        self.assertEqual(contract.identity.image_size, 0x3000)
        self.assertEqual(contract.identity.entry_rva, 0x1000)
        self.assertEqual(contract.identity.bitness, 32)
        self.assertEqual(contract.runtime_headers.data, image[:0x200])

        text, idata = contract.sections
        self.assertTrue(text.executable)
        self.assertEqual(text.initialized, ())
        self.assertEqual(text.zero_fill, ())
        self.assertFalse(idata.executable)
        self.assertEqual(idata.initialized[0].data, image[0x400:0x600])
        self.assertEqual(idata.zero_fill, ())

        descriptor = contract.imports[0]
        cell = descriptor.cells[0]
        self.assertEqual(descriptor.dll, "kernel32.dll")
        self.assertEqual(cell.symbol, "ExitProcess")
        self.assertIsNone(cell.ordinal)
        self.assertEqual(cell.iat_rva, 0x2040)
        self.assertEqual(cell.pointer_width, 4)
        self.assertEqual(contract.completeness.import_iat_cell_count, 1)
        self.assertTrue(contract.completeness.complete)

    def test_non_executable_virtual_tail_is_explicit_zero_fill(self) -> None:
        image = bytearray(
            pe32_import_image(b"\xc3", symbol="GetLastError")
        )
        idata_section = SECTION_TABLE_OFFSET + 40
        struct.pack_into("<I", image, idata_section + 8, 0x300)

        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "zero-fill.exe"
            original.write_bytes(image)
            contract = build_stage_a_load_image_contract(original)

        idata = contract.sections[1]
        self.assertEqual(len(idata.initialized[0].data), 0x200)
        self.assertEqual(
            [(item.rva, item.size) for item in idata.zero_fill],
            [(0x2200, 0x100)],
        )
        self.assertEqual(contract.completeness.initialized_byte_count, 0x200)
        self.assertEqual(contract.completeness.zero_fill_byte_count, 0x100)

    def test_import_directory_may_include_tables_and_names_after_descriptors(self) -> None:
        image = bytearray(pe32_import_image(b"\xc3", symbol="ExitProcess"))
        optional_prefix_size = 96
        import_directory = OPTIONAL_OFFSET + optional_prefix_size + 8
        struct.pack_into("<I", image, import_directory + 4, 0x100)

        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "wide-import-directory.exe"
            original.write_bytes(image)
            contract = build_stage_a_load_image_contract(original)

        self.assertEqual(contract.imports[0].dll, "kernel32.dll")
        self.assertEqual(contract.imports[0].cells[0].symbol, "ExitProcess")

    def test_relocations_and_tls_callback_order_are_typed(self) -> None:
        relocation_image = _pe32_image_with_relocated_data(0x3000)
        tls_image = _pe32_tls_image((0x1020, 0x1010))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relocation_path = root / "relocation.exe"
            tls_path = root / "tls.exe"
            relocation_path.write_bytes(relocation_image)
            tls_path.write_bytes(tls_image)

            relocation_contract = build_stage_a_load_image_contract(
                relocation_path
            )
            tls_contract = build_stage_a_load_image_contract(tls_path)

        block = relocation_contract.relocations[0]
        self.assertEqual(block.page_rva, 0x1000)
        self.assertEqual(block.slot_count, 2)
        relocation = block.relocations[0]
        self.assertEqual(relocation.kind, "highlow")
        self.assertEqual(relocation.target_rva, 0x1002)
        self.assertEqual(relocation.preferred_value, 0x403000)
        self.assertEqual(block.relocations[1].kind, "absolute_padding")
        self.assertEqual(
            relocation_contract.completeness.base_relocation_count, 1
        )

        self.assertIsNotNone(tls_contract.tls)
        assert tls_contract.tls is not None
        self.assertEqual(tls_contract.tls.template_rva, 0x2080)
        self.assertEqual(tls_contract.tls.template_data, bytes(4))
        self.assertEqual(
            [(item.order, item.rva) for item in tls_contract.tls.callbacks],
            [(0, 0x1020), (1, 0x1010)],
        )
        self.assertEqual(tls_contract.completeness.tls_callback_count, 2)

    def test_written_contract_is_deterministic_and_needs_no_runtime_original(self) -> None:
        image = pe32_import_image(b"\xc3", symbol="ExitProcess")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            first_out = root / "first.json"
            second_out = root / "second.json"
            original.write_bytes(image)

            first = write_stage_a_load_image_contract(
                original_pe=original, out=first_out
            )
            write_stage_a_load_image_contract(
                original_pe=original, out=second_out
            )
            self.assertEqual(first_out.read_bytes(), second_out.read_bytes())
            self.assertNotIn(str(original), first_out.read_text(encoding="utf-8"))

            verified = load_stage_a_load_image_contract(
                first_out, original_pe=original
            )
            self.assertEqual(verified, first)
            original.unlink()
            opaque_runtime = load_stage_a_load_image_contract(first_out)

        self.assertEqual(opaque_runtime, first)

    def test_schema_hash_binding_and_completeness_fail_closed(self) -> None:
        image = pe32_import_image(b"\xc3", symbol="ExitProcess")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            changed = root / "changed.exe"
            original.write_bytes(image)
            changed.write_bytes(image + b"overlay")
            contract = build_stage_a_load_image_contract(original)
            payload = contract.to_payload()

            with self.assertRaisesRegex(StageAInputError, "does not bind"):
                contract.validate(original_pe=changed)

        unknown = copy.deepcopy(payload)
        unknown["source_path"] = "forbidden.exe"
        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            StageALoadImageContract.parse(unknown)

        missing_headers = copy.deepcopy(payload)
        del missing_headers["runtime_headers"]["data_hex"]
        with self.assertRaisesRegex(StageAInputError, "missing fields"):
            StageALoadImageContract.parse(missing_headers)

        incomplete_section = copy.deepcopy(payload)
        incomplete_section["sections"][1]["initialized"] = []
        with self.assertRaisesRegex(StageAInputError, "initialized coverage"):
            StageALoadImageContract.parse(incomplete_section)

        incomplete_imports = copy.deepcopy(payload)
        incomplete_imports["imports"] = []
        with self.assertRaisesRegex(StageAInputError, "import inventory"):
            StageALoadImageContract.parse(incomplete_imports)

        changed_bytes = copy.deepcopy(payload)
        changed_bytes["sections"][1]["initialized"][0]["data_hex"] = (
            "00" + changed_bytes["sections"][1]["initialized"][0]["data_hex"][2:]
        )
        with self.assertRaisesRegex(StageAInputError, "byte hash changed"):
            StageALoadImageContract.parse(changed_bytes)

    def test_unsupported_relocation_type_is_rejected(self) -> None:
        image = bytearray(_pe32_image_with_relocated_data(0x3000))
        struct.pack_into("<H", image, 0x600 + 8, 0x5002)
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "unsupported-relocation.exe"
            original.write_bytes(image)
            with self.assertRaisesRegex(
                StageAInputError, "unsupported PE base-relocation type 5"
            ):
                build_stage_a_load_image_contract(original)

    def test_json_loader_rejects_non_object_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps([]), encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "must be an object"):
                load_stage_a_load_image_contract(path)


if __name__ == "__main__":
    unittest.main()
