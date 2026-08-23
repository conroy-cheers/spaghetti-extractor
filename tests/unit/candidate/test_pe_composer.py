from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

import pefile

from tests.pe_fixtures import pe32_image

from spaghetti_extractor.candidate.pe import (
    PAYLOAD_RELOCATION_INVENTORY_FORMAT,
    PECompositionError,
    compose_spx_pe,
    plan_spx_pe_composition,
)
from spaghetti_extractor.roundtrip_fuzz.image_io import (
    write_spx_load_image_contract,
)
from spaghetti_extractor.util import sha256_bytes


PE_OFFSET = 0x80
OPTIONAL_OFFSET = PE_OFFSET + 4 + 20
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 224


def _payload(*, rva: int = 0x4000) -> bytes:
    payload = bytearray(pe32_image(b"\xb8\x2a\x00\x00\x00\xc3"))
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 16, rva)
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 20, rva)
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 56, rva + 0x1000)
    struct.pack_into("<I", payload, SECTION_TABLE_OFFSET + 12, rva)
    return bytes(payload)


def _relocations(payload: bytes) -> dict[str, object]:
    return {
        "format": PAYLOAD_RELOCATION_INVENTORY_FORMAT,
        "complete": True,
        "payload_sha256": sha256_bytes(payload),
        "image_base": 0x400000,
        "relocations": [],
    }


class DirectIngressPEComposerTests(unittest.TestCase):
    def test_declared_module_uses_linked_ingress_without_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            contract = root / "load-image-contract.json"
            write_spx_load_image_contract(original_pe=original, out=contract)
            payload = _payload()

            plan = plan_spx_pe_composition(
                load_image_contract=contract,
                payload_pe=payload,
                entry_rva=0x4000,
                payload_relocation_inventory=_relocations(payload),
            )
            self.assertEqual(plan.entry_rva, 0x4000)

            result = compose_spx_pe(
                load_image_contract=contract,
                payload_pe=payload,
                entry_rva=0x4000,
                payload_relocation_inventory=_relocations(payload),
                out_dir=root / "out",
                candidate_filename="hello.exe",
            )
            self.assertEqual(result["candidate"]["path"], "hello.exe")
            self.assertNotIn("anchors", result)
            self.assertNotIn("executable_anchor_manifest", result["inputs"])
            candidate = pefile.PE(str(root / "out" / "hello.exe"))
            try:
                self.assertEqual(candidate.OPTIONAL_HEADER.AddressOfEntryPoint, 0x4000)
            finally:
                candidate.close()

    def test_invalid_ingress_or_loader_basename_fails_closed(self) -> None:
        payload = _payload()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            contract = root / "load-image-contract.json"
            write_spx_load_image_contract(original_pe=original, out=contract)
            with self.assertRaisesRegex(PECompositionError, "entry RVA"):
                plan_spx_pe_composition(
                    load_image_contract=contract,
                    payload_pe=payload,
                    entry_rva=-1,
                    payload_relocation_inventory=_relocations(payload),
                )
            with self.assertRaisesRegex(PECompositionError, "loader basename"):
                compose_spx_pe(
                    load_image_contract=contract,
                    payload_pe=payload,
                    entry_rva=0x4000,
                    payload_relocation_inventory=_relocations(payload),
                    out_dir=root / "out",
                    candidate_filename="nested/hello.exe",
                )


if __name__ == "__main__":
    unittest.main()
