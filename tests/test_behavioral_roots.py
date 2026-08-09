from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.behavioral_roots import (
    BEHAVIORAL_ROOTS_FORMAT,
    BehavioralRootsError,
    behavioral_roots_sha256,
    canonical_behavioral_roots_payload,
    generate_behavioral_roots,
    load_behavioral_roots,
    validate_behavioral_roots,
)

from tests.pe_fixtures import pe32_image, pe32_tls_image
from tests.test_stage_a_pe_entry_surface import _pe32_export_surface_image


_PE_OFFSET = 0x80
_OPTIONAL_OFFSET = _PE_OFFSET + 4 + 20
_EXPORT_DIRECTORY_OFFSET = _OPTIONAL_OFFSET + 96
_TLS_DIRECTORY_SIZE_OFFSET = _OPTIONAL_OFFSET + 96 + 9 * 8 + 4


class BehavioralRootsTests(unittest.TestCase):
    def test_generates_deterministic_entry_only_artifact_and_loads_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "entry.exe"
            identical = root / "renamed-copy.exe"
            artifact = root / "behavioral-roots.json"
            image = pe32_image(b"\xc3")
            original.write_bytes(image)
            identical.write_bytes(image)

            first = generate_behavioral_roots(original)
            second = generate_behavioral_roots(identical)
            artifact.write_text(json.dumps(first, indent=2), encoding="utf-8")

            self.assertEqual(first, second)
            self.assertEqual(first["format"], BEHAVIORAL_ROOTS_FORMAT)
            self.assertEqual(first["status"], "complete")
            self.assertEqual(
                first["roots"],
                [
                    {
                        "kind": "pe_entrypoint",
                        "identity": "pe-entrypoint",
                        "rva": 0x1000,
                    }
                ],
            )
            self.assertEqual(first["pe"]["machine"], "i386")
            self.assertEqual(first["pe"]["bitness"], 32)
            self.assertEqual(first["pe"]["image_base"], 0x400000)
            self.assertEqual(first["pe"]["entrypoint_rva"], 0x1000)
            self.assertEqual(
                first["contract_sha256"], behavioral_roots_sha256(first)
            )
            self.assertEqual(
                canonical_behavioral_roots_payload(first),
                canonical_behavioral_roots_payload(second),
            )
            self.assertEqual(
                load_behavioral_roots(artifact, original_pe=original), first
            )

    def test_omits_zero_pe_entrypoint(self) -> None:
        image = bytearray(pe32_image(b"\xc3"))
        struct.pack_into("<I", image, _OPTIONAL_OFFSET + 16, 0)

        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "no-entry.exe"
            original.write_bytes(image)
            artifact = generate_behavioral_roots(original)

            self.assertEqual(artifact["pe"]["entrypoint_rva"], 0)
            self.assertEqual(artifact["roots"], [])
            self.assertEqual(artifact["counts"]["pe_entrypoint"], 0)

    def test_includes_only_executable_non_forwarded_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "exports.dll"
            original.write_bytes(_pe32_export_surface_image())

            artifact = generate_behavioral_roots(original)
            exports = [
                root for root in artifact["roots"] if root["kind"] == "pe_export"
            ]

            self.assertEqual(
                [(root["ordinal"], root["name"], root["rva"]) for root in exports],
                [
                    (7, "code_alias", 0x1000),
                    (7, "code_export", 0x1000),
                    (10, None, 0x1010),
                ],
            )
            self.assertEqual(artifact["counts"]["pe_export"], 3)
            self.assertNotIn(
                "data_export", {root.get("name") for root in artifact["roots"]}
            )
            self.assertNotIn(
                "forwarded", {root.get("name") for root in artifact["roots"]}
            )

    def test_includes_exact_immutable_tls_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "tls.exe"
            original.write_bytes(pe32_tls_image((0x1100, 0x1108)))

            artifact = generate_behavioral_roots(original)
            callbacks = [
                root
                for root in artifact["roots"]
                if root["kind"] == "pe_tls_callback"
            ]

            self.assertEqual(
                callbacks,
                [
                    {
                        "kind": "pe_tls_callback",
                        "identity": "pe-tls-callback:index:0",
                        "rva": 0x1100,
                        "callback_index": 0,
                    },
                    {
                        "kind": "pe_tls_callback",
                        "identity": "pe-tls-callback:index:1",
                        "rva": 0x1108,
                        "callback_index": 1,
                    },
                ],
            )

    def test_rejects_stale_hash_and_resealed_duplicate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "entry.exe"
            original.write_bytes(pe32_image(b"\xc3"))
            artifact = generate_behavioral_roots(original)

            stale = copy.deepcopy(artifact)
            stale["pe"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(BehavioralRootsError, "self-hash is stale"):
                validate_behavioral_roots(stale, original_pe=original)

            duplicate = copy.deepcopy(artifact)
            duplicate["roots"].append(copy.deepcopy(duplicate["roots"][0]))
            duplicate["counts"]["roots"] += 1
            duplicate["counts"]["pe_entrypoint"] += 1
            duplicate["contract_sha256"] = behavioral_roots_sha256(duplicate)
            with self.assertRaisesRegex(
                BehavioralRootsError, "duplicates a kind or identity"
            ):
                validate_behavioral_roots(duplicate, original_pe=original)

    def test_fails_closed_on_incomplete_export_or_tls_parsing(self) -> None:
        cases: dict[str, tuple[bytes, int, int, str]] = {
            "export": (
                _pe32_export_surface_image(),
                _EXPORT_DIRECTORY_OFFSET,
                0,
                "strict PE export parsing failed",
            ),
            "TLS": (
                pe32_tls_image((0x1100,)),
                _TLS_DIRECTORY_SIZE_OFFSET,
                23,
                "strict PE TLS parsing failed",
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, (raw, offset, value, message) in cases.items():
                with self.subTest(name=name):
                    image = bytearray(raw)
                    struct.pack_into("<I", image, offset, value)
                    original = root / f"malformed-{name}.exe"
                    original.write_bytes(image)
                    with self.assertRaisesRegex(BehavioralRootsError, message):
                        generate_behavioral_roots(original)

    def test_rejects_nonzero_entrypoint_outside_executable_bounds(self) -> None:
        image = bytearray(pe32_image(b"\xc3"))
        struct.pack_into("<I", image, _OPTIONAL_OFFSET + 16, 0x1800)

        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "bad-entry.exe"
            original.write_bytes(image)
            with self.assertRaisesRegex(
                BehavioralRootsError, "PE entrypoint is outside executable bounds"
            ):
                generate_behavioral_roots(original)


if __name__ == "__main__":
    unittest.main()
