from __future__ import annotations

import copy
import hashlib
import json
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.relational.full_machine_lockstep import (
    FULL_MACHINE_LOCKSTEP_ARTIFACT_FORMAT,
    FullMachineLockstepArtifact,
    FullMachineLockstepImportIdentity,
    FullMachineLockstepSelectionMode,
    build_full_machine_lockstep_artifact,
    full_machine_lockstep_artifact_sha256,
    parse_full_machine_lockstep_artifact,
    serialize_full_machine_lockstep_artifact,
)
from spaghetti_extractor.stage_binary import (
    StageAImport,
    StageAInputError,
    _parse_stage_a_pe,
)
from tests.pe_fixtures import pe32_import_image


def _ordinal_import_image(ordinal: int) -> bytes:
    image = bytearray(pe32_import_image(b"\xc3", symbol="placeholder"))
    ordinal_lookup = 0x80000000 | ordinal
    struct.pack_into("<I", image, 0x430, ordinal_lookup)
    struct.pack_into("<I", image, 0x440, ordinal_lookup)
    return bytes(image)


def _rehash(payload: dict[str, object]) -> None:
    body = {key: value for key, value in payload.items() if key != "artifact_sha256"}
    payload["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


class StageAFullMachineLockstepContractTests(unittest.TestCase):
    def test_symbol_and_ordinal_imports_roundtrip_from_pe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            symbol_original = root / "symbol-original.exe"
            symbol_candidate = root / "symbol-candidate.exe"
            ordinal_original = root / "ordinal-original.exe"
            ordinal_candidate = root / "ordinal-candidate.exe"
            symbol_original.write_bytes(
                pe32_import_image(b"\x90\xc3", symbol="GetTickCount")
            )
            symbol_candidate.write_bytes(
                pe32_import_image(b"\xc3", symbol="GetTickCount")
            )
            ordinal_original.write_bytes(_ordinal_import_image(42))
            ordinal_candidate.write_bytes(_ordinal_import_image(42))

            symbol_artifact = build_full_machine_lockstep_artifact(
                symbol_original, symbol_candidate
            )
            ordinal_artifact = build_full_machine_lockstep_artifact(
                ordinal_original, ordinal_candidate
            )

            self.assertEqual(
                symbol_artifact.common_imports,
                (
                    FullMachineLockstepImportIdentity(
                        dll="kernel32.dll", symbol="GetTickCount"
                    ),
                ),
            )
            self.assertEqual(
                ordinal_artifact.common_imports,
                (
                    FullMachineLockstepImportIdentity(
                        dll="kernel32.dll", ordinal=42
                    ),
                ),
            )
            payload = serialize_full_machine_lockstep_artifact(symbol_artifact)
            self.assertEqual(payload["format"], FULL_MACHINE_LOCKSTEP_ARTIFACT_FORMAT)
            self.assertIs(payload["acceptance_authority"], False)
            self.assertEqual(
                payload["theorem_assumption"],
                {
                    "same_site": True,
                    "same_order": True,
                    "same_import": True,
                    "complete_related_machine_boundary": True,
                    "paired_stateful_environment_must_reestablish": "StateRel",
                },
            )
            reparsed = parse_full_machine_lockstep_artifact(
                json.loads(json.dumps(payload)),
                expected_original=symbol_original,
                expected_candidate=symbol_candidate,
            )
            self.assertEqual(reparsed, symbol_artifact)
            self.assertIsInstance(reparsed, FullMachineLockstepArtifact)

    def test_selected_import_mismatch_and_duplicates_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_path = root / "original.exe"
            candidate_path = root / "candidate.exe"
            original_path.write_bytes(
                pe32_import_image(b"\xc3", symbol="WriteFile")
            )
            candidate_path.write_bytes(
                pe32_import_image(b"\xc3", symbol="ReadFile")
            )
            with self.assertRaisesRegex(StageAInputError, "import mismatch"):
                build_full_machine_lockstep_artifact(
                    original_path,
                    candidate_path,
                    mode=FullMachineLockstepSelectionMode.SELECTED,
                    selected_imports=[
                        {"dll": "KERNEL32.dll", "symbol": "WriteFile"}
                    ],
                )

            parsed = _parse_stage_a_pe(original_path)
            duplicate = replace(parsed, imports=parsed.imports + parsed.imports)
            with self.assertRaisesRegex(StageAInputError, "duplicate import"):
                build_full_machine_lockstep_artifact(duplicate, parsed)

            with self.assertRaisesRegex(StageAInputError, "duplicate import"):
                build_full_machine_lockstep_artifact(
                    parsed,
                    parsed,
                    mode="selected",
                    selected_imports=[parsed.imports[0], parsed.imports[0]],
                )

    def test_selection_and_hash_are_canonical_and_content_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "base.exe"
            path.write_bytes(pe32_import_image(b"\xc3", symbol="unused"))
            base = _parse_stage_a_pe(path)
            imports = (
                StageAImport(
                    dll="USER32.dll",
                    symbol="MessageBoxA",
                    ordinal=None,
                    thunk_rva=0x2044,
                ),
                StageAImport(
                    dll="KERNEL32.dll",
                    symbol=None,
                    ordinal=42,
                    thunk_rva=0x2040,
                ),
            )
            original = replace(base, imports=imports)
            candidate = replace(base, imports=tuple(reversed(imports)))
            selectors = [
                FullMachineLockstepImportIdentity(
                    dll="user32.dll", symbol="MessageBoxA"
                ),
                FullMachineLockstepImportIdentity(
                    dll="kernel32.dll", ordinal=42
                ),
            ]
            first = build_full_machine_lockstep_artifact(
                original,
                candidate,
                mode="selected",
                selected_imports=selectors,
            )
            second = build_full_machine_lockstep_artifact(
                original,
                candidate,
                mode="selected",
                selected_imports=reversed(selectors),
            )
            self.assertEqual(first, second)
            self.assertEqual(
                full_machine_lockstep_artifact_sha256(first),
                full_machine_lockstep_artifact_sha256(second.to_payload()),
            )

            all_common = build_full_machine_lockstep_artifact(original, candidate)
            self.assertEqual(
                all_common.selection.mode,
                FullMachineLockstepSelectionMode.ALL_COMMON,
            )
            self.assertEqual(all_common.selection.imports, all_common.common_imports)
            self.assertNotEqual(
                first.artifact_sha256, all_common.artifact_sha256
            )

    def test_parser_fails_closed_on_tampering_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.exe"
            path.write_bytes(pe32_import_image(b"\xc3", symbol="ExitProcess"))
            payload = serialize_full_machine_lockstep_artifact(
                build_full_machine_lockstep_artifact(path, path)
            )

            unknown = copy.deepcopy(payload)
            unknown["unexpected"] = True
            with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
                parse_full_machine_lockstep_artifact(unknown)

            authority = copy.deepcopy(payload)
            authority["acceptance_authority"] = True
            _rehash(authority)
            with self.assertRaisesRegex(StageAInputError, "acceptance_authority"):
                parse_full_machine_lockstep_artifact(authority)

            numeric_authority = copy.deepcopy(payload)
            numeric_authority["acceptance_authority"] = 0
            _rehash(numeric_authority)
            with self.assertRaisesRegex(StageAInputError, "acceptance_authority"):
                parse_full_machine_lockstep_artifact(numeric_authority)

            theorem = copy.deepcopy(payload)
            theorem["theorem_assumption"]["same_order"] = 1
            _rehash(theorem)
            with self.assertRaisesRegex(StageAInputError, "theorem assumption"):
                parse_full_machine_lockstep_artifact(theorem)

            incomplete_common = copy.deepcopy(payload)
            incomplete_common["common_imports"] = []
            incomplete_common["selection"]["imports"] = []
            _rehash(incomplete_common)
            with self.assertRaisesRegex(StageAInputError, "exactly match"):
                parse_full_machine_lockstep_artifact(incomplete_common)

            bad_digest = copy.deepcopy(payload)
            bad_digest["artifact_sha256"] = "0" * 64
            with self.assertRaisesRegex(StageAInputError, "digest does not match"):
                parse_full_machine_lockstep_artifact(bad_digest)

    def test_delay_imports_and_forwarder_chains_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.exe"
            path.write_bytes(pe32_import_image(b"\xc3", symbol="ExitProcess"))

            delayed = _parse_stage_a_pe(path)
            delayed.pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress = 0x3000
            delayed.pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size = 32
            with self.assertRaisesRegex(StageAInputError, "delay imports"):
                build_full_machine_lockstep_artifact(delayed, delayed)

            forwarded = _parse_stage_a_pe(path)
            forwarded.pe.DIRECTORY_ENTRY_IMPORT[0].struct.ForwarderChain = 1
            with self.assertRaisesRegex(StageAInputError, "forwarder chain"):
                build_full_machine_lockstep_artifact(forwarded, forwarded)


if __name__ == "__main__":
    unittest.main()
