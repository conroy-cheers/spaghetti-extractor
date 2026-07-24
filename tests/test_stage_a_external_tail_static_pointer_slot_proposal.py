from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.lean.external_tail_static_pointer_slot_authority import (
    ExternalTailStaticPointerSlotAuthorityError,
    load_external_tail_static_pointer_slot_authorities,
)
from spaghetti_extractor.relational.lean.external_tail_static_pointer_slot_proposal import (
    construct_external_tail_static_pointer_slot_authorities,
    write_external_tail_static_pointer_slot_authorities,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    OriginalGenerationBlocker,
    OriginalRegion,
)
from tests.test_stage_a_relational_interpreter_mixed_original import (
    _pe32_writable_static_word_call_image,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_image() -> bytes:
    image = bytearray(_pe32_writable_static_word_call_image())
    struct.pack_into("<I", image, 0x408, 0)
    # Remove the HIGHLOW relocation over the now initially-zero slot.
    struct.pack_into("<H", image, 0x600 + 16 + 8 + 4, 0)
    return bytes(image)


def _row(
    rva: int,
    size: int,
    *,
    instructions: list[dict[str, object]],
    memory_events: list[dict[str, object]],
    ordered_events: list[dict[str, object]],
    outcome: dict[str, object],
) -> dict[str, object]:
    return {
        "format": "stage-a-semantic-transfer-contract-v1",
        "original": {
            "rva_start": rva,
            "rva_end": rva + size,
            "size": size,
        },
        "instructions": instructions,
        "memory_events": memory_events,
        "ordered_events": ordered_events,
        "outcome": outcome,
    }


class StageAExternalTailStaticPointerSlotProposalTests(unittest.TestCase):
    def test_exact_profile_emits_one_named_static_authority(self) -> None:
        image_base = 0x400000
        slot_va = image_base + 0x2008
        callback_va = image_base + 0x1040
        source = _row(
            0x1000,
            12,
            instructions=[
                {"rva": 0x1000, "size": 7, "mnemonic": "mov"},
                {"rva": 0x1007, "size": 5, "mnemonic": "call"},
            ],
            memory_events=[],
            ordered_events=[
                {
                    "instruction_rva": 0x1007,
                    "kind": "internal_call",
                    "return_rva": 0x100C,
                    "stack_inputs": [
                        {
                            "offset": 0,
                            "value": {
                                "op": "const",
                                "value": callback_va,
                                "width": 32,
                            },
                        }
                    ],
                    "target_rva": 0x1020,
                }
            ],
            outcome={"kind": "fallthrough", "target_rva": 0x100C},
        )
        wrapper = _row(
            0x1020,
            12,
            instructions=[
                {"rva": 0x1020, "size": 4, "mnemonic": "mov"},
                {"rva": 0x1024, "size": 5, "mnemonic": "mov"},
                {"rva": 0x1029, "size": 3, "mnemonic": "jmp"},
            ],
            memory_events=[
                {
                    "address": {
                        "op": "const",
                        "value": slot_va,
                        "width": 32,
                    },
                    "kind": "write",
                    "value": {
                        "address": {
                            "args": [
                                {"op": "const", "value": 4, "width": 32},
                                {
                                    "name": "esp",
                                    "op": "reg",
                                    "width": 32,
                                },
                            ],
                            "op": "add32",
                        },
                        "op": "load",
                        "width": 4,
                    },
                    "width": 4,
                }
            ],
            ordered_events=[],
            outcome={
                "dll": "msvcrt.dll",
                "kind": "external_jump",
                "symbol": "__setusermatherr",
            },
        )
        continuation = _row(
            0x100C,
            1,
            instructions=[{"rva": 0x100C, "size": 1, "mnemonic": "ret"}],
            memory_events=[],
            ordered_events=[],
            outcome={"kind": "return"},
        )
        callback = _row(
            0x1040,
            1,
            instructions=[{"rva": 0x1040, "size": 1, "mnemonic": "ret"}],
            memory_events=[],
            ordered_events=[],
            outcome={"kind": "return"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "fixture.exe"
            state = root / "state-machine.jsonl"
            report = root / "machine-import-report.json"
            pe.write_bytes(_fixture_image())
            state.write_text(
                "".join(
                    json.dumps(row, sort_keys=True) + "\n"
                    for row in (source, continuation, wrapper, callback)
                ),
                encoding="utf-8",
            )
            report.write_text(
                json.dumps(
                    {
                        "inputs": {
                            "original_sha256": _sha256(pe),
                            "state_machine_sha256": _sha256(state),
                        },
                        "signatures": [
                            {
                                "abi": "cdecl",
                                "arity": {"kind": "fixed", "words": 1},
                                "callback_mode": "registration",
                                "id": 7,
                                "import": {
                                    "dll": "msvcrt.dll",
                                    "symbol": "__setusermatherr",
                                },
                                "memory_footprints": [],
                            }
                        ],
                        "boundaries": [
                            {
                                "argument_words": 1,
                                "continuation_rva": 0x100C,
                                "frame_entry_rva": 0x1020,
                                "frame_entry_size": 12,
                                "id": 9,
                                "import": {
                                    "dll": "msvcrt.dll",
                                    "symbol": "__setusermatherr",
                                },
                                "instruction_rva": 0x1007,
                                "route": "framed_thunk_tail",
                                "signature_id": 7,
                                "source_rva": 0x1000,
                                "source_size": 12,
                                "tail_rva": 0x1020,
                                "tail_size": 12,
                            }
                        ],
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            plan = SimpleNamespace(
                state_machine_sha256=_sha256(state),
                regions=(
                    OriginalRegion(0, 0x1000, 12, (1, 2), False),
                    OriginalRegion(1, 0x100C, 1, (), False),
                    OriginalRegion(2, 0x1020, 12, (), False),
                    OriginalRegion(3, 0x1040, 1, (), False),
                ),
                blockers=(
                    OriginalGenerationBlocker(
                        "unresolved_indirect_control",
                        0x1000,
                        "static_pointer_slot at 0x1007: fixture frontier",
                    ),
                ),
            )
            authority = (
                construct_external_tail_static_pointer_slot_authorities(
                    original_pe=pe,
                    state_machine=state,
                    machine_import_report=report,
                    mixed_original_plan=plan,
                    context_term="StageA.Fixture.context",
                    original_context_term="StageA.Fixture.originalContext",
                    original_decoded_authority_term=(
                        "StageA.Fixture.originalAuthority"
                    ),
                    original_module="StageA.Fixture",
                )
            )
            report_path, sources = (
                write_external_tail_static_pointer_slot_authorities(
                    root / "out", authority
                )
            )

            payload = json.loads(report_path.read_text(encoding="utf-8"))
            generated = sources[0].read_text(encoding="utf-8")
            references = load_external_tail_static_pointer_slot_authorities(
                report_path,
                original_sha256=_sha256(pe),
                state_machine_sha256=_sha256(state),
                machine_import_report_sha256=_sha256(report),
            )
            with self.assertRaisesRegex(
                ExternalTailStaticPointerSlotAuthorityError,
                "original_sha256 does not match",
            ):
                load_external_tail_static_pointer_slot_authorities(
                    report_path,
                    original_sha256="0" * 64,
                    state_machine_sha256=_sha256(state),
                    machine_import_report_sha256=_sha256(report),
                )

        self.assertEqual(len(authority.bindings), 1)
        binding = authority.bindings[0]
        self.assertEqual(
            (
                binding.source_target_id,
                binding.wrapper_target_id,
                binding.continuation_target_id,
                binding.slot_target_id,
            ),
            (0, 2, 1, 3),
        )
        self.assertEqual(binding.route_kind, "direct_import")
        self.assertEqual(payload["counts"]["authority_terms"], 1)
        self.assertEqual(
            payload["counts"]["matching_mixed_original_frontiers"], 1
        )
        self.assertEqual(payload["counts"]["consumed_authority_terms"], 0)
        self.assertEqual(
            payload["counts"]["mixed_original_blockers_before"],
            payload["counts"]["mixed_original_blockers_after"],
        )
        self.assertIn("generatedStaticAuthority", generated)
        self.assertIn("allowedTargetIds := .exact [3]", generated)
        self.assertNotIn("native_decide", generated)
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0].key.callsite_rva, 0x1007)
        self.assertEqual(references[0].key.slot_rva, 0x2008)
        self.assertEqual(
            references[0].term.qualified,
            "StageA.Generated.ExternalTailStaticPointerSlotAuthority0009."
            "generatedStaticAuthority",
        )

    def test_nested_callback_signature_fails_closed(self) -> None:
        # The exact rejection is covered at the scanner boundary; the macro has
        # no constructor that can turn a nested callback protocol into a site.
        source = Path(
            "src/spaghetti_extractor/relational/lean/"
            "external_tail_static_pointer_slot_proposal.py"
        ).read_text(encoding="utf-8")
        self.assertIn('signature.get("callback_mode") == "nestedFrames"', source)
        self.assertIn("outside this macro profile", source)


if __name__ == "__main__":
    unittest.main()
